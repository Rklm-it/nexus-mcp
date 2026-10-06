"""Перенастройка нод Remnawave с хаба и каскад RU → Cloudflare → EU.

Зачем. Клиенту на Remnawave (бот 3XUIStore поверх) ноды нужно не только
ставить (`remna_install`), но и перенастраивать — быстро и без «зашёл в
панель, поправил профиль, забыл хост». Правка — одной операцией:

* `reality_sni` — SNI/dest Reality-инбаунда ноды + SNI его хостов;
* `host`        — поля строки подписки (подпись, адрес, порт, SNI, отпечаток,
                  скрыть/показать);
* `squad`       — инбаунд ноды в сквад / из сквада;
* `cf_exit`     — выход каскада на европейской ноде: VLESS+WS+TLS за
                  Cloudflare (A-запись с облаком, самоподписанный сертификат —
                  зона в режиме Full, порт открыт только сетям Cloudflare) и
                  реле-юзер со своим сквадом, в котором только этот инбаунд;
* `cascade_entry` — вход каскада на российской ноде: Reality-инбаунд
                  (firefox, minClientVer 1.0.0), реле на CF-домен выхода с mux,
                  правила «udp/53 и Рунет — напрямую, остальное — в реле»,
                  строка подписки (скрытая, пока не проверена с симок).

Рецепт каскада — тот, что работает у Nexus на ru-enter (vgx3d,
docs/journal/CDN.md 29.09–04.10.2026, services/cascade.py): телефон ходит на
российский IP, путь «российский ДЦ → Cloudflare» мобильные операторы не
морозят, заблокированный IP европейской ноды не нужен нигде. Под белыми
списками ТСПУ каскад CDN-ноды не заменяет.

Порядок любой операции — как у `node_edit`: без confirm — план (что
изменится, какие ноды перезапустят xray, проблемы, `plan_hash`); с confirm и
тем же `plan_hash` — применение. Всё, что применение создало или поменяло в
панели и Cloudflare, откатывается, если нода после правки не вышла на связь
или фронт не прошёл WebSocket-рукопожатие через Cloudflare.

Секреты (vlessUuid реле, privateKey Reality, токены) в ответы не попадают.
"""

from __future__ import annotations

import asyncio
import base64
import copy
import hashlib
import ipaddress
import json
import re
import secrets
import ssl
from dataclasses import dataclass, field
from typing import Any

import httpx

from nexus_mcp import config, remna, ssh
from nexus_mcp.node_install import parse_kv, scrub

OPS = ("reality_sni", "host", "squad", "cf_exit", "cascade_entry", "cascade_remove", "cf_exit_remove")

# Порты, которые Cloudflare проксирует по HTTPS без Spectrum: edge-порт =
# порт на ноде. Как у фронта Nexus (vgx3d services/cf_front.HTTPS_PORTS).
CF_PORTS = (2087, 2053, 2083, 2096, 8443)
# Порты входов каскада на российской ноде (vgx3d services/cascade.PORT_CANDIDATES).
ENTRY_PORTS = (8443, 2053, 2083, 2096, 9443, *range(10443, 40443, 1000))
CF_TAG = "HUB_CF_"
ENTRY_TAG = "HUB_CASCADE_"
RELAY_TAG = "HUB_RELAY_"
RELAY_USER = "hub-relay-"
# До стольких соединений клиентов на один WS к ноде выхода: без mux каждое
# соединение заново идёт TLS к Cloudflare + WS-апгрейд, 1–1,5 с до первого байта.
RELAY_MUX = 8
CF_CERT_DIR = "/etc/letsencrypt/hub-cf"
DONE_MARK = "RN_EDIT_DONE"
FAR_FUTURE = "2099-12-31T00:00:00.000Z"

SETTLE_S = 8          # Remnawave перезапускает xray на нодах профиля не мгновенно
HEALTH_WAIT_S = 60
VERIFY_ATTEMPTS = 6
VERIFY_PAUSE_S = 5.0
VERIFY_TIMEOUT_S = 12.0

# https://www.cloudflare.com/ips-v4 — порт фронта открыт только им, иначе IP
# ноды выдаёт себя сканеру (и фильтру) прямым ответом на этом порту.
CF_NETS = (
    "173.245.48.0/20", "103.21.244.0/22", "103.22.200.0/22", "103.31.4.0/22",
    "141.101.64.0/18", "108.162.192.0/18", "190.93.240.0/20", "188.114.96.0/20",
    "197.234.240.0/22", "198.41.128.0/17", "162.158.0.0/15", "104.16.0.0/13",
    "104.24.0.0/14", "172.64.0.0/13", "131.0.72.0/22",
)

# Рунет с входа каскада — напрямую с российского IP: банки и Госуслуги не
# пускают иностранные адреса. Без geosite: у образа remnawave/node свой
# geosite.dat, а ссылка на отсутствующую категорию = xray не стартует вовсе
# (инвариант 8 vgx3d). Наборы Яндекса/VK/Госуслуг — копия vgx3d
# services/service_domains.py, совпадение стережёт tests/test_remna_edit.py.
RU_TLD = ["domain:ru", "domain:su", "domain:xn--p1ai"]
YANDEX_DOMAINS = [
    "domain:yandex.ru", "domain:yandex.net", "domain:yandex.com", "domain:yandex.st",
    "domain:ya.ru", "domain:yastatic.net", "domain:yastat.net", "domain:yadi.sk",
    "domain:yandexcloud.net", "domain:yandex-team.ru", "domain:yandexmetrica.com",
    "domain:yandex.com.tr", "domain:yandexsport.com", "domain:yandexadexchange.net",
    "domain:kinopoisk.ru", "domain:kinopoisk.com", "domain:dzen.ru", "domain:zen.ru",
    "domain:taxi.yandex.net", "domain:appmetrica.yandex.net", "domain:tns-counter.ru",
]
VK_DOMAINS = [
    "domain:vk.com", "domain:vk.ru", "domain:vkontakte.ru", "domain:vk.cc",
    "domain:userapi.com", "domain:vk-cdn.net", "domain:vk-cdn.me", "domain:vkuser.net",
    "domain:vkuservideo.com", "domain:vkuservideo.net", "domain:vkuserlive.net",
    "domain:vk-apps.com", "domain:vkforms.ru", "domain:vkvideo.ru",
    "domain:vkplay.ru", "domain:vkplay.live", "domain:vkplaycdn.ru",
    "domain:mycdn.me", "domain:vk-portal.net", "domain:vkgroup.net",
    "domain:mail.ru", "domain:imgsmail.ru", "domain:my.com", "domain:mradar.imgsmail.ru",
    "domain:ok.ru", "domain:odnoklassniki.ru", "domain:okcdn.ru",
]
GOSUSLUGI_DOMAINS = ["domain:gosuslugi.ru", "domain:esia.gosuslugi.ru", "domain:gu-st.ru"]
RU_DIRECT = list(dict.fromkeys([*RU_TLD, *YANDEX_DOMAINS, *VK_DOMAINS, *GOSUSLUGI_DOMAINS]))

# Поля строки подписки, которые можно менять операцией `host`.
HOST_FIELDS = {"remark": str, "address": str, "port": int, "sni": str, "host": str, "path": str,
               "fingerprint": str, "alpn": str, "isDisabled": bool, "securityLayer": str}
FINGERPRINTS = ("firefox", "chrome", "safari", "ios", "android", "edge", "qq", "random", "randomized")

# Заглушки секретов в плане: ключи генерируются только при применении, чтобы
# plan_hash плана и применения совпадал.
_PK = "__HUB_REALITY_PRIVATE_KEY__"
_SID = "__HUB_SHORT_ID__"

# Для тестов: подмена транспорта Cloudflare и рукопожатия.
_CF_TRANSPORT: httpx.AsyncBaseTransport | None = None
CF_API = "https://api.cloudflare.com/client/v4"


class EditError(Exception):
    pass


# ── Мелочи ─────────────────────────────────────────────────────────────────

def _slug(name: str) -> str:
    return re.sub(r"[^A-Za-z0-9]", "", name or "").upper()[:16] or "NODE"


def _dns_slug(name: str) -> str:
    return re.sub(r"[^a-z0-9-]+", "-", (name or "").lower()).strip("-")[:40] or "node"


def relay_username(exit_name: str) -> str:
    return (RELAY_USER + _dns_slug(exit_name))[:36].rstrip("-")


def _is_ip(v: str) -> bool:
    try:
        ipaddress.ip_address(v)
        return True
    except ValueError:
        return False


def _in_cf(ip: str) -> bool:
    try:
        a = ipaddress.ip_address(ip)
    except ValueError:
        return False
    return any(a in ipaddress.ip_network(n) for n in CF_NETS)


def _resolve(host: str) -> list[str]:
    from nexus_mcp import remna_install
    return remna_install._resolve_ip(host)


def _hash(obj: Any) -> str:
    return hashlib.sha256(json.dumps(obj, sort_keys=True, ensure_ascii=False, default=str)
                          .encode()).hexdigest()[:16]


def _uuid_of(x: Any) -> str:
    return (x.get("uuid") if isinstance(x, dict) else x) or ""


def _direct_tag(cfg: dict) -> str:
    for o in cfg.get("outbounds") or []:
        if o.get("protocol") == "freedom" and o.get("tag"):
            return o["tag"]
    return ""


def _block_tags(cfg: dict) -> set[str]:
    return {o.get("tag") for o in cfg.get("outbounds") or [] if o.get("protocol") == "blackhole"}


# ── Состояние ноды ─────────────────────────────────────────────────────────

@dataclass
class State:
    panel: dict
    node: dict
    nodes: list[dict]
    profile: dict
    config: dict
    active: list[dict]            # [{uuid, tag}] — инбаунды профиля, включённые на ноде
    hosts: list[dict]             # строки подписки этой ноды
    all_hosts: list[dict]
    squads: list[dict]
    sharing: list[str]            # другие ноды на том же профиле

    @property
    def active_tags(self) -> list[str]:
        return [a["tag"] for a in self.active]

    def inbound(self, tag: str) -> dict | None:
        return next((i for i in self.config.get("inbounds") or [] if i.get("tag") == tag), None)

    def inbound_uuid(self, tag: str) -> str:
        return next((i.get("uuid", "") for i in self.profile.get("inbounds") or []
                     if i.get("tag") == tag), "")

    def fingerprint(self) -> dict:
        return {
            "node": self.node.get("uuid"),
            "profile": self.profile.get("uuid"),
            "config": self.config,
            "active": self.active_tags,
            "hosts": sorted((h.get("uuid", ""), _hash(h)) for h in self.hosts),
            "squads": sorted((s.get("uuid", ""), sorted(_uuid_of(i) for i in s.get("inbounds") or []))
                             for s in self.squads),
        }


async def load(p: dict, node_name: str) -> State:
    nodes = remna._list(await remna.request(p, "GET", "/api/nodes"))
    key = (node_name or "").strip().lower()
    hit = [n for n in nodes if key in ((n.get("name") or "").lower(), (n.get("address") or "").lower())
           or n.get("uuid") == node_name]
    if not hit:
        raise EditError(f"ноды «{node_name}» в Remnawave нет. Есть: "
                        + ", ".join(n.get("name", "?") for n in nodes))
    node = hit[0]
    cp = node.get("configProfile") or {}
    prof_uuid = cp.get("activeConfigProfileUuid")
    if not prof_uuid:
        raise EditError(f"у ноды «{node.get('name')}» нет конфиг-профиля")
    prof = await remna.request(p, "GET", f"/api/config-profiles/{prof_uuid}")
    by_uuid = {i.get("uuid"): i.get("tag") for i in prof.get("inbounds") or []}
    active = []
    for a in cp.get("activeInbounds") or []:
        uid = _uuid_of(a)
        tag = (a.get("tag") if isinstance(a, dict) else None) or by_uuid.get(uid)
        if tag:
            active.append({"uuid": uid or next((u for u, t in by_uuid.items() if t == tag), ""), "tag": tag})
    act_uuids = {a["uuid"] for a in active}
    all_hosts = remna._list(await remna.request(p, "GET", "/api/hosts"))
    hosts = [h for h in all_hosts
             if ((h.get("inbound") or {}).get("configProfileInboundUuid")
                 or h.get("configProfileInboundUuid")) in act_uuids]
    squads = remna._list(await remna.request(p, "GET", "/api/internal-squads"), "internalSquads")
    sharing = [n.get("name") for n in nodes if n.get("uuid") != node.get("uuid")
               and (n.get("configProfile") or {}).get("activeConfigProfileUuid") == prof_uuid]
    return State(p, node, nodes, prof, copy.deepcopy(prof.get("config") or {}), active,
                 hosts, all_hosts, squads, sharing)


# ── Изменение ──────────────────────────────────────────────────────────────

@dataclass
class Change:
    summary: list[str] = field(default_factory=list)
    problems: list[str] = field(default_factory=list)
    warnings: list[str] = field(default_factory=list)
    new_config: dict | None = None
    activate: list[str] = field(default_factory=list)          # теги инбаундов включить на ноде
    host_patches: list[tuple[str, dict, dict]] = field(default_factory=list)   # (uuid, new, old)
    host_creates: list[tuple[str, dict]] = field(default_factory=list)         # (тег инбаунда, тело)
    squad_add: list[tuple[str, str]] = field(default_factory=list)             # (uuid сквада, тег)
    squad_remove: list[tuple[str, str]] = field(default_factory=list)
    relay: dict | None = None        # {"username", "squad", "tag"} — реле-юзер выхода
    cf: dict | None = None           # {"host", "ip", "create": bool, "zone_id"}
    ssh_script: str = ""
    verify: dict | None = None       # {"host", "port", "path"}
    extra: dict = field(default_factory=dict)
    # Снятие (cascade_remove, cf_exit_remove): что выключить на ноде, из каких
    # сквадов убрать инбаунд (uuid сквада, uuid инбаунда) — с откатом; уборка
    # после проверки нод (хосты, юзер и сквад реле, запись Cloudflare) — без
    # отката: она безвредна, а её «вернуть» означало бы новые uuid.
    deactivate: list[str] = field(default_factory=list)
    squad_remove_uuid: list[tuple[str, str]] = field(default_factory=list)
    cleanup: list[tuple] = field(default_factory=list)

    def restarts(self, st: State) -> list[str]:
        if self.new_config is not None:
            return [st.node.get("name"), *st.sharing]
        return [st.node.get("name")] if self.activate or self.deactivate else []


def _pick_squad(squads: list[dict], name: str) -> dict | None:
    from nexus_mcp import remna_install
    return remna_install._pick_squad(squads, name)


def _reality_inbounds(st: State) -> list[dict]:
    return [i for i in st.config.get("inbounds") or [] if i.get("tag") in st.active_tags
            and ((i.get("streamSettings") or {}).get("security") == "reality")]


def _host_ref(h: dict) -> str:
    return f"«{h.get('remark')}» ({h.get('address')}:{h.get('port')})"


def op_reality_sni(st: State, args: dict) -> Change:
    ch = Change()
    sni = str(args.get("sni") or "").strip().lower().rstrip(".")
    if not re.match(r"^([a-z0-9-]+\.)+[a-z]{2,63}$", sni):
        ch.problems.append("args.sni — домен для SNI/dest (для мобильных — только из белого списка ТСПУ)")
        return ch
    reals = _reality_inbounds(st)
    tag = str(args.get("inbound") or "")
    if tag:
        reals = [i for i in reals if i.get("tag") == tag]
    if not reals:
        ch.problems.append("на ноде нет такого Reality-инбаунда" if tag else "на ноде нет Reality-инбаундов")
        return ch
    if len(reals) > 1:
        ch.problems.append("Reality-инбаундов несколько — укажите args.inbound: "
                           + ", ".join(i["tag"] for i in reals))
        return ch
    ib_tag = reals[0]["tag"]
    cfg = copy.deepcopy(st.config)
    rs = next(i for i in cfg["inbounds"] if i.get("tag") == ib_tag)["streamSettings"]["realitySettings"]
    old = list(rs.get("serverNames") or [])
    rs["serverNames"] = [sni]
    rs["target" if "target" in rs and "dest" not in rs else "dest"] = f"{sni}:443"
    rs.setdefault("minClientVer", "1.0.0")
    ch.new_config = cfg
    ch.summary.append(f"{ib_tag}: SNI {', '.join(old) or '—'} → {sni}, dest {sni}:443")
    uid = st.inbound_uuid(ib_tag)
    for h in st.hosts:
        if ((h.get("inbound") or {}).get("configProfileInboundUuid")) == uid and h.get("sni") != sni:
            ch.host_patches.append((h["uuid"], {"sni": sni}, {"sni": h.get("sni")}))
            ch.summary.append(f"строка {_host_ref(h)}: sni → {sni}")
    ch.warnings.append("Reality SNI — только из белого списка ТСПУ (dpi-checkers tcp-16-20), "
                       "иначе на мобильных соединение замерзает после ~16 КБ (инвариант 53)")
    return ch


def _find_host(st: State, ref: str) -> tuple[dict | None, str]:
    ref = (ref or "").strip()
    if not ref:
        if len(st.hosts) == 1:
            return st.hosts[0], ""
        return None, "у ноды несколько строк — укажите args.host (подпись или uuid): " + \
            ", ".join(_host_ref(h) for h in st.hosts)
    exact = [h for h in st.hosts if h.get("uuid") == ref or (h.get("remark") or "") == ref]
    part = exact or [h for h in st.hosts if ref.lower() in (h.get("remark") or "").lower()]
    if len(part) == 1:
        return part[0], ""
    if not part:
        return None, f"строки «{ref}» у ноды нет. Есть: " + ", ".join(_host_ref(h) for h in st.hosts)
    return None, f"под «{ref}» подходит несколько строк: " + ", ".join(_host_ref(h) for h in part)


def op_host(st: State, args: dict) -> Change:
    ch = Change()
    h, err = _find_host(st, str(args.get("host") or ""))
    if err:
        ch.problems.append(err)
        return ch
    new, old = {}, {}
    for k, v in (args.get("set") or {}).items():
        if k not in HOST_FIELDS:
            ch.problems.append(f"поле «{k}» менять нельзя; можно: {', '.join(HOST_FIELDS)}")
            continue
        try:
            if HOST_FIELDS[k] is bool and isinstance(v, str):
                v = v.strip().lower() in ("1", "true", "yes", "да")
            else:
                v = HOST_FIELDS[k](v)
        except (TypeError, ValueError):
            ch.problems.append(f"{k}: неверное значение «{v}»")
            continue
        if k == "fingerprint" and v not in FINGERPRINTS:
            ch.problems.append(f"fingerprint: {', '.join(FINGERPRINTS)}")
            continue
        if k == "fingerprint" and v == "chrome":
            ch.warnings.append("chrome режут МТС и Билайн без БС — для Reality нужен firefox (инвариант 56)")
        if k == "port" and not 0 < v < 65536:
            ch.problems.append("port: от 1 до 65535")
            continue
        if h.get(k) != v:
            new[k], old[k] = v, h.get(k)
    if not new and not ch.problems:
        ch.problems.append("args.set пуст или ничего не меняет")
    if new:
        ch.host_patches.append((h["uuid"], new, old))
        ch.summary.append(f"строка {_host_ref(h)}: "
                          + ", ".join(f"{k} {old[k]!r} → {new[k]!r}" for k in new))
    if "address" in new or "port" in new:
        ch.warnings.append("адрес/порт строки клиенты получат со следующего обновления подписки")
    return ch


def op_squad(st: State, args: dict) -> Change:
    ch = Change()
    tag = str(args.get("inbound") or "")
    if tag not in st.active_tags:
        ch.problems.append(f"инбаунда «{tag}» на ноде нет. Есть: {', '.join(st.active_tags)}")
        return ch
    sq = _pick_squad(st.squads, str(args.get("squad") or ""))
    if sq is None:
        ch.problems.append(f"сквад «{args.get('squad')}» не найден. Есть: "
                           + ", ".join(s.get("name", "?") for s in st.squads))
        return ch
    action = str(args.get("action") or "add")
    uid = st.inbound_uuid(tag)
    has = uid in [_uuid_of(i) for i in sq.get("inbounds") or []]
    if action == "add":
        if has:
            ch.problems.append(f"{tag} уже в скваде «{sq.get('name')}»")
        else:
            ch.squad_add.append((sq["uuid"], tag))
            ch.summary.append(f"{tag} → в сквад «{sq.get('name')}» (его клиенты получат строку)")
    elif action == "remove":
        if not has:
            ch.problems.append(f"{tag} нет в скваде «{sq.get('name')}»")
        else:
            ch.squad_remove.append((sq["uuid"], tag))
            ch.summary.append(f"{tag} — из сквада «{sq.get('name')}» "
                              f"({(sq.get('info') or {}).get('membersCount', '?')} клиентов потеряют строку)")
    else:
        ch.problems.append("args.action: add или remove")
    return ch


# ── Cloudflare ─────────────────────────────────────────────────────────────

async def _cf(p: dict, method: str, path: str, *, params: dict | None = None, body: Any = None) -> Any:
    kw: dict[str, Any] = {"timeout": 30.0,
                          "headers": {"Authorization": f"Bearer {p.get('cf_token', '')}"}}
    if _CF_TRANSPORT is not None:
        kw["transport"] = _CF_TRANSPORT
    async with httpx.AsyncClient(**kw) as c:
        try:
            r = await c.request(method, CF_API + path, params=params, json=body)
        except httpx.HTTPError as e:
            raise EditError(f"Cloudflare API не ответил: {type(e).__name__}: {e}") from e
    try:
        data = r.json()
    except ValueError:
        raise EditError(f"Cloudflare {r.status_code}: {(r.text or '')[:200]}") from None
    if not data.get("success"):
        errs = "; ".join(f"{e.get('code')}: {e.get('message')}" for e in data.get("errors") or [])
        raise EditError(f"Cloudflare {r.status_code}: {errs or 'отказ без причины'}")
    return data.get("result")


async def _cf_plan(st: State, ch: Change, host: str, ip: str, zone: str) -> None:
    p = st.panel
    if p.get("cf_token") and zone:
        try:
            zones = await _cf(p, "GET", "/zones", params={"name": zone})
            if not zones:
                ch.problems.append(f"зоны {zone} у токена Cloudflare нет")
                return
            zid = zones[0]["id"]
            mode = (await _cf(p, "GET", f"/zones/{zid}/settings/ssl") or {}).get("value")
            if mode == "strict":
                ch.problems.append(f"TLS зоны {zone} — Full (strict): самоподписанный сертификат ноды "
                                   "Cloudflare отвергнет (526). Нужен Full")
            elif mode != "full":
                ch.problems.append(f"TLS зоны {zone} — «{mode}»: к ноде Cloudflare пойдёт без TLS. Нужен Full")
            recs = await _cf(p, "GET", f"/zones/{zid}/dns_records", params={"name": host})
        except EditError as e:
            ch.problems.append(str(e))
            return
        if recs:
            r = recs[0]
            if r.get("type") != "A" or r.get("content") != ip or not r.get("proxied"):
                ch.problems.append(f"запись {host} уже есть: {r.get('type')} {r.get('content')}, "
                                   f"облако {'вкл' if r.get('proxied') else 'выкл'} — нужна A {ip} с облаком. "
                                   "Укажите другой args.cf_host или поправьте запись")
            else:
                ch.summary.append(f"Cloudflare: {host} → {ip} (облако) уже есть")
            ch.cf = {"host": host, "ip": ip, "create": False, "zone_id": zid}
        else:
            ch.summary.append(f"Cloudflare: A {host} → {ip}, оранжевое облако")
            ch.cf = {"host": host, "ip": ip, "create": True, "zone_id": zid}
        return
    ips = _resolve(host)
    if ips and all(_in_cf(i) for i in ips):
        ch.warnings.append(f"токена Cloudflare на хабе нет: запись {host} есть (адреса Cloudflare), "
                           "но куда она ведёт и режим TLS зоны (нужен Full) не проверить "
                           "(nexus-mcp-remna cf <панель> <зона> <токен>)")
        ch.cf = {"host": host, "ip": ip, "create": False, "zone_id": ""}
    else:
        ch.problems.append(f"{host} не за Cloudflare ({', '.join(ips) or 'не резолвится'}), а токена "
                           f"Cloudflare на хабе нет: создайте A {host} → {ip} с оранжевым облаком "
                           "или дайте хабу токен: nexus-mcp-remna cf <панель> <зона> <токен>")


# ── Скрипты на ноде ────────────────────────────────────────────────────────

def exit_precheck_script(port: int) -> str:
    return (
        "set +e\n"
        "echo \"mounts=$(docker inspect remnanode --format '{{range .Mounts}}{{.Destination}},{{end}}' 2>/dev/null)\"\n"
        "echo \"container=$(docker ps --filter name=remnanode --format '{{.Status}}' 2>/dev/null | head -1)\"\n"
        f"[ -s {CF_CERT_DIR}/fullchain.pem ] && echo hubcert=present || echo hubcert=absent\n"
        "command -v openssl >/dev/null 2>&1 && echo openssl=ok || echo openssl=absent\n"
        "echo \"ufw=$(ufw status 2>/dev/null | head -1 | awk '{print $2}')\"\n"
        f"o=$(ss -Hlnt 2>/dev/null | awk '$4 ~ \":{port}$\"' | head -1)\n"
        "[ -n \"$o\" ] && echo busy=yes || echo busy=no\n"
    )


def exit_apply_script(port: int, host: str, make_cert: bool) -> str:
    cert = ""
    if make_cert:
        cert = (
            f"if [ ! -s {CF_CERT_DIR}/fullchain.pem ]; then\n"
            f"  mkdir -p {CF_CERT_DIR} && chmod 700 {CF_CERT_DIR}\n"
            "  openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:prime256v1 -nodes -days 3650 \\\n"
            f"    -subj '/CN={host}' -keyout {CF_CERT_DIR}/privkey.pem -out {CF_CERT_DIR}/fullchain.pem \\\n"
            "    >/tmp/rn-cf-cert.log 2>&1 || { echo \"RN_ERR=сертификат не создан: $(tail -2 /tmp/rn-cf-cert.log | tr '\\n' ' ')\"; exit 12; }\n"
            "fi\n"
            "echo cert=ok\n"
        )
    nets = " ".join(CF_NETS)
    fw = (
        "if ufw status 2>/dev/null | grep -q '^Status: active'; then\n"
        f"  for n in {nets}; do ufw allow from \"$n\" to any port {port} proto tcp >/dev/null; done\n"
        "  echo ufw=opened\n"
        "fi\n"
    )
    return "set -u\n" + cert + fw + f"echo {DONE_MARK}\n"


def _ssh_node(st: State, args: dict) -> dict:
    addr = st.node.get("address") or ""
    ip = addr if _is_ip(addr) else (_resolve(addr) or [addr])[0]
    n = {"name": st.node.get("name"), "ssh_host": f"[{ip}]" if ":" in ip else ip,
         "ssh_port": int(args.get("ssh_port") or 22), "ssh_source": "адрес ноды Remnawave"}
    if args.get("ssh_user"):
        n["ssh_user"] = str(args["ssh_user"])
    return n


def _node_ip(st: State) -> str:
    addr = st.node.get("address") or ""
    if _is_ip(addr):
        return addr
    ips = _resolve(addr)
    return ips[0] if ips else ""


def _free_port(cfg: dict, candidates: tuple[int, ...], want: int = 0) -> int:
    used = {int(i.get("port") or 0) for i in cfg.get("inbounds") or [] if str(i.get("port", "")).isdigit()}
    if want:
        return 0 if want in used else want
    return next((c for c in candidates if c not in used), 0)


# ── Выход каскада ─────────────────────────────────────────────────────────

def cf_inbound(tag: str, port: int, path: str, host: str, cert: tuple[str, str]) -> dict:
    return {
        "tag": tag, "port": port, "listen": "0.0.0.0", "protocol": "vless",
        "settings": {"clients": [], "decryption": "none"},
        "sniffing": {"enabled": True, "routeOnly": True, "destOverride": ["http", "tls", "quic"]},
        "streamSettings": {
            "network": "ws", "security": "tls",
            # Имя фронта живёт в самом инбаунде: по нему вход каскада находит,
            # куда вести реле, без отдельного хранилища.
            "wsSettings": {"path": path, "host": host},
            "tlsSettings": {
                # Cloudflare ходит к origin за WebSocket по HTTP/1.1; h2 ломает Upgrade.
                "alpn": ["http/1.1"],
                "certificates": [{"certificateFile": cert[0], "keyFile": cert[1]}],
            },
            "sockopt": {"tcpKeepAliveInterval": 30, "tcpNoDelay": True, "tcpUserTimeout": 10000},
        },
    }


def _existing_cert(st: State) -> tuple[str, str] | None:
    for i in st.config.get("inbounds") or []:
        if i.get("tag") not in st.active_tags:
            continue
        for c in ((i.get("streamSettings") or {}).get("tlsSettings") or {}).get("certificates") or []:
            if c.get("certificateFile") and c.get("keyFile"):
                return c["certificateFile"], c["keyFile"]
    return None


def cf_front_of(st: State) -> dict | None:
    """Фронт выхода на этой ноде (тег HUB_CF_*): {tag, host, port, path}."""
    for i in st.config.get("inbounds") or []:
        if str(i.get("tag", "")).startswith(CF_TAG) and i.get("tag") in st.active_tags:
            ws = (i.get("streamSettings") or {}).get("wsSettings") or {}
            return {"tag": i["tag"], "host": ws.get("host") or "", "port": i.get("port"),
                    "path": ws.get("path") or "/"}
    return None


async def _find_user(p: dict, username: str) -> dict | None:
    try:
        return await remna.request(p, "GET", f"/api/users/by-username/{username}")
    except remna.RemnaError as e:
        if e.status == 404:
            return None
        raise


async def op_cf_exit(st: State, args: dict) -> Change:
    ch = Change()
    name = st.node.get("name") or ""
    if cf_front_of(st):
        f = cf_front_of(st)
        ch.problems.append(f"фронт уже есть: {f['tag']} → {f['host']}:{f['port']}")
        return ch
    zone = str(args.get("zone") or st.panel.get("cf_zone") or "").lower().strip(".")
    host = str(args.get("cf_host") or (f"{_dns_slug(name)}.{zone}" if zone else "")).lower()
    if not host:
        ch.problems.append("нет зоны Cloudflare: args.zone или nexus-mcp-remna cf <панель> <зона> <токен>")
        return ch
    if zone and not host.endswith("." + zone):
        ch.problems.append(f"{host} не в зоне {zone}")
    ip = _node_ip(st)
    if not ip:
        ch.problems.append(f"адрес ноды {st.node.get('address')} не резолвится")
        return ch
    port = _free_port(st.config, CF_PORTS, int(args.get("port") or 0))
    if not port:
        ch.problems.append(f"порт {args.get('port')} уже занят в профиле" if args.get("port")
                           else f"в профиле заняты все порты Cloudflare {CF_PORTS}")
        return ch
    if port not in CF_PORTS:
        ch.problems.append(f"порт {port} Cloudflare не проксирует как есть; можно: {CF_PORTS}")
    path = "/" + hashlib.sha256(f"{st.node.get('uuid')}:cf".encode()).hexdigest()[:12]
    tag = CF_TAG + _slug(name)

    # Сервер: сертификат (самоподписанный — зона в Full) и файрвол.
    res = await ssh.run_script(_ssh_node(st, args), exit_precheck_script(port), timeout=40)
    pre = parse_kv(res.stdout) if res.ok else {}
    cert: tuple[str, str] | None = None
    make_cert = False
    if res.ok:
        if pre.get("busy") == "yes":
            ch.problems.append(f"порт {port} на ноде уже кто-то слушает")
        if "/etc/letsencrypt" in (pre.get("mounts") or ""):
            cert = (f"{CF_CERT_DIR}/fullchain.pem", f"{CF_CERT_DIR}/privkey.pem")
            make_cert = pre.get("hubcert") != "present"
            if make_cert and pre.get("openssl") != "ok":
                ch.problems.append("на ноде нет openssl — сертификат фронта не создать")
        else:
            cert = _existing_cert(st)
            if cert:
                ch.warnings.append("/etc/letsencrypt не смонтирован в remnanode — фронт возьмёт "
                                   f"сертификат ноды ({cert[0]}); режим Full его примет")
        if pre.get("ufw") == "active":
            ch.summary.append(f"ufw: порт {port}/tcp — только сетям Cloudflare")
        ch.ssh_script = exit_apply_script(port, host, make_cert)
    else:
        cert = _existing_cert(st)
        msg = f"SSH до ноды не прошёл ({res.hint() or res.stderr[-200:]})"
        if cert:
            ch.warnings.append(msg + f": фронт возьмёт сертификат ноды, файрвол не трогаю — "
                                     f"порт {port}/tcp откройте сетям Cloudflare сами")
        else:
            ch.problems.append(msg + ": сертификата для фронта нет и создать его негде "
                                     "(ключ хаба — в authorized_keys ноды)")
    if cert is None and not ch.problems:
        ch.problems.append("сертификата для фронта нет: /etc/letsencrypt не смонтирован в remnanode "
                           "и TLS-инбаундов с сертификатом на ноде нет")
    if make_cert:
        ch.summary.append(f"на ноде: самоподписанный сертификат {CF_CERT_DIR} (зона в режиме Full)")

    await _cf_plan(st, ch, host, ip, zone)

    cfg = copy.deepcopy(st.config)
    if cert:
        cfg.setdefault("inbounds", []).append(cf_inbound(tag, port, path, host, cert))
    ch.new_config = cfg
    ch.activate.append(tag)
    ch.summary.append(f"профиль {st.profile.get('name')}: инбаунд {tag} VLESS+WS+TLS :{port}, путь {path}; "
                      f"включён только на {name}")
    uname = relay_username(name)
    if await _find_user(st.panel, uname):
        ch.problems.append(f"реле-юзер {uname} уже есть — фронт заводили и снимали руками? "
                           "Удалите его или переименуйте")
    sq_name = uname
    if any((s.get("name") or "").lower() == sq_name for s in st.squads):
        ch.problems.append(f"сквад {sq_name} уже есть")
    ch.relay = {"username": uname, "squad": sq_name, "tag": tag}
    ch.summary.append(f"реле: сквад {sq_name} (только {tag}) и юзер {uname} без срока и лимита — "
                      "через него входы каскада ходят к этой ноде")
    ch.warnings.append(f"юзер {uname} — служебный: бот 3XUIStore его не знает; не удалять и не продлевать")
    if args.get("public"):
        sq = _pick_squad(st.squads, str(args.get("squad") or ""))
        if sq is None:
            ch.problems.append("сквад для публичной строки не найден")
        else:
            remark = str(args.get("remark") or f"{name} · CF")[:100]
            ch.host_creates.append((tag, {
                "remark": remark, "address": host, "port": port, "sni": host, "host": host,
                "path": path, "alpn": "http/1.1", "fingerprint": "firefox", "securityLayer": "TLS",
                "nodes": [st.node.get("uuid")], "isDisabled": bool(args.get("hidden", False)),
            }))
            ch.squad_add.append((sq["uuid"], tag))
            ch.summary.append(f"строка «{remark}» → {host}:{port} (Wi-Fi), сквад «{sq.get('name')}»")
            ch.warnings.append("CF-строка — для домашнего интернета: с мобильного без БС соединение к "
                               "Cloudflare замерзает после ~16 КБ (инвариант 53)")
    ch.verify = {"host": host, "port": port, "path": path}
    ch.extra = {"front": {"host": host, "port": port, "tag": tag}}
    return ch


# ── Вход каскада ──────────────────────────────────────────────────────────

def relay_outbound(tag: str, front: dict, relay_uuid: str) -> dict:
    host = front["host"]
    return {
        "tag": tag, "protocol": "vless",
        "settings": {"vnext": [{"address": host, "port": int(front["port"]),
                                "users": [{"id": relay_uuid, "encryption": "none"}]}]},
        "streamSettings": {
            "network": "ws", "security": "tls",
            "tlsSettings": {"serverName": host, "fingerprint": "chrome", "alpn": ["http/1.1"]},
            "wsSettings": {"path": front["path"], "headers": {"Host": host}},
            # Без keepAlive мобильные/CGNAT режут простаивающий TCP за 5–10 минут.
            "sockopt": {"tcpKeepAliveInterval": 30, "tcpKeepAliveIdle": 60, "tcpNoDelay": True,
                        "tcpUserTimeout": 10000, "domainStrategy": "UseIPv4"},
        },
        # UDP мимо mux (-1): DNS телефонов внутри mux не получал ответа (CDN.md 30.09).
        "mux": {"enabled": True, "concurrency": RELAY_MUX, "xudpConcurrency": -1,
                "xudpProxyUDP443": "skip"},
    }


def entry_inbound(tag: str, port: int, sni: str) -> dict:
    return {
        "tag": tag, "port": port, "listen": "0.0.0.0", "protocol": "vless",
        "settings": {"clients": [], "decryption": "none", "flow": "xtls-rprx-vision"},
        "sniffing": {"enabled": True, "routeOnly": True, "destOverride": ["http", "tls", "quic"]},
        "streamSettings": {
            "network": "tcp", "security": "reality",
            "realitySettings": {
                "show": False, "xver": 0, "dest": f"{sni}:443", "serverNames": [sni],
                "privateKey": _PK, "shortIds": [_SID, ""],
                # xray 26.7.11+ иначе не пускает Happ/INCY/sing-box старее 26.3.27 (инвариант 55).
                "minClientVer": "1.0.0",
            },
        },
    }


def entry_rules(in_tag: str, relay_tag: str, direct: str) -> list[dict]:
    return [
        {"type": "field", "inboundTag": [in_tag], "domain": list(RU_DIRECT), "outboundTag": direct},
        {"type": "field", "inboundTag": [in_tag], "outboundTag": relay_tag},
    ]


def _dns_rule(direct: str) -> dict:
    # Без inboundTag: DNS телефонов отвечает российский IP напрямую, через реле
    # UDP терялся — пинг есть, сайты нет (CDN.md 30.09).
    return {"type": "field", "network": "udp", "port": "53", "outboundTag": direct}


def _insert_at(rules: list[dict], blocks: set[str]) -> int:
    i = 0
    while i < len(rules) and rules[i].get("outboundTag") in blocks:
        i += 1
    return i


async def op_cascade_entry(st: State, args: dict) -> Change:
    ch = Change()
    exit_name = str(args.get("exit") or "")
    if not exit_name:
        ch.problems.append("args.exit — нода выхода (европейская, с фронтом cf_exit)")
        return ch
    try:
        ex = await load(st.panel, exit_name)
    except EditError as e:
        ch.problems.append(str(e))
        return ch
    if ex.node.get("uuid") == st.node.get("uuid"):
        ch.problems.append("вход и выход — одна нода")
        return ch
    front = cf_front_of(ex)
    if not front or not front["host"]:
        ch.problems.append(f"у {ex.node.get('name')} нет фронта Cloudflare — сначала op=cf_exit на ней")
        return ch
    relay_user = await _find_user(st.panel, relay_username(ex.node.get("name") or ""))
    relay_uuid = (relay_user or {}).get("vlessUuid") or ""
    if not relay_uuid:
        ch.problems.append(f"реле-юзера {relay_username(ex.node.get('name') or '')} нет — "
                           f"повторите op=cf_exit на {ex.node.get('name')}")
        return ch
    sni = str(args.get("sni") or "").strip().lower().rstrip(".")
    if not re.match(r"^([a-z0-9-]+\.)+[a-z]{2,63}$", sni):
        ch.problems.append("args.sni — SNI входа: для мобильных — домен из белого списка ТСПУ "
                           "(как у рабочих Reality клиента), для Wi-Fi — свой домен (инвариант 62)")
        return ch
    in_tag = ENTRY_TAG + _slug(ex.node.get("name") or "")
    out_tag = RELAY_TAG + _slug(ex.node.get("name") or "")
    if st.inbound(in_tag):
        ch.problems.append(f"вход {in_tag} на ноде уже есть")
        return ch
    port = _free_port(st.config, ENTRY_PORTS, int(args.get("port") or 0))
    if not port:
        ch.problems.append(f"порт {args.get('port')} уже занят в профиле" if args.get("port")
                           else "в профиле кончились порты под входы")
        return ch

    cfg = copy.deepcopy(st.config)
    direct = _direct_tag(cfg)
    if not direct:
        direct = "DIRECT"
        cfg.setdefault("outbounds", []).append({"tag": direct, "protocol": "freedom"})
        ch.summary.append("в профиль добавлен выход DIRECT (freedom)")
    cfg.setdefault("inbounds", []).append(entry_inbound(in_tag, port, sni))
    cfg["outbounds"] = [o for o in cfg.get("outbounds") or [] if o.get("tag") != out_tag]
    cfg["outbounds"].append(relay_outbound(out_tag, front, relay_uuid))
    routing = cfg.setdefault("routing", {})
    rules = list(routing.get("rules") or [])
    at = _insert_at(rules, _block_tags(cfg))
    new_rules = entry_rules(in_tag, out_tag, direct)
    if not any(r.get("network") == "udp" and str(r.get("port")) == "53" for r in rules):
        new_rules.insert(0, _dns_rule(direct))
    rules[at:at] = new_rules
    routing["rules"] = rules
    ch.new_config = cfg
    ch.activate.append(in_tag)
    ex_name = ex.node.get("name")
    ch.summary += [
        f"профиль {st.profile.get('name')}: вход {in_tag} VLESS Reality :{port} (SNI {sni}, "
        "minClientVer 1.0.0); ключи сгенерирует панель при применении",
        f"реле {out_tag} → {front['host']}:{front['port']} (WS+TLS, mux {RELAY_MUX}) — юзер "
        f"{relay_username(ex_name or '')}",
        f"правила (перед общими): udp/53 и Рунет ({len(RU_DIRECT)} доменов) — {direct}, "
        f"остальное с {in_tag} — в {out_tag}",
    ]
    sq = _pick_squad(st.squads, str(args.get("squad") or ""))
    if sq is None:
        ch.problems.append(f"сквад «{args.get('squad')}» не найден")
    else:
        flag = remark_flag(ex.node.get("countryCode") or "")
        remark = str(args.get("remark") or f"{flag} {ex_name} · через РФ").strip()[:100]
        hidden = bool(args.get("hidden", True))
        ch.host_creates.append((in_tag, {
            "remark": remark, "address": st.node.get("address"), "port": port, "sni": sni,
            "fingerprint": "firefox", "securityLayer": "DEFAULT",
            "nodes": [st.node.get("uuid")], "isDisabled": hidden,
        }))
        ch.squad_add.append((sq["uuid"], in_tag))
        ch.summary.append(f"строка «{remark}» → {st.node.get('address')}:{port}"
                          + (" — СКРЫТА, пока не проверена с симок (op=host, set isDisabled=false)"
                             if hidden else "") + f"; сквад «{sq.get('name')}»")
    ch.warnings.append("каскад — для мобильных без белых списков и Wi-Fi; под БС работают только "
                       "CDN-ноды (инвариант 45)")
    ch.warnings.append("проверять вход домашним пробником/симками, не только хабом: у хаба свежий xray "
                       "(инвариант 55)")
    ch.extra = {"exit": ex_name, "front": front}
    return ch


# ── Снятие каскада ────────────────────────────────────────────────────────

def _remove_inbound_parts(st: State, ch: Change, tag: str) -> None:
    """Инбаунд уходит с ноды: из сквадов (с откатом), его строки — уборкой."""
    uid = st.inbound_uuid(tag)
    for sq in st.squads:
        if uid and uid in [_uuid_of(i) for i in sq.get("inbounds") or []]:
            ch.squad_remove_uuid.append((sq["uuid"], uid))
            ch.summary.append(f"{tag} — из сквада «{sq.get('name')}»")
    for h in st.all_hosts:
        if ((h.get("inbound") or {}).get("configProfileInboundUuid")) == uid:
            ch.cleanup.append(("host", h["uuid"]))
            ch.summary.append(f"строка {_host_ref(h)} — удалить")
    ch.deactivate.append(tag)


def op_cascade_remove(st: State, args: dict) -> Change:
    ch = Change()
    exit_name = str(args.get("exit") or "")
    entries = [t for t in st.active_tags if t.startswith(ENTRY_TAG)]
    in_tag = ENTRY_TAG + _slug(exit_name) if exit_name else (entries[0] if len(entries) == 1 else "")
    if not in_tag or in_tag not in st.active_tags:
        ch.problems.append("входа каскада с таким выходом на ноде нет. Есть: " + (", ".join(entries) or "—")
                           + ("" if exit_name or len(entries) < 2 else " — укажите args.exit"))
        return ch
    ib = st.inbound(in_tag) or {}
    out_tags = {r.get("outboundTag") for r in (st.config.get("routing") or {}).get("rules") or []
                if r.get("inboundTag") == [in_tag] and str(r.get("outboundTag", "")).startswith(RELAY_TAG)}
    cfg = copy.deepcopy(st.config)
    cfg["inbounds"] = [i for i in cfg.get("inbounds") or [] if i.get("tag") != in_tag]
    rules = [r for r in (cfg.get("routing") or {}).get("rules") or [] if r.get("inboundTag") != [in_tag]]
    cfg.setdefault("routing", {})["rules"] = rules
    used = {r.get("outboundTag") for r in rules}
    dropped = [t for t in out_tags if t not in used]
    cfg["outbounds"] = [o for o in cfg.get("outbounds") or [] if o.get("tag") not in dropped]
    ch.new_config = cfg
    ch.summary.append(f"профиль {st.profile.get('name')}: убрать вход {in_tag} (:{ib.get('port')}), его правила"
                      + (f" и реле {', '.join(sorted(dropped))}" if dropped else ""))
    _remove_inbound_parts(st, ch, in_tag)
    ch.warnings.append("у клиентов строка входа пропадёт со следующего обновления подписки; до него "
                       "она перестанет работать сразу")
    return ch


async def _profiles(p: dict) -> list[dict]:
    rows = remna._list(await remna.request(p, "GET", "/api/config-profiles"), "configProfiles")
    out = []
    for r in rows:
        if "config" not in r and r.get("uuid"):
            r = await remna.request(p, "GET", f"/api/config-profiles/{r['uuid']}")
        out.append(r)
    return out


async def op_cf_exit_remove(st: State, args: dict) -> Change:
    ch = Change()
    front = cf_front_of(st)
    if not front:
        ch.problems.append("фронта Cloudflare (HUB_CF_*) на ноде нет")
        return ch
    # Входы каскада, смотрящие на этот фронт, иначе молча лишатся выхода.
    users_of = []
    for pr in await _profiles(st.panel):
        for o in (pr.get("config") or {}).get("outbounds") or []:
            vn = ((o.get("settings") or {}).get("vnext") or [{}])[0]
            if vn.get("address") == front["host"]:
                nodes = [n.get("name") for n in st.nodes
                         if (n.get("configProfile") or {}).get("activeConfigProfileUuid") == pr.get("uuid")]
                users_of.append(f"{pr.get('name')} ({', '.join(nodes) or 'без нод'}): {o.get('tag')}")
    if users_of:
        ch.problems.append("на фронт ещё смотрят входы каскада — сперва op=cascade_remove на их нодах: "
                           + "; ".join(users_of))
    cfg = copy.deepcopy(st.config)
    cfg["inbounds"] = [i for i in cfg.get("inbounds") or [] if i.get("tag") != front["tag"]]
    ch.new_config = cfg
    ch.summary.append(f"профиль {st.profile.get('name')}: убрать фронт {front['tag']} (:{front['port']})")
    _remove_inbound_parts(st, ch, front["tag"])
    uname = relay_username(st.node.get("name") or "")
    user = await _find_user(st.panel, uname)
    if user:
        ch.cleanup.append(("user", user["uuid"]))
        ch.summary.append(f"реле-юзер {uname} — удалить")
    for sq in st.squads:
        if (sq.get("name") or "").lower() == uname:
            ch.cleanup.append(("squad", sq["uuid"]))
            ch.summary.append(f"сквад {uname} — удалить")
    p = st.panel
    ip = _node_ip(st)
    if p.get("cf_token") and p.get("cf_zone") and front["host"].endswith("." + p["cf_zone"]):
        try:
            zones = await _cf(p, "GET", "/zones", params={"name": p["cf_zone"]})
            recs = await _cf(p, "GET", f"/zones/{zones[0]['id']}/dns_records",
                             params={"name": front["host"]}) if zones else []
        except EditError as e:
            recs = []
            ch.warnings.append(f"Cloudflare: {e} — запись {front['host']} уберите руками")
        for r in recs:
            if r.get("type") == "A" and r.get("content") == ip:
                ch.cleanup.append(("cf", zones[0]["id"], r["id"]))
                ch.summary.append(f"Cloudflare: удалить A {front['host']} → {ip}")
    else:
        ch.warnings.append(f"запись Cloudflare {front['host']} хаб не уберёт (нет токена зоны) — уберите руками")
    ch.warnings.append(f"правило ufw для порта {front['port']} на ноде остаётся (безвредно)")
    return ch


def remark_flag(cc: str) -> str:
    cc = (cc or "").upper()
    return "".join(chr(0x1F1E6 + ord(c) - 65) for c in cc) if re.match(r"^[A-Z]{2}$", cc) else ""


# ── План и применение ─────────────────────────────────────────────────────

async def _change(st: State, op: str, args: dict) -> Change:
    if op == "reality_sni":
        return op_reality_sni(st, args)
    if op == "host":
        return op_host(st, args)
    if op == "squad":
        return op_squad(st, args)
    if op == "cf_exit":
        return await op_cf_exit(st, args)
    if op == "cascade_entry":
        return await op_cascade_entry(st, args)
    if op == "cascade_remove":
        return op_cascade_remove(st, args)
    if op == "cf_exit_remove":
        return await op_cf_exit_remove(st, args)
    raise EditError(f"op: {', '.join(OPS)}")


def _plan_hash(st: State, op: str, args: dict, ch: Change) -> str:
    safe_args = {k: v for k, v in args.items() if k not in ("ssh_user",)}
    return _hash({"op": op, "args": safe_args, "state": st.fingerprint(),
                  "config": ch.new_config, "hosts": ch.host_creates, "patches": ch.host_patches,
                  "cf": ch.cf, "ssh": ch.ssh_script, "cleanup": ch.cleanup})


async def plan(panel_name: str, node: str, op: str, args: dict | None = None) -> dict:
    if op not in OPS:
        raise EditError(f"op: {', '.join(OPS)}")
    args = dict(args or {})
    p = remna.resolve(panel_name)
    st = await load(p, node)
    ch = await _change(st, op, args)
    restarts = ch.restarts(st)
    if restarts:
        ch.warnings.append("xray перезапустится на: " + ", ".join(restarts)
                           + " — у клиентов этих нод соединения оборвутся на секунды")
    if st.sharing and op == "reality_sni":
        ch.warnings.append(f"профиль {st.profile.get('name')} общий с: {', '.join(st.sharing)} — "
                           "SNI сменится и у них")
    if not st.node.get("isConnected"):
        ch.warnings.append(f"нода {st.node.get('name')} сейчас не на связи с панелью — после правки "
                           "проверить её не получится")
    return {
        "ok": not ch.problems,
        "panel": p["name"],
        "node": st.node.get("name"),
        "op": op,
        "changes": ch.summary,
        "problems": ch.problems,
        "warnings": ch.warnings,
        "plan_hash": _plan_hash(st, op, args, ch),
        "next": "покажите план человеку; согласится — тот же вызов с confirm=true и plan_hash"
                if not ch.problems else "исправьте проблемы и запросите план снова",
    }


def _fill_secrets(cfg: dict, keys: dict | None) -> None:
    for i in cfg.get("inbounds") or []:
        rs = (i.get("streamSettings") or {}).get("realitySettings") or {}
        if rs.get("privateKey") == _PK:
            if not keys or not keys.get("privateKey"):
                raise EditError("панель не отдала ключи Reality (/api/system/tools/x25519/generate)")
            rs["privateKey"] = keys["privateKey"]
        if _SID in (rs.get("shortIds") or []):
            rs["shortIds"] = [secrets.token_hex(4) if s == _SID else s for s in rs["shortIds"]]


async def ws_handshake(host: str, port: int, path: str, timeout: float = VERIFY_TIMEOUT_S) -> int:
    """WebSocket-рукопожатие через Cloudflare до xray — сырой код ответа
    (101 или 52x Cloudflare). Копия логики vgx3d services/cf_front.ws_handshake."""
    ctx = ssl.create_default_context()
    reader, writer = await asyncio.wait_for(
        asyncio.open_connection(host, port, ssl=ctx, server_hostname=host), timeout=timeout)
    try:
        key = base64.b64encode(secrets.token_bytes(16)).decode()
        writer.write((f"GET {path} HTTP/1.1\r\nHost: {host}\r\nUpgrade: websocket\r\n"
                      f"Connection: Upgrade\r\nSec-WebSocket-Key: {key}\r\n"
                      "Sec-WebSocket-Version: 13\r\nUser-Agent: Mozilla/5.0\r\n\r\n").encode())
        await writer.drain()
        line = await asyncio.wait_for(reader.readline(), timeout=timeout)
    finally:
        writer.close()
        try:
            await writer.wait_closed()
        except Exception:  # noqa: BLE001
            pass
    parts = line.decode(errors="replace").split()
    if len(parts) < 2 or not parts[1].isdigit():
        raise ConnectionError(f"непонятный ответ: {line[:80]!r}")
    return int(parts[1])


_CF_CODES = {
    521: "Cloudflare: нода отказала в соединении (521) — xray не слушает порт или файрвол",
    522: "Cloudflare не дождался ноды (522) — порт закрыт файрволом или нода недоступна",
    525: "TLS между Cloudflare и нодой не сошёлся (525)",
    526: "Cloudflare отверг сертификат ноды (526): зона в Full (strict), нужен Full",
    530: "Cloudflare не нашёл адрес (530) — A-запись ещё не доехала",
}


async def verify_front(host: str, port: int, path: str) -> dict:
    last, code = "", 0
    for attempt in range(VERIFY_ATTEMPTS):
        try:
            code = await ws_handshake(host, port, path)
        except Exception as e:  # noqa: BLE001
            code, last = 0, f"{type(e).__name__}: {e}"
        else:
            if code == 101:
                return {"ok": True, "attempts": attempt + 1}
            last = _CF_CODES.get(code, f"ответ HTTP {code} вместо 101")
        if attempt + 1 < VERIFY_ATTEMPTS:
            await asyncio.sleep(VERIFY_PAUSE_S)
    return {"ok": False, "code": code, "error": last}


async def _wait_healthy(p: dict, uuids: list[str]) -> list[str]:
    """Ноды из списка, не вышедшие на связь после правки (пусто — все в порядке)."""
    if not uuids:
        return []
    await asyncio.sleep(SETTLE_S)
    bad: list[str] = []
    for _ in range(max(1, HEALTH_WAIT_S // 5)):
        bad = []
        for uid in uuids:
            try:
                n = await remna.request(p, "GET", f"/api/nodes/{uid}")
            except remna.RemnaError:
                bad.append(uid)
                continue
            if not n.get("isConnected"):
                bad.append(n.get("name") or uid)
        if not bad:
            return []
        await asyncio.sleep(5)
    return bad


async def apply(panel_name: str, node: str, op: str, args: dict | None, plan_hash: str) -> dict:
    if not config.settings.allow_actions:
        return {"ok": False, "error": "actions_disabled",
                "detail": "действия выключены на хабе (NEXUS_ALLOW_ACTIONS=1 чтобы включить)"}
    if op not in OPS:
        raise EditError(f"op: {', '.join(OPS)}")
    args = dict(args or {})
    p = remna.resolve(panel_name)
    st = await load(p, node)
    ch = await _change(st, op, args)
    if ch.problems:
        return {"ok": False, "error": "plan_problems", "problems": ch.problems}
    if plan_hash != _plan_hash(st, op, args, ch):
        return {"ok": False, "error": "plan_changed",
                "detail": "нода или панель изменились с момента показа плана — покажите новый",
                "plan": await plan(panel_name, node, op, args)}

    log: list[str] = []
    undo: list[tuple[str, Any]] = []
    secrets_seen: list[str] = []

    async def rollback(reason: str) -> dict:
        undone = []
        for kind, data in reversed(undo):
            try:
                if kind == "cf":
                    await _cf(p, "DELETE", f"/zones/{data[0]}/dns_records/{data[1]}")
                elif kind in ("host_delete", "user_delete", "squad_delete"):
                    path = {"host_delete": "/api/hosts/", "user_delete": "/api/users/",
                            "squad_delete": "/api/internal-squads/"}[kind]
                    await remna.request(p, "DELETE", path + data)
                else:
                    path = {"profile": "/api/config-profiles", "node": "/api/nodes",
                            "host": "/api/hosts", "squad": "/api/internal-squads"}[kind]
                    await remna.request(p, "PATCH", path, body=data)
                undone.append(kind)
            except (remna.RemnaError, EditError) as e:
                undone.append(f"{kind}: не откатилось ({e})")
        return {"ok": False, "error": "edit_failed", "detail": scrub(reason, secrets_seen),
                "log": log, "rolled_back": undone}

    # 1. Сервер (сертификат фронта, файрвол) — безвредно и без отката.
    if ch.ssh_script:
        res = await ssh.run_script(_ssh_node(st, args), ch.ssh_script, timeout=120)
        out = res.stdout + "\n" + res.stderr
        if DONE_MARK not in out:
            err = next((ln.split("=", 1)[1] for ln in out.splitlines() if ln.startswith("RN_ERR=")), "")
            return {"ok": False, "error": "server_failed",
                    "detail": err or (out.strip().splitlines() or ["нет вывода"])[-1][:300]}
        kv = parse_kv(out)
        log.append("нода: " + (", ".join(f"{k} {kv[k]}" for k in ("cert", "ufw") if kv.get(k)) or "ok"))

    try:
        # 2а. Снятие: сперва убрать инбаунд из сквадов и выключить на ноде —
        # профиль без инбаунда, который нода ещё держит включённым, панель
        # может не принять.
        if ch.squad_remove_uuid:
            squads = remna._list(await remna.request(p, "GET", "/api/internal-squads"), "internalSquads")
            for sq_uuid in dict.fromkeys(s_ for s_, _ in ch.squad_remove_uuid):
                sq = next((x for x in squads if x.get("uuid") == sq_uuid), None)
                if sq is None:
                    continue
                cur = [_uuid_of(i) for i in sq.get("inbounds") or []]
                rem = {u for s_, u in ch.squad_remove_uuid if s_ == sq_uuid}
                await remna.request(p, "PATCH", "/api/internal-squads",
                                    body={"uuid": sq_uuid, "inbounds": [u for u in cur if u not in rem]})
                undo.append(("squad", {"uuid": sq_uuid, "inbounds": cur}))
                log.append(f"сквад «{sq.get('name')}»: −{len(rem)}")
        if ch.deactivate:
            old_active = [a["uuid"] for a in st.active]
            gone = {a["uuid"] for a in st.active if a["tag"] in ch.deactivate}
            await remna.request(p, "PATCH", "/api/nodes", body={
                "uuid": st.node["uuid"],
                "configProfile": {"activeConfigProfileUuid": st.profile["uuid"],
                                  "activeInbounds": [u for u in old_active if u not in gone]}})
            undo.append(("node", {"uuid": st.node["uuid"], "configProfile": {
                "activeConfigProfileUuid": st.profile["uuid"], "activeInbounds": old_active}}))
            log.append(f"на {st.node.get('name')} выключены: {', '.join(ch.deactivate)}")

        # 2. Cloudflare.
        if ch.cf and ch.cf.get("create"):
            rec = await _cf(p, "POST", f"/zones/{ch.cf['zone_id']}/dns_records",
                            body={"type": "A", "name": ch.cf["host"], "content": ch.cf["ip"],
                                  "proxied": True, "ttl": 1,
                                  "comment": f"nexus-hub: фронт {st.node.get('name')}"})
            undo.append(("cf", (ch.cf["zone_id"], rec["id"])))
            log.append(f"Cloudflare: {ch.cf['host']} → {ch.cf['ip']}")

        # 3. Профиль.
        tag_uuid: dict[str, str] = {}
        if ch.new_config is not None:
            cfg = copy.deepcopy(ch.new_config)
            if any(((i.get("streamSettings") or {}).get("realitySettings") or {}).get("privateKey") == _PK
                   for i in cfg.get("inbounds") or []):
                keys = await remna.request(p, "GET", "/api/system/tools/x25519/generate")
                keys = (keys.get("keypairs") or [keys])[0] if isinstance(keys, dict) else keys
                secrets_seen.append((keys or {}).get("privateKey") or "")
                _fill_secrets(cfg, keys)
            prof = await remna.request(p, "PATCH", "/api/config-profiles",
                                       body={"uuid": st.profile["uuid"], "config": cfg})
            undo.append(("profile", {"uuid": st.profile["uuid"], "config": st.config}))
            tag_uuid = {i.get("tag"): i.get("uuid") for i in prof.get("inbounds") or []}
            log.append(f"профиль {st.profile.get('name')} обновлён")
        else:
            tag_uuid = {i.get("tag"): i.get("uuid") for i in st.profile.get("inbounds") or []}

        def need(tag: str) -> str:
            uid = tag_uuid.get(tag)
            if not uid:
                raise EditError(f"панель не вернула инбаунд {tag} в профиле")
            return uid

        # 4. Инбаунды на ноде.
        if ch.activate:
            old_active = [a["uuid"] for a in st.active]
            new_active = [*old_active, *(need(t) for t in ch.activate)]
            await remna.request(p, "PATCH", "/api/nodes", body={
                "uuid": st.node["uuid"],
                "configProfile": {"activeConfigProfileUuid": st.profile["uuid"], "activeInbounds": new_active}})
            undo.append(("node", {"uuid": st.node["uuid"], "configProfile": {
                "activeConfigProfileUuid": st.profile["uuid"], "activeInbounds": old_active}}))
            log.append(f"на {st.node.get('name')} включены: {', '.join(ch.activate)}")

        # 5. Реле-юзер выхода: свой сквад только с инбаундом фронта.
        if ch.relay:
            sq = await remna.request(p, "POST", "/api/internal-squads",
                                     body={"name": ch.relay["squad"], "inbounds": [need(ch.relay["tag"])]})
            undo.append(("squad_delete", sq["uuid"]))
            user = await remna.request(p, "POST", "/api/users", body={
                "username": ch.relay["username"], "expireAt": FAR_FUTURE, "trafficLimitBytes": 0,
                "trafficLimitStrategy": "NO_RESET", "activeInternalSquads": [sq["uuid"]],
                "description": "реле каскада (хаб nexus-mcp): не удалять, не продлевать"})
            undo.append(("user_delete", user["uuid"]))
            secrets_seen.append(user.get("vlessUuid") or "")
            log.append(f"реле: сквад и юзер {ch.relay['username']}")

        # 6. Строки подписки.
        for tag, body in ch.host_creates:
            h = await remna.request(p, "POST", "/api/hosts", body={
                **body, "inbound": {"configProfileUuid": st.profile["uuid"],
                                    "configProfileInboundUuid": need(tag)}})
            undo.append(("host_delete", h["uuid"]))
            log.append(f"строка «{body['remark']}»" + (" (скрыта)" if body.get("isDisabled") else ""))
        for uid, new, old in ch.host_patches:
            await remna.request(p, "PATCH", "/api/hosts", body={"uuid": uid, **new})
            undo.append(("host", {"uuid": uid, **old}))
            log.append(f"строка {uid[:8]}: {', '.join(new)}")

        # 7. Сквады — по свежему состоянию: между планом и сюда их мог тронуть бот.
        if ch.squad_add or ch.squad_remove:
            squads = remna._list(await remna.request(p, "GET", "/api/internal-squads"), "internalSquads")
            for sq_uuid in dict.fromkeys([s for s, _ in ch.squad_add + ch.squad_remove]):
                sq = next((s for s in squads if s.get("uuid") == sq_uuid), None)
                if sq is None:
                    raise EditError(f"сквад {sq_uuid} пропал")
                cur = [_uuid_of(i) for i in sq.get("inbounds") or []]
                add = [need(t) for s, t in ch.squad_add if s == sq_uuid]
                rem = {need(t) for s, t in ch.squad_remove if s == sq_uuid}
                new = [u for u in cur if u not in rem] + [u for u in add if u not in cur]
                await remna.request(p, "PATCH", "/api/internal-squads", body={"uuid": sq_uuid, "inbounds": new})
                undo.append(("squad", {"uuid": sq_uuid, "inbounds": cur}))
                log.append(f"сквад «{sq.get('name')}»: +{len(add)} −{len(rem)}")
    except (remna.RemnaError, EditError, KeyError, TypeError) as e:
        return await rollback(f"панель: {e}")

    # 8. Проверка: ноды профиля на связи, фронт отвечает через Cloudflare.
    watch = [n["uuid"] for n in st.nodes if n.get("isConnected") and (
        n["uuid"] == st.node["uuid"] or (ch.new_config is not None and n.get("name") in st.sharing))]
    if ch.new_config is not None or ch.activate or ch.deactivate:
        bad = await _wait_healthy(p, watch)
        if bad:
            return await rollback(f"после правки не на связи: {', '.join(bad)} — профиль, вероятно, "
                                  "не принят xray; всё возвращено как было")
        log.append("ноды профиля на связи")
    if ch.verify:
        v = await verify_front(ch.verify["host"], ch.verify["port"], ch.verify["path"])
        if not v["ok"]:
            return await rollback(f"фронт {ch.verify['host']}:{ch.verify['port']} не отвечает через "
                                  f"Cloudflare: {v.get('error')}")
        log.append(f"фронт {ch.verify['host']}:{ch.verify['port']}: WebSocket через Cloudflare — 101")
    # 9. Уборка после снятия: безвредна, отката не требует; 404 — уже убрано
    # самой панелью (строки удалённого инбаунда она чистит сама).
    left: list[str] = []
    for item in ch.cleanup:
        kind = item[0]
        try:
            if kind == "cf":
                await _cf(p, "DELETE", f"/zones/{item[1]}/dns_records/{item[2]}")
            else:
                path = {"host": "/api/hosts/", "user": "/api/users/", "squad": "/api/internal-squads/"}[kind]
                await remna.request(p, "DELETE", path + item[1])
            log.append(f"удалено: {kind}")
        except remna.RemnaError as e:
            if e.status != 404:
                left.append(f"{kind} {item[-1][:8]}: {e}")
        except EditError as e:
            left.append(f"{kind}: {e}")
    out = {"ok": True, "node": st.node.get("name"), "op": op, "log": log}
    if left:
        out["cleanup_left"] = left
    if op == "cf_exit":
        out["next"] = (f"вход каскада: remna_node_edit(<RU-нода>, op='cascade_entry', "
                       f"args={{'exit': '{st.node.get('name')}', 'sni': <SNI из белого списка>}})")
    if op == "cascade_entry":
        out["next"] = ("строка скрыта: проверить с симок и домашним пробником, затем "
                       "op='host', args={'host': <подпись>, 'set': {'isDisabled': false}}")
    return json.loads(scrub(json.dumps(out, ensure_ascii=False), secrets_seen))
