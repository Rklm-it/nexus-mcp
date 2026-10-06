"""Обслуживание нод Remnawave с хаба: разбор, действия, проверка подписки.

Дополняет `remna_install` (новая нода) и `remna_edit` (перенастройка):

* `diagnose` — «нода не работает»: что о ней думает панель, чего не хватает
  в профиле (строки, сквады, minClientVer, отпечаток), что на сервере
  (контейнер, перезапуски, ошибки xray, слушаются ли порты, срок
  сертификатов), открываются ли входы с хаба и домашних пробников, отвечает
  ли фронт Cloudflare и выход каскада.
* `node_action` — перезапуск ноды/контейнера, включить, выключить, удалить.
* служебный юзер `hub-probe` — во всех сквадах клиентов, без срока: его
  подписка — то, что видит клиент (через страницу бота 3XUIStore), а его
  ссылки на ноду (и на СКРЫТЫЕ строки — вход каскада до проверки) — то, что
  уходит в пробники и SIM-проверки. Ссылки на хабе, в ответы не попадают.
* `sub_check` — каждая строка подписки служебного юзера с точки обзора.
* `get` / `call` — запасной путь к любой ручке Remnawave: чтение — сразу,
  изменение — предпросмотр, затем confirm. Секреты маскируются.
"""

from __future__ import annotations

import base64
import re
from typing import Any
from urllib.parse import quote, urlencode

from nexus_mcp import config, remna, ssh
from nexus_mcp import remna_edit as re_
from nexus_mcp.node_install import parse_kv

PROBE_USER = "hub-probe"
PROBE_NOTE = ("Служебный (хаб nexus-mcp): проверка нод и подписки. Не удалять, не продлевать — "
              "удалённого хаб заведёт заново.")
FAR_FUTURE = re_.FAR_FUTURE
ACTIONS = ("restart", "restart_container", "enable", "disable", "delete")
CERT_WARN_DAYS = 14
LIST_LIMIT = 50
# Ручки, которые через запасной путь не трогаем: токены и вход в панель.
_FORBIDDEN = re.compile(r"^/api/(tokens|api-tokens|auth|passkeys|keygen)(/|$)")
# В общем чтении скрываем ещё и ссылку подписки: по ней ходит VPN клиента.
_LINK_KEY = re.compile(r"^(shortuuid|subscriptionurl|vlessuuid|trojanpassword|sspassword|hwid)$", re.I)


class OpsError(Exception):
    pass


# ── X25519: публичный ключ Reality из приватного (RFC 7748) ───────────────
# Remnawave хранит в профиле только privateKey, а ссылке нужен pbk. Своя
# реализация, а не `cryptography`: хабу хватает httpx и mcp.

_P = 2 ** 255 - 19


def x25519_public(private_b64: str) -> str:
    raw = base64.urlsafe_b64decode(private_b64 + "=" * (-len(private_b64) % 4))
    if len(raw) != 32:
        raise OpsError("privateKey Reality не 32 байта")
    b = bytearray(raw)
    b[0] &= 248
    b[31] &= 127
    b[31] |= 64
    k = int.from_bytes(b, "little")
    x1, x2, z2, x3, z3, swap = 9, 1, 0, 9, 1, 0
    for t in reversed(range(255)):
        kt = (k >> t) & 1
        swap ^= kt
        if swap:
            x2, x3, z2, z3 = x3, x2, z3, z2
        swap = kt
        a, b_ = (x2 + z2) % _P, (x2 - z2) % _P
        aa, bb = a * a % _P, b_ * b_ % _P
        e = (aa - bb) % _P
        c, d = (x3 + z3) % _P, (x3 - z3) % _P
        da, cb = d * a % _P, c * b_ % _P
        x3, z3 = (da + cb) ** 2 % _P, x1 * (da - cb) ** 2 % _P
        x2, z2 = aa * bb % _P, e * (aa + 121665 * e) % _P
    if swap:
        x2, z2 = x3, z3
    pub = (x2 * pow(z2, _P - 2, _P) % _P).to_bytes(32, "little")
    return base64.urlsafe_b64encode(pub).decode().rstrip("=")


# ── Маскировка для запасного пути ─────────────────────────────────────────

def mask_all(obj: Any) -> Any:
    obj = remna.mask(obj)

    def walk(o: Any) -> Any:
        if isinstance(o, dict):
            return {k: ("***" if isinstance(k, str) and _LINK_KEY.match(k) and o[k] not in (None, "")
                        else walk(v)) for k, v in o.items()}
        if isinstance(o, list):
            out = [walk(x) for x in o[:LIST_LIMIT]]
            if len(o) > LIST_LIMIT:
                out.append(f"… ещё {len(o) - LIST_LIMIT} (сузьте запрос: start/size)")
            return out
        return o
    return walk(obj)


# ── Служебный юзер ─────────────────────────────────────────────────────────

def _client_squads(squads: list[dict]) -> list[dict]:
    return [s for s in squads if not (s.get("name") or "").lower().startswith(re_.RELAY_USER)]


async def probe_user(p: dict) -> dict | None:
    return await re_._find_user(p, PROBE_USER)  # noqa: SLF001


async def probe_plan(panel: str) -> dict:
    p = remna.resolve(panel)
    squads = _client_squads(remna._list(await remna.request(p, "GET", "/api/internal-squads"), "internalSquads"))
    u = await probe_user(p)
    want = {s["uuid"] for s in squads}
    have = {_sq_uuid(x) for x in (u or {}).get("activeInternalSquads") or []}
    if u is None:
        todo = f"завести {PROBE_USER}: без срока и лимита, сквады: " + ", ".join(s.get("name", "?") for s in squads)
    elif want - have or (u.get("status") != "ACTIVE"):
        todo = f"досыпать {PROBE_USER} сквады: " + ", ".join(s.get("name", "?") for s in squads
                                                             if s["uuid"] not in have) \
               + ("; включить (сейчас " + str(u.get("status")) + ")" if u.get("status") != "ACTIVE" else "")
    else:
        todo = ""
    return {"ok": True, "panel": p["name"], "exists": u is not None, "todo": todo or "ничего — юзер на месте",
            "next": "confirm=true — завести/обновить" if todo else "remna_sub_check / remna_node_diagnose"}


def _sq_uuid(x: Any) -> str:
    return x.get("uuid") if isinstance(x, dict) else str(x)


async def ensure_probe_user(panel: str) -> dict:
    if not config.settings.allow_actions:
        return {"ok": False, "error": "actions_disabled",
                "detail": "действия выключены на хабе (NEXUS_ALLOW_ACTIONS=1 чтобы включить)"}
    p = remna.resolve(panel)
    squads = _client_squads(remna._list(await remna.request(p, "GET", "/api/internal-squads"), "internalSquads"))
    want = [s["uuid"] for s in squads]
    u = await probe_user(p)
    if u is None:
        await remna.request(p, "POST", "/api/users", body={
            "username": PROBE_USER, "expireAt": FAR_FUTURE, "trafficLimitBytes": 0,
            "trafficLimitStrategy": "NO_RESET", "activeInternalSquads": want, "description": PROBE_NOTE})
        return {"ok": True, "panel": p["name"], "detail": f"{PROBE_USER} заведён, сквадов: {len(want)}"}
    have = [_sq_uuid(x) for x in u.get("activeInternalSquads") or []]
    k, v = remna.user_key(u)
    body: dict = {k: v, "activeInternalSquads": list(dict.fromkeys([*have, *want]))}
    if u.get("status") != "ACTIVE":
        body.update({"status": "ACTIVE", "expireAt": FAR_FUTURE})
    await remna.request(p, "PATCH", "/api/users", body=body)
    return {"ok": True, "panel": p["name"], "detail": f"{PROBE_USER} на месте, сквадов: {len(body['activeInternalSquads'])}"}


# ── Ссылки служебного юзера на ноду (и на скрытые строки) ─────────────────

def build_link(host: dict, inbound: dict, user: dict) -> str:
    """Строка подписки так, как её собрал бы Remnawave, — для пробников и SIM.
    Пусто — протокол, который хаб не собирает (тогда берите подписку)."""
    ss = inbound.get("streamSettings") or {}
    sec, net = ss.get("security") or "none", ss.get("network") or "tcp"
    addr, port = host.get("address") or "", int(host.get("port") or inbound.get("port") or 443)
    remark = quote(host.get("remark") or inbound.get("tag") or "", safe="")
    proto = inbound.get("protocol")
    uid = user.get("vlessUuid") or ""
    at = f"[{addr}]" if ":" in addr else addr
    if proto == "vless" and sec == "reality" and net in ("tcp", "raw"):
        rs = ss.get("realitySettings") or {}
        sid = next((x for x in rs.get("shortIds") or [] if x), "")
        q = {"type": "tcp", "security": "reality", "encryption": "none",
             "sni": host.get("sni") or (rs.get("serverNames") or [""])[0],
             "pbk": x25519_public(rs.get("privateKey") or ""), "sid": sid,
             "fp": host.get("fingerprint") or "firefox", "flow": "xtls-rprx-vision"}
        return f"vless://{uid}@{at}:{port}?{urlencode(q)}#{remark}"
    if proto == "vless" and net == "ws":
        ws = ss.get("wsSettings") or {}
        layer = host.get("securityLayer") or "DEFAULT"
        tls = layer == "TLS" or (layer == "DEFAULT" and sec == "tls")
        q = {"type": "ws", "security": "tls" if tls else "none", "encryption": "none",
             "path": host.get("path") or ws.get("path") or "/", "host": host.get("host") or ws.get("host") or addr,
             "sni": host.get("sni") or addr, "fp": host.get("fingerprint") or "firefox",
             "alpn": host.get("alpn") or "http/1.1"}
        return f"vless://{uid}@{at}:{port}?{urlencode(q)}#{remark}"
    if proto == "hysteria":
        q = {"sni": host.get("sni") or addr, "alpn": host.get("alpn") or "h3"}
        return f"hysteria2://{uid}@{at}:{port}?{urlencode(q)}#{remark}"
    return ""


async def node_links(panel: str, node: str, include_hidden: bool = True) -> dict:
    """Ссылки служебного юзера на строки ноды: {node, links, targets, sni_hosts, skipped}."""
    p = remna.resolve(panel)
    st = await re_.load(p, node)
    u = await probe_user(p)
    if u is None:
        raise OpsError(f"служебного юзера {PROBE_USER} в панели нет — remna_probe_user(panel='{p['name']}', "
                       "confirm=true)")
    inb = {i.get("tag"): i for i in st.config.get("inbounds") or []}
    by_uuid = {a["uuid"]: a["tag"] for a in st.active}
    links, targets, snis, skipped = [], [], [], []
    for h in st.hosts:
        if h.get("isDisabled") and not include_hidden:
            continue
        tag = by_uuid.get((h.get("inbound") or {}).get("configProfileInboundUuid") or "")
        ib = inb.get(tag)
        if not ib:
            continue
        try:
            link = build_link(h, ib, u)
        except (OpsError, ValueError) as e:
            skipped.append(f"{h.get('remark')}: {e}")
            continue
        if not link:
            skipped.append(f"{h.get('remark')} ({ib.get('protocol')})")
            continue
        links.append(link)
        targets.append(f"{h.get('address')}:{h.get('port')}")
        if h.get("sni") and h["sni"] not in snis:
            snis.append(h["sni"])
    return {"node": f"remna:{p['name']}/{st.node.get('name')}", "links": links[:20], "targets": targets[:10],
            "sni_hosts": snis[:10], "skipped": skipped}


def parse_remna_node(node: str) -> tuple[str, str] | None:
    """«remna:pablo/ru01s3» → ("pablo", "ru01s3"); «remna:ru01s3» — панель одна."""
    if not (node or "").startswith("remna:"):
        return None
    rest = node[len("remna:"):]
    panel, _, name = rest.rpartition("/")
    return panel, name


# ── Проверка подписки ─────────────────────────────────────────────────────

async def sub_check(panel: str, probe: str = "hub") -> dict:
    from nexus_mcp import links as sublinks
    from nexus_mcp import sweep

    p = remna.resolve(panel)
    u = await probe_user(p)
    if u is None:
        raise OpsError(f"служебного юзера {PROBE_USER} нет — remna_probe_user(panel='{p['name']}', confirm=true)")
    short = u.get("shortUuid") or ""
    if p.get("sub_url"):
        url, via = p["sub_url"] + short, "страница бота (как у клиентов)"
    else:
        url, via = f"{p['url']}/api/sub/{short}", "подписка Remnawave (адреса бота в реестре нет)"
    try:
        uris = await sublinks.fetch_links(url)
    except sublinks.LinksError as e:
        return {"ok": False, "error": "subscription", "detail": str(e), "via": via}
    rows = [sweep.link_row(x) for x in uris]
    jobs = [(i, sweep.reach_job(r)) for i, r in enumerate(rows)]
    todo = [(i, j) for i, j in jobs if j]
    results = await sweep._run_batch(probe, [j for _, j in todo]) if todo else []  # noqa: SLF001
    out = []
    for r in rows:
        out.append({k: r[k] for k in ("remark", "scheme", "transport", "security", "host", "port", "sni")}
                   | {"status": "udp_unchecked" if r["udp"] else "unchecked"})
    for (i, j), res in zip(todo, results):
        out[i]["status"] = sweep.reach_status(j["kind"], res)
        if res.get("error"):
            out[i]["error"] = res.get("error")
    bad = [r for r in out if r["status"] not in ("reachable", "ok", "udp_unchecked", "unchecked", "via_vpn")]
    return {"ok": True, "panel": p["name"], "probe": probe, "via": via, "lines": len(out),
            "problems": len(bad), "rows": out,
            "note": "UDP (Hysteria2) по TCP не проверить — сквозная: probe_speed / sim_vless(node='remna:…')"}


# ── Разбор ноды ───────────────────────────────────────────────────────────

def _f(level: str, code: str, text: str) -> dict:
    return {"level": level, "code": code, "text": text}


def diagnose_script(cert_files: list[str]) -> str:
    certs = "\n".join(
        f"d=$(openssl x509 -enddate -noout -in '{c}' 2>/dev/null | cut -d= -f2); "
        f"[ -n \"$d\" ] && echo \"cert_{i}=$(( ($(date -d \"$d\" +%s) - $(date +%s)) / 86400 ))\" "
        f"|| echo \"cert_{i}=missing\""
        for i, c in enumerate(cert_files[:6]))
    return (
        "set +e\n"
        "echo \"container=$(docker ps -a --filter name=remnanode --format '{{.Status}}' 2>/dev/null | head -1)\"\n"
        "echo \"restarts=$(docker inspect -f '{{.RestartCount}}' remnanode 2>/dev/null)\"\n"
        "echo \"image=$(docker inspect -f '{{.Config.Image}}' remnanode 2>/dev/null)\"\n"
        "echo \"listen=$(ss -Hlntu 2>/dev/null | awk '{n=split($5,a,\":\"); print $1\":\"a[n]}' "
        "| sort -u | tr '\\n' ',')\"\n"
        "docker inspect remnanode >/dev/null 2>&1 && echo \"errors=$(docker logs --since 6h remnanode 2>&1 | grep -iE 'error|fail|panic|invalid' | grep -viE "
        "'context canceled|connection reset|i/o timeout|broken pipe|EOF' | tail -5 | tr '\\n' '|' | cut -c1-600)\"\n"
        "echo \"ufw=$(ufw status 2>/dev/null | head -1 | awk '{print $2}')\"\n"
        "echo \"load=$(cut -d' ' -f1 /proc/loadavg) cpus=$(nproc)\"\n"
        "echo \"mem_free_mb=$(awk '/MemAvailable/{print int($2/1024)}' /proc/meminfo)\"\n"
        "echo \"disk_use=$(df -P / | awk 'NR==2{print $5}')\"\n"
        + certs + "\n"
    )


async def diagnose(panel: str, node: str, probes: list[str] | None = None, ssh_port: int = 22,
                   ssh_user: str = "") -> dict:
    from nexus_mcp import sweep
    from nexus_mcp.probes import HUB, ProbeError, registry

    p = remna.resolve(panel)
    st = await re_.load(p, node)
    n = st.node
    view = remna.node_view(n)
    fs: list[dict] = []

    # 1. Панель.
    if n.get("isDisabled"):
        fs.append(_f("bad", "disabled", "нода выключена в панели — клиентам её строки не уходят"))
    elif not n.get("isConnected"):
        fs.append(_f("bad", "not_connected", "панель не на связи с нодой: " + (n.get("lastStatusMessage") or
                     "причины панель не дала") + f" (порт ноды {n.get('port')} с IP панели, контейнер remnanode)"))
    else:
        fs.append(_f("ok", "connected", f"на связи, онлайн {n.get('usersOnline') or 0}"))
    if n.get("isConnected") and isinstance(n.get("xrayUptime"), (int, float)) and n["xrayUptime"] < 300:
        fs.append(_f("warn", "xray_restarted", f"xray поднялся {int(n['xrayUptime'])} с назад — перезапуск или падение"))

    # 2. Профиль, строки, сквады.
    inb = {i.get("tag"): i for i in st.config.get("inbounds") or []}
    squad_uuids = {_uuid_of_inb for s in st.squads for _uuid_of_inb in
                   [x.get("uuid") if isinstance(x, dict) else x for x in s.get("inbounds") or []]}
    cert_files, ports = [], []
    for a in st.active:
        ib = inb.get(a["tag"]) or {}
        ss = ib.get("streamSettings") or {}
        proto = "udp" if ib.get("protocol") == "hysteria" else "tcp"
        ports.append((a["tag"], int(ib.get("port") or 0), proto, ss))
        hosts = [h for h in st.hosts if ((h.get("inbound") or {}).get("configProfileInboundUuid")) == a["uuid"]]
        if not hosts and not a["tag"].startswith(re_.CF_TAG):
            fs.append(_f("warn", "no_host", f"{a['tag']}: строки подписки нет — клиентам не уходит"))
        elif hosts and all(h.get("isDisabled") for h in hosts):
            fs.append(_f("info", "hidden", f"{a['tag']}: все строки скрыты (isDisabled)"))
        if a["uuid"] not in squad_uuids:
            fs.append(_f("warn", "no_squad", f"{a['tag']}: ни в одном скваде — на ноде у него нет ни одного юзера"))
        rs = ss.get("realitySettings") or {}
        if ss.get("security") == "reality":
            if rs.get("minClientVer") != "1.0.0":
                fs.append(_f("bad", "min_client_ver", f"{a['tag']}: minClientVer не 1.0.0 — xray 26.7.11+ не "
                             "пустит Happ/INCY/sing-box старее 26.3.27 (пинг есть, туннеля нет)"))
            for h in hosts:
                if (h.get("fingerprint") or "") == "chrome":
                    fs.append(_f("warn", "fp_chrome", f"строка «{h.get('remark')}»: отпечаток chrome — МТС/Билайн "
                                 "без БС режут; нужен firefox (remna_node_edit op=host)"))
        for c in (ss.get("tlsSettings") or {}).get("certificates") or []:
            if c.get("certificateFile"):
                cert_files.append(c["certificateFile"])

    # 3. Сервер.
    server: dict = {}
    node_ip = re_._node_ip(st)  # noqa: SLF001
    res = await ssh.run_script(re_._ssh_node(st, {"ssh_port": ssh_port, "ssh_user": ssh_user}),  # noqa: SLF001
                               diagnose_script(cert_files), timeout=40)
    if not res.ok:
        fs.append(_f("info", "no_ssh", f"SSH не прошёл ({res.hint() or res.stderr[-160:]}) — сервер не осмотрен "
                     "(ключ хаба: nexus-hub → «Положить ключ хаба на сервер»)"))
    else:
        kv = parse_kv(res.stdout)
        server = {k: kv.get(k) for k in ("container", "restarts", "image", "ufw", "load", "mem_free_mb", "disk_use")}
        if not (kv.get("container") or "").startswith("Up"):
            fs.append(_f("bad", "container", f"контейнер remnanode: {kv.get('container') or 'нет'}"))
        if (kv.get("restarts") or "0").isdigit() and int(kv["restarts"]) > 3:
            fs.append(_f("warn", "restarts", f"remnanode перезапускался {kv['restarts']} раз"))
        listen = set((kv.get("listen") or "").strip(",").split(","))
        for tag, port, proto, _ss in ports:
            if port and f"{proto}:{port}" not in listen:
                fs.append(_f("bad", "not_listening", f"{tag}: порт {port}/{proto} никто не слушает — xray не "
                             "поднял инбаунд (конфиг не принят? docker logs remnanode)"))
        if kv.get("errors"):
            fs.append(_f("warn", "xray_errors", "ошибки в журнале за 6 ч: " + kv["errors"].strip("|")[:400]))
        for i, c in enumerate(cert_files[:6]):
            v = kv.get(f"cert_{i}")
            if v == "missing":
                fs.append(_f("bad", "cert_missing", f"сертификат {c} не читается — TLS-инбаунд не поднимется"))
            elif v and v.lstrip("-").isdigit() and int(v) < CERT_WARN_DAYS:
                fs.append(_f("bad" if int(v) < 3 else "warn", "cert_expiry", f"сертификат {c}: осталось {v} дн."))
        disk = (kv.get("disk_use") or "0%").rstrip("%")
        if disk.isdigit() and int(disk) > 90:
            fs.append(_f("warn", "disk", f"диск занят на {disk}%"))

    # 4. Доступность входов с точек обзора (UDP по TCP не проверить).
    reach = []
    for probe in [HUB, *[x for x in (probes or []) if x != HUB]]:
        for tag, port, proto, ss in ports:
            if proto != "tcp" or not port or tag.startswith(re_.CF_TAG):
                continue
            sni = ((ss.get("realitySettings") or {}).get("serverNames") or [""])[0]
            kind = "tls" if ss.get("security") in ("reality", "tls") else "tcp"
            args = {"host": node_ip, "port": port, "timeout": 8}
            if kind == "tls" and sni:
                args["sni"] = sni
            try:
                r = await registry.run(probe, kind, args, timeout=20)
            except ProbeError as e:
                r = {"ok": False, "error": "probe_error", "detail": str(e)}
            status = sweep.reach_status(kind, r)
            reach.append({"probe": probe, "inbound": tag, "port": port, "status": status,
                          **({"error": r.get("error")} if r.get("error") else {})})
            if status in ("down", "filtered", "refused") and probe != HUB:
                fs.append(_f("bad", "unreachable", f"[{probe}] {tag} :{port} — {status}: этот провайдер не "
                             "пускает до ноды"))
            elif status in ("down", "refused") and probe == HUB:
                fs.append(_f("bad", "unreachable_hub", f"[хаб] {tag} :{port} — {status}"))

    # 5. Каскад: свой фронт и выход входов.
    front = re_.cf_front_of(st)
    checks = []
    if front:
        checks.append(("front", front["host"], int(front["port"]), front["path"]))
    for o in st.config.get("outbounds") or []:
        if str(o.get("tag", "")).startswith(re_.RELAY_TAG):
            vn = ((o.get("settings") or {}).get("vnext") or [{}])[0]
            ws = (o.get("streamSettings") or {}).get("wsSettings") or {}
            checks.append((o["tag"], vn.get("address"), int(vn.get("port") or 443), ws.get("path") or "/"))
    cascade = []
    for what, host, port, path in checks:
        try:
            code = await re_.ws_handshake(host, port, path)
        except Exception as e:  # noqa: BLE001
            code, err = 0, f"{type(e).__name__}: {e}"
        else:
            err = "" if code == 101 else re_._CF_CODES.get(code, f"HTTP {code}")  # noqa: SLF001
        cascade.append({"check": what, "target": f"{host}:{port}", "ok": code == 101, **({"error": err} if err else {})})
        if code != 101:
            fs.append(_f("bad", "cascade", (f"фронт {host}:{port}" if what == "front" else f"выход {what} → {host}:{port}")
                         + f" не отвечает через Cloudflare: {err}"))

    order = {"bad": 0, "warn": 1, "info": 2, "ok": 3}
    fs.sort(key=lambda f: order.get(f["level"], 9))
    return {"ok": True, "panel": p["name"], "node": view, "profile": st.profile.get("name"),
            "shared_with": st.sharing, "inbounds": [{"tag": t, "port": po, "proto": pr} for t, po, pr, _ in ports],
            "verdict": "bad" if any(f["level"] == "bad" for f in fs) else
                       ("warn" if any(f["level"] == "warn" for f in fs) else "ok"),
            "findings": fs, "server": server, "reach": reach, "cascade": cascade}


# ── Действия ──────────────────────────────────────────────────────────────

async def action_plan(panel: str, node: str, action: str) -> dict:
    if action not in ACTIONS:
        raise OpsError(f"action: {', '.join(ACTIONS)}")
    p = remna.resolve(panel)
    n = await remna.find_node(p, node)
    online = n.get("usersOnline") or 0
    what = {
        "restart": "перезапуск xray на ноде через панель (секунды; соединения клиентов оборвутся)",
        "restart_container": "docker restart remnanode по SSH (когда панель до ноды не достаёт)",
        "enable": "включить ноду: её строки вернутся клиентам",
        "disable": "выключить ноду: её строки пропадут у клиентов со следующего обновления подписки",
        "delete": "УДАЛИТЬ ноду из панели (необратимо; профиль и строки остаются, сервер не трогается)",
    }[action]
    warns = []
    if action in ("restart", "restart_container", "disable", "delete") and online:
        warns.append(f"сейчас онлайн {online} — у них оборвётся")
    if action == "delete":
        warns.append("строки этой ноды останутся без ноды — уберите их (remna_node_edit op=host / remna_call)")
    return {"ok": True, "panel": p["name"], "node": n.get("name"), "action": action, "does": what,
            "warnings": warns, "next": "confirm=true — выполнить"}


async def action_run(panel: str, node: str, action: str, ssh_port: int = 22, ssh_user: str = "") -> dict:
    if not config.settings.allow_actions:
        return {"ok": False, "error": "actions_disabled",
                "detail": "действия выключены на хабе (NEXUS_ALLOW_ACTIONS=1 чтобы включить)"}
    if action not in ACTIONS:
        raise OpsError(f"action: {', '.join(ACTIONS)}")
    p = remna.resolve(panel)
    n = await remna.find_node(p, node)
    uid = n["uuid"]
    if action == "restart_container":
        st = await re_.load(p, node)
        res = await ssh.run_script(re_._ssh_node(st, {"ssh_port": ssh_port, "ssh_user": ssh_user}),  # noqa: SLF001
                                   "docker restart remnanode >/dev/null 2>&1 && sleep 3 && "
                                   "echo \"container=$(docker ps --filter name=remnanode --format '{{.Status}}')\"",
                                   timeout=90)
        kv = parse_kv(res.stdout)
        if not res.ok or not (kv.get("container") or "").startswith("Up"):
            return {"ok": False, "error": "restart_failed",
                    "detail": res.hint() or res.stderr[-300:] or f"контейнер: {kv.get('container') or 'нет'}"}
        return {"ok": True, "node": n.get("name"), "detail": f"remnanode: {kv['container']}"}
    if action == "delete":
        await remna.request(p, "DELETE", f"/api/nodes/{uid}")
        return {"ok": True, "node": n.get("name"), "detail": "нода удалена из панели"}
    await remna.request(p, "POST", f"/api/nodes/{uid}/actions/{action}")
    after = await remna.request(p, "GET", f"/api/nodes/{uid}")
    return {"ok": True, "node": n.get("name"), "detail": f"{action}: выполнено",
            "now": {k: after.get(k) for k in ("isConnected", "isDisabled", "lastStatusMessage")}}


# ── Запасной путь ─────────────────────────────────────────────────────────

def _check_path(path: str) -> str:
    path = "/" + (path or "").lstrip("/")
    if not path.startswith("/api/") or ".." in path:
        raise OpsError("path — ручка Remnawave вида /api/…")
    if _FORBIDDEN.match(path):
        raise OpsError("токены, вход и ключи панели через хаб не трогаем")
    return path


async def get(panel: str, path: str, params: dict | None = None) -> Any:
    p = remna.resolve(panel)
    return mask_all(await remna.request(p, "GET", _check_path(path), params=params or None))


async def call_plan(panel: str, method: str, path: str, body: Any = None) -> dict:
    method = (method or "").upper()
    if method not in ("POST", "PATCH", "PUT", "DELETE"):
        raise OpsError("method: POST, PATCH, PUT, DELETE (чтение — remna_get)")
    p = remna.resolve(panel)
    return {"ok": True, "panel": p["name"], "method": method, "path": _check_path(path),
            "body": mask_all(body), "next": "покажите человеку; согласится — тот же вызов с confirm=true"}


async def call_run(panel: str, method: str, path: str, body: Any = None) -> Any:
    if not config.settings.allow_actions:
        return {"ok": False, "error": "actions_disabled",
                "detail": "действия выключены на хабе (NEXUS_ALLOW_ACTIONS=1 чтобы включить)"}
    plan = await call_plan(panel, method, path, body)
    p = remna.resolve(panel)
    res = await remna.request(p, plan["method"], plan["path"], body=body)
    return {"ok": True, "response": mask_all(res)}
