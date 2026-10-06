"""Новая нода Remnawave на чистом сервере — с хаба, одним вызовом.

Зачем. Клиентам на Remnawave (бот 3XUIStore поверх) ноды нужно разворачивать
быстро и одинаково: руками это шесть мест (сервер, сертификат, профиль,
нода, хост, сквад), и забытое одно — нода есть, а у клиентов строки нет.
Хаб делает всё сам, как `node_install` для Nexus:

1. План (без confirm, ничего не меняет): SSH до сервера — ОС, Docker, кто
   держит 80/443/порт ноды, нет ли уже remnanode; для Hysteria2 — смотрит ли
   домен на этот IP (иначе сертификат не выдадут). В панели — нет ли ноды с
   тем же адресом/именем, в какой сквад встанет инбаунд. Итог — что будет
   создано, и `plan_hash`.
2. Установка (confirm=true + plan_hash): Docker, `/opt/remnanode`
   (`SECRET_KEY` из `GET /api/keygen` — только через stdin SSH, в вывод не
   попадает), для Hysteria2 — сертификат Let's Encrypt на домен ноды
   (certbot standalone, после продления — перезапуск remnanode), файрвол.
   Затем в панели: конфиг-профиль по образцу рабочих нод клиента, нода,
   хост (строка подписки), инбаунд в сквад. Ждём, пока нода выйдет на связь.
   Упало посреди — созданное в панели этим запуском удаляется.

Шаблоны (как у клиента на 06.10.2026):
* `hysteria2` — встроенный в xray `hysteria` v2, TLS с сертификатом на домен
  ноды, ALPN h3, BBR; строка `hysteria2://<uuid>@<домен>:443`.
* `reality` — VLESS TCP Reality, `flow` vision; ключи генерирует сама панель
  (`/api/system/tools/x25519/generate`), `minClientVer: "1.0.0"` (иначе
  xray 26.7.11+ не пускает старые Happ/INCY/sing-box — инвариант 55 vgx3d),
  отпечаток в строке — firefox (МТС/Билайн режут chrome — инвариант 56).
  SNI/dest задаёт человек: для мобильных — только из белого списка ТСПУ.
"""

from __future__ import annotations

import asyncio
import hashlib
import ipaddress
import json
import re
import secrets
import shlex
import socket
from urllib.parse import urlparse

from nexus_mcp import config, remna, ssh
from nexus_mcp.node_install import InstallError, parse_kv, scrub

TEMPLATES = ("hysteria2", "reality")
_COUNTRY_RE = re.compile(r"^[A-Z]{2}$")
_HOST_RE = re.compile(r"^(?=.{1,253}$)([a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,63}$")
_NODE_NAME_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9 _.-]{2,29}$")
NODE_DIR = "/opt/remnanode"
DONE_MARK = "RN_INSTALL_DONE"
CONNECT_WAIT_S = 90


def _flag(cc: str) -> str:
    return "".join(chr(0x1F1E6 + ord(c) - 65) for c in cc.upper()) if _COUNTRY_RE.match(cc or "") else ""


def check_params(ip: str, name: str, country: str, *, template: str = "hysteria2",
                 domain: str = "", reality_sni: str = "", node_port: int = 2222,
                 ssh_port: int = 22, remark: str = "", squad: str = "") -> dict:
    try:
        addr = str(ipaddress.ip_address((ip or "").strip()))
    except ValueError:
        raise InstallError(f"«{ip}» — не IP-адрес сервера") from None
    if ipaddress.ip_address(addr).is_private or ipaddress.ip_address(addr).is_loopback:
        raise InstallError(f"{addr} — внутренний адрес: нода должна быть доступна из интернета")
    nm = (name or "").strip()
    if not _NODE_NAME_RE.match(nm):
        raise InstallError("имя ноды: 3–30 символов, латиница, цифры, пробел, _ . -")
    cc = (country or "").strip().upper()
    if not _COUNTRY_RE.match(cc):
        raise InstallError(f"страна «{country}» — код из двух латинских букв: DE, NL, FI")
    if template not in TEMPLATES:
        raise InstallError(f"template: {', '.join(TEMPLATES)}")
    dom = (domain or "").strip().lower().rstrip(".")
    if template == "hysteria2" and not dom:
        raise InstallError("для hysteria2 нужен domain — поддомен с A-записью на IP сервера "
                           "(сертификат Let's Encrypt выдаётся на него)")
    if dom and not _HOST_RE.match(dom):
        raise InstallError(f"«{domain}» — не домен")
    sni = (reality_sni or "").strip().lower().rstrip(".")
    if template == "reality":
        if not sni or not _HOST_RE.match(sni):
            raise InstallError("для reality нужен reality_sni — домен для SNI/dest. Для мобильных "
                               "под белыми списками — только домен из белого списка ТСПУ")
    try:
        nport, sport = int(node_port), int(ssh_port)
    except (TypeError, ValueError):
        raise InstallError("node_port / ssh_port — числа") from None
    for label, v in (("node_port", nport), ("ssh_port", sport)):
        if not 0 < v < 65536:
            raise InstallError(f"{label}: от 1 до 65535")
    if nport in (80, 443):
        raise InstallError("node_port не может быть 80/443 — они нужны строке подписки и сертификату")
    return {"ip": addr, "name": nm, "country": cc, "template": template, "domain": dom,
            "reality_sni": sni, "node_port": nport, "ssh_port": sport,
            "remark": (remark or "").strip()[:100] or f"{_flag(cc)} {nm}".strip(),
            "squad": (squad or "").strip()}


def ssh_node(params: dict, ssh_user: str = "") -> dict:
    host = params["ip"]
    if ":" in host:
        host = f"[{host}]"
    n = {"name": params["name"], "ssh_host": host, "ssh_port": params["ssh_port"],
         "ssh_source": "адрес из remna_node_install"}
    if ssh_user:
        n["ssh_user"] = ssh_user
    return n


# ── Скрипты на сервере ─────────────────────────────────────────────────────

def precheck_script(params: dict) -> str:
    """Только чтение: ОС, Docker, порты и кто их держит, нет ли remnanode."""
    ports = " ".join(str(p) for p in (80, 443, params["node_port"]))
    return f"""set +e
echo "os=$(. /etc/os-release 2>/dev/null; echo "$PRETTY_NAME")"
echo "user=$(id -un)"
command -v docker >/dev/null 2>&1 && echo "docker=$(docker --version 2>/dev/null | cut -d, -f1)" || echo "docker=absent"
[ -f {NODE_DIR}/docker-compose.yml ] && echo "remnanode=present" || echo "remnanode=absent"
command -v x-ui >/dev/null 2>&1 && echo "xui=present"
systemctl is-active --quiet vpn-cell 2>/dev/null && echo "cell=active"
busy=""
for p in {ports}; do
  o=$(ss -Hlntup 2>/dev/null | awk -v p=":$p" '$5 ~ p"$" {{print $7}}' | grep -o '"[^"]*"' | head -1 | tr -d '"')
  [ -n "$o" ] && busy="$busy$p:$o,"
done
echo "busy=$busy"
echo "ufw=$(ufw status 2>/dev/null | head -1 | awk '{{print $2}}')"
timeout 8 curl -s -o /dev/null --connect-timeout 5 https://get.docker.com && echo "docker_get=ok" || echo "docker_get=fail"
timeout 8 curl -s -o /dev/null --connect-timeout 5 https://registry-1.docker.io/v2/ && echo "registry=ok" || echo "registry=fail"
"""


def compose_yaml() -> str:
    return """services:
  remnanode:
    container_name: remnanode
    hostname: remnanode
    image: remnawave/node:latest
    network_mode: host
    restart: always
    env_file: .env
    volumes:
      - /etc/letsencrypt:/etc/letsencrypt:ro
"""


def install_script(params: dict, secret_key: str, panel_ip: str = "") -> str:
    """Docker + remnanode (+ сертификат для hysteria2) + файрвол.

    SECRET_KEY подставляется в скрипт, который уходит через stdin SSH, — в
    командной строке его нет, в вывод он не печатается."""
    dom = params["domain"]
    nport = params["node_port"]
    q = shlex.quote
    cert = ""
    if params["template"] == "hysteria2":
        cert = f"""
if [ ! -s /etc/letsencrypt/live/{dom}/fullchain.pem ]; then
  command -v certbot >/dev/null 2>&1 || {{ timeout 300 apt-get update -qq >/dev/null 2>&1; timeout 300 apt-get install -y -qq certbot >/dev/null 2>&1; }}
  command -v certbot >/dev/null 2>&1 || {{ echo "RN_ERR=certbot не установился"; exit 12; }}
  timeout 300 certbot certonly --standalone -d {q(dom)} --agree-tos --register-unsafely-without-email \\
    --non-interactive --preferred-challenges http \\
    --deploy-hook "docker restart remnanode" >/tmp/rn-cert.log 2>&1 \\
    || {{ echo "RN_ERR=сертификат не выдан: $(tail -3 /tmp/rn-cert.log | tr '\\n' ' ')"; exit 12; }}
fi
echo "cert=ok"
"""
    fw = ""
    if panel_ip:
        fw = f"""
if ufw status 2>/dev/null | grep -q '^Status: active'; then
  ufw allow 443/tcp >/dev/null; ufw allow 443/udp >/dev/null; ufw allow 80/tcp >/dev/null
  ufw allow from {q(panel_ip)} to any port {nport} proto tcp >/dev/null
  echo "ufw=opened"
fi
"""
    return f"""set -u
export DEBIAN_FRONTEND=noninteractive
if ! command -v docker >/dev/null 2>&1; then
  timeout 600 sh -c 'curl -fsSL --connect-timeout 15 https://get.docker.com | sh' >/tmp/rn-docker.log 2>&1 \\
    || {{ echo "RN_ERR=Docker не установился: $(tail -3 /tmp/rn-docker.log | tr '\\n' ' ')"; exit 10; }}
fi
docker compose version >/dev/null 2>&1 || {{ echo "RN_ERR=нет docker compose"; exit 11; }}
echo "docker=ok"
{cert}
mkdir -p {NODE_DIR}
umask 077
printf 'NODE_PORT=%s\\nSECRET_KEY=%s\\n' {nport} {q(secret_key)} > {NODE_DIR}/.env
cat > {NODE_DIR}/docker-compose.yml <<'RNCOMPOSE'
{compose_yaml()}RNCOMPOSE
cd {NODE_DIR} && timeout 600 docker compose up -d >/tmp/rn-up.log 2>&1 \\
  || {{ echo "RN_ERR=remnanode не поднялся: $(tail -3 /tmp/rn-up.log | tr '\\n' ' ')"; exit 13; }}
sleep 3
echo "container=$(docker ps --filter name=remnanode --format '{{{{.Status}}}}' | head -1)"
{fw}
echo "{DONE_MARK}"
"""


# ── Профиль, хост ──────────────────────────────────────────────────────────

def _tag(prefix: str) -> str:
    return f"{prefix}_{secrets.token_hex(3).upper()}"


def profile_config(params: dict, tag: str, keys: dict | None = None) -> dict:
    """Конфиг-профиль по образцу рабочих нод клиента (06.10.2026)."""
    rules = [
        {"ip": ["geoip:private"], "outboundTag": "BLOCK"},
        {"domain": ["geosite:private"], "outboundTag": "BLOCK"},
        {"protocol": ["bittorrent"], "outboundTag": "BLOCK"},
    ]
    if params["template"] == "hysteria2":
        dom = params["domain"]
        inbound = {
            "tag": tag, "port": 443, "listen": "0.0.0.0", "protocol": "hysteria",
            "settings": {"clients": [], "version": 2},
            "streamSettings": {
                "network": "hysteria", "security": "tls",
                "finalmask": {"quicParams": {"debug": False, "congestion": "bbr"}},
                "tlsSettings": {
                    "alpn": ["h3"], "serverName": dom,
                    "certificates": [{
                        "keyFile": f"/etc/letsencrypt/live/{dom}/privkey.pem",
                        "certificateFile": f"/etc/letsencrypt/live/{dom}/fullchain.pem",
                    }],
                },
                "hysteriaSettings": {"version": 2},
            },
        }
    else:
        sni = params["reality_sni"]
        inbound = {
            "tag": tag, "port": 443, "listen": "0.0.0.0", "protocol": "vless",
            "settings": {"clients": [], "decryption": "none", "flow": "xtls-rprx-vision"},
            "sniffing": {"enabled": True, "routeOnly": True, "destOverride": ["http", "tls", "quic"]},
            "streamSettings": {
                "network": "tcp", "security": "reality",
                "realitySettings": {
                    "show": False, "xver": 0, "dest": f"{sni}:443", "serverNames": [sni],
                    "privateKey": (keys or {}).get("privateKey", ""),
                    "shortIds": [secrets.token_hex(4), ""],
                    "minClientVer": "1.0.0",
                },
            },
        }
    return {
        "log": {"loglevel": "none"},
        "inbounds": [inbound],
        "outbounds": [{"tag": "DIRECT", "protocol": "freedom"}, {"tag": "BLOCK", "protocol": "blackhole"}],
        "routing": {"rules": rules},
    }


def host_body(params: dict, profile_uuid: str, inbound_uuid: str, node_uuid: str) -> dict:
    body = {
        "inbound": {"configProfileUuid": profile_uuid, "configProfileInboundUuid": inbound_uuid},
        "remark": params["remark"],
        "port": 443,
        "nodes": [node_uuid],
    }
    if params["template"] == "hysteria2":
        body.update({"address": params["domain"], "sni": params["domain"], "alpn": "h3",
                     "securityLayer": "TLS"})
    else:
        body.update({"address": params["ip"], "sni": params["reality_sni"], "fingerprint": "firefox",
                     "securityLayer": "DEFAULT"})
    return body


def _profile_name(params: dict) -> str:
    slug = re.sub(r"[^A-Za-z0-9_-]+", "-", params["name"]).strip("-")
    return f"hub-{slug}"[:30]


# ── Панель ─────────────────────────────────────────────────────────────────

def _resolve_ip(host: str) -> list[str]:
    try:
        return sorted({i[4][0] for i in socket.getaddrinfo(host, 443, socket.AF_INET)})
    except OSError:
        return []


async def _squads(p: dict) -> list[dict]:
    return remna._list(await remna.request(p, "GET", "/api/internal-squads"), "internalSquads")


def _pick_squad(squads: list[dict], name: str) -> dict | None:
    if name:
        return next((s for s in squads if (s.get("name") or "").lower() == name.lower()), None)
    # По умолчанию — сквад, где больше всего клиентов: «все ноды для всех».
    def members(s):
        return int(((s.get("info") or {}).get("membersCount")) or 0)
    return max(squads, key=members) if squads else None


def _plan_hash(params: dict, squad_uuid: str) -> str:
    raw = json.dumps({**params, "squad_uuid": squad_uuid}, sort_keys=True, ensure_ascii=False)
    return hashlib.sha256(raw.encode()).hexdigest()[:16]


async def plan(panel_name: str, params: dict, ssh_user: str = "") -> dict:
    p = remna.resolve(panel_name)
    problems: list[str] = []
    warns: list[str] = []

    pre_res = await ssh.run_script(ssh_node(params, ssh_user), precheck_script(params), timeout=40)
    pre = parse_kv(pre_res.stdout) if pre_res.ok else {}
    if not pre_res.ok:
        problems.append(f"SSH до сервера не прошёл: {pre_res.hint() or pre_res.stderr[-300:]} "
                        "(ключ хаба — в authorized_keys сервера: nexus-mcp-info)")
    else:
        if pre.get("remnanode") == "present":
            problems.append(f"на сервере уже есть {NODE_DIR} — нода Remnawave стоит, переустановку не делаю")
        if pre.get("cell") == "active":
            problems.append("на сервере работает агент Nexus (vpn-cell) — это нода другой панели")
        if pre.get("xui") == "present":
            warns.append("на сервере есть x-ui — проверьте, что он не держит 443")
        busy = {k: v for k, v in (x.split(":", 1) for x in pre.get("busy", "").split(",") if ":" in x)}
        for port, owner in busy.items():
            if port in ("443", str(params["node_port"])) or (port == "80" and params["template"] == "hysteria2"):
                problems.append(f"порт {port} занят ({owner})")
        if pre.get("docker") == "absent" and pre.get("docker_get") == "fail":
            problems.append("Docker не установлен, а get.docker.com с сервера не открывается")
        if pre.get("registry") == "fail":
            warns.append("Docker Hub с сервера не отвечает — образ remnawave/node может не скачаться")

    if params["template"] == "hysteria2":
        ips = _resolve_ip(params["domain"])
        if params["ip"] not in ips:
            problems.append(f"{params['domain']} смотрит на {', '.join(ips) or 'никуда'}, а не на "
                            f"{params['ip']}: сертификат не выдадут. Нужна A-запись (без прокси Cloudflare)")

    nodes = remna._list(await remna.request(p, "GET", "/api/nodes"))
    for n in nodes:
        if (n.get("name") or "").lower() == params["name"].lower():
            problems.append(f"нода с именем «{n['name']}» уже есть")
        addr = (n.get("address") or "").lower()
        if addr in (params["ip"], params["domain"]):
            problems.append(f"нода с адресом {addr} уже есть: «{n.get('name')}»")

    squads = await _squads(p)
    sq = _pick_squad(squads, params["squad"])
    if sq is None:
        problems.append(f"сквад «{params['squad']}» не найден" if params["squad"] else "в панели нет сквадов")

    panel_host = urlparse(p["url"]).hostname or ""
    panel_ips = _resolve_ip(panel_host)
    return {
        "ok": not problems,
        "panel": p["name"],
        "server": {k: pre.get(k) for k in ("os", "docker", "ufw") if pre.get(k)},
        "will_create": {
            "on_server": f"Docker (если нет), {NODE_DIR} с remnanode на порту {params['node_port']}"
                         + (f", сертификат Let's Encrypt для {params['domain']}" if params["template"] == "hysteria2" else "")
                         + (f", ufw: 443 tcp/udp, {params['node_port']} только с панели {panel_ips[0]}" if pre.get("ufw") == "active" and panel_ips else ""),
            "profile": _profile_name(params),
            "inbound": "Hysteria2 :443 (TLS, h3, BBR)" if params["template"] == "hysteria2"
                       else f"VLESS Reality :443 (SNI {params['reality_sni']}, minClientVer 1.0.0)",
            "node": f"{params['name']} → {params['ip']}:{params['node_port']} ({params['country']})",
            "host": f"«{params['remark']}» → "
                    + (f"{params['domain']}:443" if params["template"] == "hysteria2" else f"{params['ip']}:443"),
            "squad": (sq or {}).get("name"),
        },
        "problems": problems,
        "warnings": warns,
        "plan_hash": _plan_hash(params, (sq or {}).get("uuid", "")),
        "next": "покажите план человеку; согласится — тот же вызов с confirm=true и plan_hash"
                if not problems else "исправьте проблемы и запросите план снова",
    }


async def _wait_connected(p: dict, node_uuid: str) -> bool:
    for _ in range(CONNECT_WAIT_S // 5):
        try:
            n = await remna.request(p, "GET", f"/api/nodes/{node_uuid}")
            if n.get("isConnected"):
                return True
        except remna.RemnaError:
            pass
        await asyncio.sleep(5)
    return False


async def install(panel_name: str, params: dict, plan_hash: str, ssh_user: str = "") -> dict:
    if not config.settings.allow_actions:
        return {"ok": False, "error": "actions_disabled",
                "detail": "действия выключены на хабе (NEXUS_ALLOW_ACTIONS=1 чтобы включить)"}
    pl = await plan(panel_name, params, ssh_user)
    if not pl["ok"]:
        return {"ok": False, "error": "plan_problems", "problems": pl["problems"]}
    if plan_hash != pl["plan_hash"]:
        return {"ok": False, "error": "plan_changed",
                "detail": "план изменился с момента показа человеку — покажите новый", "plan": pl}
    p = remna.resolve(panel_name)
    log: list[str] = []
    created: list[tuple[str, str]] = []   # (тип, uuid) — для отката

    async def rollback(reason: str) -> dict:
        undone = []
        for kind, uid in reversed(created):
            path = {"host": f"/api/hosts/{uid}", "node": f"/api/nodes/{uid}",
                    "profile": f"/api/config-profiles/{uid}"}[kind]
            try:
                await remna.request(p, "DELETE", path)
                undone.append(kind)
            except remna.RemnaError as e:
                undone.append(f"{kind}: не удалён ({e})")
        return {"ok": False, "error": "install_failed", "detail": reason, "log": log,
                "rolled_back": undone,
                "note": f"на сервере {NODE_DIR} мог остаться — при повторе план это покажет"}

    # 1. Секрет ноды и сервер.
    key = await remna.request(p, "GET", "/api/keygen")
    secret_key = (key or {}).get("secretKey") or (key or {}).get("pubKey") or ""
    if not secret_key:
        return {"ok": False, "error": "no_secret", "detail": "панель не отдала secretKey (/api/keygen)"}
    panel_ips = _resolve_ip(urlparse(p["url"]).hostname or "")
    res = await ssh.run_script(ssh_node(params, ssh_user),
                               install_script(params, secret_key, panel_ips[0] if panel_ips else ""),
                               timeout=1500)
    out = scrub(res.stdout + "\n" + res.stderr, [secret_key])
    kv = parse_kv(out)
    if DONE_MARK not in out:
        return {"ok": False, "error": "server_failed",
                "detail": kv.get("rn_err") or (out.strip().splitlines() or ["нет вывода"])[-1][:300],
                "server_log": out[-1500:]}
    log.append(f"сервер: docker {kv.get('docker', '?')}, remnanode {kv.get('container', '?')}"
               + (", сертификат ok" if kv.get("cert") else ""))

    # 2. Панель: профиль → нода → хост → сквад.
    try:
        keys = None
        tag = _tag("HYSTERIA_BBR" if params["template"] == "hysteria2" else "VLESS_REALITY")
        if params["template"] == "reality":
            keys = await remna.request(p, "GET", "/api/system/tools/x25519/generate")
            keys = (keys.get("keypairs") or [keys])[0] if isinstance(keys, dict) else keys
        prof = await remna.request(p, "POST", "/api/config-profiles",
                                   body={"name": _profile_name(params),
                                         "config": profile_config(params, tag, keys)})
        created.append(("profile", prof["uuid"]))
        inbound = next(i for i in prof.get("inbounds") or [] if i.get("tag") == tag)
        log.append(f"профиль {prof.get('name')}, инбаунд {tag}")

        node = await remna.request(p, "POST", "/api/nodes", body={
            "name": params["name"], "address": params["ip"], "port": params["node_port"],
            "countryCode": params["country"], "isTrafficTrackingActive": True,
            "configProfile": {"activeConfigProfileUuid": prof["uuid"], "activeInbounds": [inbound["uuid"]]},
        })
        created.append(("node", node["uuid"]))
        log.append(f"нода {node.get('name')}")

        host = await remna.request(p, "POST", "/api/hosts",
                                   body=host_body(params, prof["uuid"], inbound["uuid"], node["uuid"]))
        created.append(("host", host["uuid"]))
        log.append(f"хост «{host.get('remark')}»")

        squads = await _squads(p)
        sq = _pick_squad(squads, params["squad"])
        current = [i.get("uuid") for i in (sq.get("inbounds") or []) if isinstance(i, dict)]
        await remna.request(p, "PATCH", "/api/internal-squads",
                            body={"uuid": sq["uuid"], "inbounds": [*current, inbound["uuid"]]})
        log.append(f"инбаунд в скваде «{sq.get('name')}» — клиенты сквада получат строку")
    except (remna.RemnaError, KeyError, StopIteration) as e:
        return await rollback(f"панель: {e}")

    connected = await _wait_connected(p, node["uuid"])
    log.append("нода на связи" if connected else
               f"нода не вышла на связь за {CONNECT_WAIT_S} с — смотрите remna_nodes (порт "
               f"{params['node_port']} с панели, docker logs remnanode)")
    return {"ok": True, "connected": connected, "node": params["name"], "log": log}
