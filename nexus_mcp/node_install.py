"""Поставить ноду на чистый сервер и добавить её в панель — с хаба.

Зачем. Команда установки из панели (`curl <панель>/api/v1/install-node.sh | bash`)
требует зайти на сервер по SSH, а с компьютера владельца это выходит не
всегда: провайдер режет, порт закрыт, ключа нет. Хаб же до зарубежных машин
достаёт, и его ключ владелец кладёт в authorized_keys через веб-консоль
хостера. Дальше хаб делает то же, что человек в терминале:

1. План (без confirm, ничего не меняет): SSH до сервера, ОС, занятые порты,
   нет ли уже агента, достаёт ли сервер до панели напрямую или только через
   реле хаба; в панели — нет ли уже ноды с таким IP или именем.
2. Установка (confirm=true): хаб качает установщик у СВОЕЙ панели (тот самый
   install-node.sh, что отдаёт кнопка «Добавить ноду»), передаёт его на
   сервер через stdin SSH и запускает без вопросов (ADMIN_TOKEN, NODE_NAME,
   COUNTRY, NODE_IP — окружением). Скрипт ставит Cell-агент и регистрирует
   ноду в панели.
3. Проверка по панели: нода с этим IP появилась. Не появилась, а агент встал
   (сервер не достал до панели POST'ом: фильтр по дороге, или шли через
   реле, где регистрации нет) — регистрирует сам хаб тем же телом, что и
   установщик, токеном агента с сервера.

Реле (`route="relay"`, в auto — когда напрямую панель с сервера не
открывается): установщик качает бандл агента через `<хаб>/relay/<панель>`, и
этот же адрес уходит агенту в CELL_BRAIN_URL — heartbeat и обновления пойдут
через хаб, как после node_action use_relay.

Секреты: X-Admin-Token панели уходит на сервер только внутри stdin SSH (не в
командной строке) — так же, как его вводит человек; в вывод, который видит
модель, не попадает ни он, ни API-Key агента (строки с ним вырезаются на
сервере, значения — ещё раз на хабе).
"""

from __future__ import annotations

import base64
import ipaddress
import re
import shlex

import httpx

from nexus_mcp import inventory, panels, recipes, relay, ssh
from nexus_mcp import panel as panel_api

# Откуда панель отдаёт установщик ноды (vgx3d brain/app/api/v1/licenses.py).
INSTALLER_PATH = "/api/v1/install-node.sh"
# Строка, которую панель подставляет своим адресом, — признак, что пришёл
# настоящий скрипт, а не страница входа или заглушка CDN.
INSTALLER_MARK = 'MASTER_BRAIN_URL="${MASTER_BRAIN_URL:-'
# Порт Cell API по умолчанию (--port установщика, api_port в панели).
CELL_PORT = 9090
# Строки вывода установщика с секретом агента — режутся ещё на сервере.
SECRET_LINES = ("API-Key",)
# Протоколы, которые установщик ставит и регистрирует (PROTOCOLS по умолчанию).
DEFAULT_PROTOCOLS = ("reality", "reality_grpc", "hysteria2", "shadowsocks")
CDN_PROTOCOLS = ("vless_xhttp_cdn",)
ROUTES = ("auto", "direct", "relay")
# Установка идёт минутами (apt, xray, hysteria); с запасом на медленный apt.
INSTALL_TIMEOUT = 1800.0

_COUNTRY_RE = re.compile(r"^[A-Z]{2}$")
_HOST_RE = re.compile(r"^(?=.{1,253}$)([A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?\.)+[A-Za-z]{2,63}$")


class InstallError(ValueError):
    """Параметр не прошёл проверку или установка невозможна — с причиной."""


def check_params(ip: str, name: str, country: str, ssh_port: int = 22,
                 cdn_domain: str = "", route: str = "auto") -> dict:
    try:
        addr = str(ipaddress.ip_address((ip or "").strip()))
    except ValueError:
        raise InstallError(f"«{ip}» — не IP-адрес сервера") from None
    if ipaddress.ip_address(addr).is_private or ipaddress.ip_address(addr).is_loopback:
        raise InstallError(f"{addr} — внутренний адрес: нода должна быть доступна клиентам из интернета")
    nm = (name or "").strip()
    if not nm or len(nm) > 64 or any(ord(c) < 32 for c in nm):
        raise InstallError("имя ноды: от 1 до 64 символов, без переводов строки")
    cc = (country or "").strip().upper()
    if not _COUNTRY_RE.match(cc):
        raise InstallError(f"страна «{country}» — нужен код из двух латинских букв: DE, NL, FI")
    try:
        port = int(ssh_port)
    except (TypeError, ValueError):
        raise InstallError("ssh_port: нужно число") from None
    if not 0 < port < 65536:
        raise InstallError("ssh_port: от 1 до 65535")
    cdn = (cdn_domain or "").strip().lower().rstrip(".")
    if cdn and not _HOST_RE.match(cdn):
        raise InstallError(f"«{cdn_domain}» — не домен (origin-домен ноды с A-записью на её IP)")
    if route not in ROUTES:
        raise InstallError(f"route: {', '.join(ROUTES)}")
    return {"ip": addr, "name": nm, "country": cc, "ssh_port": port, "cdn_domain": cdn, "route": route}


def ssh_node(params: dict, ssh_user: str = "") -> dict:
    """Нода для ssh.run_script: её ещё нет ни в панели, ни в nodes.json."""
    host = params["ip"]
    if ":" in host:
        host = f"[{host}]"
    n = {"name": params["name"], "ssh_host": host, "ssh_port": params["ssh_port"],
         "ssh_source": "адрес из node_install"}
    if ssh_user:
        n["ssh_user"] = ssh_user
    return n


# ── Скрипты на сервере ─────────────────────────────────────────────────────

def precheck_script(panel_url: str, relay_url: str = "") -> str:
    """Только чтение: что за машина и достаёт ли она до панели. Код ответа
    `/install/brain-ip` — тот же пинг, которым установщик проверяет панель."""
    panel_q = shlex.quote(recipes._url(panel_url) + "/install/brain-ip")
    lines = [
        "set +e",
        'echo "os=$(. /etc/os-release 2>/dev/null; echo "$PRETTY_NAME")"',
        'echo "user=$(id -un)"',
        'echo "arch=$(uname -m)"',
        f'[ -f {recipes.CELL_DIR}/.env ] && echo "cell=present" || echo "cell=absent"',
        "echo \"ports=$(ss -Hltnu 2>/dev/null | awk '{print $5}' | grep -oE '[0-9]+$' | sort -un | tr '\\n' ',')\"",
        'command -v curl >/dev/null && echo "curl=yes" || echo "curl=no"',
        "code() { curl -s -o /dev/null -w '%{http_code}' --connect-timeout 10 --max-time 20 \"$1\" 2>/dev/null || echo 000; }",
        f'echo "panel_direct=$(code {panel_q})"',
    ]
    if relay_url:
        lines.append(f'echo "panel_relay=$(code {shlex.quote(recipes._url(relay_url) + "/install/brain-ip")})"')
    return "\n".join(lines) + "\n"


def parse_kv(text: str) -> dict:
    out = {}
    for line in (text or "").splitlines():
        k, sep, v = line.partition("=")
        if sep and re.fullmatch(r"[a-z_]+", k.strip()):
            out[k.strip()] = v.strip()
    return out


def install_script(installer: str, params: dict, admin_token: str, brain_url: str = "") -> str:
    """Установщик панели → скрипт для `bash -s` на сервере.

    Установщик передаётся base64 внутри heredoc: ни кавычки, ни `$` из него
    не раскрываются, и он целиком на диске до запуска (обрыв SSH не оставит
    выполненной половину, инвариант 32). Значения — окружением через
    shlex.quote; stdin установщика — /dev/null, чтобы он ничего не спросил
    и не съел остаток нашего скрипта.
    """
    if INSTALLER_MARK not in installer:
        raise InstallError("панель отдала не установщик ноды (нет MASTER_BRAIN_URL)")
    env = {
        "ADMIN_TOKEN": admin_token,
        "NODE_NAME": params["name"],
        "COUNTRY": params["country"],
        # Иначе установщик спросит свой IP у панели (/install/node-ip), а
        # через реле панель увидела бы адрес хаба.
        "NODE_IP": params["ip"],
    }
    if brain_url:
        env["MASTER_BRAIN_URL"] = recipes._url(brain_url)
    if params.get("cdn_domain"):
        env["CDN_DOMAIN"] = params["cdn_domain"]
    exports = "\n".join(f"export {k}={shlex.quote(str(v))}" for k, v in env.items())
    b64 = base64.encodebytes(installer.encode("utf-8")).decode("ascii")
    drop = "|".join(SECRET_LINES)
    return f"""set +e
F=$(mktemp /tmp/nexus-install-node.XXXXXX) || {{ echo "NO_TMP: mktemp не сработал"; exit 3; }}
base64 -d > "$F" <<'NEXUS_INSTALLER_B64'
{b64}NEXUS_INSTALLER_B64
{exports}
bash "$F" </dev/null 2>&1 | sed -r 's/\\x1B\\[[0-9;]*[A-Za-z]//g' | grep -vE '{drop}' | tail -80
rc=${{PIPESTATUS[0]}}
rm -f "$F"
echo "rc=$rc"
"""


AGENT_DOWN = "AGENT_DOWN"


def cell_token_script() -> str:
    """Токен Cell API с сервера — для регистрации ноды хабом. Только если
    агент запущен: установщик, упавший посреди cell-setup, оставляет .env с
    токеном, и хаб завёл бы в панель неработающую ноду. Вывод в модель не
    отдаётся."""
    return f"""set +e
systemctl is-active --quiet vpn-cell || {{ echo {AGENT_DOWN}; exit 0; }}
grep -E '^CELL_API_TOKEN=' {recipes.CELL_DIR}/.env 2>/dev/null | tail -1 | cut -d= -f2- | tr -d "\\"' \\r"
"""


def scrub(text: str, secrets: list[str]) -> str:
    for s in secrets:
        if s and len(s) >= 6:
            text = text.replace(s, "***")
    return text


# ── Панель ─────────────────────────────────────────────────────────────────

async def fetch_installer(p: dict) -> str:
    """install-node.sh с панели — с адресом панели внутри, как у кнопки."""
    try:
        async with httpx.AsyncClient(timeout=60, auth=inventory._brain_auth(p), follow_redirects=True) as c:
            r = await c.get(p["url"] + INSTALLER_PATH, headers=inventory._brain_headers(p))
    except httpx.HTTPError as e:
        raise InstallError(f"панель {p['name']} не отдала установщик: {type(e).__name__}: {e}") from e
    if r.status_code != 200:
        raise InstallError(f"панель {p['name']} ответила {r.status_code} на {INSTALLER_PATH}: {r.text[:200]}")
    if INSTALLER_MARK not in r.text:
        raise InstallError(f"панель {p['name']} отдала на {INSTALLER_PATH} не установщик ноды")
    return r.text


async def panel_servers(p: dict) -> list[dict]:
    rows = await inventory.brain_get("/api/v1/servers", p)
    return rows if isinstance(rows, list) else []


def conflicts(rows: list[dict], params: dict) -> list[str]:
    out = []
    for r in rows:
        if str(r.get("ip_address") or "") == params["ip"]:
            out.append(f"в панели уже есть нода {r.get('name')} с IP {params['ip']}")
        elif str(r.get("name") or "").lower() == params["name"].lower():
            out.append(f"имя «{params['name']}» уже занято нодой с IP {r.get('ip_address')}")
    return out


def find_server(rows: list[dict], ip: str) -> dict | None:
    return next((r for r in rows if str(r.get("ip_address") or "") == ip), None)


def register_body(params: dict, api_token: str) -> dict:
    """Тело POST /api/v1/servers — то же, что шлёт установщик (Шаг 5)."""
    cdn = bool(params.get("cdn_domain"))
    return {
        "name": params["name"],
        "ip_address": params["ip"],
        "api_port": CELL_PORT,
        "api_token": api_token,
        "country": params["country"],
        "sub_type": "bypass" if cdn else "vpn",
        "protocols": list(CDN_PROTOCOLS if cdn else DEFAULT_PROTOCOLS),
    }


async def register(p: dict, params: dict, api_token: str) -> dict:
    data = await panel_api.request("POST", "/api/v1/servers", None, 180.0, p["name"],
                                   body=register_body(params, api_token), raw=True)
    return data if isinstance(data, dict) else {}


# ── План и установка ───────────────────────────────────────────────────────

def pick_route(route: str, pre: dict, relay_url: str) -> tuple[str, str, bool]:
    """(маршрут, что сказать человеку, мешает ли это ставить). direct — сервер
    сам достаёт до панели; relay — через реле хаба."""
    direct = pre.get("panel_direct") or "000"
    via = pre.get("panel_relay") or "не проверялось"
    direct_ok = direct in ("200", "204")
    relay_ok = via in ("200", "204")
    if route == "direct":
        if direct_ok:
            return "direct", "", False
        return "direct", (f"с сервера панель не открывается (HTTP {direct}) — установщик не скачает "
                          "агент; ставьте route=\"relay\""), True
    if route == "relay":
        if not relay_url:
            return "relay", "реле хаба не настроено (нет публичного адреса хаба, NEXUS_MCP_PUBLIC_HOSTS)", True
        if relay_ok:
            return "relay", "агент будет ходить к панели через хаб (heartbeat, обновления)", False
        return "relay", f"реле хаба с сервера не открывается (HTTP {via})", True
    if direct_ok:
        return "direct", "", False
    if relay_ok:
        return "relay", (f"с сервера панель напрямую не открывается (HTTP {direct}) — ставим через реле "
                         "хаба: агент будет ходить к панели через хаб"), False
    return "direct", (f"с сервера не открывается ни панель (HTTP {direct}), ни реле хаба (HTTP {via}) — "
                      "установщик не скачает агент"), True


async def plan(panel_name: str, params: dict, ssh_user: str = "") -> dict:
    """Проверки без изменений. Отказ SSH — тоже план: с причиной и советом."""
    try:
        p = panels.resolve(panel_name)
    except panels.PanelConfigError as e:
        raise InstallError(str(e)) from e
    try:
        relay_url = relay.relay_url(p["name"])
    except relay.RelayError:
        relay_url = ""
    node = ssh_node(params, ssh_user)
    res = await ssh.run_script(node, precheck_script(p["url"], relay_url), timeout=60)
    out: dict = {"panel": p["name"], "panel_url": p["url"], "node": params, "ssh": {"ok": res.ok}}
    blockers: list[str] = []
    warnings: list[str] = []
    if not res.ok:
        out["ssh"] = res.as_dict()
        hint = res.hint()
        if res.failure == "auth":
            hint = ("сервер не принял ключ хаба: добавьте публичный ключ хаба (/etc/nexus-mcp/id_ed25519.pub) "
                    "в /root/.ssh/authorized_keys сервера через веб-консоль хостера")
        blockers.append(f"SSH не прошёл ({res.failure}): {hint}")
        pre = {}
    else:
        pre = parse_kv(res.stdout)
        out["server"] = {k: pre.get(k) for k in ("os", "user", "arch", "cell", "ports", "curl")}
        if pre.get("user") != "root":
            blockers.append(f"вошли как {pre.get('user')}, а установщику нужен root")
        if pre.get("cell") == "present":
            blockers.append(f"на сервере уже стоит Cell-агент ({recipes.CELL_DIR}/.env) — это не чистый сервер")
        busy = {x for x in (pre.get("ports") or "").split(",") if x}
        taken = sorted(busy & {"443", "8443", str(CELL_PORT)}, key=int)
        if taken:
            warnings.append(f"заняты порты {', '.join(taken)} — их занимают протоколы и Cell API")
        route, why, blocking = pick_route(params["route"], pre, relay_url)
        out["route"] = route
        if route == "relay":
            out["relay_url"] = relay_url
        if why:
            (blockers if blocking else warnings).append(why)
    try:
        rows = await panel_servers(p)
        blockers += conflicts(rows, params)
    except inventory.InventoryError as e:
        blockers.append(f"список нод панели не получен: {e}")
    out["blockers"] = blockers
    out["warnings"] = warnings
    out["ready"] = not blockers
    return out


async def install(panel_name: str, params: dict, ssh_user: str = "") -> dict:
    """Установка целиком: план → установщик → проверка панели → регистрация
    хабом, если установщик сам не смог."""
    pl = await plan(panel_name, params, ssh_user)
    if not pl["ready"]:
        return {"ok": False, "error": "not_ready", "detail": "; ".join(pl["blockers"]), "plan": pl}
    p = panels.resolve(panel_name)
    token = p.get("token") or ""
    if not token:
        return {"ok": False, "error": "no_token", "detail": f"у панели {p['name']} на хабе нет токена"}
    installer = await fetch_installer(p)
    brain_url = pl["relay_url"] if pl["route"] == "relay" else ""
    node = ssh_node(params, ssh_user)
    res = await ssh.run_script(node, install_script(installer, params, token, brain_url), timeout=INSTALL_TIMEOUT)
    stdout = scrub(res.stdout, [token])
    rc_line = re.findall(r"^rc=(\d+)$", stdout, re.M)
    out: dict = {"panel": p["name"], "node": params["name"], "ip": params["ip"], "route": pl["route"],
                 "installer_rc": int(rc_line[-1]) if rc_line else None, "output": stdout[-12000:]}
    if pl["route"] == "relay":
        out["relay_url"] = pl["relay_url"]
    if not res.ok:
        out.update({"ok": False, "error": res.failure or "ssh", "hint": res.hint(),
                    "stderr": scrub(res.stderr, [token])[-2000:]})
        return out

    rows = await panel_servers(p)
    server = find_server(rows, params["ip"])
    registered_by = "installer"
    if server is None:
        # Агент встал, а в панели ноды нет: регистрация с сервера не дошла.
        tok = await ssh.run_script(node, cell_token_script(), timeout=30)
        lines = [x.strip() for x in (tok.stdout or "").splitlines() if x.strip()] if tok.ok else []
        api_token = lines[-1] if lines else ""
        if not api_token or api_token == AGENT_DOWN:
            out.update({"ok": False, "error": "no_agent",
                        "detail": "установщик не довёл дело: агент vpn-cell на сервере не запущен, в панели "
                                  "ноды нет — см. output"})
            return out
        try:
            created = await register(p, params, api_token)
        except panel_api.PanelError as e:
            out.update({"ok": False, "error": "register_failed", "detail": scrub(str(e), [token, api_token])})
            return out
        registered_by = "hub"
        server = find_server(await panel_servers(p), params["ip"]) or created
    out.update({"ok": True, "registered_by": registered_by, "server_id": str(server.get("id") or ""),
                "panel_online": bool(server.get("is_online"))})
    if params["ssh_port"] != 22 or (ssh_user and ssh_user != "root"):
        out["nodes_json"] = {"name": params["name"], "panel": p["name"], "ssh_port": params["ssh_port"],
                             **({"ssh_user": ssh_user} if ssh_user else {})}
    return out
