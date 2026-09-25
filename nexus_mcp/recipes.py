"""Скрипты, которые хаб выполняет на ноде. Только отсюда — см. ssh.py.

Каждый рецепт — функция, которая проверяет параметры и возвращает текст
bash-скрипта. Параметры не подставляются в скрипт сырыми: сервис — из
списка, числа — в пределах, IP — через `ipaddress`, URL — по шаблону.
"""

from __future__ import annotations

import ipaddress
import re
import shlex

CELL_DIR = "/opt/vpn-cell"
XRAY_CONFIG = "/usr/local/etc/xray/config.json"
SERVICES = ("vpn-cell", "xray", "hysteria-server")

# Отметка конца скрипта обновления. Код выхода 0 без неё — не успех: скрипт
# мог оборваться посреди установки (инварианты 32 и 44). Общая часть обоих
# скриптов: панельного («═══ Обновление завершено ═══») и cell/cell-update.sh
# («Обновление завершено! ✅»).
UPDATE_DONE_MARK = "Обновление завершено"


class RecipeError(ValueError):
    """Параметр рецепта не прошёл проверку."""


def _service(name: str) -> str:
    if name not in SERVICES:
        raise RecipeError(f"сервис «{name}» не из списка: {', '.join(SERVICES)}")
    return name


def _int(value, lo: int, hi: int, what: str) -> int:
    try:
        v = int(value)
    except (TypeError, ValueError):
        raise RecipeError(f"{what}: нужно число") from None
    if not lo <= v <= hi:
        raise RecipeError(f"{what}: от {lo} до {hi}")
    return v


def _ip(value: str) -> str:
    try:
        return str(ipaddress.ip_address((value or "").strip()))
    except ValueError:
        raise RecipeError(f"«{value}» — не IP-адрес") from None


_URL_RE = re.compile(r"^https?://[A-Za-z0-9.\-]+(:\d{1,5})?(/[A-Za-z0-9._~/\-]*)?$")


def _url(value: str) -> str:
    v = (value or "").strip().rstrip("/")
    if not _URL_RE.match(v):
        raise RecipeError(f"«{value}» — не похоже на адрес панели (https://домен)")
    return v


# Общая шапка: читалка .env, которая не падает на отсутствующем ключе
# (инвариант 33), и никаких `set -e` — диагностика должна дойти до конца.
_HEAD = f"""set +e
CELL={CELL_DIR}
ENV=$CELL/.env
envget() {{ grep -E "^$1=" "$ENV" 2>/dev/null | tail -1 | cut -d= -f2- | tr -d "\\"'" || true; }}
"""


def overview() -> str:
    """Всё, что нужно для диагноза, одним заходом: сервисы, версия агента,
    адрес панели, ответ агента локально, путь нода→панель, heartbeat в логе.

    Токен агента читается и используется на самой ноде — в вывод он не
    попадает.
    """
    return _HEAD + r"""
echo "hostname=$(hostname)"
echo "uptime_s=$(cut -d. -f1 /proc/uptime)"
echo "agent_version=$(cat $CELL/agent/VERSION 2>/dev/null)"
echo "has_uplink=$([ -f $CELL/agent/uplink.py ] && echo yes || echo no)"
for s in vpn-cell xray hysteria-server; do
  echo "svc_$s=$(systemctl is-active $s 2>/dev/null || true)"
done
BU=$(envget CELL_BRAIN_URL)
echo "brain_url=$BU"
PORT=$(envget CELL_API_PORT); PORT=${PORT:-9090}
echo "api_port=$PORT"
TOK=$(envget CELL_API_TOKEN)
echo "has_api_token=$([ -n "$TOK" ] && echo yes || echo no)"
echo "local_health=$(curl -s -m 5 -o /dev/null -w '%{http_code}' -H "Authorization: Bearer $TOK" http://127.0.0.1:$PORT/health)"
if [ -n "$BU" ]; then
  echo "brain_health=$(curl -s -m 12 --connect-timeout 8 -o /dev/null -w '%{http_code} %{time_total}' $BU/health)"
  # Пустой POST: 401/403/422 — дошли до самой панели; 000 — не дошли.
  HB=$(curl -s -m 12 --connect-timeout 8 -D - -o /dev/null -w 'CODE=%{http_code}' -X POST $BU/api/v1/agent/heartbeat)
  echo "brain_heartbeat_path=$(printf '%s' "$HB" | grep -o 'CODE=[0-9]*' | cut -d= -f2)"
  # 401 от Caddy (basic_auth), а не от панели: ручка агента закрыта паролем
  # панели, и heartbeat не пройдёт никогда (инвариант 4).
  echo "brain_basic_auth=$(printf '%s' "$HB" | grep -qi '^www-authenticate: *basic' && echo yes || echo no)"
fi
echo "public_ip=$(curl -s -m 6 --connect-timeout 4 https://api.ipify.org || true)"
echo "disk_pct=$(df -P / | awk 'NR==2{gsub("%","",$5); print $5}')"
echo "mem_pct=$(free | awk '/Mem:/{printf "%d", $3*100/$2}')"
echo "load=$(cut -d' ' -f1-3 /proc/loadavg)"
echo "---heartbeat"
journalctl -u vpn-cell --since "-30min" --no-pager -o cat 2>/dev/null | grep -iE "heartbeat|обратный канал|uplink" | tail -8
echo "---warnings"
journalctl -u vpn-cell --since "-30min" --no-pager -o cat -p warning 2>/dev/null | tail -10
echo "---xray"
journalctl -u xray --since "-30min" --no-pager -o cat -p warning 2>/dev/null | tail -6
"""


def logs(service: str, lines: int = 100, since_min: int = 60) -> str:
    s = _service(service)
    n = _int(lines, 1, 500, "lines")
    m = _int(since_min, 1, 7 * 24 * 60, "since_min")
    return f"journalctl -u {s} --since '-{m}min' -n {n} --no-pager -o short-iso 2>&1\n"


def listening() -> str:
    return "ss -ltnup 2>/dev/null | head -80\n"


def firewall() -> str:
    return ("iptables -S 2>/dev/null | head -120; echo '---nft'; "
            "nft list ruleset 2>/dev/null | head -80; echo '---ufw'; ufw status 2>/dev/null | head -30\n")


def xray_test() -> str:
    return (f"xray run -test -c {XRAY_CONFIG} 2>&1 | tail -20; echo \"rc=$?\"; "
            f"ls -la {XRAY_CONFIG} {XRAY_CONFIG}.good 2>&1\n")


def env_redacted() -> str:
    """.env ноды без значений секретов."""
    return _HEAD + r"""
sed -E 's/^([A-Z0-9_]*(TOKEN|KEY|SECRET|PASS|PASSWORD)[A-Z0-9_]*)=.*/\1=***/' "$ENV" 2>&1
"""


def capture(client_ip: str, seconds: int = 20, max_packets: int = 200) -> str:
    """Видит ли нода пакеты от IP клиента. Пусто — до ноды они не доходят."""
    ip = _ip(client_ip)
    sec = _int(seconds, 3, 120, "seconds")
    cnt = _int(max_packets, 10, 2000, "max_packets")
    return f"""set +e
if command -v tcpdump >/dev/null 2>&1; then
  timeout {sec} tcpdump -ni any -nn -tttt -c {cnt} host {ip} 2>&1 | tail -{cnt}
elif command -v tshark >/dev/null 2>&1; then
  timeout {sec} tshark -i any -f "host {ip}" -c {cnt} 2>&1 | tail -{cnt}
else
  echo "NO_CAPTURE_TOOL: нет ни tcpdump, ни tshark"
fi
echo "---conntrack"
(conntrack -L -s {ip} 2>/dev/null || grep -F "src={ip}" /proc/net/nf_conntrack 2>/dev/null) | head -20
"""


def brain_path(brain_url: str) -> str:
    """Путь нода → панель подробно: DNS, TCP, TLS, ответ."""
    u = _url(brain_url)
    q = shlex.quote(u)
    return f"""set +e
echo "== curl -v {u}/health"
curl -sv -m 15 --connect-timeout 8 -o /dev/null {q}/health 2>&1 | grep -E "Trying|Connected|SSL connection|HTTP/|timed out|Failed|resolve" | head -20
echo "== POST heartbeat (ожидаем 401/403/422 — дошли до панели)"
curl -s -m 15 --connect-timeout 8 -o /dev/null -w '%{{http_code}}\\n' -X POST {q}/api/v1/agent/heartbeat
"""


# ── Действия (только с allow_actions и confirm) ────────────────────────────

def restart(service: str) -> str:
    s = _service(service)
    return f"systemctl reset-failed {s} 2>/dev/null; systemctl restart {s}; sleep 2; systemctl is-active {s}; journalctl -u {s} -n 15 --no-pager -o cat\n"


def set_brain_url(brain_url: str) -> str:
    """Прописать адрес панели в .env и перезапустить агент — heartbeat и
    обратный канал включаются только с ним (см. cell/agent/uplink.py)."""
    q = shlex.quote(_url(brain_url))
    return _HEAD + f"""
[ -f "$ENV" ] || {{ echo "NO_ENV: нет $ENV"; exit 3; }}
[ -f $CELL/agent/uplink.py ] || echo "WARN_OLD_AGENT: у агента нет uplink.py — сначала обновить агент"
cp -a "$ENV" "$ENV.bak.$(date +%s)"
sed -i '/^CELL_BRAIN_URL=/d' "$ENV"
echo "CELL_BRAIN_URL="{q} >> "$ENV"
systemctl restart vpn-cell; sleep 5
systemctl is-active vpn-cell
journalctl -u vpn-cell --since "-1min" --no-pager -o cat | grep -iE "heartbeat|обратный канал" | tail -5
"""


def update_agent(brain_url: str) -> str:
    """Обновить агент скриптом панели — тем же путём, что «Обновить агент»
    в самой панели: `<панель>/install/cell-update.sh` (без пароля, тарбол
    агента берётся оттуда же, CELL_BRAIN_URL скрипт прописывает сам). Не из
    GitHub: репозиторий панели приватный, хабу к нему доступа нет.

    Скрипт сперва скачивается целиком и только потом выполняется: `bash <(curl)`
    при обрыве выполнил бы половину установки и вышел с нулём (инвариант 32).
    """
    src = shlex.quote(_url(brain_url) + "/install/cell-update.sh")
    return f"""set +e
F=/tmp/nexus-cell-update.sh
rm -f $F
curl -fsSL --connect-timeout 15 -m 120 -o $F {src} || {{ echo "DOWNLOAD_FAILED: скрипт обновления не скачался с панели"; exit 4; }}
bash $F 2>&1 | sed -r 's/\\x1B\\[[0-9;]*m//g' | tail -60
echo "rc=${{PIPESTATUS[0]}}"
"""


def parse_overview(text: str) -> dict:
    """Вывод overview() → словарь + секции логов."""
    data: dict = {}
    section = None
    blocks: dict[str, list[str]] = {}
    for line in (text or "").splitlines():
        if line.startswith("---"):
            section = line[3:].strip()
            blocks[section] = []
            continue
        if section is None:
            if "=" in line:
                k, _, v = line.partition("=")
                data[k.strip()] = v.strip()
        else:
            blocks[section].append(line)
    data["logs"] = {k: [x for x in v if x.strip()] for k, v in blocks.items()}
    return data
