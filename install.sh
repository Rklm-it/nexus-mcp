#!/usr/bin/env bash
# =============================================================================
# Nexus MCP — установка хаба диагностики нод.
#
# Ставить на машину, ОТКУДА ДО НОД ДОСТАЁТСЯ (не на brain: его путь к нодам
# режется, разбор 22.09.2026). Проверка перед установкой — README, раздел
# «Куда ставить».
#
# Одной командой на VPS под root:
#   bash <(curl -fsSL --connect-timeout 15 \
#     https://raw.githubusercontent.com/Rklm-it/nexus-mcp/main/install.sh) \
#     --brain-url https://panel.example.ru --brain-token <VPN_ADMIN_TOKEN>
#
# Домен необязателен: без --domain берётся <IP>.sslip.io. Порт сам уйдёт на
# 9443, если 443 занят (нода с xray). Прочее: [--domain d] [--port p]
# [--no-caddy] [--no-xray]. Из скачанной копии: bash install.sh <те же флаги>.
#
# Что делает: код в /opt/nexus-mcp/app, разреженный клон vgx3d в
# /opt/nexus-mcp/vgx3d (сборщик конфигов подписки), venv, SSH-ключ хаба,
# секреты, /etc/nexus-mcp.env, systemd, xray для сквозной проверки, Caddy с
# сертификатом Let's Encrypt для домена (нужен свободный 80 порт).
# =============================================================================
{
set -euo pipefail

RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'; CYAN='\033[0;36m'; NC='\033[0m'
log()  { echo -e "${GREEN}[+]${NC} $*"; }
warn() { echo -e "${YELLOW}[!]${NC} $*"; }
die()  { echo -e "${RED}[x]${NC} $*" >&2; exit 1; }

FINISHED=0
on_exit() {
    local rc=$?
    if [ "$FINISHED" != "1" ]; then
        echo -e "${RED}[x] Установка оборвалась (код $rc) — хаб НЕ готов. Вывод выше называет шаг.${NC}" >&2
    fi
}
trap on_exit EXIT
trap 'exit 130' INT TERM

DOMAIN=""; PORT="443"; PORT_SET=0; BRAIN_URL=""; BRAIN_TOKEN=""; WITH_CADDY=1; WITH_XRAY=1
REPO_URL="https://github.com/Rklm-it/nexus-mcp.git"; BRANCH="main"; GH_TOKEN="${GH_TOKEN:-}"
VGX3D_URL="https://github.com/Rklm-it/vgx3d.git"
BASE=/opt/nexus-mcp; ETC=/etc/nexus-mcp; ENVF=/etc/nexus-mcp.env; STATE=/var/lib/nexus-mcp

while [[ $# -gt 0 ]]; do
    case "$1" in
        --domain)      DOMAIN="$2"; shift 2 ;;
        --port)        PORT="$2"; PORT_SET=1; shift 2 ;;
        --brain-url)   BRAIN_URL="${2%/}"; shift 2 ;;
        --brain-token) BRAIN_TOKEN="$2"; shift 2 ;;
        --repo)        REPO_URL="$2"; shift 2 ;;
        --token)       GH_TOKEN="$2"; shift 2 ;;
        --vgx3d)       VGX3D_URL="$2"; shift 2 ;;
        --branch)      BRANCH="$2"; shift 2 ;;
        --no-caddy)    WITH_CADDY=0; shift ;;
        --no-xray)     WITH_XRAY=0; shift ;;
        -h|--help)     [ -f "${BASH_SOURCE[0]:-}" ] && sed -n 2,22p "${BASH_SOURCE[0]}"; FINISHED=1; exit 0 ;;
        *) die "неизвестный параметр: $1" ;;
    esac
done

[ "$(id -u)" = "0" ] || die "нужен root"

port_busy() { ss -ltnH "sport = :$1" 2>/dev/null | grep -q . || return 1; }
envget() { grep -E "^$1=" "$ENVF" 2>/dev/null | tail -1 | cut -d= -f2- || true; }

# ── 1. Пакеты ────────────────────────────────────────────────────────────────
log "Пакеты: git, python3-venv, openssh-client, curl"
export DEBIAN_FRONTEND=noninteractive
apt-get update -qq >/dev/null 2>&1 || warn "apt-get update не прошёл — пробуем с тем, что есть"
apt-get install -y -qq git python3 python3-venv openssh-client curl unzip ca-certificates >/dev/null \
    || die "apt-get install не прошёл"

# ── Адрес и порт хаба ────────────────────────────────────────────────────────
# Повторный запуск (обновление) берёт прежние — иначе сменился бы URL коннектора.
[ -n "$DOMAIN" ] || DOMAIN="$(envget NEXUS_MCP_PUBLIC_HOSTS)"
if [ "$PORT_SET" = "0" ] && [ -n "$(envget NEXUS_MCP_PUBLIC_PORT)" ]; then
    PORT="$(envget NEXUS_MCP_PUBLIC_PORT)"; PORT_SET=1
fi
if [ "$WITH_CADDY" = "1" ]; then
    if [ -z "$DOMAIN" ]; then
        PUBIP="$(curl -fsS -4 --connect-timeout 5 -m 10 https://api.ipify.org 2>/dev/null || true)"
        [[ "$PUBIP" =~ ^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$ ]] \
            || die "не узнал внешний IP (api.ipify.org не ответил) — укажите --domain"
        DOMAIN="${PUBIP//./-}.sslip.io"
        log "Домен не задан — беру $DOMAIN (sslip.io отвечает этим IP, DNS настраивать не нужно)"
    fi
    if [ "$PORT_SET" = "0" ] && port_busy 443 && ! ss -ltnpH 'sport = :443' | grep -q caddy; then
        PORT=9443
        warn "443 занят ($(ss -ltnpH 'sport = :443' | head -1 | awk '{print $NF}')) — хаб встанет на $PORT"
    fi
fi

# ── 2. Код ───────────────────────────────────────────────────────────────────
mkdir -p "$BASE" "$ETC" "$STATE"
chmod 700 "$ETC" "$STATE"
APP="$BASE/app"

# Три пути: запуск из уже скачанной копии (скрипт лежит рядом с nexus_mcp/),
# обновление уже стоящего или свежий клон. --token нужен только для
# приватного форка.
# Под `curl | bash` BASH_SOURCE пуст — тогда копии рядом нет, клонируем.
SELF_DIR=""
if [ -f "${BASH_SOURCE[0]:-}" ]; then
    SELF_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" 2>/dev/null && pwd || true)"
fi
AUTH_URL="$REPO_URL"
if [ -n "$GH_TOKEN" ]; then
    AUTH_URL="$(printf '%s' "$REPO_URL" | sed "s#https://#https://x-access-token:${GH_TOKEN}@#")"
fi
if [ -n "$SELF_DIR" ] && [ -d "$SELF_DIR/nexus_mcp" ] && [ "$SELF_DIR" != "$APP" ]; then
    log "Беру код из $SELF_DIR"
    rm -rf "$APP" && cp -a "$SELF_DIR" "$APP"
elif [ -d "$APP/.git" ]; then
    log "Обновляю хаб"
    git -C "$APP" fetch -q --depth 1 "$AUTH_URL" "$BRANCH" && git -C "$APP" reset -q --hard FETCH_HEAD \
        || die "git fetch не прошёл: доступ к GitHub с этой машины? (приватный форк — --token)"
else
    log "Клонирую хаб"
    timeout 300 git clone -q --depth 1 -b "$BRANCH" "$AUTH_URL" "$APP" \
        || die "git clone не прошёл (5 минут): доступ к GitHub с этой машины? (приватный форк — --token)"
    # Токен не должен остаться в .git/config.
    git -C "$APP" remote set-url origin "$REPO_URL"
fi
[ -f "$APP/requirements.txt" ] || die "в $APP нет requirements.txt — не та копия?"

# Клон панели: из него хаб берёт xray_json.py — тот же сборщик клиентских
# конфигов, что у подписки (второй сборщик разошёлся бы молча).
log "Клон vgx3d (сборщик конфигов подписки)"
if [ -d "$BASE/vgx3d/.git" ]; then
    git -C "$BASE/vgx3d" pull -q --ff-only || warn "vgx3d не обновился — работаем со старой копией"
else
    timeout 300 git clone -q --depth 1 --filter=blob:none --sparse "$VGX3D_URL" "$BASE/vgx3d" \
        && git -C "$BASE/vgx3d" sparse-checkout set brain/app/services cell \
        || { rm -rf "$BASE/vgx3d"; timeout 600 git clone -q --depth 1 "$VGX3D_URL" "$BASE/vgx3d"; } \
        || die "vgx3d не склонировался — сквозная проверка без него не соберёт конфиги"
fi

log "venv и зависимости"
[ -d "$BASE/venv" ] || python3 -m venv "$BASE/venv"
"$BASE/venv/bin/pip" install -q --upgrade pip >/dev/null 2>&1 || true
timeout 600 "$BASE/venv/bin/pip" install -q -r "$APP/requirements.txt" \
    || die "pip install не прошёл: доступ к pypi.org с этой машины?"

# ── 3. SSH-ключ хаба ─────────────────────────────────────────────────────────
if [ ! -f "$ETC/id_ed25519" ]; then
    log "Создаю SSH-ключ хаба"
    ssh-keygen -q -t ed25519 -N "" -C "nexus-mcp@$(hostname)" -f "$ETC/id_ed25519"
fi
chmod 600 "$ETC/id_ed25519"
[ -f "$ETC/nodes.json" ] || echo '{"defaults": {"ssh_user": "root", "ssh_port": 22}, "nodes": []}' > "$ETC/nodes.json"

# ── 4. Настройки ─────────────────────────────────────────────────────────────
gen() { head -c 48 /dev/urandom | base64 | tr -dc 'A-Za-z0-9' | head -c "$1"; }
SECRET="$(envget NEXUS_MCP_SECRET)"; [ -n "$SECRET" ] || SECRET="$(gen 40)"
PROBE_TOKEN="$(envget NEXUS_PROBE_TOKENS)"; [ -n "$PROBE_TOKEN" ] || PROBE_TOKEN="$(gen 32)"
[ -n "$BRAIN_URL" ] || BRAIN_URL="$(envget NEXUS_BRAIN_URL)"
[ -n "$BRAIN_TOKEN" ] || BRAIN_TOKEN="$(envget NEXUS_BRAIN_ADMIN_TOKEN)"
TEST_SUB="$(envget NEXUS_TEST_SUB_URL)"
ALLOW="$(envget NEXUS_ALLOW_ACTIONS)"; [ -n "$ALLOW" ] || ALLOW=0
BASIC="$(envget NEXUS_BRAIN_BASIC_AUTH)"

log "Пишу $ENVF"
umask 077
cat > "$ENVF" <<EOF
# Хаб диагностики нод Nexus. После правки: systemctl restart nexus-mcp
NEXUS_MCP_SECRET=$SECRET
NEXUS_PROBE_TOKENS=$PROBE_TOKEN
NEXUS_BRAIN_URL=$BRAIN_URL
NEXUS_BRAIN_ADMIN_TOKEN=$BRAIN_TOKEN
NEXUS_BRAIN_BASIC_AUTH=$BASIC
NEXUS_TEST_SUB_URL=$TEST_SUB
NEXUS_ALLOW_ACTIONS=$ALLOW
NEXUS_SSH_KEY=$ETC/id_ed25519
NEXUS_INVENTORY=$ETC/nodes.json
NEXUS_STATE_DIR=$STATE
NEXUS_REPO_DIR=$BASE/vgx3d
NEXUS_XRAY=/usr/local/bin/xray
NEXUS_MCP_HOST=127.0.0.1
NEXUS_MCP_PORT=8765
NEXUS_MCP_PUBLIC_HOSTS=$DOMAIN
NEXUS_MCP_PUBLIC_PORT=$PORT
EOF
umask 022

# ── 5. xray для сквозной проверки ────────────────────────────────────────────
if [ "$WITH_XRAY" = "1" ] && [ ! -x /usr/local/bin/xray ]; then
    log "Ставлю xray (сквозная проверка протоколов)"
    ARCH="$(uname -m)"; case "$ARCH" in x86_64) XA=64 ;; aarch64) XA=arm64-v8a ;; *) XA="" ;; esac
    if [ -n "$XA" ]; then
        TMPX="$(mktemp -d)"
        if curl -fsSL --connect-timeout 15 -m 180 -o "$TMPX/x.zip" \
            "https://github.com/XTLS/Xray-core/releases/latest/download/Xray-linux-$XA.zip"; then
            unzip -q -o "$TMPX/x.zip" xray -d /usr/local/bin/ && chmod +x /usr/local/bin/xray \
                && log "xray: $(/usr/local/bin/xray version 2>/dev/null | head -1)"
        else
            warn "xray не скачался — сквозная проверка с хаба будет недоступна (остальное работает)"
        fi
        rm -rf "$TMPX"
    else
        warn "архитектура $ARCH — xray ставьте руками в /usr/local/bin/xray"
    fi
fi

# ── 6. systemd ───────────────────────────────────────────────────────────────
log "systemd-юнит nexus-mcp"
cat > /etc/systemd/system/nexus-mcp.service <<EOF
[Unit]
Description=Nexus MCP — хаб диагностики нод
After=network-online.target
Wants=network-online.target

[Service]
EnvironmentFile=$ENVF
WorkingDirectory=$APP
ExecStart=$BASE/venv/bin/python -m nexus_mcp
Restart=always
RestartSec=3

[Install]
WantedBy=multi-user.target
EOF
systemctl daemon-reload
systemctl enable nexus-mcp >/dev/null 2>&1
systemctl restart nexus-mcp
sleep 3
if curl -fsS --connect-timeout 5 -m 8 http://127.0.0.1:8765/healthz >/dev/null; then
    log "хаб отвечает на 127.0.0.1:8765"
else
    journalctl -u nexus-mcp -n 30 --no-pager >&2 || true
    die "хаб не поднялся — лог выше"
fi

# ── 7. Caddy (TLS) ───────────────────────────────────────────────────────────
if [ "$WITH_CADDY" = "1" ]; then
    if port_busy 80; then
        die "порт 80 занят ($(ss -ltnpH 'sport = :80' | head -1)) — Let's Encrypt не выдаст сертификат. Освободите 80 или поставьте --no-caddy и отдайте TLS своим прокси на 127.0.0.1:8765."
    fi
    if port_busy "$PORT" && ! ss -ltnpH "sport = :$PORT" | grep -q caddy; then
        die "порт $PORT занят ($(ss -ltnpH "sport = :$PORT" | head -1)). Выберите другой: --port 9443"
    fi
    if ! command -v caddy >/dev/null 2>&1; then
        log "Ставлю Caddy"
        ARCH="$(dpkg --print-architecture 2>/dev/null || echo amd64)"
        curl -fsSL --connect-timeout 15 -m 180 -o /usr/local/bin/caddy \
            "https://caddyserver.com/api/download?os=linux&arch=$ARCH" \
            || die "Caddy не скачался (caddyserver.com). Поставьте вручную или --no-caddy"
        chmod +x /usr/local/bin/caddy
    fi
    CADDY_BIN="$(command -v caddy)"
    mkdir -p /etc/caddy-nexus-mcp
    cat > /etc/caddy-nexus-mcp/Caddyfile <<EOF
{
    http_port 80
    https_port $PORT
}
$DOMAIN:$PORT {
    reverse_proxy 127.0.0.1:8765 {
        flush_interval -1
    }
}
EOF
    cat > /etc/systemd/system/nexus-mcp-caddy.service <<EOF
[Unit]
Description=Caddy для Nexus MCP
After=network-online.target nexus-mcp.service

[Service]
ExecStart=$CADDY_BIN run --config /etc/caddy-nexus-mcp/Caddyfile --adapter caddyfile
Restart=always
RestartSec=5
Environment=XDG_DATA_HOME=/var/lib/nexus-mcp-caddy

[Install]
WantedBy=multi-user.target
EOF
    systemctl daemon-reload
    systemctl enable nexus-mcp-caddy >/dev/null 2>&1
    systemctl restart nexus-mcp-caddy
    log "Caddy запущен; сертификат для $DOMAIN выпускается при первом запросе"
fi

# ── Итог ─────────────────────────────────────────────────────────────────────
PUB="$(cat "$ETC/id_ed25519.pub")"
if [ "$PORT" = "443" ]; then HUB_URL="https://$DOMAIN"; else HUB_URL="https://$DOMAIN:$PORT"; fi
[ "$WITH_CADDY" = "1" ] || HUB_URL="https://<ваш-домен>"
echo
echo -e "${CYAN}══════════════════════════════════════════════════════════════${NC}"
echo -e "${GREEN}  Хаб установлен${NC}"
echo -e "${CYAN}══════════════════════════════════════════════════════════════${NC}"
echo
echo "1) Коннектор в claude.ai (Настройки → Коннекторы → Добавить свой):"
echo "     $HUB_URL/mcp/$SECRET"
echo
echo "2) Ключ хаба — добавить на КАЖДУЮ ноду (в /root/.ssh/authorized_keys):"
echo "     $PUB"
echo
echo "3) Домашний пробник (на компьютере или роутере дома):"
echo "     python3 probe.py --hub $HUB_URL --token $PROBE_TOKEN --name <провайдер-дом>"
echo "   probe.py: $APP/probe/probe.py"
echo
echo "Настройки: $ENVF (подписка тестового юзера — NEXUS_TEST_SUB_URL;"
echo "действия с нодами — NEXUS_ALLOW_ACTIONS=1), затем systemctl restart nexus-mcp"
echo
FINISHED=1
}
