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
#     --brain-url https://panel.example.ru --brain-token <VPN_ADMIN_TOKEN> \
#     --brain-gate <VPN_PANEL_GATE_SECRET>
#
# Домен необязателен: без --domain берётся <IP>.sslip.io. Порт сам уйдёт на
# 9443, если 443 занят (нода с xray). Прочее: [--domain d] [--port p]
# [--no-caddy] [--no-xray] [--no-chat] [--bsbord-key bsk_live_…] [--foreground]. Из скачанной копии: bash install.sh <те же флаги>.
#
# Что делает: код в /opt/nexus-mcp/app, venv, SSH-ключ хаба, секреты,
# /etc/nexus-mcp.env, systemd, xray для сквозной проверки, Caddy с
# сертификатом Let's Encrypt для домена (нужен свободный 80 порт), чат с
# Claude для приложения Nexus Admin (nexus-chat; вход в подписку — nexus-chat-login).
# Репозиторий панели (vgx3d, приватный) хабу не нужен: сборщик конфигов
# лежит копией в самом хабе, агент нода берёт с панели.
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
# Без доступа к репо git должен отказать сразу, а не молча ждать логина.
export GIT_TERMINAL_PROMPT=0

DOMAIN=""; PORT="443"; PORT_SET=0; BRAIN_URL=""; BRAIN_TOKEN=""; BRAIN_GATE=""; WITH_CADDY=1; WITH_XRAY=1; WITH_CHAT=1; BSBORD_KEY=""
REPO_URL="https://github.com/Rklm-it/nexus-mcp.git"; BRANCH="main"; GH_TOKEN="${GH_TOKEN:-}"
BASE=/opt/nexus-mcp; ETC=/etc/nexus-mcp; ENVF=/etc/nexus-mcp.env; STATE=/var/lib/nexus-mcp
FOREGROUND=0; ARGS=("$@")
UNIT=nexus-mcp-install; LOG=/var/log/nexus-mcp-install.log
# Имя юнита текущей фоновой установки. У каждого запуска имя своё: юнит
# прошлой установки (RemainAfterExit) systemd выгружает не сразу, и повтор
# с тем же именем падал «Unit … was already loaded or has a fragment file»
# — обновление хаба из меню не запускалось вовсе.
UNITF="${NEXUS_INSTALL_UNITF:-/run/nexus-mcp-install.unit}"

while [[ $# -gt 0 ]]; do
    case "$1" in
        --domain)      DOMAIN="$2"; shift 2 ;;
        --port)        PORT="$2"; PORT_SET=1; shift 2 ;;
        --brain-url)   BRAIN_URL="${2%/}"; shift 2 ;;
        --brain-token) BRAIN_TOKEN="$2"; shift 2 ;;
        --brain-gate)  BRAIN_GATE="$2"; shift 2 ;;
        --repo)        REPO_URL="$2"; shift 2 ;;
        --token)       GH_TOKEN="$2"; shift 2 ;;
        --branch)      BRANCH="$2"; shift 2 ;;
        --no-caddy)    WITH_CADDY=0; shift ;;
        --no-xray)     WITH_XRAY=0; shift ;;
        --no-chat)     WITH_CHAT=0; shift ;;
        --bsbord-key)  BSBORD_KEY="$2"; shift 2 ;;
        --foreground)  FOREGROUND=1; shift ;;
        -h|--help)     [ -f "${BASH_SOURCE[0]:-}" ] && sed -n 2,23p "${BASH_SOURCE[0]}"; FINISHED=1; exit 0 ;;
        *) die "неизвестный параметр: $1" ;;
    esac
done

[ "$(id -u)" = "0" ] || die "нужен root"

# ── Фоном: обрыв SSH не убивает установку ────────────────────────────────────
# Установка идёт юнитом systemd, лог — в $LOG, здесь только показ лога.
# Оборвалось SSH или нажали Ctrl+C — установка продолжается; та же команда
# ещё раз снова показывает лог идущей установки, а не запускает вторую.
if [ -z "${NEXUS_INSTALL_BG:-}" ] && [ "$FOREGROUND" = "0" ] && command -v systemd-run >/dev/null 2>&1; then
    CUR="$(cat "$UNITF" 2>/dev/null || true)"; [ -n "$CUR" ] || CUR="$UNIT"
    if [ "$(systemctl show -p SubState --value "$CUR" 2>/dev/null)" = "running" ]; then
        UNIT="$CUR"
        warn "Установка уже идёт — показываю её лог"
    else
        SELF=""
        [ -f "${BASH_SOURCE[0]:-}" ] && SELF="$(readlink -f "${BASH_SOURCE[0]}")"
        if [ -z "$SELF" ]; then
            # Под `bash <(curl …)` файла скрипта нет — берём копию той же ветки.
            SELF=/root/nexus-mcp-install.sh
            timeout 90 curl -fsSL --connect-timeout 15 -o "$SELF" \
                "https://raw.githubusercontent.com/Rklm-it/nexus-mcp/$BRANCH/install.sh" \
                || die "не скачал install.sh с GitHub — запустите с --foreground"
        fi
        # Хвосты прошлых запусков (и старого общего имени) — убрать, не мешают.
        for u in "$UNIT" "$CUR"; do
            systemctl stop "$u" >/dev/null 2>&1 || true
            systemctl reset-failed "$u" >/dev/null 2>&1 || true
        done
        UNIT="nexus-mcp-install-$(date +%s)"
        : > "$LOG"; chmod 600 "$LOG"
        BG_ENV=(--setenv=NEXUS_INSTALL_BG=1 --setenv=HOME=/root)
        [ -n "$GH_TOKEN" ] && BG_ENV+=("--setenv=GH_TOKEN=$GH_TOKEN")
        systemd-run --quiet --unit "$UNIT" --description "Nexus MCP: установка" \
            -p RemainAfterExit=yes -p "StandardOutput=append:$LOG" -p "StandardError=append:$LOG" \
            "${BG_ENV[@]}" /bin/bash "$SELF" "${ARGS[@]}" \
            || die "systemd-run не запустил установку ($UNIT) — запустите с --foreground"
        echo "$UNIT" > "$UNITF"
    fi
    echo -e "${CYAN}Установка идёт в фоне. Обрыв SSH ей не мешает; лог: tail -f $LOG${NC}"
    tail -n +1 -f "$LOG" & TAILPID=$!
    trap 'kill $TAILPID 2>/dev/null; echo; warn "Установка продолжается в фоне. Лог: tail -f $LOG"; FINISHED=1; exit 0' INT TERM HUP
    while [ "$(systemctl show -p SubState --value "$UNIT" 2>/dev/null)" = "running" ]; do sleep 2; done
    sleep 1; kill $TAILPID 2>/dev/null || true; wait $TAILPID 2>/dev/null || true
    RC="$(systemctl show -p ExecMainStatus --value "$UNIT" 2>/dev/null || echo 1)"
    FINISHED=1
    exit "${RC:-1}"
fi

port_busy() { ss -ltnH "sport = :$1" 2>/dev/null | grep -q . || return 1; }
# Порт держит НАШ Caddy (nexus-mcp-caddy) — это обновление хаба, а не чужой
# сервис: Caddy перезапустится с новым конфигом. Сверка по PID, не по имени:
# Caddy панели на той же машине — тоже «caddy», но наш на его порт не встанет.
own_caddy_port() {
    local pid
    pid="$(systemctl show -p MainPID --value nexus-mcp-caddy 2>/dev/null || true)"
    [ -n "$pid" ] && [ "$pid" != "0" ] || return 1
    ss -ltnpH "sport = :$1" 2>/dev/null | grep -q "pid=$pid," || return 1
}
envget() { grep -E "^$1=" "$ENVF" 2>/dev/null | tail -1 | cut -d= -f2- || true; }

# ── 1. Пакеты ────────────────────────────────────────────────────────────────
log "Пакеты: git, python3-venv, openssh-client, curl"
export DEBIAN_FRONTEND=noninteractive
# Таймауты: без них apt молча ждёт зеркало или чужую блокировку dpkg
# (unattended-upgrades на свежей машине) — вывод скрыт, выглядит как зависание.
APT=(-o DPkg::Lock::Timeout=180 -o Acquire::http::Timeout=30 -o Acquire::https::Timeout=30)
timeout 300 apt-get "${APT[@]}" update -qq >/dev/null 2>&1 || warn "apt-get update не прошёл — пробуем с тем, что есть"
timeout 900 apt-get "${APT[@]}" install -y -qq git python3 python3-venv openssh-client curl unzip ca-certificates >/dev/null \
    || die "apt-get install не прошёл (или занят dpkg: ps aux | grep -E 'apt|dpkg')"

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
    timeout 300 git -C "$APP" fetch -q --depth 1 "$AUTH_URL" "$BRANCH" && git -C "$APP" reset -q --hard FETCH_HEAD \
        || die "git fetch не прошёл: доступ к GitHub с этой машины? (приватный форк — --token)"
else
    log "Клонирую хаб"
    timeout 300 git clone -q --depth 1 -b "$BRANCH" "$AUTH_URL" "$APP" \
        || die "git clone не прошёл (5 минут): доступ к GitHub с этой машины? (приватный форк — --token)"
    # Токен не должен остаться в .git/config.
    git -C "$APP" remote set-url origin "$REPO_URL"
fi
[ -f "$APP/requirements.txt" ] || die "в $APP нет requirements.txt — не та копия?"

# Прежние версии клонировали сюда vgx3d — больше не нужен.
rm -rf "$BASE/vgx3d"

log "venv и зависимости"
# Проверяем pip, а не каталог: оборванный запуск или venv без ensurepip
# (нет python3.X-venv) оставляет каталог без pip — такой пересоздаём.
if [ ! -x "$BASE/venv/bin/pip" ]; then
    PYV="$(python3 -c 'import sys; print("%d.%d" % sys.version_info[:2])')"
    timeout 600 apt-get "${APT[@]}" install -y -qq "python${PYV}-venv" >/dev/null 2>&1 || true
    rm -rf "$BASE/venv"
    python3 -m venv "$BASE/venv" \
        || die "python3 -m venv не прошёл — поставьте пакет: apt-get install python${PYV}-venv"
fi
PIP=(--timeout 30 --retries 3 --progress-bar off --disable-pip-version-check)
timeout 180 "$BASE/venv/bin/pip" install -q "${PIP[@]}" --upgrade pip >/dev/null 2>&1 || true
# Без -q: видно, какой пакет качается, — иначе долгая загрузка неотличима от зависания.
if ! timeout 900 "$BASE/venv/bin/pip" install "${PIP[@]}" -r "$APP/requirements.txt" 2>&1 \
        | { grep -E --line-buffered '^(Collecting|Successfully|ERROR)' || true; }; then
    die "pip install не прошёл (15 минут): доступ к pypi.org с этой машины?"
fi
if [ "$WITH_CHAT" = "1" ]; then
    # Claude Agent SDK везёт Claude Code внутри колеса (~230 МБ): Node не нужен.
    log "Чат с Claude для приложения: claude-agent-sdk"
    if ! timeout 900 "$BASE/venv/bin/pip" install "${PIP[@]}" -r "$APP/requirements-chat.txt" 2>&1 \
            | { grep -E --line-buffered '^(Collecting|Successfully|ERROR)' || true; }; then
        warn "claude-agent-sdk не встал — хаб работает, чат нет. Повторите установку или --no-chat"
        WITH_CHAT=0
    elif ! "$BASE/venv/bin/python" -c "import claude_agent_sdk" 2>/dev/null; then
        warn "claude-agent-sdk не импортируется (Python $(python3 -V 2>&1 | cut -d' ' -f2); нужен 3.10+) — чат выключен"
        WITH_CHAT=0
    fi
fi

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
[ -n "$BRAIN_GATE" ] || BRAIN_GATE="$(envget NEXUS_BRAIN_GATE)"
TEST_SUB="$(envget NEXUS_TEST_SUB_URL)"
ALLOW="$(envget NEXUS_ALLOW_ACTIONS)"; [ -n "$ALLOW" ] || ALLOW=0
BASIC="$(envget NEXUS_BRAIN_BASIC_AUTH)"
CHAT_TOKEN="$(envget NEXUS_CHAT_TOKEN)"; [ -n "$CHAT_TOKEN" ] || CHAT_TOKEN="$(gen 48)"
CHAT_MODEL="$(envget NEXUS_CHAT_MODEL)"
CHAT_EFFORT="$(envget NEXUS_CHAT_EFFORT)"
CHAT_AUDIT="$(envget NEXUS_CHAT_AUDIT_AT)"
CHAT_TZ="$(envget NEXUS_CHAT_TZ)"; [ -n "$CHAT_TZ" ] || CHAT_TZ="Europe/Moscow"
[ -n "$BSBORD_KEY" ] || BSBORD_KEY="$(envget NEXUS_BSBORD_KEY)"
BSBORD_DAILY="$(envget NEXUS_BSBORD_DAILY_RUB)"; [ -n "$BSBORD_DAILY" ] || BSBORD_DAILY=300

log "Пишу $ENVF"
umask 077
cat > "$ENVF" <<EOF
# Хаб диагностики нод Nexus. После правки: systemctl restart nexus-mcp
NEXUS_MCP_SECRET=$SECRET
NEXUS_PROBE_TOKENS=$PROBE_TOKEN
NEXUS_BRAIN_URL=$BRAIN_URL
NEXUS_BRAIN_ADMIN_TOKEN=$BRAIN_TOKEN
NEXUS_BRAIN_GATE=$BRAIN_GATE
NEXUS_BRAIN_BASIC_AUTH=$BASIC
NEXUS_TEST_SUB_URL=$TEST_SUB
NEXUS_ALLOW_ACTIONS=$ALLOW
NEXUS_SSH_KEY=$ETC/id_ed25519
NEXUS_INVENTORY=$ETC/nodes.json
NEXUS_STATE_DIR=$STATE
NEXUS_XRAY=/usr/local/bin/xray
NEXUS_MCP_HOST=127.0.0.1
NEXUS_MCP_PORT=8765
NEXUS_MCP_PUBLIC_HOSTS=$DOMAIN
NEXUS_MCP_PUBLIC_PORT=$PORT
NEXUS_CHAT_TOKEN=$CHAT_TOKEN
NEXUS_CHAT_PORT=8766
NEXUS_CHAT_MODEL=$CHAT_MODEL
NEXUS_CHAT_EFFORT=$CHAT_EFFORT
NEXUS_CHAT_AUDIT_AT=$CHAT_AUDIT
NEXUS_CHAT_TZ=$CHAT_TZ
NEXUS_BSBORD_KEY=$BSBORD_KEY
NEXUS_BSBORD_DAILY_RUB=$BSBORD_DAILY
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

# ── Чат с Claude для приложения ──────────────────────────────────────────────
if [ "$WITH_CHAT" = "1" ]; then
    log "systemd-юнит nexus-chat"
    mkdir -p "$STATE/chat/home" "$STATE/chat/work"
    # Токен подписки — отдельным файлом: его читает только чат, не хаб.
    [ -f "$ETC/claude.env" ] || { umask 077; : > "$ETC/claude.env"; umask 022; }
    chmod 600 "$ETC/claude.env"
    cat > /etc/systemd/system/nexus-chat.service <<EOF
[Unit]
Description=Nexus chat — Claude для приложения администратора
After=network-online.target nexus-mcp.service
Wants=nexus-mcp.service

[Service]
EnvironmentFile=$ENVF
EnvironmentFile=-$ETC/claude.env
Environment=HOME=$STATE/chat/home
Environment=DISABLE_AUTOUPDATER=1
Environment=CLAUDE_CODE_DISABLE_NONESSENTIAL_TRAFFIC=1
WorkingDirectory=$APP
ExecStart=$BASE/venv/bin/python -m nexus_chat
Restart=always
RestartSec=3
TimeoutStopSec=15

[Install]
WantedBy=multi-user.target
EOF
    systemctl daemon-reload
    systemctl enable nexus-chat >/dev/null 2>&1
    systemctl restart nexus-chat
    sleep 3
    if curl -fsS --connect-timeout 5 -m 8 http://127.0.0.1:8766/chat/healthz >/dev/null; then
        log "чат отвечает на 127.0.0.1:8766"
    else
        journalctl -u nexus-chat -n 30 --no-pager >&2 || true
        warn "чат не поднялся — лог выше; хаб работает без него"
    fi
else
    systemctl disable --now nexus-chat >/dev/null 2>&1 || true
fi

# ── 7. Caddy (TLS) ───────────────────────────────────────────────────────────
if [ "$WITH_CADDY" = "1" ]; then
    if port_busy 80 && ! own_caddy_port 80; then
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
    # Реле нода → хаб → панель для нод, до которых путь к панели режется
    # (nexus_mcp/relay.py). Файл маршрутов пересобирает и nexus-mcp-panels.
    if ! ( cd "$APP" && set -a && . "$ENVF" && set +a && \
           "$BASE/venv/bin/python" -m nexus_mcp.relay caddy --no-reload ); then
        warn "маршруты реле не собрались — хаб работает без реле"
        echo "# реле не собрано установщиком" > /etc/caddy-nexus-mcp/relay.caddy
    fi
    cat > /etc/caddy-nexus-mcp/Caddyfile <<EOF
{
    http_port 80
    https_port $PORT
}
$DOMAIN:$PORT {
    import /etc/caddy-nexus-mcp/relay.caddy
    handle /chat/* {
        reverse_proxy 127.0.0.1:8766 {
            flush_interval -1
        }
    }
    handle {
        reverse_proxy 127.0.0.1:8765 {
            flush_interval -1
        }
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
    log "Caddy запущен; жду сертификат для $DOMAIN (до 90 секунд)"
    # Сертификат выпускается при первом запросе — сразу после старта https
    # ещё не отвечает, и итог ниже показал бы ложный ✗.
    HUBURL="https://$DOMAIN"; [ "$PORT" = "443" ] || HUBURL="https://$DOMAIN:$PORT"
    for _ in $(seq 18); do
        curl -fsS --connect-timeout 5 -m 10 "$HUBURL/healthz" >/dev/null 2>&1 && break
        sleep 5
    done
fi

# ── Итог ─────────────────────────────────────────────────────────────────────
install -m 0755 "$APP/bin/nexus-mcp-info" /usr/local/bin/nexus-mcp-info
install -m 0755 "$APP/bin/nexus-mcp-panels" /usr/local/bin/nexus-mcp-panels
install -m 0755 "$APP/bin/nexus-chat-login" /usr/local/bin/nexus-chat-login
install -m 0755 "$APP/bin/nexus-hub" /usr/local/bin/nexus-hub
echo
echo -e "${CYAN}══════════════════════════════════════════════════════════════${NC}"
echo -e "${GREEN}  Хаб установлен${NC}"
echo -e "${CYAN}══════════════════════════════════════════════════════════════${NC}"
/usr/local/bin/nexus-mcp-info || true
echo "Показать это снова в любой момент: nexus-mcp-info   (только ссылку: nexus-mcp-info --url)"
echo -e "${CYAN}Меню хаба — панели, ноды, ключи, секреты, журналы: nexus-hub${NC}"
echo
FINISHED=1
}
