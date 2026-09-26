#!/bin/sh
# Пробник Nexus на роутере OpenWrt: проверки нод с домашнего интернета.
#
# Роутер сам ходит к хабу (long-poll), белый IP и проброс портов не нужны.
# Хаб и приложение Nexus Admin видят его в списке точек обзора и гоняют с
# него подписку: что из неё открывается у домашнего провайдера.
#
# Команду целиком (с адресом хаба и токеном) выдаёт приложение:
# Nexus Admin → Ноды → «Проверка из дома» → «Подключить роутер». Вручную:
#
#   wget -qO- https://raw.githubusercontent.com/Rklm-it/nexus-mcp/main/probe/openwrt/install.sh \
#     | sh -s -- --hub https://<хаб> --token <PROBE_TOKEN> --name роутер-дом [--xray tmp|auto|no]
#
#   --xray tmp   — сквозная проверка: xray качается в ОЗУ перед проверкой и
#                  удаляется после 10 минут простоя (на флеш он не влезает);
#   --xray auto  — только если xray уже стоит на роутере (по умолчанию);
#   --xray no    — только доступность (TCP/TLS), без сквозной.
#   --remove     — удалить пробник (пакеты python3 остаются).
#
# Что ставится: python3-light и пять его модулей (~10 МБ флеша), служба
# /etc/init.d/nexus-probe (procd, перезапуск при падении), настройки в
# /etc/config/nexus-probe. Логи: logread -e nexus-probe.
#
# Весь скрипт в скобках и с отметкой конца: при обрыве загрузки посреди
# `wget | sh` полкоманды не выполнится (инвариант 32 vgx3d).
{
set -u

SRC="https://raw.githubusercontent.com/Rklm-it/nexus-mcp/main"
HUB=""; TOKEN=""; NAME=""; XRAY="auto"; REMOVE=0
# ROOT — только для теста установщика (tests/test_openwrt_install.py): прогон
# секции с заглушками вместо чтения кода (инвариант 35 vgx3d). На роутере пуст.
ROOT="${NEXUS_PROBE_ROOT:-}"
DIR="$ROOT/usr/share/nexus-probe"
INIT="$ROOT/etc/init.d/nexus-probe"
CFG="$ROOT/etc/config/nexus-probe"
# Флеш под python3 и модули; меньше — установка не влезет и оставит полпакета.
NEED_FLASH_KB=12000
PKGS="python3-light python3-openssl python3-urllib python3-email python3-codecs python3-unicodedata python3-logging ca-bundle"
FINISHED=0

say()  { echo "[nexus-probe] $*"; }
warn() { echo "[nexus-probe] ⚠ $*" >&2; }
die()  { echo "[nexus-probe] ✗ $*" >&2; exit 1; }
trap '[ "$FINISHED" = 1 ] || echo "[nexus-probe] ✗ установка не дошла до конца — запустите команду ещё раз" >&2' EXIT
trap 'exit 130' INT TERM

need_arg() { [ $# -ge 2 ] && [ -n "$2" ] || die "у $1 нет значения"; }
while [ $# -gt 0 ]; do
    case "$1" in
        --hub)    need_arg "$@"; HUB="${2%/}"; shift 2 ;;
        --token)  need_arg "$@"; TOKEN="$2"; shift 2 ;;
        --name)   need_arg "$@"; NAME="$2"; shift 2 ;;
        --xray)   need_arg "$@"; XRAY="$2"; shift 2 ;;
        --src)    need_arg "$@"; SRC="${2%/}"; shift 2 ;;
        --remove) REMOVE=1; shift ;;
        *) die "неизвестный параметр: $1" ;;
    esac
done

[ -f "$ROOT/etc/openwrt_release" ] || die "это не OpenWrt (нет /etc/openwrt_release)"
[ "$(id -u)" = 0 ] || die "нужен root"

if [ "$REMOVE" = 1 ]; then
    [ -x "$INIT" ] && { "$INIT" stop 2>/dev/null; "$INIT" disable 2>/dev/null; }
    rm -rf "$INIT" "$DIR" "$CFG" "$ROOT/tmp/nexus-xray"
    say "пробник удалён (python3 оставлен: opkg remove python3-light — если не нужен)"
    FINISHED=1
    exit 0
fi

[ -n "$HUB" ] || die "нужен --hub https://<адрес хаба>"
[ -n "$TOKEN" ] || die "нужен --token (NEXUS_PROBE_TOKENS на хабе)"
case "$HUB" in https://*) ;; *) die "--hub должен начинаться с https:// (а не «$HUB»)" ;; esac
case "$XRAY" in tmp|auto|no) ;; *) die "--xray: tmp | auto | no (а не «$XRAY»)" ;; esac
[ -n "$NAME" ] || NAME="роутер-$(cat /proc/sys/kernel/hostname 2>/dev/null || echo дом)"

. "$ROOT/etc/openwrt_release" 2>/dev/null || true
say "роутер: ${DISTRIB_DESCRIPTION:-OpenWrt} ($(uname -m)), имя пробника: $NAME"

# ── 1. python3 ─────────────────────────────────────────────────────────────
if command -v apk >/dev/null 2>&1; then
    PM=apk; pm_update() { apk update; }; pm_add() { apk add "$@"; }
elif command -v opkg >/dev/null 2>&1; then
    PM=opkg; pm_update() { opkg update; }; pm_add() { opkg install "$@"; }
else
    die "нет ни opkg, ни apk — не знаю, как ставить пакеты"
fi

py_check() {
    # Всё, что пробник импортирует. Отказ — с именем модуля: «python не
    # работает» не говорит, какой пакет доставить (инвариант 26).
    python3 - <<'PY' 2>&1
import importlib, sys
missing = []
for m in ("json", "socket", "ssl", "subprocess", "tempfile", "threading", "shutil", "platform",
          "argparse", "zipfile", "concurrent.futures", "urllib.request", "urllib.parse",
          "encodings.idna"):
    try:
        importlib.import_module(m)
    except Exception as e:
        missing.append(f"{m} ({type(e).__name__}: {e})")
if missing:
    print("нет модулей: " + "; ".join(missing))
    sys.exit(1)
PY
}

if command -v python3 >/dev/null 2>&1 && py_check >/dev/null 2>&1; then
    say "python3 уже есть и подходит: $(python3 --version 2>&1)"
else
    free_kb="$(df -k "$ROOT/overlay" 2>/dev/null | awk 'NR==2 {print $4}')"
    if [ -n "$free_kb" ] && [ "$free_kb" -lt "$NEED_FLASH_KB" ]; then
        die "на флеше свободно $((free_kb / 1024)) МБ, а python3 с модулями — около $((NEED_FLASH_KB / 1024)) МБ. Освободите место (opkg remove …) и повторите"
    fi
    say "ставлю python3 ($PM): $PKGS"
    pm_update >/tmp/nexus-probe-pm.log 2>&1 || { tail -5 /tmp/nexus-probe-pm.log >&2; die "$PM update не прошёл — есть ли интернет у роутера?"; }
    # shellcheck disable=SC2086
    pm_add $PKGS >>/tmp/nexus-probe-pm.log 2>&1 || { tail -8 /tmp/nexus-probe-pm.log >&2; die "пакеты не встали (лог: /tmp/nexus-probe-pm.log)"; }
    why="$(py_check)" || die "python3 встал, но не хватает модулей: $why"
    say "python3 готов: $(python3 --version 2>&1)"
fi

# ── 2. probe.py ────────────────────────────────────────────────────────────
mkdir -p "$DIR"
say "качаю probe.py: $SRC/probe/probe.py"
# -T: без таймаута мёртвый хост молчит минутами и это выглядит зависанием (инвариант 27).
if ! wget -q -T 20 -O "$DIR/probe.py.part" "$SRC/probe/probe.py"; then
    rm -f "$DIR/probe.py.part"
    die "probe.py не скачался с $SRC — GitHub недоступен с роутера? Можно указать зеркало: --src <адрес>"
fi
python3 -c "import ast,sys; ast.parse(open(sys.argv[1]).read())" "$DIR/probe.py.part" 2>/dev/null \
    || { rm -f "$DIR/probe.py.part"; die "скачался не probe.py (обрыв или страница-заглушка провайдера)"; }
mv "$DIR/probe.py.part" "$DIR/probe.py"
say "probe.py $(grep -m1 '^PROBE_VERSION' "$DIR/probe.py" | cut -d'"' -f2) → $DIR"

# ── 3. xray ────────────────────────────────────────────────────────────────
XRAY_BIN=""; XRAY_URL=""
case "$(uname -m)" in
    aarch64|arm64) XARCH=arm64-v8a ;;
    armv7*)        XARCH=arm32-v7a ;;
    x86_64)        XARCH=64 ;;
    mipsel|mips*el) XARCH=mips32le ;;
    mips*)         XARCH=mips32 ;;
    *)             XARCH="" ;;
esac
for c in "$(command -v xray 2>/dev/null)" "$ROOT/usr/bin/xray" "$ROOT/usr/local/bin/xray"; do
    [ -n "$c" ] && [ -x "$c" ] && { XRAY_BIN="$c"; break; }
done
if [ "$XRAY" = no ]; then
    XRAY_BIN=""
    say "сквозная проверка выключена (--xray no): только доступность"
elif [ -n "$XRAY_BIN" ]; then
    say "xray уже есть на роутере: $XRAY_BIN"
elif [ "$XRAY" = tmp ]; then
    [ -n "$XARCH" ] || die "для $(uname -m) нет сборки xray — повторите с --xray no"
    XRAY_URL="https://github.com/XTLS/Xray-core/releases/latest/download/Xray-linux-$XARCH.zip"
    say "xray: по требованию в ОЗУ ($XRAY_URL), удаляется после 10 мин простоя"
else
    say "xray нет — только доступность. Сквозная проверка: повторите с --xray tmp"
fi

# ── 4. служба ──────────────────────────────────────────────────────────────
touch "$CFG"
uci -q delete nexus-probe.main
uci set nexus-probe.main=probe
uci set nexus-probe.main.hub="$HUB"
uci set nexus-probe.main.token="$TOKEN"
uci set nexus-probe.main.name="$NAME"
uci set nexus-probe.main.xray="$XRAY_BIN"
uci set nexus-probe.main.xray_url="$XRAY_URL"
uci set nexus-probe.main.min_mem_mb=48
uci commit nexus-probe
chmod 600 "$CFG"

cat > "$INIT" <<'INITEOF'
#!/bin/sh /etc/rc.common
# Пробник Nexus: проверки нод с домашнего интернета (probe/openwrt/install.sh).
START=99
STOP=10
USE_PROCD=1

start_service() {
    local hub token name xray xray_url min_mem
    config_load nexus-probe
    config_get hub main hub
    config_get token main token
    config_get name main name
    config_get xray main xray
    config_get xray_url main xray_url
    config_get min_mem main min_mem_mb 48
    [ -n "$hub" ] && [ -n "$token" ] || { echo "nexus-probe: нет hub/token в /etc/config/nexus-probe" >&2; return 1; }
    procd_open_instance
    procd_set_param command /usr/bin/python3 -u /usr/share/nexus-probe/probe.py --hub "$hub" --name "$name"
    [ -n "$xray" ] && procd_append_param command --xray "$xray"
    [ -n "$xray_url" ] && procd_append_param command --xray-url "$xray_url"
    # Токен — окружением, а не аргументом: так его не видно в ps.
    procd_set_param env NEXUS_PROBE_TOKEN="$token" NEXUS_PROBE_MIN_MEM_MB="$min_mem" \
        SSL_CERT_FILE=/etc/ssl/certs/ca-certificates.crt
    procd_set_param respawn 3600 10 0
    procd_set_param stdout 1
    procd_set_param stderr 1
    procd_close_instance
}
INITEOF
chmod 755 "$INIT"
"$INIT" enable
"$INIT" restart 2>/dev/null || "$INIT" start

# ── 5. проверка: пробник дошёл до хаба ─────────────────────────────────────
# Статус службы «работает» ничего не говорит о связи с хабом: смотрим, что
# пробник написал сам (он печатает отказ хаба с кодом и причиной).
say "жду связи с хабом…"
ok=0; i=0
while [ $i -lt 20 ]; do
    sleep 1; i=$((i + 1))
    log="$(logread -e nexus-probe 2>/dev/null | tail -n 5)"
    case "$log" in
        *"хаб ответил 401"*|*"хаб ответил 403"*) echo "$log" >&2; die "хаб не принял токен — сверьте с NEXUS_PROBE_TOKENS на хабе" ;;
    esac
    if [ $i -ge 3 ] && hz="$(wget -q -T 10 -O - "$HUB/healthz" 2>/dev/null)" && [ -n "$hz" ]; then
        case "$log" in *"нет связи с хабом"*) ;; *) ok=1; break ;; esac
    fi
done
if [ "$ok" = 1 ]; then
    say "✓ пробник «$NAME» работает и ходит к хабу $HUB"
    say "  в приложении: Ноды → «Проверка из дома» → выберите «$NAME»"
else
    warn "связи с хабом не видно за 20 с. Последние строки лога:"
    logread -e nexus-probe 2>/dev/null | tail -n 5 >&2
    warn "служба оставлена включённой — она будет пробовать сама. Проверка: logread -e nexus-probe"
fi
for svc in podkop passwall passwall2 sing-box xray openclash ssclash mihomo; do
    if [ -x "$ROOT/etc/init.d/$svc" ] && "$ROOT/etc/init.d/$svc" enabled 2>/dev/null; then
        warn "на роутере включён $svc: если он заворачивает трафик САМОГО роутера в VPN, пробник"
        warn "проверит ноды через него, а не через провайдера. Адрес, с которого пробник пришёл"
        warn "к хабу, приложение показывает рядом с его именем — сверьте с домашним IP"
        break
    fi
done
FINISHED=1
}
