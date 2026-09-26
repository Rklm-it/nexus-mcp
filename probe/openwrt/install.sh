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
#   --python auto — python3 на флеш, а если там меньше 12 МБ — в ОЗУ (по умолчанию);
#   --python tmp  — python3 в ОЗУ (/tmp/nexus-py): флеш не тратится, после
#                   перезагрузки роутера служба сама ставит его заново (нужен интернет);
#   --python flash — только на флеш.
#
#   --xray tmp   — сквозная проверка: xray качается в ОЗУ перед проверкой и
#                  удаляется после 10 минут простоя (на флеш он не влезает);
#   --xray auto  — только если xray уже стоит на роутере (по умолчанию);
#   --xray no    — только доступность (TCP/TLS), без сквозной.
#   --remove     — удалить пробник (пакеты python3 остаются).
#
# Что ставится: python3-light и его модули (~11 МБ флеша или ОЗУ), служба
# /etc/init.d/nexus-probe (procd, перезапуск при падении), настройки в
# /etc/config/nexus-probe. Логи: logread -e nexus-probe.
#
# Весь скрипт в скобках и с отметкой конца: при обрыве загрузки посреди
# `wget | sh` полкоманды не выполнится (инвариант 32 vgx3d).
{
set -u

SRC="https://raw.githubusercontent.com/Rklm-it/nexus-mcp/main"
HUB=""; TOKEN=""; NAME=""; XRAY="auto"; PYMODE="auto"; REMOVE=0
# ROOT — только для теста установщика (tests/test_openwrt_install.py): прогон
# секции с заглушками вместо чтения кода (инвариант 35 vgx3d). На роутере пуст.
ROOT="${NEXUS_PROBE_ROOT:-}"
DIR="$ROOT/usr/share/nexus-probe"
INIT="$ROOT/etc/init.d/nexus-probe"
CFG="$ROOT/etc/config/nexus-probe"
# Размер python3 с модулями считается по спискам opkg (pkg_need_kb); это —
# оценка, если посчитать не вышло. Меньше — установка не влезет и оставит полпакета.
NEED_FLASH_KB=12000
# Флеш не заполняем в ноль: без места ломается сохранение настроек роутера.
FLASH_RESERVE_KB=1024
# python3 в ОЗУ: сам python (tmpfs) + этот запас на работу пробника и роутера.
RAM_RESERVE_KB=40960
PY_TMP="$ROOT/tmp/nexus-py"
# unicodedata (нужен encodings.idna → ssl) живёт в python3-codecs: отдельного
# python3-unicodedata в OpenWrt нет, и opkg из-за него отказал бы целиком.
PKGS="python3-light python3-openssl python3-urllib python3-email python3-codecs python3-logging ca-bundle"
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
        --python) need_arg "$@"; PYMODE="$2"; shift 2 ;;
        --src)    need_arg "$@"; SRC="${2%/}"; shift 2 ;;
        --remove) REMOVE=1; shift ;;
        *) die "неизвестный параметр: $1" ;;
    esac
done

[ -f "$ROOT/etc/openwrt_release" ] || die "это не OpenWrt (нет /etc/openwrt_release)"
[ "$(id -u)" = 0 ] || die "нужен root"

if [ "$REMOVE" = 1 ]; then
    [ -x "$INIT" ] && { "$INIT" stop 2>/dev/null; "$INIT" disable 2>/dev/null; }
    rm -rf "$INIT" "$DIR" "$CFG" "$ROOT/tmp/nexus-xray" "$PY_TMP"
    say "пробник удалён (python3 оставлен: opkg remove python3-light — если не нужен)"
    FINISHED=1
    exit 0
fi

[ -n "$HUB" ] || die "нужен --hub https://<адрес хаба>"
[ -n "$TOKEN" ] || die "нужен --token (NEXUS_PROBE_TOKENS на хабе)"
case "$HUB" in https://*) ;; *) die "--hub должен начинаться с https:// (а не «$HUB»)" ;; esac
case "$XRAY" in tmp|auto|no) ;; *) die "--xray: tmp | auto | no (а не «$XRAY»)" ;; esac
case "$PYMODE" in auto|flash|tmp) ;; *) die "--python: auto | flash | tmp (а не «$PYMODE»)" ;; esac
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

# PY_DEST пуст — python3 системный (флеш); иначе — python3 в ОЗУ под PY_DEST.
PY_DEST=""
py() {
    if [ -n "$PY_DEST" ] && [ -x "$PY_DEST/usr/bin/python3" ]; then
        LD_LIBRARY_PATH="$PY_DEST/usr/lib:$PY_DEST/lib" PYTHONHOME="$PY_DEST/usr" "$PY_DEST/usr/bin/python3" "$@"
    else
        python3 "$@"
    fi
}

py_check() {
    # Всё, что пробник импортирует. Отказ — с именем модуля: «python не
    # работает» не говорит, какой пакет доставить (инвариант 26).
    py - <<'PY' 2>&1
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

# Сколько КБ займут $PKGS с зависимостями, которых на роутере ещё нет —
# по Installed-Size из списков opkg (после opkg update). Пусто — не вышло.
pkg_need_kb() {
    [ "$PM" = opkg ] || return 1
    {
        opkg list-installed 2>/dev/null | awk '{print "I " $1}'
        for f in "$ROOT"/var/opkg-lists/*; do
            case "$f" in *.sig) continue ;; esac
            [ -f "$f" ] || continue
            gunzip -c "$f" 2>/dev/null || cat "$f"
        done
    } | awk -v want="$PKGS" '
        /^I / { inst[$2] = 1; next }
        /^Package: / { p = $2; next }
        /^Provides: / { n = split(substr($0, 11), a, /, */)
                        for (i = 1; i <= n; i++) { sub(/[ (].*/, "", a[i]); if (!(a[i] in prov)) prov[a[i]] = p }
                        next }
        /^Depends: / { if (!(p in dep)) dep[p] = substr($0, 10); next }
        /^Installed-Size: / { if (!(p in size)) size[p] = $2; next }
        function have(x) { return (x in inst) || ((x in prov) && (prov[x] in inst)) }
        END {
            tail = split(want, q, " "); head = 1; total = 0
            while (head <= tail) {
                x = q[head++]
                if (!(x in size) && (x in prov)) x = prov[x]
                if ((x in seen) || have(x)) continue
                seen[x] = 1
                if (!(x in size)) exit 1          # пакета нет в списках — не угадываем
                total += size[x]
                m = split(dep[x], d, /, */)
                for (i = 1; i <= m; i++) {
                    k = split(d[i], alt, / *\| */); pick = ""; ok = 0
                    for (j = 1; j <= k; j++) {
                        nm = alt[j]; sub(/ *\(.*/, "", nm); gsub(/ /, "", nm)
                        if (nm == "") continue
                        if (have(nm)) { ok = 1; break }
                        if (pick == "") pick = nm
                    }
                    if (!ok && pick != "") q[++tail] = pick
                }
            }
            printf "%d\n", (total + 1023) / 1024
        }'
}

if [ "$PYMODE" != tmp ] && command -v python3 >/dev/null 2>&1 && py_check >/dev/null 2>&1; then
    say "python3 уже есть и подходит: $(python3 --version 2>&1)"
elif [ "$PYMODE" != flash ] && [ -x "$PY_TMP/usr/bin/python3" ] && PY_DEST="$PY_TMP" && py_check >/dev/null 2>&1; then
    say "python3 уже есть в ОЗУ ($PY_DEST): $(py --version 2>&1)"
else
    PY_DEST=""
    say "обновляю список пакетов ($PM)…"
    pm_update >/tmp/nexus-probe-pm.log 2>&1 || { tail -5 /tmp/nexus-probe-pm.log >&2; die "$PM update не прошёл — есть ли интернет у роутера?"; }
    need_kb="$(pkg_need_kb 2>/dev/null)" || need_kb=""
    case "$need_kb" in ''|*[!0-9]*) need_kb="$NEED_FLASH_KB"; how="оценка" ;; *) how="по спискам $PM" ;; esac
    free_kb="$(df -k "$ROOT/overlay" 2>/dev/null | awk 'NR==2 {print $4}')"
    mem_kb="$(awk '/^MemAvailable:/ {print $2}' "$ROOT/proc/meminfo" 2>/dev/null)"
    free_txt="?"; [ -n "$free_kb" ] && free_txt="$((free_kb / 1024)) МБ"
    mem_txt="?"; [ -n "$mem_kb" ] && mem_txt="$((mem_kb / 1024)) МБ"
    say "python3 с модулями: $(( (need_kb + 1023) / 1024 )) МБ ($how); свободно: флеш $free_txt, ОЗУ $mem_txt"
    short=0
    [ -n "$free_kb" ] && [ "$free_kb" -lt $((need_kb + FLASH_RESERVE_KB)) ] && short=1
    if [ "$PYMODE" = flash ] && [ "$short" = 1 ]; then
        die "на флеше не хватает места: нужно $(( (need_kb + FLASH_RESERVE_KB) / 1024 )) МБ с запасом. Освободите место (opkg remove …) или поставьте python3 в ОЗУ: --python tmp"
    fi
    if [ "$PYMODE" = tmp ] || [ "$short" = 1 ]; then
        [ "$short" = 1 ] && say "на флеш не влезает — ставлю python3 в ОЗУ"
        # В ОЗУ ставит только opkg (--add-dest); apk так не умеет.
        [ "$PM" = opkg ] || die "python3 в ОЗУ ставится только через opkg, а здесь $PM. Освободите на флеше $(( (need_kb + FLASH_RESERVE_KB) / 1024 )) МБ и повторите"
        need_ram=$((need_kb + RAM_RESERVE_KB))
        [ -n "$mem_kb" ] && [ "$mem_kb" -ge "$need_ram" ] \
            || die "в ОЗУ не хватает места: свободно $mem_txt, а python3 ($(( (need_kb + 1023) / 1024 )) МБ) с запасом на работу роутера — $((need_ram / 1024)) МБ. Освободите на флеше $(( (need_kb + FLASH_RESERVE_KB) / 1024 )) МБ (opkg remove …) и повторите"
        PY_DEST="$PY_TMP"
        pm_add() { opkg --add-dest "nexuspy:$PY_DEST" -d nexuspy install "$@"; }
        say "python3 будет в ОЗУ ($PY_DEST): флеш не тратится, после перезагрузки роутера служба поставит его заново сама (нужен интернет, ~1 мин)"
    fi
    say "ставлю python3 ($PM): $PKGS"
    # shellcheck disable=SC2086
    pm_add $PKGS >>/tmp/nexus-probe-pm.log 2>&1 || { tail -8 /tmp/nexus-probe-pm.log >&2; die "пакеты не встали (лог: /tmp/nexus-probe-pm.log)"; }
    why="$(py_check)" || die "python3 встал, но не хватает модулей: $why"
    say "python3 готов: $(py --version 2>&1)"
fi

# ── 2. probe.py ────────────────────────────────────────────────────────────
mkdir -p "$DIR"
say "качаю probe.py: $SRC/probe/probe.py"
# -T: без таймаута мёртвый хост молчит минутами и это выглядит зависанием (инвариант 27).
if ! wget -q -T 20 -O "$DIR/probe.py.part" "$SRC/probe/probe.py"; then
    rm -f "$DIR/probe.py.part"
    die "probe.py не скачался с $SRC — GitHub недоступен с роутера? Можно указать зеркало: --src <адрес>"
fi
py -c "import ast,sys; ast.parse(open(sys.argv[1]).read())" "$DIR/probe.py.part" 2>/dev/null \
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
# Запуск через run.sh: python3 в ОЗУ после перезагрузки роутера пропадает —
# run.sh ставит его заново и только потом запускает пробник.
cat > "$DIR/run.sh" <<'RUNEOF'
#!/bin/sh
# Запуск пробника Nexus (probe/openwrt/install.sh). NEXUS_PY_DEST — python3
# в ОЗУ: после перезагрузки его нет, ставим заново (нужен интернет).
d="${NEXUS_PY_DEST:-}"
if [ -n "$d" ]; then
    export LD_LIBRARY_PATH="$d/usr/lib:$d/lib" PYTHONHOME="$d/usr" PATH="$d/usr/bin:$PATH"
    [ -f "${SSL_CERT_FILE:-}" ] || export SSL_CERT_FILE="$d/etc/ssl/certs/ca-certificates.crt"
    if ! "$d/usr/bin/python3" -c "import ssl, urllib.request, concurrent.futures" >/dev/null 2>&1; then
        echo "[nexus-probe] python3 в ОЗУ нет (роутер перезагружался?) — ставлю в $d"
        # shellcheck disable=SC2086
        if ! { opkg update && opkg --add-dest "nexuspy:$d" -d nexuspy install $NEXUS_PY_PKGS; } >/tmp/nexus-probe-pm.log 2>&1; then
            tail -n 5 /tmp/nexus-probe-pm.log
            echo "[nexus-probe] python3 не встал (нет интернета?) — повтор через минуту"
            sleep 60
            exit 1
        fi
    fi
    exec "$d/usr/bin/python3" -u /usr/share/nexus-probe/probe.py "$@"
fi
exec /usr/bin/python3 -u /usr/share/nexus-probe/probe.py "$@"
RUNEOF
chmod 755 "$DIR/run.sh"

touch "$CFG"
uci -q delete nexus-probe.main
uci set nexus-probe.main=probe
uci set nexus-probe.main.hub="$HUB"
uci set nexus-probe.main.token="$TOKEN"
uci set nexus-probe.main.name="$NAME"
uci set nexus-probe.main.xray="$XRAY_BIN"
uci set nexus-probe.main.xray_url="$XRAY_URL"
uci set nexus-probe.main.min_mem_mb=48
uci set nexus-probe.main.python_dest="$PY_DEST"
uci set nexus-probe.main.python_pkgs="$PKGS"
uci commit nexus-probe
chmod 600 "$CFG"

cat > "$INIT" <<'INITEOF'
#!/bin/sh /etc/rc.common
# Пробник Nexus: проверки нод с домашнего интернета (probe/openwrt/install.sh).
START=99
STOP=10
USE_PROCD=1

start_service() {
    local hub token name xray xray_url min_mem py_dest py_pkgs
    config_load nexus-probe
    config_get hub main hub
    config_get token main token
    config_get name main name
    config_get xray main xray
    config_get xray_url main xray_url
    config_get min_mem main min_mem_mb 48
    config_get py_dest main python_dest
    config_get py_pkgs main python_pkgs
    [ -n "$hub" ] && [ -n "$token" ] || { echo "nexus-probe: нет hub/token в /etc/config/nexus-probe" >&2; return 1; }
    procd_open_instance
    procd_set_param command /bin/sh /usr/share/nexus-probe/run.sh --hub "$hub" --name "$name"
    [ -n "$xray" ] && procd_append_param command --xray "$xray"
    [ -n "$xray_url" ] && procd_append_param command --xray-url "$xray_url"
    # Токен — окружением, а не аргументом: так его не видно в ps.
    procd_set_param env NEXUS_PROBE_TOKEN="$token" NEXUS_PROBE_MIN_MEM_MB="$min_mem" \
        NEXUS_PY_DEST="$py_dest" NEXUS_PY_PKGS="$py_pkgs" \
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
