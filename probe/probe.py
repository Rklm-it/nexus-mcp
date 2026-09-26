#!/usr/bin/env python3
"""Пробник Nexus: проверки ноды с той сети, где он запущен.

Один файл, только стандартная библиотека Python 3.8+ — чтобы его можно было
положить на домашний компьютер (Windows, Linux) или роутер с python3 и не
ставить ничего сверху.

Зачем отдельно от хаба
──────────────────────
Для домашних нод правду говорит только домашний интернет: у Ростелекома,
Дом.ру и местных провайдеров свои ТСПУ, и дата-центр (хаб, check-host)
видит другую картину. Пробник сам ходит к хабу (long-poll), поэтому дома не
нужны ни белый IP, ни проброс портов.

Те же функции хаб зовёт у себя напрямую — это его собственная точка обзора.
Поэтому здесь нет ничего про MCP: только сами пробы и цикл опроса.

Запуск дома:
    python3 probe.py --hub https://mcp.example.ru --token <PROBE_TOKEN> \
        --name "ростелеком-дом" [--xray /path/to/xray]

Что умеет (kind задания → функция):
    tcp     — TCP-соединение: открылось ли, за сколько, чем кончилось
    banner  — пришли ли ДАННЫЕ от сервера (SSH-баннер). «TCP есть, данных
              нет» — ровно та фильтрация, что режет пакеты с нагрузкой
    tls     — полное TLS-рукопожатие: данные в обе стороны
    http    — GET по URL мимо любых прокси
    e2e     — поднять клиент (xray или sing-box) с конфигом от хаба и открыть
              сайт через него: работает ли протокол на самом деле. На роутере
              с podkop sing-box уже стоит — ничего не качаем
    update  — хаб прислал свою версию probe.py: заменить себя и перезапуститься
    batch   — пачка лёгких проб (tcp/banner/tls/http) параллельно, одним
              заданием: прогон всей подписки не упирается в очередь

Роутер (OpenWrt) — probe/openwrt/install.sh: python3-light, служба procd.
Памяти там мало, поэтому сквозная проверка идёт по одной и отказывается
запускать xray, если свободной памяти меньше NEXUS_PROBE_MIN_MEM_MB
(по умолчанию 48): лучше «не проверили», чем OOM, убивший домашний интернет.
"""

from __future__ import annotations

import argparse
import concurrent.futures
import json
import os
import platform
import shutil
import socket
import ssl
import subprocess
import sys
import tempfile
import threading
import time
import urllib.error
import urllib.request

PROBE_VERSION = "1.2.1"

# Лёгкие пробы, которые можно гнать пачкой. e2e сюда не входит: каждая —
# отдельный процесс xray, на роутере это десятки мегабайт.
BATCH_KINDS = ("tcp", "banner", "tls", "http")
BATCH_MAX = 200
BATCH_PARALLEL_MAX = 16

# Бандл корней OpenWrt (пакет ca-bundle). Python там собран без своего пути
# к сертификатам, и проверка TLS хаба падает на ровном месте.
CA_BUNDLES = ("/etc/ssl/certs/ca-certificates.crt", "/etc/ssl/cert.pem")

# Куда ходим в сквозной проверке: крошечный ответ 204, есть у всех клиентов.
E2E_DEFAULT_URL = "https://www.gstatic.com/generate_204"


# ── Классификация сетевых ошибок ────────────────────────────────────────────

def _kind(exc: BaseException) -> str:
    """Отказ → короткое имя. Разные имена чинятся по-разному, поэтому их
    нельзя сваливать в одно «не отвечает» (инвариант 26)."""
    if isinstance(exc, socket.timeout):
        return "timeout"
    if isinstance(exc, ConnectionRefusedError):
        return "refused"
    if isinstance(exc, ConnectionResetError):
        return "reset"
    if isinstance(exc, socket.gaierror):
        return "dns"
    if isinstance(exc, ssl.SSLError):
        return "ssl_error"
    if isinstance(exc, OSError):
        errno = getattr(exc, "errno", None)
        # ENETUNREACH / EHOSTUNREACH (Linux 101/113, Windows 10051/10065)
        if errno in (101, 113, 10051, 10065):
            return "unreachable"
        if errno in (110, 10060):
            return "timeout"
        if errno in (111, 10061):
            return "refused"
        if errno in (104, 10054):
            return "reset"
    return "error"


def _ms(t0: float) -> float:
    return round((time.monotonic() - t0) * 1000, 1)


# FakeIP sing-box (podkop на OpenWrt и родня): имя из их списков резолвится в
# 198.18.0.0/15, и соединение уходит в VPN роутера. Проба тогда зеленеет
# картиной VPN, а не провайдера — поэтому адрес, куда ушли, едет в ответ.
FAKEIP_NETS = (("198.18.0.0", 15),)


def _is_fakeip(ip: str) -> bool:
    try:
        packed = int.from_bytes(socket.inet_aton(ip), "big")
    except OSError:
        return False
    for net, bits in FAKEIP_NETS:
        base = int.from_bytes(socket.inet_aton(net), "big")
        mask = (0xFFFFFFFF << (32 - bits)) & 0xFFFFFFFF
        if packed & mask == base & mask:
            return True
    return False


def _peer(host: str, port: int) -> dict:
    """Куда на самом деле пойдёт соединение: адрес и признак FakeIP."""
    try:
        infos = socket.getaddrinfo(host, int(port), type=socket.SOCK_STREAM)
    except OSError:
        return {}
    ip = infos[0][4][0] if infos else ""
    out = {"peer": ip} if ip and ip != host else {}
    if ip and _is_fakeip(ip):
        out["fakeip"] = True
    return out


# ── Пробы ───────────────────────────────────────────────────────────────────

def probe_tcp(host: str, port: int, timeout: float = 7.0) -> dict:
    """Открывается ли TCP-соединение."""
    peer = _peer(host, port)
    t0 = time.monotonic()
    try:
        with socket.create_connection((host, int(port)), timeout=timeout):
            return {"ok": True, "ms": _ms(t0), **peer}
    except Exception as e:  # noqa: BLE001
        return {"ok": False, "ms": _ms(t0), "error": _kind(e), "detail": str(e)[:200], **peer}


def _with_peer(fn):
    """Добавить в ответ пробы адрес, куда ушло соединение (см. _peer)."""
    def wrapped(host, port, *a, **kw):
        res = fn(host, port, *a, **kw)
        res.update(_peer(host, port))
        return res
    wrapped.__name__ = fn.__name__
    wrapped.__doc__ = fn.__doc__
    return wrapped


@_with_peer
def probe_banner(host: str, port: int = 22, timeout: float = 8.0) -> dict:
    """Пришли ли данные ОТ сервера после соединения.

    SSH-сервер шлёт баннер первым, без запроса. Если соединение открылось, а
    баннера нет — пакеты с нагрузкой режутся по дороге, хотя служебные
    (SYN/ACK) проходят. Это признак фильтра, а не мёртвого sshd: мёртвый
    sshd даёт `refused`.
    """
    t0 = time.monotonic()
    try:
        sock = socket.create_connection((host, int(port)), timeout=timeout)
    except Exception as e:  # noqa: BLE001
        return {"ok": False, "stage": "connect", "ms": _ms(t0), "error": _kind(e),
                "detail": str(e)[:200]}
    connect_ms = _ms(t0)
    try:
        sock.settimeout(timeout)
        data = sock.recv(128)
        if not data:
            return {"ok": False, "stage": "data", "connect_ms": connect_ms,
                    "error": "closed", "detail": "сервер закрыл соединение без данных"}
        return {"ok": True, "connect_ms": connect_ms, "ms": _ms(t0),
                "banner": data.decode("latin-1", "replace").strip()[:100]}
    except Exception as e:  # noqa: BLE001
        return {"ok": False, "stage": "data", "connect_ms": connect_ms, "ms": _ms(t0),
                "error": _kind(e),
                "detail": "TCP открылся, но данные от сервера не пришли"}
    finally:
        try:
            sock.close()
        except OSError:
            pass


@_with_peer
def probe_tls(host: str, port: int = 443, sni: str | None = None,
              timeout: float = 8.0, alpn: list | None = None) -> dict:
    """Полное TLS-рукопожатие. Сертификат не проверяем: нам важно, дошли ли
    байты туда и обратно, а не кто подписал.

    `ssl_error` — сервер ответил (пусть и не тем): дорога живая.
    `timeout` на стадии handshake — ClientHello ушёл и пропал: «TLS
    заморожен», типовой почерк ТСПУ.
    """
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    if alpn:
        try:
            ctx.set_alpn_protocols(list(alpn))
        except NotImplementedError:
            pass
    t0 = time.monotonic()
    try:
        raw = socket.create_connection((host, int(port)), timeout=timeout)
    except Exception as e:  # noqa: BLE001
        return {"ok": False, "stage": "connect", "ms": _ms(t0), "error": _kind(e),
                "detail": str(e)[:200]}
    connect_ms = _ms(t0)
    raw.settimeout(timeout)
    try:
        with ctx.wrap_socket(raw, server_hostname=sni or None) as tls:
            return {
                "ok": True, "connect_ms": connect_ms, "ms": _ms(t0),
                "version": tls.version(), "cipher": (tls.cipher() or [None])[0],
                "alpn": tls.selected_alpn_protocol(),
            }
    except Exception as e:  # noqa: BLE001
        kind = _kind(e)
        detail = str(e)[:200]
        if kind == "timeout":
            detail = "TCP открылся, TLS-рукопожатие не завершилось (ClientHello пропал)"
        return {"ok": False, "stage": "handshake", "connect_ms": connect_ms,
                "ms": _ms(t0), "error": kind, "detail": detail}
    finally:
        try:
            raw.close()
        except OSError:
            pass


def probe_http(url: str, timeout: float = 10.0) -> dict:
    """GET мимо системных прокси (иначе дома проверили бы свой же VPN)."""
    opener = urllib.request.build_opener(urllib.request.ProxyHandler({}))
    req = urllib.request.Request(url, headers={"User-Agent": "Mozilla/5.0"})
    t0 = time.monotonic()
    try:
        with opener.open(req, timeout=timeout) as resp:
            return {"ok": True, "status": resp.status, "ms": _ms(t0)}
    except urllib.error.HTTPError as e:
        # Код ответа — это ответ: сервер достижим.
        return {"ok": True, "status": e.code, "ms": _ms(t0)}
    except Exception as e:  # noqa: BLE001
        reason = getattr(e, "reason", e)
        return {"ok": False, "ms": _ms(t0), "error": _kind(reason) if isinstance(reason, BaseException) else "error",
                "detail": str(reason)[:200]}


# ── Сквозная проверка через xray ────────────────────────────────────────────

def _free_port() -> int:
    s = socket.socket()
    s.bind(("127.0.0.1", 0))
    port = s.getsockname()[1]
    s.close()
    return port


def _socks5_connect(port: int, host: str, dport: int, timeout: float) -> socket.socket:
    """Минимальный SOCKS5-клиент (без авторизации) — чтобы не тянуть PySocks."""
    s = socket.create_connection(("127.0.0.1", port), timeout=timeout)
    s.settimeout(timeout)
    s.sendall(b"\x05\x01\x00")
    if s.recv(2) != b"\x05\x00":
        s.close()
        raise OSError("SOCKS5: клиент (xray/sing-box) не принял приветствие")
    hb = host.encode("idna")
    s.sendall(b"\x05\x01\x00\x03" + bytes([len(hb)]) + hb + int(dport).to_bytes(2, "big"))
    head = s.recv(4)
    if len(head) < 4 or head[1] != 0:
        code = head[1] if len(head) > 1 else -1
        s.close()
        raise OSError(f"SOCKS5: клиент не смог соединиться с {host}:{dport} через ноду (код {code})")
    atyp = head[3]
    if atyp == 1:
        s.recv(4 + 2)
    elif atyp == 4:
        s.recv(16 + 2)
    else:
        ln = s.recv(1)[0]
        s.recv(ln + 2)
    return s


def _fetch_via_socks(port: int, url: str, timeout: float) -> dict:
    from urllib.parse import urlparse

    u = urlparse(url)
    host = u.hostname or ""
    https = u.scheme == "https"
    dport = u.port or (443 if https else 80)
    path = (u.path or "/") + (("?" + u.query) if u.query else "")
    t0 = time.monotonic()
    s = _socks5_connect(port, host, dport, timeout)
    try:
        if https:
            ctx = ssl.create_default_context()
            s = ctx.wrap_socket(s, server_hostname=host)
        s.sendall(
            f"GET {path} HTTP/1.1\r\nHost: {host}\r\nUser-Agent: Mozilla/5.0\r\n"
            f"Connection: close\r\n\r\n".encode()
        )
        first = b""
        while b"\r\n" not in first and len(first) < 4096:
            chunk = s.recv(1024)
            if not chunk:
                break
            first += chunk
        line = first.split(b"\r\n", 1)[0].decode("latin-1", "replace")
        parts = line.split(" ")
        status = int(parts[1]) if len(parts) > 1 and parts[1].isdigit() else None
        return {"status": status, "ms": _ms(t0), "status_line": line[:80]}
    finally:
        try:
            s.close()
        except OSError:
            pass


def find_xray(explicit: str | None = None) -> str | None:
    """Путь к xray: явный, из NEXUS_XRAY, из PATH или типовые места."""
    for cand in (explicit, os.environ.get("NEXUS_XRAY")):
        if cand and os.path.isfile(cand):
            return cand
    found = shutil.which("xray") or shutil.which("xray.exe")
    if found:
        return found
    # /tmp/nexus-xray — роутер: флеша мало, xray качается в память при старте.
    for cand in ("/usr/local/bin/xray", "/usr/bin/xray", "/opt/xray/xray",
                 "/tmp/nexus-xray/xray", "/usr/share/nexus-probe/xray"):
        if os.path.isfile(cand):
            return cand
    return None


def find_singbox() -> str | None:
    """sing-box: на роутере с podkop он уже на флеше — сквозная без скачивания."""
    cand = os.environ.get("NEXUS_SINGBOX")
    if cand and os.path.isfile(cand):
        return cand
    found = shutil.which("sing-box")
    if found:
        return found
    for cand in ("/usr/bin/sing-box", "/usr/local/bin/sing-box"):
        if os.path.isfile(cand):
            return cand
    return None


# ── xray по требованию (роутер) ────────────────────────────────────────────
# На флеш роутера xray (~30 МБ) не влезает, а держать его в /tmp постоянно —
# отдать 30 МБ ОЗУ из 256 навсегда. Поэтому: качаем zip в память перед
# сквозной проверкой и удаляем после XRAY_IDLE_S простоя.

XRAY_TMP_DIR = "/tmp/nexus-xray"
XRAY_IDLE_S = 600
# zip (~12 МБ) + распакованный xray (~30 МБ) + его работа.
XRAY_FETCH_MIN_MEM_MB = 110
_XRAY_URL = os.environ.get("NEXUS_XRAY_URL", "")
_XRAY_FETCH_LOCK = threading.Lock()
_xray_last_used = 0.0


def fetch_xray(url: str, timeout: float = 120.0) -> tuple[str | None, str]:
    """Скачать и распаковать xray в XRAY_TMP_DIR. (путь, причина отказа)."""
    import zipfile

    with _XRAY_FETCH_LOCK:
        path = os.path.join(XRAY_TMP_DIR, "xray")
        if os.path.isfile(path):
            return path, ""
        avail = mem_available_mb()
        if avail is not None and avail < XRAY_FETCH_MIN_MEM_MB:
            return None, (f"свободно {avail} МБ ОЗУ, для скачивания xray нужно {XRAY_FETCH_MIN_MEM_MB} МБ "
                          "(zip + распакованный + работа)")
        os.makedirs(XRAY_TMP_DIR, exist_ok=True)
        zpath = os.path.join(XRAY_TMP_DIR, "xray.zip")
        try:
            opener = urllib.request.build_opener(urllib.request.ProxyHandler({}),
                                                 urllib.request.HTTPSHandler(context=hub_ssl_context()))
            req = urllib.request.Request(url, headers={"User-Agent": f"nexus-probe/{PROBE_VERSION}"})
            with opener.open(req, timeout=timeout) as resp, open(zpath, "wb") as f:
                shutil.copyfileobj(resp, f, 256 * 1024)
            with zipfile.ZipFile(zpath) as z:
                name = next((n for n in z.namelist() if os.path.basename(n) == "xray"), None)
                if not name:
                    return None, "в архиве нет файла xray"
                with z.open(name) as src, open(path + ".part", "wb") as dst:
                    shutil.copyfileobj(src, dst, 256 * 1024)
            os.chmod(path + ".part", 0o755)
            os.replace(path + ".part", path)
            return path, ""
        except Exception as e:  # noqa: BLE001 — причина уходит в ответ пробы
            shutil.rmtree(XRAY_TMP_DIR, ignore_errors=True)
            return None, f"xray не скачался с {url}: {str(e)[:160]}"
        finally:
            try:
                os.remove(zpath)
            except OSError:
                pass


def drop_idle_xray() -> None:
    """Освободить память: скачанный xray не нужен после простоя."""
    if not _XRAY_URL or not os.path.isdir(XRAY_TMP_DIR):
        return
    if time.time() - _xray_last_used < XRAY_IDLE_S or _E2E_LOCK.locked():
        return
    shutil.rmtree(XRAY_TMP_DIR, ignore_errors=True)


def probe_e2e(config: dict, url: str = E2E_DEFAULT_URL, timeout: float = 15.0,
              xray_bin: str | None = None, singbox: dict | None = None) -> dict:
    """Поднять клиент с готовым конфигом и открыть `url` через него.

    `config` — полный клиентский xray-конфиг (хаб собирает его из ссылки
    подписки), `singbox` — тот же профиль для sing-box (None — в sing-box не
    перекладывается). Ядро: xray, если он уже есть; иначе sing-box, если есть
    он (роутер с podkop); иначе xray по требованию. Входы заменяем одним SOCKS
    на свободном порту: чужие 10808/10809 может занимать домашний клиент.
    """
    global _xray_last_used
    engine, binary = "xray", find_xray(xray_bin)
    if not binary and singbox:
        sb = find_singbox()
        if sb:
            engine, binary = "sing-box", sb
    if not binary and _XRAY_URL:
        binary, why = fetch_xray(_XRAY_URL)
        if not binary:
            return {"ok": False, "error": "no_xray", "detail": why}
    if not binary:
        return {"ok": False, "error": "no_xray",
                "detail": "нет ни xray, ни sing-box: укажите --xray или положите xray в PATH"}
    if engine == "xray":
        _xray_last_used = time.time()
    with _E2E_LOCK:
        # Память смотрим уже под замком: пока ждали очереди, её могли занять.
        # Прошлый клиент мог ещё не отдать память — ждём немного, а не отказ.
        need = min_mem_mb(engine)
        avail = mem_available_mb()
        deadline = time.monotonic() + E2E_MEM_WAIT_S
        while avail is not None and avail < need and time.monotonic() < deadline:
            time.sleep(1)
            avail = mem_available_mb()
        if avail is not None and avail < need:
            return {"ok": False, "error": "low_memory",
                    "detail": f"свободно {avail} МБ, {engine} запускается от {need} МБ "
                              f"({'NEXUS_PROBE_SINGBOX_MIN_MEM_MB' if engine == 'sing-box' else 'NEXUS_PROBE_MIN_MEM_MB'}): "
                              "на роутере это защита от OOM"}
        try:
            if engine == "sing-box":
                res = _probe_e2e_singbox(binary, singbox or {}, url, timeout)
            else:
                res = _probe_e2e(binary, config, url, timeout)
            res["engine"] = engine
            return res
        finally:
            if engine == "xray":
                _xray_last_used = time.time()


# Одна сквозная проверка за раз: два xray на роутере с 256 МБ — уже риск.
_E2E_LOCK = threading.Lock()


def mem_available_mb() -> int | None:
    """MemAvailable из /proc/meminfo; None — не Linux или не прочитать."""
    try:
        with open("/proc/meminfo", encoding="ascii") as f:
            for line in f:
                if line.startswith("MemAvailable:"):
                    return int(line.split()[1]) // 1024
    except (OSError, ValueError, IndexError):
        pass
    return None


# Сколько ждать, пока прошлый клиент отдаст память, прежде чем отказать.
E2E_MEM_WAIT_S = 8


def min_mem_mb(engine: str = "xray") -> int:
    """Порог свободной памяти для запуска клиента. sing-box (~20 МБ) легче
    xray, и на роутере с podkop свободно бывает ~50 МБ — порог у него свой."""
    var, default = (("NEXUS_PROBE_SINGBOX_MIN_MEM_MB", 32) if engine == "sing-box"
                    else ("NEXUS_PROBE_MIN_MEM_MB", 48))
    try:
        return int(os.environ.get(var) or default)
    except ValueError:
        return default


def _probe_e2e(xray: str, config: dict, url: str, timeout: float) -> dict:
    port = _free_port()
    cfg = json.loads(json.dumps(config))
    cfg["inbounds"] = [{
        "tag": "socks", "listen": "127.0.0.1", "port": port, "protocol": "socks",
        "settings": {"auth": "noauth", "udp": False},
    }]
    cfg["log"] = {"loglevel": "warning"}
    # Маршрутизация клиентского профиля (geoip:private → direct) проверке не
    # нужна, а без geoip.dat рядом с xray он с ней не запускается вовсе.
    cfg.pop("routing", None)
    return _run_client([xray, "run", "-c"], "xray", cfg, port, url, timeout)


def _probe_e2e_singbox(singbox: str, config: dict, url: str, timeout: float) -> dict:
    port = _free_port()
    cfg = json.loads(json.dumps(config))
    cfg["inbounds"] = [{"type": "socks", "tag": "socks", "listen": "127.0.0.1", "listen_port": port}]
    cfg.setdefault("log", {"level": "warn"})
    return _run_client([singbox, "run", "-c"], "sing-box", cfg, port, url, timeout)


def _run_client(cmd: list, engine: str, cfg: dict, port: int, url: str, timeout: float) -> dict:
    """Запустить клиент с конфигом и открыть `url` через его SOCKS."""
    tmpdir = tempfile.mkdtemp(prefix="nexus-probe-")
    path = os.path.join(tmpdir, "config.json")
    with open(path, "w", encoding="utf-8") as f:
        json.dump(cfg, f)
    proc = subprocess.Popen(
        [*cmd, path],
        stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
    )
    try:
        # Ждём, пока клиент откроет порт (или умрёт на разборе конфига).
        deadline = time.monotonic() + 5
        while time.monotonic() < deadline:
            if proc.poll() is not None:
                out = (proc.stdout.read() or b"").decode("utf-8", "replace") if proc.stdout else ""
                return {"ok": False, "error": "xray_failed",
                        "detail": f"{engine} не запустился с этим конфигом", "xray_log": out[-800:]}
            try:
                socket.create_connection(("127.0.0.1", port), timeout=0.3).close()
                break
            except OSError:
                time.sleep(0.1)
        try:
            res = _fetch_via_socks(port, url, timeout)
        except Exception as e:  # noqa: BLE001
            return {"ok": False, "error": _kind(e), "detail": str(e)[:200],
                    "xray_log": _drain(proc)}
        ok = res.get("status") is not None and res["status"] < 500
        out = {"ok": ok, **res}
        if not ok:
            out["xray_log"] = _drain(proc)
        return out
    finally:
        proc.terminate()
        try:
            proc.wait(timeout=3)
        except subprocess.TimeoutExpired:
            proc.kill()
        shutil.rmtree(tmpdir, ignore_errors=True)


def _drain(proc: subprocess.Popen) -> str:
    """Хвост лога xray. Процесс ещё жив — читаем, остановив его."""
    proc.terminate()
    try:
        out, _ = proc.communicate(timeout=3)
    except subprocess.TimeoutExpired:
        proc.kill()
        out, _ = proc.communicate()
    return (out or b"").decode("utf-8", "replace")[-800:]


# ── Диспетчер заданий ──────────────────────────────────────────────────────

def run_job(kind: str, args: dict, xray_bin: str | None = None) -> dict:
    """Одно задание хаба → результат. Неизвестное задание — ошибка с причиной."""
    a = dict(args or {})
    try:
        if kind == "tcp":
            return probe_tcp(a["host"], int(a["port"]), float(a.get("timeout", 7)))
        if kind == "banner":
            return probe_banner(a["host"], int(a.get("port", 22)), float(a.get("timeout", 8)))
        if kind == "tls":
            return probe_tls(a["host"], int(a.get("port", 443)), a.get("sni"),
                             float(a.get("timeout", 8)), a.get("alpn"))
        if kind == "http":
            return probe_http(a["url"], float(a.get("timeout", 10)))
        if kind == "e2e":
            return probe_e2e(a["config"], a.get("url") or E2E_DEFAULT_URL,
                             float(a.get("timeout", 15)), xray_bin, a.get("singbox"))
        if kind == "update":
            return self_update(a["code"], str(a.get("version") or ""))
        if kind == "batch":
            return run_batch(a.get("jobs") or [], int(a.get("parallel") or 8))
        if kind == "info":
            return {"ok": True, **probe_info(xray_bin)}
    except KeyError as e:
        return {"ok": False, "error": "bad_args", "detail": f"нет параметра {e}"}
    return {"ok": False, "error": "unknown_kind", "detail": f"неизвестное задание: {kind}"}


def run_batch(jobs: list, parallel: int = 8) -> dict:
    """Пачка лёгких проб параллельно; результаты — в порядке заданий.

    Одно задание вместо сотни: очередь пробника не копит проб, у каждой из
    которых на хабе тикает свой таймаут, и прогон подписки не зависит от того,
    успевает ли пробник по одной.
    """
    if not isinstance(jobs, list) or not jobs:
        return {"ok": False, "error": "bad_args", "detail": "пустая пачка"}
    if len(jobs) > BATCH_MAX:
        return {"ok": False, "error": "bad_args", "detail": f"в пачке больше {BATCH_MAX} проб"}

    def one(job) -> dict:
        if not isinstance(job, dict) or job.get("kind") not in BATCH_KINDS:
            kind = job.get("kind") if isinstance(job, dict) else job
            return {"ok": False, "error": "bad_args", "detail": f"в пачке только {', '.join(BATCH_KINDS)}, а не {kind}"}
        t0 = time.monotonic()
        try:
            r = run_job(job["kind"], job.get("args") or {})
        except Exception as e:  # noqa: BLE001 — одна проба не роняет пачку
            r = {"ok": False, "error": "error", "detail": str(e)[:200]}
        r.setdefault("took_ms", _ms(t0))
        return r

    workers = max(1, min(int(parallel or 1), BATCH_PARALLEL_MAX, len(jobs)))
    t0 = time.monotonic()
    with concurrent.futures.ThreadPoolExecutor(max_workers=workers) as ex:
        results = list(ex.map(one, jobs))
    return {"ok": True, "results": results, "ms": _ms(t0)}


ROUTER_VPN_SERVICES = ("podkop", "passwall", "passwall2", "sing-box", "openclash", "mihomo", "ssclash")


def router_vpn() -> str:
    """Включённый на роутере VPN-клиент (OpenWrt): он может завернуть и
    трафик самого пробника. Пусто — не нашли (или не OpenWrt)."""
    rc = "/etc/rc.d"
    try:
        enabled = os.listdir(rc)
    except OSError:
        return ""
    for svc in ROUTER_VPN_SERVICES:
        # /etc/rc.d/S99podkop — включён; K… — только остановка при выключении.
        if any(n.startswith("S") and n[1:].lstrip("0123456789") == svc for n in enabled):
            return svc
    return ""


# ── Обновление от хаба ─────────────────────────────────────────────────────
# Хаб присылает свою версию probe.py (ту же, что гоняет у себя), и пробник
# на роутере обновляется сам — без SSH и без GitHub. Выключить:
# NEXUS_PROBE_NO_UPDATE=1.

def self_update(code: str, version: str) -> dict:
    """Заменить свой файл кодом от хаба. Перезапуск — после отправки ответа
    (serve смотрит на restart)."""
    import ast

    if os.environ.get("NEXUS_PROBE_NO_UPDATE"):
        return {"ok": False, "error": "disabled", "detail": "обновление выключено (NEXUS_PROBE_NO_UPDATE)"}
    try:
        ast.parse(code)
    except SyntaxError as e:
        return {"ok": False, "error": "bad_args", "detail": f"присланный probe.py не разбирается: {e}"}
    if f'PROBE_VERSION = "{version}"' not in code:
        return {"ok": False, "error": "bad_args", "detail": f"в присланном коде нет версии {version}"}
    me = os.path.abspath(__file__)
    try:
        with open(me + ".part", "w", encoding="utf-8") as f:
            f.write(code)
        os.replace(me + ".part", me)
    except OSError as e:
        return {"ok": False, "error": "error", "detail": f"не записать {me}: {e}"}
    return {"ok": True, "from": PROBE_VERSION, "to": version, "restart": True}


def _restart() -> None:
    """Перезапустить себя тем же процессом (procd/systemd не нужны)."""
    print("[nexus-probe] обновился — перезапуск", flush=True)
    os.execv(sys.executable, [sys.executable, "-u", os.path.abspath(__file__), *sys.argv[1:]])


def probe_info(xray_bin: str | None = None) -> dict:
    return {
        "version": PROBE_VERSION,
        "platform": platform.platform(),
        "python": platform.python_version(),
        # Скачиваемый по требованию — тоже «есть»: хаб по этому полю решает,
        # предлагать ли сквозную проверку.
        "xray": find_xray(xray_bin) or ("по требованию" if _XRAY_URL else None),
        "singbox": find_singbox(),
        "batch": True,
        "self_update": not os.environ.get("NEXUS_PROBE_NO_UPDATE"),
        "mem_available_mb": mem_available_mb(),
        "router_vpn": router_vpn(),
    }


# ── Цикл опроса хаба ───────────────────────────────────────────────────────

def _call(hub: str, token: str, method: str, path: str, body: dict | None = None,
          timeout: float = 40.0) -> dict:
    data = json.dumps(body).encode() if body is not None else None
    req = urllib.request.Request(
        hub.rstrip("/") + path, data=data, method=method,
        headers={"Authorization": f"Bearer {token}", "Content-Type": "application/json",
                 "User-Agent": f"nexus-probe/{PROBE_VERSION}"},
    )
    opener = urllib.request.build_opener(urllib.request.ProxyHandler({}),
                                         urllib.request.HTTPSHandler(context=hub_ssl_context()))
    with opener.open(req, timeout=timeout) as resp:
        raw = resp.read()
        return json.loads(raw) if raw else {}


def hub_ssl_context() -> ssl.SSLContext:
    """Проверка сертификата хаба — всегда. На OpenWrt у Python нет своего
    пути к корням, поэтому берём бандл системы, если по умолчанию пусто."""
    ctx = ssl.create_default_context()
    if not os.environ.get("SSL_CERT_FILE") and not ctx.get_ca_certs():
        for path in CA_BUNDLES:
            if os.path.isfile(path):
                ctx.load_verify_locations(cafile=path)
                break
    return ctx


def serve(hub: str, token: str, name: str, xray_bin: str | None) -> None:
    """Опрос хаба. Задания выполняются в фоне: пока идёт сквозная проверка
    (десятки секунд), пробник продолжает забирать и выполнять лёгкие."""
    from urllib.parse import quote

    info = probe_info(xray_bin)
    print(f"[nexus-probe] {name} → {hub} (xray: {info['xray'] or 'нет'}, "
          f"sing-box: {info['singbox'] or 'нет'}, версия {PROBE_VERSION})", flush=True)
    pool = concurrent.futures.ThreadPoolExecutor(max_workers=4)

    def work(job: dict) -> None:
        t0 = time.monotonic()
        try:
            result = run_job(job.get("kind", ""), job.get("args") or {}, xray_bin)
        except Exception as e:  # noqa: BLE001 — упавшая проба = ответ с причиной
            result = {"ok": False, "error": "error", "detail": str(e)[:200]}
        result.setdefault("took_ms", _ms(t0))
        for attempt in range(3):
            try:
                _call(hub, token, "POST", "/probe/result",
                      {"name": name, "id": job.get("id"), "result": result}, timeout=20)
                break
            except Exception as e:  # noqa: BLE001
                if attempt == 2:
                    print(f"[nexus-probe] результат {job.get('id')} не отправлен: {e}",
                          file=sys.stderr, flush=True)
                time.sleep(1 + attempt)
        if result.get("restart"):
            _restart()

    backoff = 2.0
    while True:
        try:
            info["mem_available_mb"] = mem_available_mb()
            info["xray"] = find_xray(xray_bin) or ("по требованию" if _XRAY_URL else None)
            drop_idle_xray()
            resp = _call(hub, token, "POST", f"/probe/poll?name={quote(name)}", {"info": info})
            backoff = 2.0
            for job in resp.get("jobs", []):
                pool.submit(work, job)
        except urllib.error.HTTPError as e:
            # 401/403 — неверный токен: повторять бессмысленно, но и падать
            # молча нельзя — пишем причину и ждём дольше.
            detail = e.read().decode("utf-8", "replace")[:200]
            print(f"[nexus-probe] хаб ответил {e.code}: {detail}", file=sys.stderr, flush=True)
            time.sleep(60 if e.code in (401, 403) else backoff)
            backoff = min(backoff * 2, 60)
        except Exception as e:  # noqa: BLE001
            print(f"[nexus-probe] нет связи с хабом: {e}", file=sys.stderr, flush=True)
            time.sleep(backoff)
            backoff = min(backoff * 2, 60)


def main() -> None:
    p = argparse.ArgumentParser(description="Пробник Nexus: проверки нод с этой сети")
    p.add_argument("--hub", required=True, help="адрес хаба, например https://mcp.example.ru")
    p.add_argument("--token", default=os.environ.get("NEXUS_PROBE_TOKEN", ""),
                   help="токен пробника (или NEXUS_PROBE_TOKEN)")
    p.add_argument("--name", default=socket.gethostname(),
                   help="имя пробника, лучше с провайдером: «ростелеком-дом»")
    p.add_argument("--xray", default=None, help="путь к xray для сквозной проверки")
    p.add_argument("--xray-url", default=os.environ.get("NEXUS_XRAY_URL", ""),
                   help="zip с xray: качать в /tmp перед сквозной проверкой и удалять после "
                        "простоя (роутер, где xray не влезает на флеш)")
    p.add_argument("--once", default=None, metavar="HOST",
                   help="не подключаться к хабу, а один раз проверить HOST и выйти")
    a = p.parse_args()
    if a.once:
        for kind, args in (("tcp", {"host": a.once, "port": 22}),
                           ("banner", {"host": a.once, "port": 22}),
                           ("tcp", {"host": a.once, "port": 443}),
                           ("tls", {"host": a.once, "port": 443})):
            print(kind, args.get("port"), json.dumps(run_job(kind, args, a.xray), ensure_ascii=False))
        return
    if not a.token:
        p.error("нужен --token (или переменная NEXUS_PROBE_TOKEN)")
    global _XRAY_URL
    _XRAY_URL = a.xray_url or ""
    serve(a.hub, a.token, a.name, a.xray)


if __name__ == "__main__":
    main()
