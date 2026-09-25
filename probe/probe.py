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
    e2e     — поднять xray-клиент с конфигом от хаба и открыть сайт через
              него: работает ли протокол на самом деле
"""

from __future__ import annotations

import argparse
import json
import os
import platform
import shutil
import socket
import ssl
import subprocess
import sys
import tempfile
import time
import urllib.error
import urllib.request

PROBE_VERSION = "1.0.0"

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


# ── Пробы ───────────────────────────────────────────────────────────────────

def probe_tcp(host: str, port: int, timeout: float = 7.0) -> dict:
    """Открывается ли TCP-соединение."""
    t0 = time.monotonic()
    try:
        with socket.create_connection((host, int(port)), timeout=timeout):
            return {"ok": True, "ms": _ms(t0)}
    except Exception as e:  # noqa: BLE001
        return {"ok": False, "ms": _ms(t0), "error": _kind(e), "detail": str(e)[:200]}


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
        raise OSError("SOCKS5: xray не принял приветствие")
    hb = host.encode("idna")
    s.sendall(b"\x05\x01\x00\x03" + bytes([len(hb)]) + hb + int(dport).to_bytes(2, "big"))
    head = s.recv(4)
    if len(head) < 4 or head[1] != 0:
        code = head[1] if len(head) > 1 else -1
        s.close()
        raise OSError(f"SOCKS5: xray не смог соединиться с {host}:{dport} (код {code})")
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
    for cand in ("/usr/local/bin/xray", "/usr/bin/xray", "/opt/xray/xray"):
        if os.path.isfile(cand):
            return cand
    return None


def probe_e2e(config: dict, url: str = E2E_DEFAULT_URL, timeout: float = 15.0,
              xray_bin: str | None = None) -> dict:
    """Поднять xray-клиент с готовым конфигом и открыть `url` через него.

    `config` — полный клиентский xray-конфиг (хаб собирает его из ссылки
    подписки). Входы в нём заменяем одним SOCKS на свободном порту: чужие
    фиксированные порты 10808/10809 могут быть заняты домашним клиентом.
    """
    xray = find_xray(xray_bin)
    if not xray:
        return {"ok": False, "error": "no_xray",
                "detail": "xray не найден: укажите --xray или положите его в PATH"}
    port = _free_port()
    cfg = json.loads(json.dumps(config))
    cfg["inbounds"] = [{
        "tag": "socks", "listen": "127.0.0.1", "port": port, "protocol": "socks",
        "settings": {"auth": "noauth", "udp": False},
    }]
    cfg["log"] = {"loglevel": "warning"}
    tmpdir = tempfile.mkdtemp(prefix="nexus-probe-")
    path = os.path.join(tmpdir, "config.json")
    with open(path, "w", encoding="utf-8") as f:
        json.dump(cfg, f)
    proc = subprocess.Popen(
        [xray, "run", "-c", path],
        stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
    )
    try:
        # Ждём, пока xray откроет порт (или умрёт на разборе конфига).
        deadline = time.monotonic() + 5
        while time.monotonic() < deadline:
            if proc.poll() is not None:
                out = (proc.stdout.read() or b"").decode("utf-8", "replace") if proc.stdout else ""
                return {"ok": False, "error": "xray_failed",
                        "detail": "xray не запустился с этим конфигом", "xray_log": out[-800:]}
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
                             float(a.get("timeout", 15)), xray_bin)
        if kind == "info":
            return {"ok": True, **probe_info(xray_bin)}
    except KeyError as e:
        return {"ok": False, "error": "bad_args", "detail": f"нет параметра {e}"}
    return {"ok": False, "error": "unknown_kind", "detail": f"неизвестное задание: {kind}"}


def probe_info(xray_bin: str | None = None) -> dict:
    return {
        "version": PROBE_VERSION,
        "platform": platform.platform(),
        "python": platform.python_version(),
        "xray": find_xray(xray_bin),
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
    opener = urllib.request.build_opener(urllib.request.ProxyHandler({}))
    with opener.open(req, timeout=timeout) as resp:
        raw = resp.read()
        return json.loads(raw) if raw else {}


def serve(hub: str, token: str, name: str, xray_bin: str | None) -> None:
    from urllib.parse import quote

    info = probe_info(xray_bin)
    print(f"[nexus-probe] {name} → {hub} (xray: {info['xray'] or 'нет'})", flush=True)
    backoff = 2.0
    while True:
        try:
            resp = _call(hub, token, "POST", f"/probe/poll?name={quote(name)}", {"info": info})
            backoff = 2.0
            for job in resp.get("jobs", []):
                t0 = time.monotonic()
                result = run_job(job.get("kind", ""), job.get("args") or {}, xray_bin)
                result.setdefault("took_ms", _ms(t0))
                _call(hub, token, "POST", "/probe/result",
                      {"name": name, "id": job.get("id"), "result": result}, timeout=20)
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
    serve(a.hub, a.token, a.name, a.xray)


if __name__ == "__main__":
    main()
