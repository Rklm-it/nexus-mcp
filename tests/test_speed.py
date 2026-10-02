"""Замер скорости с пробника: варианты ссылки, прокси до хаба, сами замеры.

Что стережётся:
  • вариант подменяет поля extra и сливает xmux, а не затирает его;
  • связь с хабом идёт через прокси, а пробы — нет (иначе мерили бы прокси);
  • скачивание и отправка меряются по байтам и времени, отказ сервера при
    отправке — не скорость;
  • повторы одного варианта сводятся медианой;
  • пробник старее 1.3.0 получает внятный отказ, а не молчаливый таймаут.
"""

from __future__ import annotations

import json
import socket
import struct
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import parse_qs, urlparse

import pytest

from nexus_mcp import speed
from nexus_mcp.probes import Probe, probe_lib, registry

LINK = (
    "vless://11111111-2222-3333-4444-555555555555@cdn.example.ru:443"
    "?type=xhttp&security=tls&sni=cdn.example.ru&path=/assets/api/v2&mode=packet-up"
    "&extra=%7B%22scMinPostsIntervalMs%22%3A%2230-80%22%2C%22uplinkHTTPMethod%22%3A%22GET%22"
    "%2C%22xmux%22%3A%7B%22maxConnections%22%3A%222%22%2C%22hKeepAlivePeriod%22%3A5%7D%7D#t"
)


def _extra(uri: str) -> dict:
    return json.loads(parse_qs(urlparse(uri).query)["extra"][0])


def test_variant_overrides_extra_and_merges_xmux():
    uri = speed.variant_uri(LINK, {
        "sc_max_each_post_bytes": "8000-12000",
        "sc_min_posts_interval_ms": "10-30",
        "max_connections": "4",
        "mode": "stream-one",
    })
    extra = _extra(uri)
    assert extra["scMaxEachPostBytes"] == "8000-12000"
    assert extra["scMinPostsIntervalMs"] == "10-30"
    assert extra["uplinkHTTPMethod"] == "GET"  # не тронутое — на месте
    # xmux слит: прежний hKeepAlivePeriod не потерян.
    assert extra["xmux"] == {"maxConnections": "4", "hKeepAlivePeriod": 5}
    assert parse_qs(urlparse(uri).query)["mode"] == ["stream-one"]
    assert uri.endswith("#t")


def test_as_is_is_the_link_itself():
    assert speed.variant_uri(LINK, {}) == LINK


def test_variant_config_reaches_xray_settings():
    from nexus_mcp import links

    cfg = links.config_for(speed.variant_uri(LINK, {"uplink_data_placement": "header"}))
    extra = cfg["outbounds"][0]["streamSettings"]["xhttpSettings"]["extra"]
    assert extra["uplinkDataPlacement"] == "header"


def test_summary_is_a_median_per_variant():
    rows = [
        {"name": "a", "ok": True, "dl_mbit": 10, "ul_mbit": 1, "overrides": {}},
        {"name": "a", "ok": True, "dl_mbit": 30, "ul_mbit": 3, "overrides": {}},
        {"name": "a", "ok": True, "dl_mbit": 20, "ul_mbit": 2, "overrides": {}},
        {"name": "b", "ok": False, "dl_mbit": 0, "ul_mbit": 0, "overrides": {"x": 1}},
    ]
    s = {r["name"]: r for r in speed.summarize(rows)}
    assert s["a"]["dl_mbit"] == 20 and s["a"]["ul_mbit"] == 2 and s["a"]["ok_runs"] == 3
    assert s["b"]["ok_runs"] == 0 and s["b"]["dl_mbit"] == 0.0


def test_old_probe_is_told_to_update(monkeypatch):
    monkeypatch.setitem(registry.probes, "phone", Probe(name="phone", info={"version": "1.2.1", "xray": True}))
    with pytest.raises(speed.SpeedError, match="1.3.0"):
        speed.check_probe("phone")
    monkeypatch.setitem(registry.probes, "phone", Probe(name="phone", info={"version": "1.3.0", "xray": True}))
    speed.check_probe("phone")


# ── Пробник ────────────────────────────────────────────────────────────────

def test_hub_proxy_only_for_the_hub(monkeypatch):
    lib = probe_lib()
    monkeypatch.setattr(lib, "_HUB_PROXY", "http://127.0.0.1:10809")
    h = lib._hub_proxy_handler()
    assert h.proxies.get("https") == "http://127.0.0.1:10809"
    monkeypatch.setattr(lib, "_HUB_PROXY", "")
    assert lib._hub_proxy_handler().proxies == {}
    # Прямые пробы прокси не знают вовсе — ни при каком _HUB_PROXY.
    import inspect

    assert "_hub_proxy_handler" not in inspect.getsource(lib.probe_http)


def test_speed_job_without_config_is_bad_args():
    lib = probe_lib()
    assert lib.run_job("speed", {})["error"] == "bad_args"


class _Http(BaseHTTPRequestHandler):
    DOWN = 2_000_000

    def log_message(self, *a):  # тишина в выводе тестов
        pass

    def do_GET(self):
        if self.path.startswith("/api"):
            body = json.dumps({"download": {"probes": [{"url": "http://probe.test/probes/50mb"}]},
                               "upload": {"probes": [{"postUrl": "http://probe.test/up"}]}}).encode()
        else:
            body = b"x" * self.DOWN
        self.send_response(200)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def do_POST(self):
        n = int(self.headers.get("Content-Length") or 0)
        got = 0
        while got < n:
            chunk = self.rfile.read(min(65536, n - got))
            if not chunk:
                break
            got += len(chunk)
        code = 413 if self.path.startswith("/reject") else 200
        self.send_response(code)
        self.send_header("Content-Length", "0")
        self.end_headers()


def _socks_to(target_port: int) -> int:
    """SOCKS5 на localhost, который любой CONNECT ведёт на target_port."""
    srv = socket.socket()
    srv.bind(("127.0.0.1", 0))
    srv.listen(8)

    def pipe(a, b):
        try:
            while True:
                d = a.recv(65536)
                if not d:
                    break
                b.sendall(d)
        except OSError:
            pass
        finally:
            for s in (a, b):
                try:
                    s.shutdown(socket.SHUT_RDWR)
                except OSError:
                    pass

    def handle(c):
        c.recv(3)
        c.sendall(b"\x05\x00")
        head = c.recv(4)
        if head[3] == 3:
            c.recv(c.recv(1)[0])
        elif head[3] == 1:
            c.recv(4)
        c.recv(2)
        up = socket.create_connection(("127.0.0.1", target_port))
        c.sendall(b"\x05\x00\x00\x01" + socket.inet_aton("127.0.0.1") + struct.pack(">H", 0))
        threading.Thread(target=pipe, args=(c, up), daemon=True).start()
        threading.Thread(target=pipe, args=(up, c), daemon=True).start()

    def loop():
        while True:
            c, _ = srv.accept()
            threading.Thread(target=handle, args=(c,), daemon=True).start()

    threading.Thread(target=loop, daemon=True).start()
    return srv.getsockname()[1]


@pytest.fixture()
def socks_port():
    http = ThreadingHTTPServer(("127.0.0.1", 0), _Http)
    threading.Thread(target=http.serve_forever, daemon=True).start()
    yield _socks_to(http.server_address[1])
    http.shutdown()


def test_download_counts_bytes_and_respects_the_cap(socks_port):
    lib = probe_lib()
    r = lib._speed_download(socks_port, "http://probe.test/probes/50mb", 1_000_000, 10, 5)
    assert r["status"] == 200
    # Остановились на потолке байт, а не дочитали все 2 МБ.
    assert 1_000_000 <= r["bytes"] < 2_000_000
    assert r["mbit"] > 0


def test_upload_waits_for_the_server_and_rejection_is_not_speed(socks_port):
    lib = probe_lib()
    ok = lib._speed_upload(socks_port, "http://probe.test/up", 500_000, 10, 5)
    assert ok["status"] == 200 and ok["complete"] and ok["bytes"] == 500_000 and ok["mbit"] > 0
    bad = lib._speed_upload(socks_port, "http://probe.test/reject", 200_000, 10, 5)
    assert bad["status"] == 413 and bad["mbit"] == 0.0 and not bad["complete"]


def test_probes_are_taken_from_the_internetometer_api(socks_port, monkeypatch):
    lib = probe_lib()
    monkeypatch.setattr(lib, "SPEED_PROBES_URL", "http://probe.test/api")
    urls = lib._speed_probes(socks_port, 5)
    assert urls == {"download": "http://probe.test/probes/50mb", "upload": "http://probe.test/up"}
