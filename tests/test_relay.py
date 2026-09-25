"""Реле нода → хаб → панель: маршруты Caddy и обновление агента через реле.

Маршруты гоняются через НАСТОЯЩИЙ Caddy перед поддельной панелью (в CI Caddy
ставится шагом workflow; локально без него тест пропускается, в CI — падает).
Рецепт обновления — настоящим bash с заглушкой curl (инвариант 35 vgx3d:
установщик проверять прогоном, а не чтением). Прогон и нашёл, что пара
`uri strip_prefix` + `rewrite` у панели под путём давала /vip/relay/vip/….
"""

from __future__ import annotations

import os
import shutil
import socket
import subprocess
import sys
import threading
import time
import urllib.request
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

import pytest

from nexus_mcp import recipes, relay

PANELS = [{"name": "main", "url": "http://127.0.0.1:{port}"},
          {"name": "vip", "url": "http://127.0.0.1:{port}/vip", "gate": "g123"}]


def test_snippet_has_only_agent_paths_and_right_rewrites():
    items = [{"name": "main", "url": "https://panel.example.ru"},
             {"name": "vip", "url": "https://panel.example.ru/vip", "gate": "g123"},
             {"name": "Bad Name", "url": "https://x.example"}]
    text = relay.caddy_snippet(items)
    assert "path /relay/main/api/v1/agent/* /relay/main/api/v1/traffic/report /relay/main/install/* /relay/main/health" in text
    assert "uri strip_prefix /relay/main" in text
    assert "uri path_regexp ^/relay/vip /vip" in text
    assert "rewrite" not in text                     # см. docstring модуля: rewrite выполняется раньше uri
    assert "header_up Host panel.example.ru" in text
    assert "nexus_gate" not in text and "g123" not in text   # секретов панелей в маршрутах нет
    assert "header_up -Cookie" in text
    assert "пропущена панель «Bad Name»" in text and "@relay_Bad" not in text
    assert "/admin" not in text


def _free_port() -> int:
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


class _Panel(BaseHTTPRequestHandler):
    def _answer(self):
        body = f"{self.command} {self.path} host={self.headers.get('Host')} cookie={self.headers.get('Cookie')}"
        data = body.encode()
        self.send_response(200)
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        self.wfile.write(data)

    do_GET = do_POST = _answer

    def log_message(self, *a):
        pass


def test_relay_through_real_caddy(tmp_path):
    caddy = shutil.which("caddy") or os.environ.get("CADDY_BIN")
    if not caddy:
        if os.environ.get("CI"):
            pytest.fail("в CI нужен Caddy (шаг workflow): маршруты реле без него не проверены")
        pytest.skip("нет caddy локально")
    pport, cport = _free_port(), _free_port()
    srv = ThreadingHTTPServer(("127.0.0.1", pport), _Panel)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    items = [{**p, "url": p["url"].format(port=pport)} for p in PANELS]
    (tmp_path / "relay.caddy").write_text(relay.caddy_snippet(items))
    (tmp_path / "Caddyfile").write_text(
        "{\n  admin off\n  auto_https off\n}\n"
        f":{cport} {{\n  import {tmp_path}/relay.caddy\n  handle {{\n    respond \"hub: 404\" 404\n  }}\n}}\n")
    proc = subprocess.Popen([caddy, "run", "--config", str(tmp_path / "Caddyfile"), "--adapter", "caddyfile"],
                            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    try:
        def get(path, method="GET"):
            for _ in range(50):
                try:
                    req = urllib.request.Request(f"http://127.0.0.1:{cport}{path}", method=method,
                                                 data=b"x" if method == "POST" else None)
                    with urllib.request.urlopen(req, timeout=5) as r:
                        return r.status, r.read().decode()
                except urllib.error.HTTPError as e:
                    return e.code, e.read().decode()
                except OSError:
                    time.sleep(0.1)
            raise AssertionError("caddy не поднялся")

        def raw_get(path):
            # urllib нормализует «..» сам — шлём путь как есть сокетом.
            with socket.create_connection(("127.0.0.1", cport), timeout=5) as s:
                s.sendall(f"GET {path} HTTP/1.1\r\nHost: x\r\nConnection: close\r\n\r\n".encode())
                data = b""
                while chunk := s.recv(4096):
                    data += chunk
            head, _, body = data.decode(errors="replace").partition("\r\n\r\n")
            return int(head.split()[1]), body

        st, body = get("/relay/main/api/v1/agent/heartbeat", "POST")
        assert st == 200 and body.startswith(f"POST /api/v1/agent/heartbeat host=127.0.0.1:{pport}")
        st, body = get("/relay/vip/api/v1/traffic/report", "POST")
        assert st == 200 and "POST /vip/api/v1/traffic/report" in body and "cookie=None" in body
        st, body = get("/relay/main/install/cell-update.sh")
        assert st == 200 and body.startswith("GET /install/cell-update.sh")
        # Через реле — только пути агента: админка и чужие панели падают в 404 хаба.
        assert get("/relay/main/api/v1/admin/users")[0] == 404
        assert get("/relay/nope/install/cell-update.sh")[0] == 404
        # Обход путей — мимо: ни в админку своей панели, ни в чужую.
        for bad in ("/relay/main/api/v1/agent/../admin/users",
                    "/relay/main/api/v1/agent/%2e%2e/admin/users",
                    "/relay/main/install/..%2f..%2fapi/v1/admin/users",
                    "/relay/vip/api/v1/agent/../../../main/admin"):
            st, body = raw_get(bad)
            assert st == 404 and "admin" not in body, (bad, st, body)
    finally:
        proc.terminate()
        proc.wait(timeout=10)
        srv.shutdown()


def test_update_via_relay_swaps_brain_url(tmp_path):
    """Скрипт панели вшивает её прямой адрес в BRAIN_URL: через реле его надо
    подменить, иначе тарбол и heartbeat снова пошли бы напрямую."""
    stub = tmp_path / "bin"
    stub.mkdir()
    (stub / "curl").write_text(
        "#!/usr/bin/env bash\n"
        "out=''; url=''\n"
        "while [ $# -gt 0 ]; do case \"$1\" in -o) out=$2; shift 2;; -*) shift;; *) url=$1; shift;; esac; done\n"
        "echo \"$url\" >> " + str(tmp_path / "urls") + "\n"
        "printf '#!/usr/bin/env bash\\nBRAIN_URL=\"https://panel.example.ru\"\\necho \"brain=$BRAIN_URL\"\\n"
        "echo \"%s\"\\n' '" + recipes.UPDATE_DONE_MARK + "' > \"$out\"\n")
    (stub / "curl").chmod(0o755)
    via = "https://hub.example/relay/main"
    script = recipes.update_agent("https://panel.example.ru", via=via)
    r = subprocess.run(["bash", "-c", script], capture_output=True, text=True, timeout=30,
                       env={**os.environ, "PATH": f"{stub}:{os.environ['PATH']}"})
    assert f"brain={via}" in r.stdout
    assert recipes.UPDATE_DONE_MARK in r.stdout
    assert (tmp_path / "urls").read_text().strip() == via + "/install/cell-update.sh"

    # Без реле скрипт не трогается — обычное обновление как было.
    plain = subprocess.run(["bash", "-c", recipes.update_agent("https://panel.example.ru")],
                           capture_output=True, text=True, timeout=30,
                           env={**os.environ, "PATH": f"{stub}:{os.environ['PATH']}"})
    assert "brain=https://panel.example.ru" in plain.stdout
