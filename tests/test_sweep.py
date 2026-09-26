"""Прогон подписки с пробника (роутер дома) и его путь до приложения.

Проверяется поведение: какой статус получит строка при каком отказе, что
пачка проб идёт параллельно (время), что роутер не запускает xray без памяти,
что токен пробника не открывает прогон, и что приложение через чат получает
итог от настоящего ASGI хаба. Установщик OpenWrt гоняется прогоном с
заглушками, а не чтением (инвариант 35 vgx3d).
"""

from __future__ import annotations

import asyncio
import json
import os
import re
import socket
import subprocess
import threading
import time
from pathlib import Path

import httpx
import pytest

from nexus_mcp import links, sweep
from nexus_mcp.probes import HUB, probe_lib, registry

ROOT = Path(__file__).resolve().parents[1]

REALITY = ("vless://11111111-2222-3333-4444-555555555555@203.0.113.7:443?type=tcp&security=reality"
           "&pbk=abc&sid=01&sni=www.example.com&fp=chrome&flow=xtls-rprx-vision#🇩🇪%20Германия")
GRPC = ("vless://11111111-2222-3333-4444-555555555555@203.0.113.7:8443?type=grpc&security=reality"
        "&pbk=abc&sid=01&sni=www.example.com&fp=chrome&serviceName=g#🇩🇪%20Германия%20gRPC")
HY2 = "hysteria2://pass@203.0.113.7:8888?sni=x#🇩🇪%20Hysteria"
SS = "ss://YWVzLTEyOC1nY206cGFzcw@198.51.100.9:8388#🇳🇱%20Нидерланды%20SS"
DEAD = ("vless://11111111-2222-3333-4444-555555555555@192.0.2.5:443?type=tcp&security=reality"
        "&pbk=abc&sid=01&sni=www.example.com#🇫🇮%20Финляндия")


# ── Строка подписки → проба → статус ───────────────────────────────────────

def test_reality_row_probes_tls_with_its_sni():
    job = sweep.reach_job(sweep.link_row(REALITY))
    assert job == {"kind": "tls", "args": {"host": "203.0.113.7", "port": 443, "timeout": sweep.REACH_TIMEOUT,
                                           "sni": "www.example.com"}}


def test_plain_ss_probes_tcp_and_udp_is_not_probed():
    assert sweep.reach_job(sweep.link_row(SS))["kind"] == "tcp"
    # UDP по TCP не проверить: не «зелёное», а «не проверено».
    assert sweep.reach_job(sweep.link_row(HY2)) is None


@pytest.mark.parametrize("kind,res,expected", [
    ("tls", {"ok": True}, "reachable"),
    ("tls", {"ok": False, "stage": "handshake", "error": "ssl_error"}, "reachable"),
    ("tls", {"ok": False, "stage": "handshake", "error": "timeout"}, "filtered"),
    ("tls", {"ok": False, "stage": "handshake", "error": "reset"}, "filtered"),
    ("tls", {"ok": False, "stage": "connect", "error": "refused"}, "refused"),
    ("tls", {"ok": False, "stage": "connect", "error": "timeout"}, "down"),
    ("tcp", {"ok": False, "error": "unreachable"}, "down"),
    ("tcp", {"ok": False, "error": "dns"}, "dns"),
    ("tcp", {"ok": False, "error": "probe_timeout"}, "unknown"),
    # podkop подменил адрес — зелёное оттуда врёт о провайдере
    ("tls", {"ok": True, "peer": "198.18.0.7", "fakeip": True}, "via_vpn"),
    ("tls", {"ok": False, "stage": "handshake", "error": "timeout", "fakeip": True}, "via_vpn"),
])
def test_reach_status(kind, res, expected):
    assert sweep.reach_status(kind, res) == expected
    assert expected in sweep.LINK_STATUSES and expected in sweep.REASONS


def test_node_status():
    row = lambda s: {"status": s}  # noqa: E731
    assert sweep.node_status([row("ok"), row("reachable")]) == "ok"
    assert sweep.node_status([row("ok"), row("filtered")]) == "partial"
    assert sweep.node_status([row("down"), row("refused")]) == "bad"
    assert sweep.node_status([row("unchecked"), row("unknown")]) == "unchecked"


# ── Откуда подписка ────────────────────────────────────────────────────────

def test_no_subscription_is_a_reason_with_the_command(hub_settings):
    with pytest.raises(sweep.SweepError, match="nexus-mcp-panels sub"):
        sweep.sources()


def test_panel_subscription_wins_over_env(hub_settings, tmp_path):
    hub_settings.test_sub_url = "https://env.example/sub/x"
    hub_settings.panels_file = tmp_path / "panels.json"
    hub_settings.panels_file.write_text(json.dumps({"panels": [
        {"name": "main", "url": "https://p.example", "token": "t"},
        {"name": "vip", "url": "https://p.example/vip", "token": "t", "sub_url": "https://p.example/vip/sub/v"}]}))
    assert sweep.sources("vip") == [("vip", "https://p.example/vip/sub/v")]
    assert sweep.sources("main") == [("main", "https://env.example/sub/x")]
    assert sweep.sources() == [("", "https://env.example/sub/x"), ("vip", "https://p.example/vip/sub/v")]
    with pytest.raises(sweep.SweepError, match="nope"):
        sweep.sources("nope")


def test_panels_cli_sets_and_clears_sub(hub_settings, tmp_path):
    from nexus_mcp import panels

    hub_settings.panels_file = tmp_path / "panels.json"
    panels.add("main", "https://p.example", "tok")
    assert panels.set_sub("main", "https://p.example/sub/abc")["sub"] is True
    assert panels.resolve("main")["sub_url"] == "https://p.example/sub/abc"
    assert panels.resolve("main")["token"] == "tok"  # токен не потерялся
    with pytest.raises(panels.PanelConfigError):
        panels.set_sub("main", "не ссылка")
    assert panels.set_sub("main", "-")["sub"] is False
    # переименование не теряет подписку
    panels.set_sub("main", "https://p.example/sub/abc")
    panels.rename("main", "shop")
    assert panels.resolve("shop")["sub_url"] == "https://p.example/sub/abc"


# ── Прогон целиком (пробник — заглушка реестра) ────────────────────────────

def _fake_world(monkeypatch, hub_settings, answers, *, batch=True, xray=True, calls=None):
    """Подписка из пяти строк, панель знает одну ноду; пробник отвечает по host."""
    hub_settings.test_sub_url = "https://p.example/sub/x"
    calls = calls if calls is not None else []

    async def fetch(url=""):
        return [REALITY, GRPC, HY2, SS, DEAD]

    async def load_nodes():
        return [{"name": "ger41s2", "ip": "203.0.113.7", "panel": "main"}], []

    async def run(probe, kind, args, timeout=40.0):
        calls.append((probe, kind, args))
        if kind == "batch":
            if not batch:
                return {"ok": False, "error": "unknown_kind", "detail": "неизвестное задание: batch"}
            return {"ok": True, "results": [answers[(j["args"]["host"], j["args"]["port"])] for j in args["jobs"]]}
        if kind == "e2e":
            out = args["config"]["outbounds"][0]
            addr = json.dumps(out)
            return {"ok": "8443" not in addr and "203.0.113.7" in addr, "ms": 120,
                    "error": "timeout" if "8443" in addr else None}
        return answers[(args["host"], args["port"])]

    monkeypatch.setattr(links, "fetch_links", fetch)
    monkeypatch.setattr(sweep.inventory, "load_nodes", load_nodes)
    monkeypatch.setattr(registry, "run", run)
    monkeypatch.setattr(sweep.links, "_resolve", lambda h: set())
    monkeypatch.setattr(registry, "list", lambda: [
        {"name": HUB, "online": True},
        {"name": "home", "online": True, "xray": "по требованию" if xray else None, "remote_addr": "95.1.2.3"}])
    return calls


ANSWERS = {
    ("203.0.113.7", 443): {"ok": True, "ms": 41.0},
    ("203.0.113.7", 8443): {"ok": True, "ms": 44.0},
    ("198.51.100.9", 8388): {"ok": False, "stage": "connect", "error": "refused"},
    ("192.0.2.5", 443): {"ok": False, "stage": "handshake", "error": "timeout", "connect_ms": 50},
}


def test_sweep_groups_by_node_and_hides_uuids(monkeypatch, hub_settings):
    calls = _fake_world(monkeypatch, hub_settings, ANSWERS)
    res = asyncio.run(sweep.sweep("home"))
    assert res["probe"] == "home" and res["probe_addr"] == "95.1.2.3" and res["e2e"] is False
    by = {n["name"]: n for n in res["nodes"]}
    ger = by["ger41s2"]
    assert ger["known"] is True
    assert [r["status"] for r in ger["links"]] == ["reachable", "reachable", "unchecked"]
    assert ger["status"] == "ok"  # hysteria без сквозной — «не проверено», не провал
    assert by["198.51.100.9"]["status"] == "bad" and by["198.51.100.9"]["links"][0]["status"] == "refused"
    assert by["192.0.2.5"]["links"][0]["status"] == "filtered"
    # плохие наверху
    assert res["nodes"][-1]["name"] == "ger41s2"
    # одна пачка на всю подписку, не пять заданий
    assert [c[1] for c in calls] == ["batch"]
    # UUID юзера из ссылок не уезжает ни на экран, ни в файл итога
    assert "11111111-2222" not in json.dumps(res)
    assert res["summary"]["links"] == 5


def test_sweep_e2e_marks_broken_protocol(monkeypatch, hub_settings):
    _fake_world(monkeypatch, hub_settings, ANSWERS)
    res = asyncio.run(sweep.sweep("home", e2e=True))
    assert res["e2e"] is True
    ger = {n["name"]: n for n in res["nodes"]}["ger41s2"]
    st = {r["transport"]: r["status"] for r in ger["links"]}
    # TCP до gRPC-порта есть, а сайт через протокол не открылся — broken, не ok
    assert st["tcp"] == "ok" and st["grpc"] == "broken"
    assert ger["status"] == "partial"
    # до мёртвого адреса xray не поднимали
    dead = {n["name"]: n for n in res["nodes"]}["192.0.2.5"]["links"][0]
    assert "e2e" not in dead


def test_sweep_e2e_without_xray_says_so(monkeypatch, hub_settings):
    calls = _fake_world(monkeypatch, hub_settings, ANSWERS, xray=False)
    res = asyncio.run(sweep.sweep("home", e2e=True))
    assert res["e2e"] is False
    assert any("нет xray" in n for n in res["notes"])
    assert all(c[1] != "e2e" for c in calls)


def test_old_probe_without_batch_still_checked(monkeypatch, hub_settings):
    calls = _fake_world(monkeypatch, hub_settings, ANSWERS, batch=False)
    res = asyncio.run(sweep.sweep("home"))
    assert {n["name"]: n["status"] for n in res["nodes"]}["ger41s2"] == "ok"
    assert [c[1] for c in calls].count("tls") + [c[1] for c in calls].count("tcp") == 4


def test_background_sweep_persists_last_result(monkeypatch, hub_settings):
    _fake_world(monkeypatch, hub_settings, ANSWERS)
    sw = sweep.Sweeps()

    async def go():
        st = sw.start("home")
        assert st["running"] is True
        again = sw.start("home")  # идущий не перезапускается
        assert again["id"] == st["id"]
        await sw.running["home"]["task"]
        return sw.state("home")

    st = asyncio.run(go())
    assert st["running"] is False and st["last"]["summary"]["links"] == 5
    # после рестарта хаба (новый объект) последний итог на месте
    assert sweep.Sweeps().state("home")["last"]["finished_at"] == st["last"]["finished_at"]


def test_offline_probe_is_refused_with_reason(monkeypatch, hub_settings):
    _fake_world(monkeypatch, hub_settings, ANSWERS)
    monkeypatch.setattr(registry, "list", lambda: [{"name": "home", "online": False, "last_seen_s": 400}])
    with pytest.raises(sweep.SweepError, match="logread -e nexus-probe"):
        sweep.Sweeps().start("home")
    with pytest.raises(sweep.SweepError, match="ни разу не подключался"):
        sweep.Sweeps().start("ghost")


# ── Пробник: пачка и память роутера ────────────────────────────────────────

class _Silent:
    """Принимает соединение и молчит — как фильтр, режущий данные."""

    def __init__(self):
        self.sock = socket.socket()
        self.sock.bind(("127.0.0.1", 0))
        self.sock.listen(64)
        self.port = self.sock.getsockname()[1]
        self.conns = []
        self.t = threading.Thread(target=self._loop, daemon=True)
        self.t.start()

    def _loop(self):
        while True:
            try:
                c, _ = self.sock.accept()
                self.conns.append(c)
            except OSError:
                return

    def close(self):
        self.sock.close()
        for c in self.conns:
            c.close()


def test_batch_runs_in_parallel_and_keeps_order():
    lib = probe_lib()
    silent = _Silent()
    try:
        free = socket.socket()
        free.bind(("127.0.0.1", 0))
        closed_port = free.getsockname()[1]
        free.close()
        jobs = [{"kind": "banner", "args": {"host": "127.0.0.1", "port": silent.port, "timeout": 1}}] * 8
        jobs = jobs + [{"kind": "tcp", "args": {"host": "127.0.0.1", "port": closed_port, "timeout": 1}},
                       {"kind": "e2e", "args": {}}]
        t0 = time.monotonic()
        r = lib.run_job("batch", {"jobs": jobs, "parallel": 8})
        took = time.monotonic() - t0
    finally:
        silent.close()
    assert r["ok"] and len(r["results"]) == 10
    # восемь проб по секунде молчания — параллельно, а не восемь секунд
    assert took < 4, took
    assert all(x["stage"] == "data" for x in r["results"][:8])
    assert r["results"][8]["error"] == "refused"
    # тяжёлая проба в пачку не пускается
    assert r["results"][9]["error"] == "bad_args"


def test_e2e_refuses_to_start_xray_without_memory(tmp_path, monkeypatch):
    lib = probe_lib()
    fake = tmp_path / "xray"
    fake.write_text("#!/bin/sh\nsleep 30\n")
    fake.chmod(0o755)
    monkeypatch.setattr(lib, "mem_available_mb", lambda: 30)
    started = []
    monkeypatch.setattr(lib.subprocess, "Popen", lambda *a, **k: started.append(a) or (_ for _ in ()).throw(AssertionError))
    r = lib.probe_e2e({"outbounds": []}, xray_bin=str(fake))
    assert r["error"] == "low_memory" and "30 МБ" in r["detail"]
    assert started == []


def test_xray_on_demand_download_needs_memory(monkeypatch):
    lib = probe_lib()
    monkeypatch.setattr(lib, "mem_available_mb", lambda: 60)
    monkeypatch.setattr(lib.urllib.request, "build_opener",
                        lambda *a: (_ for _ in ()).throw(AssertionError("качать нельзя")))
    path, why = lib.fetch_xray("https://example.invalid/xray.zip")
    assert path is None and "60 МБ" in why


def test_xray_on_demand_is_downloaded_unpacked_and_dropped(tmp_path, monkeypatch):
    import io
    import zipfile

    lib = probe_lib()
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as z:
        z.writestr("LICENSE", "x")
        z.writestr("xray", "#!/bin/sh\necho xray\n")
    payload = buf.getvalue()

    class Resp(io.BytesIO):
        def __enter__(self):
            return self

        def __exit__(self, *a):
            return False

    class Opener:
        def open(self, req, timeout=0):
            return Resp(payload)

    monkeypatch.setattr(lib, "XRAY_TMP_DIR", str(tmp_path / "x"))
    monkeypatch.setattr(lib, "mem_available_mb", lambda: 500)
    monkeypatch.setattr(lib.urllib.request, "build_opener", lambda *a: Opener())
    path, why = lib.fetch_xray("https://example/xray.zip")
    assert why == "" and os.access(path, os.X_OK)
    assert sorted(os.listdir(tmp_path / "x")) == ["xray"]  # zip удалён сразу
    monkeypatch.setattr(lib, "_XRAY_URL", "https://example/xray.zip")
    monkeypatch.setattr(lib, "_xray_last_used", time.time())
    lib.drop_idle_xray()
    assert os.path.exists(path)  # недавно пользовались — держим
    monkeypatch.setattr(lib, "_xray_last_used", time.time() - lib.XRAY_IDLE_S - 1)
    lib.drop_idle_xray()
    assert not os.path.exists(path)  # простой — память отдали


def test_fakeip_is_detected_in_probe_answer(monkeypatch):
    """Имя, которое podkop резолвит в 198.18.x.x, помечается в ответе пробы —
    и при удаче, и при отказе."""
    lib = probe_lib()
    real = socket.getaddrinfo

    def fake(host, port, *a, **kw):
        if host == "cdn.example":
            return [(socket.AF_INET, socket.SOCK_STREAM, 6, "", ("198.18.0.9", port))]
        return real(host, port, *a, **kw)

    monkeypatch.setattr(lib.socket, "getaddrinfo", fake)
    monkeypatch.setattr(lib.socket, "create_connection",
                        lambda *a, **k: (_ for _ in ()).throw(ConnectionRefusedError()))
    r = lib.probe_tcp("cdn.example", 443, timeout=1)
    assert r["fakeip"] is True and r["peer"] == "198.18.0.9"
    r = lib.probe_tls("cdn.example", 443, timeout=1)
    assert r["fakeip"] is True
    assert "fakeip" not in lib.probe_tcp("127.0.0.1", 1, timeout=1)
    assert lib._is_fakeip("198.19.255.1") and not lib._is_fakeip("198.20.0.1")


def test_router_vpn_seen_from_rc_d(tmp_path, monkeypatch):
    lib = probe_lib()
    rc = tmp_path / "rc.d"
    rc.mkdir()
    (rc / "S99podkop").write_text("")
    (rc / "K10dnsmasq").write_text("")
    real = os.listdir
    monkeypatch.setattr(lib.os, "listdir", lambda p: real(rc) if p == "/etc/rc.d" else real(p))
    assert lib.router_vpn() == "podkop"
    (rc / "S99podkop").unlink()
    (rc / "K10podkop").write_text("")  # выключен — только K-ссылка
    assert lib.router_vpn() == ""


def test_sweep_notes_podkop_and_fakeip_rows(monkeypatch, hub_settings):
    answers = dict(ANSWERS)
    answers[("198.51.100.9", 8388)] = {"ok": True, "peer": "198.18.0.3", "fakeip": True}
    _fake_world(monkeypatch, hub_settings, answers)
    monkeypatch.setattr(registry, "list", lambda: [
        {"name": "home", "online": True, "xray": None, "remote_addr": "95.1.2.3", "router_vpn": "podkop"}])
    res = asyncio.run(sweep.sweep("home"))
    nl = {n["name"]: n for n in res["nodes"]}["198.51.100.9"]
    assert nl["links"][0]["status"] == "via_vpn" and nl["status"] == "unchecked"
    assert any("podkop" in n and "ПОДСЕТЕЙ" in n for n in res["notes"])
    assert any("ушли в VPN роутера" in n for n in res["notes"])


def test_probe_advertises_on_demand_xray(monkeypatch):
    lib = probe_lib()
    monkeypatch.setattr(lib, "find_xray", lambda x=None: None)
    monkeypatch.setattr(lib, "_XRAY_URL", "https://example/xray.zip")
    info = lib.probe_info()
    assert info["xray"] and info["batch"] is True


# ── Авторизация и путь до приложения ───────────────────────────────────────

def test_hub_routes_need_secret_not_probe_token():
    from tests.test_hub import _asgi, _auth_app

    app, _ = _auth_app()
    assert asyncio.run(_asgi(app, "/hub/sweep", {"authorization": "Bearer " + "s" * 32}))[0] == 200
    # токен пробника лежит на роутере: всю подписку он не открывает
    assert asyncio.run(_asgi(app, "/hub/sweep", {"authorization": "Bearer probe-token"}))[0] == 401
    assert asyncio.run(_asgi(app, "/hub/probes"))[0] == 401


def test_app_gets_sweep_through_chat_and_real_hub(monkeypatch, hub_settings, tmp_path):
    """Приложение → nexus-chat → настоящий ASGI nexus-mcp → итог прогона."""
    from nexus_chat import app as chat_app
    from nexus_chat import config as chat_config
    from nexus_chat.runner import Runner
    from nexus_chat.store import Store
    from nexus_mcp import server

    _fake_world(monkeypatch, hub_settings, ANSWERS)
    monkeypatch.setattr(sweep, "sweeps", sweep.Sweeps())
    monkeypatch.setattr(server.sub_sweep, "sweeps", sweep.sweeps)
    cs = chat_config.ChatSettings()
    cs.token = "t" * 40
    cs.state_dir = tmp_path / "chat"
    cs.mcp_secret = "s" * 32
    cs.probe_token = "probe-token"
    cs.audit_at = []
    monkeypatch.setattr(chat_config, "settings", cs)
    hub_settings.public_hosts = []
    monkeypatch.setattr(chat_app, "_hub_transport", httpx.ASGITransport(app=server.build_app()))
    auth = {"authorization": "Bearer " + "t" * 40}

    async def go():
        cs.state_dir.mkdir(parents=True)
        app = chat_app.build_app(Runner(Store(cs.db_path), cs), start_background=False)
        async with httpx.AsyncClient(transport=httpx.ASGITransport(app=app),
                                     base_url="https://hub.example:9443") as c:
            r = await c.get("/chat/api/probes", headers=auth)
            assert r.status_code == 200 and [p["name"] for p in r.json()["probes"]] == [HUB, "home"]
            r = await c.post("/chat/api/probes/sweep", json={"probe": "home"}, headers=auth)
            assert r.status_code == 202, r.text
            for _ in range(50):
                st = (await c.get("/chat/api/probes/sweep", params={"probe": "home"}, headers=auth)).json()
                if not st["running"] and st.get("last"):
                    break
                await asyncio.sleep(0.05)
            assert st["last"]["summary"]["links"] == 5
            r = await c.post("/chat/api/probes/sweep", json={"probe": "ghost"}, headers=auth)
            assert r.status_code == 409 and "ни разу не подключался" in r.json()["detail"]
            r = await c.get("/chat/api/probes/setup", params={"name": "дом ростелеком!"}, headers=auth)
            body = r.json()
            assert "--hub https://hub.example:9443" in body["command"]
            assert "--token probe-token" in body["command"] and "--name домростелеком" in body["command"]
            assert body["command"].startswith("wget -qO- ") and "| sh -s --" in body["command"]
            # без токена чата — ничего
            assert (await c.get("/chat/api/probes")).status_code == 401

    asyncio.run(go())


# ── Контракт с приложением (инвариант 25 vgx3d) ────────────────────────────

def test_statuses_match_android_client(vgx3d):
    kt = (vgx3d / "admin_app/android/app/src/main/kotlin/ru/nexusflow/admin/chat/SweepModels.kt").read_text(
        encoding="utf-8")
    for const, values in (("LINK_STATUSES", sweep.LINK_STATUSES), ("NODE_STATUSES", sweep.NODE_STATUSES)):
        m = re.search(const + r"\s*=\s*listOf\(([^)]*)\)", kt)
        assert m, f"в SweepModels.kt нет {const} = listOf(...)"
        assert re.findall(r'"([a-z_]+)"', m.group(1)) == list(values), const


# ── Установщик OpenWrt: прогон с заглушками ────────────────────────────────

def _stub(bin_dir: Path, name: str, body: str) -> None:
    p = bin_dir / name
    p.write_text("#!/bin/sh\n" + body + "\n")
    p.chmod(0o755)


def _openwrt(tmp_path: Path, *, python_ok: bool = True, token_ok: bool = True,
             free_kb: int = 18000, mem_kb: int = 400000):
    root = tmp_path / "root"
    for d in ("etc/config", "etc/init.d", "usr/share", "overlay"):
        (root / d).mkdir(parents=True, exist_ok=True)
    (root / "etc/openwrt_release").write_text("DISTRIB_DESCRIPTION='OpenWrt 24.10.5'\n")
    (root / "proc").mkdir()
    (root / "proc/meminfo").write_text(f"MemTotal: 1000000 kB\nMemAvailable: {mem_kb} kB\n")
    bins = tmp_path / "bin"
    bins.mkdir()
    log = tmp_path / "calls.log"
    probe_src = (ROOT / "probe" / "probe.py").read_text(encoding="utf-8")
    src = tmp_path / "src" / "probe"
    src.mkdir(parents=True)
    (src / "probe.py").write_text(probe_src, encoding="utf-8")
    _stub(bins, "id", 'echo 0')
    _stub(bins, "uname", 'echo aarch64')
    _stub(bins, "opkg", f'echo "opkg $*" >> {log}')
    _stub(bins, "uci", f'echo "uci $*" >> {log}')
    _stub(bins, "sleep", 'exit 0')
    _stub(bins, "df", f'echo "Filesystem 1K-blocks Used Available"; echo "overlay 45000 27000 {free_kb}"')
    msg = "[nexus-probe] роутер → hub" if token_ok else "[nexus-probe] хаб ответил 401: неверный токен пробника"
    _stub(bins, "logread", f'echo "{msg}"')
    # wget: probe.py — копия из «репозитория», healthz — ответ хаба
    _stub(bins, "wget", f'''out=""; url=""
while [ $# -gt 0 ]; do case "$1" in -O) out="$2"; shift 2;; -q) shift;; -T) shift 2;; *) url="$1"; shift;; esac; done
echo "wget $url" >> {log}
case "$url" in
  */probe/probe.py) cp {src}/probe.py "$out";;
  */healthz) echo '{{"ok":true}}';;
  *) exit 1;;
esac''')
    real_py = subprocess.run(["sh", "-c", "command -v python3"], capture_output=True, text=True).stdout.strip()
    _stub(bins, "python3", f'exec {real_py} "$@"' if python_ok else 'echo "нет модулей: ssl"; exit 1')
    env = {"PATH": f"{bins}:/usr/bin:/bin", "NEXUS_PROBE_ROOT": str(root), "HOME": str(tmp_path)}
    return root, env, log, tmp_path / "src"


def _run_installer(env, *args):
    script = (ROOT / "probe" / "openwrt" / "install.sh").read_text(encoding="utf-8")
    return subprocess.run(["sh", "-s", "--", *args], input=script, capture_output=True, text=True,
                          env=env, timeout=60)


def test_openwrt_installer_sets_up_service(tmp_path):
    root, env, log, src = _openwrt(tmp_path)
    r = _run_installer(env, "--hub", "https://hub.example:9443/", "--token", "PT", "--name", "роутер-дом",
                       "--xray", "tmp", "--src", f"file://{src}")
    # init-скрипт в тесте не исполняется (/etc/rc.common) — проверяем, что он написан
    out = r.stdout + r.stderr
    assert (root / "usr/share/nexus-probe/probe.py").read_text(encoding="utf-8").startswith("#!/usr/bin/env python3")
    init = (root / "etc/init.d/nexus-probe").read_text(encoding="utf-8")
    assert "procd_set_param respawn" in init and "NEXUS_PROBE_TOKEN=" in init
    assert "--token" not in init.split("procd_set_param command", 1)[1].split("\n", 1)[0]  # токен не в ps
    calls = log.read_text(encoding="utf-8")
    assert "uci set nexus-probe.main.hub=https://hub.example:9443" in calls
    assert "uci set nexus-probe.main.token=PT" in calls
    assert "Xray-linux-arm64-v8a.zip" in calls  # aarch64 → arm64-v8a, по требованию
    assert "opkg" not in calls  # python3 уже подходит — пакеты не трогаем
    assert "установка не дошла до конца" not in out


def test_openwrt_installer_stops_on_wrong_token(tmp_path):
    root, env, log, src = _openwrt(tmp_path, token_ok=False)
    r = _run_installer(env, "--hub", "https://hub.example", "--token", "bad", "--src", f"file://{src}")
    assert r.returncode != 0
    assert "хаб не принял токен" in r.stderr


def test_openwrt_installer_names_missing_module_and_flash(tmp_path):
    root, env, log, src = _openwrt(tmp_path, python_ok=False)
    r = _run_installer(env, "--hub", "https://hub.example", "--token", "t", "--src", f"file://{src}")
    assert r.returncode != 0
    # пакеты ставились и всё равно не хватает модуля — называем какого
    assert "opkg install python3-light" in log.read_text(encoding="utf-8")
    assert "ssl" in r.stderr
    assert not (root / "etc/init.d/nexus-probe").exists()


def test_openwrt_installer_puts_python_in_ram_when_flash_is_short(tmp_path):
    """9 МБ флеша (живой случай: OpenWrt 24.10, aarch64) — python3 не отказ, а
    ОЗУ: opkg ставит его в отдельный dest, служба стартует через run.sh,
    который после перезагрузки ставит python3 заново."""
    root, env, log, src = _openwrt(tmp_path, python_ok=False, free_kb=9216)
    r = _run_installer(env, "--hub", "https://hub.example", "--token", "t", "--src", f"file://{src}")
    calls = log.read_text(encoding="utf-8")
    assert f"opkg --add-dest nexuspy:{root}/tmp/nexus-py -d nexuspy install python3-light" in calls
    assert "python3-unicodedata" not in calls  # такого пакета в OpenWrt нет
    assert "в ОЗУ" in r.stdout
    # заглушка python3 всё равно «без ssl» — установка честно называет модуль
    assert r.returncode != 0 and "ssl" in r.stderr


def test_openwrt_installer_ram_mode_writes_runner(tmp_path):
    root, env, log, src = _openwrt(tmp_path, free_kb=9216)
    r = _run_installer(env, "--hub", "https://hub.example", "--token", "t", "--python", "tmp",
                       "--src", f"file://{src}")
    assert r.returncode == 0, r.stderr
    calls = log.read_text(encoding="utf-8")
    assert "-d nexuspy install" in calls
    assert f"uci set nexus-probe.main.python_dest={root}/tmp/nexus-py" in calls
    run = (root / "usr/share/nexus-probe/run.sh").read_text(encoding="utf-8")
    assert "NEXUS_PY_DEST" in run and "opkg --add-dest" in run
    init = (root / "etc/init.d/nexus-probe").read_text(encoding="utf-8")
    assert "/usr/share/nexus-probe/run.sh" in init and "NEXUS_PY_DEST=" in init


def test_openwrt_installer_refuses_ram_mode_without_memory(tmp_path):
    root, env, log, src = _openwrt(tmp_path, free_kb=9216, mem_kb=50000, python_ok=False)
    r = _run_installer(env, "--hub", "https://hub.example", "--token", "t", "--src", f"file://{src}")
    assert r.returncode != 0 and "ОЗУ" in r.stderr
    calls = log.read_text(encoding="utf-8")
    assert "opkg install" not in calls and "nexuspy install" not in calls


_LISTS = """Package: python3-light
Version: 3.11.14-r1
Depends: libc, python3-base, libbz2, zlib
Installed-Size: 3000000

Package: python3-base
Depends: libc, libpython3-3.11
Installed-Size: 500000

Package: libpython3-3.11
Depends: libc, libpthread, zlib
Installed-Size: 2000000

Package: libbz2-1.0
Provides: libbz2
Depends: libc
Installed-Size: 60000

Package: python3-openssl
Depends: libc, python3-light, libopenssl3 (>= 3.0), ca-certs | ca-bundle
Installed-Size: 200000

Package: libopenssl3
Depends: libc
Installed-Size: 1800000

Package: python3-urllib
Depends: libc, python3-light, python3-email
Installed-Size: 150000

Package: python3-email
Depends: libc, python3-light
Installed-Size: 400000

Package: python3-codecs
Depends: libc, python3-light
Installed-Size: 1900000

Package: python3-logging
Depends: libc, python3-light
Installed-Size: 100000

Package: ca-bundle
Installed-Size: 230000
"""


def _with_lists(root, bins, log, installed):
    (root / "var/opkg-lists").mkdir(parents=True)
    (root / "var/opkg-lists/openwrt_packages").write_text(_LISTS)
    (root / "var/opkg-lists/openwrt_packages.sig").write_text("junk")
    listing = "\\n".join(f"{n} - 1" for n in installed)
    mark = root / "python-installed"
    _stub(bins, "opkg", f'echo "opkg $*" >> {log}; [ "$1" = list-installed ] && printf "{listing}\\n"; '
                        f'case "$*" in *install\\ python3*) touch {mark};; esac; exit 0')
    # python3 «появляется» только после opkg install
    real_py = subprocess.run(["sh", "-c", "command -v python3"], capture_output=True, text=True).stdout.strip()
    _stub(bins, "python3", f'[ -f {mark} ] && exec {real_py} "$@"; echo "нет модулей: ssl"; exit 1')


def test_openwrt_installer_counts_real_package_size(tmp_path):
    """Живой случай: 9 МБ флеша, 59 МБ ОЗУ. Размер — по спискам opkg (без уже
    стоящих libc, zlib, ca-bundle; libbz2 — через Provides), а не оценкой
    12 МБ: 10 МБ на флеш с запасом не влезают, а в ОЗУ (10 + 40) — да."""
    root, env, log, src = _openwrt(tmp_path, free_kb=9216, mem_kb=60416)
    _with_lists(root, tmp_path / "bin", log, ["libc", "libpthread", "zlib", "ca-bundle", "ca-certs"])
    r = _run_installer(env, "--hub", "https://hub.example", "--token", "t", "--src", f"file://{src}")
    assert r.returncode == 0, r.stdout + r.stderr
    # 3000000+500000+2000000+60000+200000+1800000+150000+400000+1900000+100000 = 10110000 Б
    assert "python3 с модулями: 10 МБ (по спискам opkg); свободно: флеш 9 МБ, ОЗУ 59 МБ\n" in r.stdout
    calls = log.read_text(encoding="utf-8")
    assert "-d nexuspy install python3-light" in calls


def test_openwrt_installer_prefers_flash_when_it_fits(tmp_path):
    root, env, log, src = _openwrt(tmp_path, free_kb=12000, mem_kb=60416)
    _with_lists(root, tmp_path / "bin", log, ["libc", "libpthread", "zlib", "ca-bundle"])
    r = _run_installer(env, "--hub", "https://hub.example", "--token", "t", "--src", f"file://{src}")
    assert r.returncode == 0, r.stdout + r.stderr
    calls = log.read_text(encoding="utf-8")
    assert "opkg install python3-light" in calls and "nexuspy" not in calls


def test_openwrt_installer_ram_threshold_follows_real_size(tmp_path):
    root, env, log, src = _openwrt(tmp_path, free_kb=4096, mem_kb=60416)
    _with_lists(root, tmp_path / "bin", log, ["libc", "libpthread", "zlib", "ca-bundle", "libopenssl3",
                                               "libbz2-1.0"])
    r = _run_installer(env, "--hub", "https://hub.example", "--token", "t", "--src", f"file://{src}")
    assert r.returncode == 0, r.stdout + r.stderr
    # без libopenssl3 и libbz2: 8250000 Б → 8 МБ; 8 + 40 запаса ≤ 59 МБ ОЗУ
    assert "python3 с модулями: 8 МБ" in r.stdout
    assert "-d nexuspy install" in log.read_text(encoding="utf-8")


def test_openwrt_installer_rejects_bad_args_and_removes(tmp_path):
    root, env, log, src = _openwrt(tmp_path)
    r = _run_installer(env, "--hub", "http://plain", "--token", "t")
    assert r.returncode != 0 and "https://" in r.stderr
    r = _run_installer(env, "--hub")
    assert r.returncode != 0 and "нет значения" in r.stderr
    (root / "etc/init.d/nexus-probe").write_text("#!/bin/sh\nexit 0\n")
    (root / "etc/init.d/nexus-probe").chmod(0o755)
    r = _run_installer(env, "--remove")
    assert r.returncode == 0, r.stderr
    assert not (root / "etc/init.d/nexus-probe").exists()


def test_installer_checks_every_module_probe_imports():
    """Установщик проверяет модули python3 на роутере своим списком — копия
    импортов probe.py (инвариант 25): новый импорт без правки списка
    дал бы «установлено», а служба падала бы на старте."""
    probe = (ROOT / "probe" / "probe.py").read_text(encoding="utf-8")
    inst = (ROOT / "probe" / "openwrt" / "install.sh").read_text(encoding="utf-8")
    imports = set(re.findall(r"^\s*(?:import|from)\s+([a-zA-Z_]+)", probe, re.M)) - {"__future__"}
    listed = re.search(r'for m in \(([^)]*)\)', inst).group(1)
    checked = {m.split(".")[0] for m in re.findall(r'"([a-z_.]+)"', listed)}
    always = {"os", "sys", "time"}  # встроены в сам python3-light
    assert imports - always <= checked, imports - always - checked
