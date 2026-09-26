"""sing-box для сквозной проверки с роутера: перекладка xray-конфига,
самообновление пробника от хаба, строки за Cloudflare."""

from __future__ import annotations

import asyncio
import importlib.util
from pathlib import Path

from nexus_mcp import links, singbox, sweep
from nexus_mcp.probes import Registry, probe_lib

U = "11111111-2222-3333-4444-555555555555"


def sb(uri: str) -> dict | None:
    return singbox.outbound(links.config_for(uri))


def test_vless_ws_behind_cf_keeps_early_data():
    ob = sb(f"vless://{U}@eng41s2.pablo.stream:2087?type=ws&path=%2Fws%3Fed%3D2048&host=eng41s2.pablo.stream"
            "&security=tls&sni=eng41s2.pablo.stream&fp=chrome#cf")
    assert ob["type"] == "vless" and ob["server"] == "eng41s2.pablo.stream" and ob["server_port"] == 2087
    assert ob["transport"] == {"type": "ws", "path": "/ws", "max_early_data": 2048,
                               "early_data_header_name": "Sec-WebSocket-Protocol",
                               "headers": {"Host": "eng41s2.pablo.stream"}}
    assert ob["tls"]["server_name"] == "eng41s2.pablo.stream"
    assert ob["tls"]["utls"] == {"enabled": True, "fingerprint": "chrome"}


def test_reality_ss_hysteria2():
    r = sb(f"vless://{U}@1.2.3.4:443?type=tcp&security=reality&sni=discord.com&pbk=PBK&sid=ab&flow=xtls-rprx-vision#r")
    assert r["flow"] == "xtls-rprx-vision" and "transport" not in r
    assert r["tls"]["reality"] == {"enabled": True, "public_key": "PBK", "short_id": "ab"}
    assert r["tls"]["utls"]["enabled"] is True  # reality в sing-box только с utls
    s = sb("ss://MjAyMi1ibGFrZTMtYWVzLTEyOC1nY206a2V5@1.2.3.4:2096#ss")
    assert s == {"type": "shadowsocks", "tag": "proxy", "server": "1.2.3.4", "server_port": 2096,
                 "method": "2022-blake3-aes-128-gcm", "password": "key"}
    h = sb("hysteria2://pw@n.example:8443?sni=n.example&insecure=1&obfs=salamander&obfs-password=ob#hy")
    assert h["password"] == "pw" and h["tls"]["insecure"] is True and h["tls"]["alpn"] == ["h3"]
    assert h["obfs"] == {"type": "salamander", "password": "ob"}


def test_what_sing_box_lacks_stays_on_xray():
    assert sb(f"vless://{U}@1.2.3.4:443?type=xhttp&path=%2Fx&security=tls&sni=a#x") is None
    assert singbox.config(None) is None


def test_probe_prefers_singbox_when_no_xray(monkeypatch, tmp_path):
    lib = probe_lib()
    fake = tmp_path / "sing-box"
    fake.write_text("#!/bin/sh\nexit 1\n")
    fake.chmod(0o755)
    monkeypatch.setattr(lib, "find_xray", lambda explicit=None: None)
    monkeypatch.setattr(lib, "find_singbox", lambda: str(fake))
    monkeypatch.setattr(lib, "_XRAY_URL", "https://example/xray.zip")  # не качаем: sing-box есть
    seen = {}
    monkeypatch.setattr(lib, "_probe_e2e_singbox", lambda b, c, u, t: seen.update(b=b) or {"ok": True})
    r = lib.probe_e2e({"outbounds": []}, "http://x/", 1, None, {"outbounds": [{"type": "direct"}]})
    assert r == {"ok": True, "engine": "sing-box"} and seen["b"] == str(fake)
    # профиль в sing-box не переложился — xray по требованию, как раньше
    monkeypatch.setattr(lib, "fetch_xray", lambda url: (None, "мало памяти"))
    r = lib.probe_e2e({"outbounds": []}, "http://x/", 1, None, None)
    assert r["error"] == "no_xray" and "мало памяти" in r["detail"]


def _load_copy(tmp_path: Path, version: str):
    src = Path(probe_lib().__file__).read_text(encoding="utf-8")
    src = src.replace(f'PROBE_VERSION = "{probe_lib().PROBE_VERSION}"', f'PROBE_VERSION = "{version}"')
    f = tmp_path / "probe.py"
    f.write_text(src, encoding="utf-8")
    spec = importlib.util.spec_from_file_location("probe_copy", f)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod, f


def test_self_update_replaces_file(tmp_path, monkeypatch):
    monkeypatch.delenv("NEXUS_PROBE_NO_UPDATE", raising=False)
    mod, f = _load_copy(tmp_path, "1.0.0")
    new = Path(probe_lib().__file__).read_text(encoding="utf-8")
    v = probe_lib().PROBE_VERSION
    assert mod.self_update("def (", v)["error"] == "bad_args"
    assert mod.self_update(new, "9.9.9")["error"] == "bad_args"  # версия не та
    assert 'PROBE_VERSION = "1.0.0"' in f.read_text(encoding="utf-8")
    r = mod.self_update(new, v)
    assert r["ok"] and r["restart"] and r["to"] == v
    assert f.read_text(encoding="utf-8") == new
    monkeypatch.setenv("NEXUS_PROBE_NO_UPDATE", "1")
    assert mod.self_update(new, v)["error"] == "disabled"


def test_hub_sends_update_once_to_older_probe():
    reg = Registry()
    v = probe_lib().PROBE_VERSION

    async def go(info):
        return await reg.poll("дом", info, "93.157.23.116", hold=0.01)

    jobs = asyncio.run(go({"version": "1.1.0", "self_update": True}))
    assert [j["kind"] for j in jobs] == ["update"] and jobs[0]["args"]["version"] == v
    assert asyncio.run(go({"version": "1.1.0", "self_update": True})) == []  # второй раз не шлём
    reg2 = Registry()
    assert asyncio.run(reg2.poll("a", {"version": "1.0.0"}, "", hold=0.01)) == []  # старый не умеет
    assert asyncio.run(reg2.poll("b", {"version": v, "self_update": True}, "", hold=0.01)) == []


def test_cf_rows_map_to_nodes_by_name():
    nodes = [{"name": "JonyX/eng41s2", "ip": "45.43.75.64"}, {"name": "pablo-vps/eng31s2", "ip": "1.1.1.2"},
             {"name": "JonyX/ru41s2-YA-CDN", "ip": "217.18.62.16"},
             {"name": "JonyX/nl41s2", "ip": "1.1.1.3"}, {"name": "pablo-vps/nl41s2", "ip": "1.1.1.4"}]
    assert sweep.node_by_name("eng41s2.pablo.stream", "JonyX", nodes)["name"] == "JonyX/eng41s2"
    assert sweep.node_by_name("eng41s2.pablo.stream", "pablo-vps", nodes)["name"] == "JonyX/eng41s2"
    assert sweep.node_by_name("ru41s2.pablo.stream", "JonyX", nodes)["name"] == "JonyX/ru41s2-YA-CDN"
    assert sweep.node_by_name("nl41s2.pablo.stream", "pablo-vps", nodes)["name"] == "pablo-vps/nl41s2"
    assert sweep.node_by_name("nl41s2.pablo.stream", "", nodes) is None  # две — не угадываем
    assert sweep.node_by_name("mia31s2.pablo.stream", "pablo-vps", nodes) is None
    assert sweep.is_cloudflare("104.21.70.134") and sweep.is_cloudflare("172.67.223.206")
    assert not sweep.is_cloudflare("45.141.118.103") and not sweep.is_cloudflare("x")


def test_sweep_cf_row_gets_node_reason_and_singbox(monkeypatch, hub_settings):
    """Живой случай: строка за CF. Нода — по имени, причина — «Cloudflare
    доступен», в сквозную уходит и профиль sing-box (роутер без xray)."""
    from nexus_mcp.probes import HUB, registry

    hub_settings.test_sub_url = "https://p.example/sub/x"
    cf = (f"vless://{U}@eng41s2.pablo.stream:2087?type=ws&path=%2Fws&security=tls"
          "&sni=eng41s2.pablo.stream#London CF")
    calls = []

    async def fetch(url=""):
        return [cf]

    async def load_nodes():
        return [{"name": "JonyX/eng41s2", "ip": "45.43.75.64"}], []

    async def run(probe, kind, args, timeout=40.0):
        calls.append((kind, args))
        if kind == "batch":
            return {"ok": True, "results": [{"ok": True, "ms": 249.0, "peer": "104.21.70.134"}]}
        return {"ok": False, "error": "no_xray", "detail": "свободно 51 МБ"}

    monkeypatch.setattr(links, "fetch_links", fetch)
    monkeypatch.setattr(sweep.inventory, "load_nodes", load_nodes)
    monkeypatch.setattr(registry, "run", run)
    monkeypatch.setattr(sweep.links, "_resolve", lambda h: {"104.21.70.134"})
    monkeypatch.setattr(registry, "list", lambda: [
        {"name": HUB, "online": True},
        {"name": "home", "online": True, "xray": None, "singbox": True, "remote_addr": "93.157.23.116"}])
    res = asyncio.run(sweep.sweep("home", e2e=True))
    node = res["nodes"][0]
    assert node["name"] == "JonyX/eng41s2" and node["known"] is True
    row = node["links"][0]
    assert row["cdn"] == "Cloudflare" and row["status"] == "reachable"
    assert "Cloudflare доступен" in row["reason"]
    e2e = [a for k, a in calls if k == "e2e"]
    assert e2e and e2e[0]["singbox"]["outbounds"][0]["type"] == "vless"
    # сквозная не состоялась — это видно в заметках, а не молча
    assert any("сквозная не состоялась" in n and "51 МБ" in n for n in res["notes"])
