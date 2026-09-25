"""Несколько панелей на одном хабе: выбор панели, имена нод, CLI."""

import asyncio
import json
import os
import stat

import httpx
import pytest

from nexus_mcp import inventory, panel, panels


def _two(hub_settings):
    hub_settings.panels_file.write_text(json.dumps({"panels": [
        {"name": "main", "url": "https://a.ru/", "token": "TA"},
        {"name": "shop2", "url": "https://b.ru", "token": "TB", "basic_auth": "u:p"},
    ]}))


@pytest.fixture(autouse=True)
def panels_file(hub_settings, tmp_path):
    hub_settings.panels_file = tmp_path / "panels.json"
    return hub_settings.panels_file


def test_legacy_single_panel_from_env(hub_settings):
    hub_settings.brain_url = "https://old.ru"
    hub_settings.brain_admin_token = "T"
    assert panels.resolve("")["url"] == "https://old.ru"
    assert panels.resolve("main")["token"] == "T"


def test_several_panels_require_a_name(hub_settings):
    _two(hub_settings)
    with pytest.raises(panels.PanelConfigError, match="main, shop2"):
        panels.resolve("")
    assert panels.resolve("shop2")["url"] == "https://b.ru"
    assert panels.resolve("main")["url"] == "https://a.ru"      # хвостовой / срезан
    with pytest.raises(panels.PanelConfigError, match="нет"):
        panels.resolve("ghost")


def test_request_goes_to_chosen_panel_with_its_token(hub_settings, monkeypatch):
    _two(hub_settings)
    seen = []
    real = httpx.AsyncClient

    def factory(*a, **kw):
        seen.append(kw.get("auth"))
        kw["transport"] = httpx.MockTransport(
            lambda req: httpx.Response(200, json={"url": str(req.url), "tok": req.headers["x-admin-token"]}))
        return real(*a, **kw)

    monkeypatch.setattr(panel.httpx, "AsyncClient", factory)
    out = asyncio.run(panel.get("/api/v1/admin/app/health", panel_name="shop2"))
    assert out["url"].startswith("https://b.ru/") and out["tok"] == "TB"
    assert seen[-1] == ("u", "p")


def test_same_node_name_in_two_panels_stays_two_nodes(hub_settings):
    rows = [{"id": "1", "name": "de-1", "ip_address": "1.1.1.1"}]
    rows2 = [{"id": "2", "name": "de-1", "ip_address": "2.2.2.2"}]
    nodes = {n["name"]: n for n in inventory.merge({"main": rows, "shop2": rows2}, {})}
    assert set(nodes) == {"main/de-1", "shop2/de-1"}
    assert nodes["shop2/de-1"]["panel"] == "shop2" and nodes["shop2/de-1"]["ip"] == "2.2.2.2"


def test_find_node_ambiguous_name_is_refused(hub_settings, monkeypatch):
    _two(hub_settings)

    async def servers(path, p, timeout=15.0):
        return [{"id": p["name"], "name": "de-1", "ip_address": "1.1.1.1" if p["name"] == "main" else "2.2.2.2"}]

    monkeypatch.setattr(inventory, "brain_get", servers)
    with pytest.raises(inventory.InventoryError, match="нескольких панелях"):
        asyncio.run(inventory.find_node("de-1"))
    assert asyncio.run(inventory.find_node("shop2/de-1"))["ip"] == "2.2.2.2"
    assert asyncio.run(inventory.find_node("2.2.2.2"))["panel"] == "shop2"


def test_one_dead_panel_does_not_hide_the_others(hub_settings, monkeypatch):
    _two(hub_settings)

    async def servers(path, p, timeout=15.0):
        if p["name"] == "main":
            raise inventory.InventoryError("панель main не ответила")
        return [{"id": "2", "name": "nl-1", "ip_address": "2.2.2.2"}]

    monkeypatch.setattr(inventory, "brain_get", servers)
    nodes, warnings = asyncio.run(inventory.load_nodes())
    assert [n["name"] for n in nodes] == ["shop2/nl-1"]
    assert any("main" in w for w in warnings)


def test_node_panel_url_used_for_heartbeat(hub_settings):
    _two(hub_settings)
    assert inventory.node_panel({"panel": "shop2"})["url"] == "https://b.ru"
    assert inventory.node_panel({"panel": None}) is None


def test_cli_add_list_remove(hub_settings, capsys):
    assert panels.main(["add", "shop3", "https://c.ru/vip", "SECRETTOKEN"]) == 0
    mode = stat.S_IMODE(os.stat(hub_settings.panels_file).st_mode)
    assert mode == 0o600                                       # токены — не всем
    assert panels.main(["list"]) == 0
    out = capsys.readouterr().out
    assert "shop3" in out and "https://c.ru/vip" in out and "SECRETTOKEN" not in out
    assert panels.main(["add", "Bad Name", "https://c.ru", "T"]) == 2
    assert panels.main(["add", "x", "not-a-url", "T"]) == 2
    assert panels.main(["remove", "shop3"]) == 0
    assert panels.main(["remove", "shop3"]) == 1


def test_panels_list_tool_hides_tokens(hub_settings):
    from nexus_mcp import server

    _two(hub_settings)
    r = asyncio.run(server.panels_list())
    assert r["ok"] and {p["name"] for p in r["panels"]} == {"main", "shop2"}
    assert "TA" not in json.dumps(r) and "u:p" not in json.dumps(r)


# ── Проход мимо пароля Caddy по cookie ─────────────────────────────────────

def test_gate_cookie_sent_with_token(hub_settings, monkeypatch):
    hub_settings.panels_file.write_text(json.dumps({"panels": [
        {"name": "main", "url": "https://a.ru", "token": "TA", "gate": "GATE123"}]}))
    seen = {}
    real = httpx.AsyncClient

    def factory(*a, **kw):
        def handler(req):
            seen["cookie"] = req.headers.get("cookie")
            seen["token"] = req.headers.get("x-admin-token")
            return httpx.Response(200, json={"ok": True})
        kw["transport"] = httpx.MockTransport(handler)
        return real(*a, **kw)

    monkeypatch.setattr(panel.httpx, "AsyncClient", factory)
    asyncio.run(panel.get("/api/v1/admin/app/health"))
    assert seen == {"cookie": "nexus_gate=GATE123", "token": "TA"}


def test_legacy_env_gate(hub_settings):
    hub_settings.brain_url, hub_settings.brain_admin_token, hub_settings.brain_gate = "https://o.ru", "T", "G"
    assert inventory._brain_headers(panels.resolve(""))["Cookie"] == "nexus_gate=G"


def test_gate_cookie_name_matches_panel(vgx3d):
    """Имя cookie — контракт с Caddyfile установщиков и brain (инвариант 25)."""
    brain = (vgx3d / "brain/app/services/admin_devices.py").read_text(encoding="utf-8")
    assert f'GATE_COOKIE = "{inventory.GATE_COOKIE}"' in brain
    setup = (vgx3d / "brain-setup.sh").read_text(encoding="utf-8")
    assert f"*{inventory.GATE_COOKIE}=" in setup


def test_cli_gate(hub_settings, capsys):
    assert panels.main(["add", "p", "https://c.ru", "TOK", "--gate", "GATESECRET"]) == 0
    panels.main(["list"])
    out = capsys.readouterr().out
    assert "(gate)" in out and "GATESECRET" not in out
