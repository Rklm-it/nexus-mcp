"""Мастер brain на хабе: отметка панели и инструменты выпуска версии.

Сторожим: мастер один (отметка переходит), переживает rename и sub; задачи
мастера и обновление панели — только с NEXUS_ALLOW_ACTIONS и confirm, без
confirm ничего не шлётся; клиент лицензии мастером не притворяется; panel_call
мимо своих инструментов в эти ручки не пускает; в чате — кнопка «Разрешить».
"""

import asyncio
import json

import httpx
import pytest

from nexus_mcp import panel, panels

V_OLD, V_NEW = "3.104.7", "3.105.0"


@pytest.fixture(autouse=True)
def panels_file(hub_settings, tmp_path):
    hub_settings.panels_file = tmp_path / "panels.json"
    hub_settings.panels_file.write_text(json.dumps({"panels": [
        {"name": "boss", "url": "https://m.ru", "token": "TM"},
        {"name": "JonyX", "url": "https://j.ru", "token": "TJ"},
    ]}))
    return hub_settings.panels_file


def test_master_flag_is_single_and_survives_rename_and_sub(hub_settings):
    assert panels.master() is None
    panels.set_master("boss", True)
    assert panels.master()["name"] == "boss"
    panels.set_master("JonyX", True)
    assert panels.master()["name"] == "JonyX"
    assert not panels.resolve("boss").get("master")
    panels.rename("JonyX", "jonyx2")
    assert panels.master()["name"] == "jonyx2"
    panels.set_sub("jonyx2", "https://j.ru/sub/abc")
    assert panels.master()["name"] == "jonyx2"
    assert panels.resolve("jonyx2")["token"] == "TJ"
    panels.set_master("jonyx2", False)
    assert panels.master() is None


def test_cli_add_master(hub_settings, capsys):
    assert panels.main(["add", "m2", "https://m2.ru", "T", "--master"]) == 0
    assert "мастер" in capsys.readouterr().out
    assert panels.master()["name"] == "m2"
    assert panels.public_view(panels.resolve("m2"))["master"] is True
    assert panels.main(["master", "boss"]) == 0
    assert panels.master()["name"] == "boss"
    panels.main(["list"])
    assert "boss" in capsys.readouterr().out.split("[мастер]")[0].splitlines()[-1]


def _mock(monkeypatch, handler):
    real = httpx.AsyncClient

    def factory(*a, **kw):
        kw["transport"] = httpx.MockTransport(handler)
        return real(*a, **kw)

    monkeypatch.setattr(panel.httpx, "AsyncClient", factory)


OVERVIEW = {
    "is_master": True, "brain": {"version": V_NEW}, "code": {"version": V_NEW},
    "image": {"exists": True, "version": V_OLD},
    "clients": {"total": 2, "active": 2, "behind": 0, "items": [
        {"id": 1, "owner": "JonyX", "active": True, "version": V_OLD, "behind_image": False,
         "behind_master": True, "update_requested": False, "silent_hours": 0.2},
        {"id": 2, "owner": "pablo", "active": True, "version": "3.104.0", "behind_image": True,
         "behind_master": True, "update_requested": False, "silent_hours": 0.1}]},
    "jobs": {"build": {"progress": {"state": "idle", "stage_title": "", "percent": 0, "error": None}}},
    "busy": [],
    "hints": [{"level": "warn", "action": "build", "text": f"Клиентам раздаётся v{V_OLD}"}],
}


@pytest.fixture
def seen(monkeypatch, hub_settings):
    panels.set_master("boss", True)
    calls = []

    def handler(req: httpx.Request):
        calls.append((req.method, req.url.host, req.url.path, req.content.decode()))
        if req.url.path == "/api/v1/admin/master/overview":
            if req.url.host == "m.ru":
                return httpx.Response(200, json=OVERVIEW)
            return httpx.Response(200, json={"is_master": False, "brain": {"version": V_OLD}})
        if req.url.path == "/api/v1/admin/system/versions":
            return httpx.Response(200, json={"brain": {"version": V_OLD}, "cells": []})
        if req.url.path.startswith("/api/v1/admin/master/jobs/"):
            return httpx.Response(200, json={"started": True, "container": "master-job-build-1"})
        if req.url.path == "/api/v1/admin/master/clients/update":
            return httpx.Response(200, json={"target": V_OLD, "marked": [{"id": 2}], "skipped": []})
        if req.url.path == "/api/v1/admin/system/update":
            return httpx.Response(200, json={"started": True})
        return httpx.Response(404, json={"detail": "Not Found"})

    _mock(monkeypatch, handler)
    return calls


def _posts(calls):
    return [c for c in calls if c[0] == "POST"]


def test_master_status_uses_marked_master(seen):
    from nexus_mcp import server

    r = asyncio.run(server.master_status())
    assert r["ok"] and r["panel"] == "boss"
    assert r["image"]["version"] == V_OLD and r["hints"][0]["action"] == "build"
    assert [c["owner"] for c in r["clients"]["items"]] == ["JonyX", "pablo"]


def test_client_panel_is_not_a_master(seen):
    from nexus_mcp import server

    r = asyncio.run(server.master_status(panel="JonyX"))
    assert r["ok"] is False and "не мастер" in r["detail"]


def test_no_master_marked(seen, hub_settings):
    from nexus_mcp import server

    panels.set_master("boss", False)
    r = asyncio.run(server.master_status())
    assert r["ok"] is False and "nexus-mcp-panels master" in r["detail"]


def test_master_job_needs_actions_and_confirm(seen, hub_settings):
    from nexus_mcp import server

    r = asyncio.run(server.master_job("build", confirm=True))
    assert r["error"] == "actions_disabled" and not _posts(seen)
    hub_settings.allow_actions = True
    r = asyncio.run(server.master_job("build", notify_clients=True))
    assert r["preview"] and r["image"] == V_OLD and r["brain"] == V_NEW and not _posts(seen)
    r = asyncio.run(server.master_job("build", notify_clients=True, confirm=True))
    assert r["ok"], r
    assert _posts(seen) == [("POST", "m.ru", "/api/v1/admin/master/jobs/build", '{"notify_clients":true}')]
    r = asyncio.run(server.master_job("rm", confirm=True))
    assert r["error"] == "unknown_kind" and "release" in r["detail"]


def test_clients_update_preview_names_who(seen, hub_settings):
    from nexus_mcp import server

    hub_settings.allow_actions = True
    r = asyncio.run(server.master_clients_update())
    assert [c["owner"] for c in r["clients"]] == ["pablo"] and not _posts(seen)
    r = asyncio.run(server.master_clients_update(confirm=True))
    assert r["ok"] and r["marked"] == [{"id": 2}]


def test_panel_update_preview_says_same_version(seen, hub_settings):
    """Панель на версии архива мастера — обновление её только перезапустит."""
    from nexus_mcp import server

    hub_settings.allow_actions = True
    r = asyncio.run(server.panel_update("JonyX"))
    assert r["preview"] and r["version"] == V_OLD and r["target"] == V_OLD
    assert "только перезапустит" in r["note"] and not _posts(seen)
    r = asyncio.run(server.panel_update("JonyX", confirm=True))
    assert r["ok"] and ("POST", "j.ru", "/api/v1/admin/system/update", "") in seen


def test_panel_call_does_not_bypass_master_tools():
    for p in ("/api/v1/admin/master/jobs/build", "/api/v1/admin/system/update",
              "/api/v1/admin/brain/self-update"):
        assert any(__import__("re").fullmatch(pat, p) for pat in panel.CALL_DENY), p


def test_chat_asks_before_master_actions():
    from nexus_chat import runner

    for t in ("master_job", "master_clients_update", "panel_update"):
        assert t in runner.PANEL_WRITE_TOOLS
    assert "образ для клиентов" in runner.describe_action("master_job", {"kind": "build"})
    assert "разослать" in runner.describe_action("master_job", {"kind": "release", "notify_clients": True})
    assert "JonyX" in runner.describe_action("panel_update", {"panel": "JonyX"})
    assert "всем отставшим" in runner.describe_action("master_clients_update", {})
