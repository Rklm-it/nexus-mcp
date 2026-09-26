"""Тестовая подписка панели: хаб заводит служебного юзера сам.

Панель — заглушка с состоянием (юзеры, привязки к нодам): проверяется, ЧТО
хаб отправил панели и что осталось на хабе (инвариант 28), а не факт вызова.
Пути ручек сверяются с кодом панели (инвариант 25).
"""

from __future__ import annotations

import asyncio
import json
import re
import uuid

import httpx
import pytest

from nexus_mcp import links, panel, panels, probe_sub, sweep
from nexus_chat import runner as chat_runner


class FakePanel:
    """Минимальная панель: юзеры, 3 активные ноды, ручки как в vgx3d."""

    def __init__(self, nodes: int = 3, fail: int | None = None):
        self.users: dict[str, dict] = {}
        self.assigned: dict[str, set] = {}
        self.nodes = [f"n{i}" for i in range(nodes)]
        self.calls: list[tuple[str, str, dict | None]] = []
        self.fail = fail

    def handler(self, req: httpx.Request) -> httpx.Response:
        path = req.url.path
        body = json.loads(req.content) if req.content else None
        self.calls.append((req.method, path, body))
        if self.fail:
            return httpx.Response(self.fail, json={"detail": "Invalid or missing X-Admin-Token"})
        m = re.fullmatch(r".*/api/v1/users/([0-9a-f-]+)/assign-servers", path)
        if req.method == "POST" and m:
            uid = m.group(1)
            have = self.assigned.setdefault(uid, set())
            add = [n for n in self.nodes if n not in have]
            have.update(add)
            return httpx.Response(200, json={"assigned": len(add), "total": len(have), "available": len(self.nodes)})
        m = re.fullmatch(r".*/api/v1/admin/users/([0-9a-f-]+)/comment", path)
        if req.method == "PATCH" and m:
            self.users[m.group(1)]["admin_comment"] = body["comment"]
            return httpx.Response(200, json={"user_id": m.group(1), "admin_comment": body["comment"]})
        m = re.fullmatch(r".*/api/v1/users/([0-9a-f-]+)", path)
        if req.method == "GET" and m:
            u = self.users.get(m.group(1))
            return httpx.Response(200, json=u) if u else httpx.Response(404, json={"detail": "User not found"})
        if req.method == "GET" and path.endswith("/api/v1/admin/users"):
            q = req.url.params.get("search", "")
            items = [u for u in self.users.values() if q in u["username"]]
            return httpx.Response(200, json={"total": len(items), "items": items})
        if req.method == "POST" and path.endswith("/api/v1/users"):
            if any(u["username"] == body["username"] for u in self.users.values()):
                return httpx.Response(409, json={"detail": "Username already exists"})
            uid = str(uuid.uuid4())
            u = {"id": uid, "username": body["username"], "sub_token": "TOKEN" + uid.replace("-", "")[:20],
                 "is_active": True, "is_blocked": False, "expire_at": None, "traffic_limit": 0}
            self.users[uid] = u
            self.assigned[uid] = set(self.nodes)  # панель сама привязывает ко всем
            return httpx.Response(201, json=u)
        return httpx.Response(404, json={"detail": "not found"})

    def writes(self) -> list[tuple[str, str]]:
        return [(m, p) for m, p, _ in self.calls if m != "GET"]


def _world(monkeypatch, hub_settings, tmp_path, fakes: dict[str, FakePanel]):
    hub_settings.panels_file = tmp_path / "panels.json"
    hub_settings.panels_file.write_text(json.dumps({"panels": [
        {"name": n, "url": f"https://{n}.example", "token": f"T-{n}"} for n in fakes]}))
    real = httpx.AsyncClient

    def factory(*a, **kw):
        def route(req: httpx.Request) -> httpx.Response:
            return fakes[req.url.host.split(".")[0]].handler(req)
        kw["transport"] = httpx.MockTransport(route)
        return real(*a, **kw)

    monkeypatch.setattr(panel.httpx, "AsyncClient", factory)

    async def fetch(url=""):
        return ["vless://u@203.0.113.7:443?security=reality#a", "vless://u@203.0.113.8:443?security=reality#b"]

    monkeypatch.setattr(links, "fetch_links", fetch)


def test_hub_creates_service_user_and_keeps_token_on_hub(monkeypatch, hub_settings, tmp_path):
    fake = FakePanel()
    _world(monkeypatch, hub_settings, tmp_path, {"main": fake})
    res = asyncio.run(probe_sub.ensure("main"))
    r = res["panels"][0]
    assert res["ok"] and r["created"] and r["links"] == 2
    (uid, u), = fake.users.items()
    assert u["username"] == "nexus-probe" and "не удалять" in u["admin_comment"].lower()
    assert fake.assigned[uid] == set(fake.nodes)
    # подписка — на хабе, с id юзера; в ответе только маска
    saved = panels.resolve("main")
    assert saved["sub_url"] == f"https://main.example/api/v1/sub/{u['sub_token']}"
    assert saved["sub_user_id"] == uid and saved["token"] == "T-main"
    assert u["sub_token"] not in json.dumps(res)
    # прогон берёт её без ручного nexus-mcp-panels sub
    assert sweep.sources("main") == [("main", saved["sub_url"])]


def test_second_call_reuses_user_and_adds_new_nodes(monkeypatch, hub_settings, tmp_path):
    fake = FakePanel()
    _world(monkeypatch, hub_settings, tmp_path, {"main": fake})
    asyncio.run(probe_sub.ensure("main"))
    fake.nodes.append("n-new")  # появилась нода
    r = asyncio.run(probe_sub.ensure("main"))["panels"][0]
    assert r["created"] is False and r["nodes"]["assigned"] == 1
    assert len(fake.users) == 1
    assert [p for m, p in fake.writes() if m == "POST" and p.endswith("/api/v1/users")] == ["/api/v1/users"]


def test_user_deleted_in_panel_is_recreated(monkeypatch, hub_settings, tmp_path):
    fake = FakePanel()
    _world(monkeypatch, hub_settings, tmp_path, {"main": fake})
    asyncio.run(probe_sub.ensure("main"))
    old = panels.resolve("main")["sub_user_id"]
    fake.users.clear()
    r = asyncio.run(probe_sub.ensure("main"))["panels"][0]
    assert r["ok"] and r["created"] and panels.resolve("main")["sub_user_id"] != old


def test_blocked_user_is_reported_not_unblocked(monkeypatch, hub_settings, tmp_path):
    fake = FakePanel()
    _world(monkeypatch, hub_settings, tmp_path, {"main": fake})
    asyncio.run(probe_sub.ensure("main"))
    next(iter(fake.users.values()))["is_blocked"] = True
    fake.calls.clear()
    r = asyncio.run(probe_sub.ensure("main"))["panels"][0]
    assert r["ok"] is False and "заблокирован" in r["detail"]
    # блок мог поставить человек — хаб его не снимает
    assert not any("block" in p for _, p in fake.writes())


def test_plan_writes_nothing(monkeypatch, hub_settings, tmp_path):
    fake = FakePanel()
    _world(monkeypatch, hub_settings, tmp_path, {"main": fake})
    res = asyncio.run(probe_sub.plan())
    assert res["steps"][0]["action"] == "create" and fake.writes() == []
    assert "sub_url" not in panels.resolve("main")


def test_one_panel_refusing_does_not_stop_others(monkeypatch, hub_settings, tmp_path):
    good, bad = FakePanel(), FakePanel(fail=403)
    _world(monkeypatch, hub_settings, tmp_path, {"main": good, "vip": bad})
    res = asyncio.run(probe_sub.ensure(""))
    by = {r["panel"]: r for r in res["panels"]}
    assert by["main"]["ok"] and not by["vip"]["ok"]
    assert "403" in by["vip"]["detail"]  # причина — на экран (инвариант 26)
    assert [x["panel"] for x in probe_sub.listing() if x["has_sub"]] == ["main"]


def test_sweep_adds_new_nodes_before_run(monkeypatch, hub_settings, tmp_path):
    fake = FakePanel()
    _world(monkeypatch, hub_settings, tmp_path, {"main": fake})
    asyncio.run(probe_sub.ensure("main"))
    fake.nodes.append("n-new")
    uid = panels.resolve("main")["sub_user_id"]

    async def run(probe, kind, args, timeout=40.0):
        # к моменту проб новая нода уже в подписке юзера
        assert "n-new" in fake.assigned[uid]
        return {"ok": True, "results": [{"ok": True, "ms": 1.0} for _ in args["jobs"]]}

    from nexus_mcp.probes import registry
    monkeypatch.setattr(registry, "run", run)
    monkeypatch.setattr(sweep.links, "_resolve", lambda h: set())
    monkeypatch.setattr(sweep.inventory, "load_nodes", lambda: _nodes())
    res = asyncio.run(sweep.sweep("hub", "main"))
    assert any("добавлено нод: 1" in n for n in res["notes"])


async def _nodes():
    return [], []


def test_no_sub_hint_names_the_tool(hub_settings):
    with pytest.raises(sweep.SweepError, match="probe_subscription"):
        sweep.sources()


def test_chat_asks_before_creating_user():
    assert "probe_subscription" in chat_runner.PANEL_WRITE_TOOLS
    title = chat_runner.describe_action("probe_subscription", {"panel": "vip", "confirm": True})
    assert "vip" in title and "nexus-probe" in title


# ── Контракт с панелью (инвариант 25 vgx3d) ─────────────────────────────────

def test_panel_routes_exist(vgx3d):
    users = (vgx3d / "brain/app/api/v1/users.py").read_text(encoding="utf-8")
    admin = (vgx3d / "brain/app/api/v1/admin/users.py").read_text(encoding="utf-8")
    sub = (vgx3d / "brain/app/api/v1/subscription.py").read_text(encoding="utf-8")
    assert '@router.post("", response_model=UserOut' in users  # POST /api/v1/users
    assert '@router.post("/{user_id}/assign-servers")' in users
    assert '"/{user_id}/comment"' in admin and 'data.get("comment"' in admin
    assert "search: str | None = None" in admin  # GET /api/v1/admin/users?search=
    assert "GET /api/v1/sub/{token}" in sub
    # без server_ids панель привязывает нового юзера ко всем активным нодам
    assert "привязать ко всем активным" in users
