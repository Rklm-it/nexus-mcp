"""Чат приложения: лента событий, подтверждения, long-poll, потерянная сессия.

Claude заменён заглушкой, отдающей сообщения тех же классов, что Claude Agent
SDK (разбор идёт по имени класса). Всё остальное настоящее: SQLite, ASGI,
ожидание кнопки. Проверяется поведение — что увидит приложение и что получит
инструмент хаба (инвариант 28), а не факт вызова.
"""

from __future__ import annotations

import asyncio
import re
import time
from dataclasses import dataclass, field
from typing import Any

import httpx
import pytest

from nexus_chat import config as chat_config
from nexus_chat.app import build_app
from nexus_chat.runner import Runner
from nexus_chat.store import EVENT_TYPES, Store

TOKEN = "t" * 40
AUTH = {"authorization": f"Bearer {TOKEN}"}


# ── Заглушки сообщений SDK (имена классов — как в claude_agent_sdk) ─────────

@dataclass
class TextBlock:
    text: str


@dataclass
class ToolUseBlock:
    id: str
    name: str
    input: dict


@dataclass
class ToolResultBlock:
    tool_use_id: str
    content: Any = None
    is_error: bool | None = None


@dataclass
class AssistantMessage:
    content: list
    model: str = "test"
    parent_tool_use_id: str | None = None
    error: str | None = None


@dataclass
class UserMessage:
    content: Any


@dataclass
class SystemMessage:
    subtype: str
    data: dict = field(default_factory=dict)


@dataclass
class StreamEvent:
    event: dict
    uuid: str = "u"
    session_id: str = "s"


@dataclass
class ResultMessage:
    subtype: str = "success"
    duration_ms: int = 1200
    duration_api_ms: int = 1000
    is_error: bool = False
    num_turns: int = 2
    session_id: str = "sess-1"
    total_cost_usd: float | None = 0.01
    result: str | None = None
    errors: list | None = None
    api_error_status: int | None = None


class FakeClient:
    """Сценарий — async-функция (opts, prompt) → async-итератор сообщений."""

    def __init__(self, opts: dict, script, calls: list):
        self.opts = opts
        self.script = script
        self.calls = calls
        self.prompt = None
        self.interrupted = False

    async def __aenter__(self):
        return self

    async def __aexit__(self, *exc):
        return False

    async def query(self, prompt):
        self.prompt = prompt
        self.calls.append({"resume": self.opts["resume"], "prompt": prompt})

    async def receive_response(self):
        async for m in self.script(self.opts, self.prompt):
            if self.interrupted:
                break
            yield m

    async def interrupt(self):
        self.interrupted = True


@pytest.fixture
def chat_settings(tmp_path, monkeypatch):
    s = chat_config.ChatSettings()
    s.token = TOKEN
    s.state_dir = tmp_path / "chat"
    s.mcp_secret = "s" * 32
    s.audit_at = []
    s.approval_timeout_s = 5
    monkeypatch.setattr(chat_config, "settings", s)
    monkeypatch.setenv("CLAUDE_CODE_OAUTH_TOKEN", "oauth-test")
    return s


def _setup(chat_settings, script):
    calls: list = []
    runner = Runner(Store(chat_settings.db_path), chat_settings,
                    client_factory=lambda opts: FakeClient(opts, script, calls))
    app = build_app(runner, start_background=False)
    client = httpx.AsyncClient(transport=httpx.ASGITransport(app=app), base_url="http://hub")
    return runner, client, calls


async def _wait_done(client, cid, timeout=5.0) -> list[dict]:
    """Крутит long-poll, как приложение, пока ответ не закончится."""
    after, v, events = 0, -1, []
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        r = await client.get(f"/chat/api/chats/{cid}/events",
                             params={"after": after, "v": v, "wait": 2}, headers=AUTH)
        body = r.json()
        events += body["events"]
        after, v = body["last_seq"], body["live"]["v"]
        if not body["live"]["running"] and any(e["type"] in ("done", "error") for e in events):
            return events
    raise AssertionError(f"ответ не закончился: {[e['type'] for e in events]}")


async def _wait_type(client, cid, etype, timeout=5.0) -> dict:
    after, v = 0, -1
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        body = (await client.get(f"/chat/api/chats/{cid}/events",
                                 params={"after": after, "v": v, "wait": 2}, headers=AUTH)).json()
        for e in body["events"]:
            if e["type"] == etype:
                return e
        after, v = body["last_seq"], body["live"]["v"]
    raise AssertionError(f"не дождался {etype}")


# ── Авторизация ────────────────────────────────────────────────────────────

def test_chat_requires_token(chat_settings):
    async def script(opts, prompt):
        if False:
            yield None

    async def go():
        _, client, _ = _setup(chat_settings, script)
        assert (await client.get("/chat/api/state")).status_code == 401
        assert (await client.get("/chat/api/state",
                                 headers={"authorization": "Bearer " + "x" * 40})).status_code == 401
        r = await client.get("/chat/api/state", headers=AUTH)
        assert r.status_code == 200 and r.json()["logged_in"] is True
        assert (await client.get("/chat/healthz")).status_code == 200

    asyncio.run(go())


def test_chat_refuses_short_token(chat_settings):
    chat_settings.token = "short"
    with pytest.raises(SystemExit):
        build_app(Runner(Store(chat_settings.db_path), chat_settings), start_background=False)


# ── Полный ответ ───────────────────────────────────────────────────────────

def test_turn_to_events_and_resume(chat_settings):
    async def script(opts, prompt):
        yield SystemMessage("init", {"session_id": "sess-1"})
        yield StreamEvent({"type": "content_block_delta", "delta": {"type": "text_delta", "text": "Смотрю"}})
        yield AssistantMessage([TextBlock("Смотрю панель."),
                                ToolUseBlock("tu1", "mcp__nexus__panel_health", {"panel": "main"})])
        yield UserMessage([ToolResultBlock("tu1", [{"type": "text", "text": '{"ok": true, "summary": "всё зелёное"}'}])])
        yield AssistantMessage([TextBlock("Всё в порядке.")])
        yield ResultMessage(session_id="sess-1")

    async def go():
        runner, client, calls = _setup(chat_settings, script)
        cid = (await client.post("/chat/api/chats", json={}, headers=AUTH)).json()["chat"]["id"]
        r = await client.post(f"/chat/api/chats/{cid}/send", json={"text": "как дела у панелей?"}, headers=AUTH)
        assert r.status_code == 202
        events = await _wait_done(client, cid)
        assert [e["type"] for e in events] == ["user", "text", "tool", "tool_result", "text", "done"]
        assert events[2]["data"]["name"] == "panel_health"
        assert events[3]["data"] == {"id": "tu1", "ok": True, "summary": "всё зелёное"}
        assert events[4]["data"]["text"] == "Всё в порядке."
        chat = (await client.get(f"/chat/api/chats/{cid}", headers=AUTH)).json()["chat"]
        assert chat["title"] == "как дела у панелей?"
        assert chat["has_session"] is True

        # Второй вопрос идёт с resume на сессию первого — контекст сохраняется.
        await client.post(f"/chat/api/chats/{cid}/send", json={"text": "а ноды?"}, headers=AUTH)
        await _wait_done(client, cid)
        assert [c["resume"] for c in calls] == [None, "sess-1"]

        # Уведомление: законченный ответ несёт свой последний текст.
        inbox = (await client.get("/chat/api/inbox", headers=AUTH)).json()
        assert inbox["items"][0]["type"] == "done"
        assert inbox["items"][0]["text"] == "Всё в порядке."

    asyncio.run(go())


def test_second_send_while_running_is_409(chat_settings):
    gate = asyncio.Event()

    async def script(opts, prompt):
        await gate.wait()
        yield ResultMessage()

    async def go():
        _, client, _ = _setup(chat_settings, script)
        cid = (await client.post("/chat/api/chats", json={}, headers=AUTH)).json()["chat"]["id"]
        await client.post(f"/chat/api/chats/{cid}/send", json={"text": "раз"}, headers=AUTH)
        r = await client.post(f"/chat/api/chats/{cid}/send", json={"text": "два"}, headers=AUTH)
        assert r.status_code == 409
        assert "ещё отвечает" in r.json()["detail"]
        gate.set()
        await _wait_done(client, cid)

    asyncio.run(go())


def test_error_reason_reaches_screen(chat_settings):
    async def script(opts, prompt):
        yield ResultMessage(is_error=True, result="rate limited", api_error_status=429)

    async def go():
        _, client, _ = _setup(chat_settings, script)
        cid = (await client.post("/chat/api/chats", json={}, headers=AUTH)).json()["chat"]["id"]
        await client.post(f"/chat/api/chats/{cid}/send", json={"text": "?"}, headers=AUTH)
        events = await _wait_done(client, cid)
        err = [e for e in events if e["type"] == "error"]
        assert err and err[0]["data"]["text"] == "HTTP 429: rate limited"

    asyncio.run(go())


def test_not_logged_in_is_503_with_reason(chat_settings, monkeypatch):
    monkeypatch.delenv("CLAUDE_CODE_OAUTH_TOKEN")
    monkeypatch.delenv("ANTHROPIC_API_KEY", raising=False)

    async def script(opts, prompt):
        yield ResultMessage()

    async def go():
        _, client, _ = _setup(chat_settings, script)
        cid = (await client.post("/chat/api/chats", json={}, headers=AUTH)).json()["chat"]["id"]
        r = await client.post(f"/chat/api/chats/{cid}/send", json={"text": "?"}, headers=AUTH)
        assert r.status_code == 503 and "nexus-chat-login" in r.json()["detail"]

    asyncio.run(go())


def test_lost_session_restarts_without_resume(chat_settings):
    async def script(opts, prompt):
        if opts["resume"]:
            yield ResultMessage(is_error=True, result="No conversation found with session ID")
            return
        yield AssistantMessage([TextBlock("Ответ заново.")])
        yield ResultMessage(session_id="sess-2")

    async def go():
        runner, client, calls = _setup(chat_settings, script)
        cid = (await client.post("/chat/api/chats", json={}, headers=AUTH)).json()["chat"]["id"]
        runner.store.set_session(cid, "gone")
        await client.post(f"/chat/api/chats/{cid}/send", json={"text": "?"}, headers=AUTH)
        events = await _wait_done(client, cid)
        assert [c["resume"] for c in calls] == ["gone", None]
        types = [e["type"] for e in events]
        assert "error" not in types and types[-1] == "done"
        assert any("не нашёлся" in e["data"].get("text", "") for e in events if e["type"] == "notice")
        assert runner.store.session_id(cid) == "sess-2"

    asyncio.run(go())


# ── Разрешения ─────────────────────────────────────────────────────────────

def _action_script(results: list):
    async def script(opts, prompt):
        inp = {"node": "de-1", "action": "restart", "service": "xray"}
        res = await opts["can_use_tool"]("mcp__nexus__node_action", inp, None)
        results.append(res)
        yield AssistantMessage([TextBlock("готово")])
        yield ResultMessage()
    return script


def _behavior(res) -> tuple[str, Any]:
    if isinstance(res, dict):
        return res["behavior"], res.get("updated_input") or res.get("message")
    return res.behavior, getattr(res, "updated_input", None) or getattr(res, "message", None)


@pytest.mark.parametrize("allow", [True, False])
def test_action_waits_for_button(chat_settings, allow):
    results: list = []

    async def go():
        _, client, _ = _setup(chat_settings, _action_script(results))
        cid = (await client.post("/chat/api/chats", json={}, headers=AUTH)).json()["chat"]["id"]
        await client.post(f"/chat/api/chats/{cid}/send", json={"text": "перезапусти xray"}, headers=AUTH)
        # Действие не выполняется, пока человек не нажал кнопку.
        ev = await _wait_type(client, cid, "approval")
        assert ev["data"]["title"] == "Перезапустить xray на ноде de-1"
        assert results == []
        state = (await client.get("/chat/api/state", headers=AUTH)).json()
        assert [a["id"] for a in state["pending_approvals"]] == [ev["data"]["approval_id"]]

        r = await client.post(f"/chat/api/approvals/{ev['data']['approval_id']}",
                              json={"allow": allow}, headers=AUTH)
        assert r.status_code == 200
        events = await _wait_done(client, cid)
        behavior, value = _behavior(results[0])
        if allow:
            # Разрешённое действие уходит в хаб с confirm=true — второй раз не спросит.
            assert behavior == "allow" and value["confirm"] is True and value["node"] == "de-1"
        else:
            assert behavior == "deny" and "Не повторяй" in value
        done = [e for e in events if e["type"] == "approval_done"]
        assert done and done[0]["data"]["allow"] is allow
        # Повторное нажатие — не второе действие, а 409.
        r = await client.post(f"/chat/api/approvals/{ev['data']['approval_id']}",
                              json={"allow": True}, headers=AUTH)
        assert r.status_code == 409

    asyncio.run(go())


def test_action_expires_without_button(chat_settings):
    chat_settings.approval_timeout_s = 0.3
    results: list = []

    async def go():
        _, client, _ = _setup(chat_settings, _action_script(results))
        cid = (await client.post("/chat/api/chats", json={}, headers=AUTH)).json()["chat"]["id"]
        await client.post(f"/chat/api/chats/{cid}/send", json={"text": "перезапусти"}, headers=AUTH)
        await _wait_done(client, cid)
        assert _behavior(results[0])[0] == "deny"

    asyncio.run(go())


def test_read_tools_pass_and_foreign_tools_denied(chat_settings):
    async def go():
        runner, _, _ = _setup(chat_settings, None)
        cid = runner.store.create_chat()["id"]
        ok, val = await runner._decide(cid, "mcp__nexus__node_diagnose", {"node": "de-1"})
        assert ok and val == {"node": "de-1"}
        ok, _ = await runner._decide(cid, "Bash", {"command": "cat /etc/nexus-mcp.env"})
        assert not ok
        ok, _ = await runner._decide(cid, "mcp__other__node_action", {})
        assert not ok
        assert runner.store.pending_approvals() == []

    asyncio.run(go())


def test_stop_releases_pending_approval(chat_settings):
    results: list = []

    async def go():
        _, client, _ = _setup(chat_settings, _action_script(results))
        cid = (await client.post("/chat/api/chats", json={}, headers=AUTH)).json()["chat"]["id"]
        await client.post(f"/chat/api/chats/{cid}/send", json={"text": "перезапусти"}, headers=AUTH)
        await _wait_type(client, cid, "approval")
        t0 = time.monotonic()
        assert (await client.post(f"/chat/api/chats/{cid}/stop", headers=AUTH)).status_code == 200
        await _wait_done(client, cid)
        # Не ждали таймаута кнопки (5 с) — «Стоп» отпускает сразу.
        assert time.monotonic() - t0 < 2
        assert _behavior(results[0])[0] == "deny"

    asyncio.run(go())


def test_restart_expires_pending_approvals(chat_settings):
    store = Store(chat_settings.db_path)
    cid = store.create_chat()["id"]
    aid = store.create_approval(cid, "node_action", "x", {})
    assert store.pending_approvals()
    store2 = Store(chat_settings.db_path)
    assert store2.pending_approvals() == []
    assert store2.approval(aid)["status"] == "expired"


# ── Long-poll ──────────────────────────────────────────────────────────────

def test_long_poll_waits_then_wakes_on_event(chat_settings):
    async def go():
        runner, client, _ = _setup(chat_settings, None)
        cid = runner.store.create_chat()["id"]
        v = runner.live(cid).version

        t0 = time.monotonic()
        r = await client.get(f"/chat/api/chats/{cid}/events",
                             params={"after": 0, "v": v, "wait": 0.5}, headers=AUTH)
        assert r.json()["events"] == []
        assert time.monotonic() - t0 >= 0.45          # без событий — держит запрос

        async def later():
            await asyncio.sleep(0.2)
            await runner.emit(cid, "notice", {"text": "эй"})

        t0 = time.monotonic()
        task = asyncio.create_task(later())
        r = await client.get(f"/chat/api/chats/{cid}/events",
                             params={"after": 0, "v": v, "wait": 10}, headers=AUTH)
        await task
        assert [e["type"] for e in r.json()["events"]] == ["notice"]
        assert time.monotonic() - t0 < 2              # и отпускает сразу по событию

    asyncio.run(go())


# ── Контракт с приложением (инвариант 25 vgx3d) ─────────────────────────────

def test_event_types_match_android_client(vgx3d):
    """Типы событий продублированы в Kotlin-клиенте приложения: разойдутся —
    ничего не упадёт, лента просто перестанет показывать часть ответа."""
    kt = vgx3d / "admin_app/android/app/src/main/kotlin/ru/nexusflow/admin/chat/ChatModels.kt"
    text = kt.read_text(encoding="utf-8")
    m = re.search(r"EVENT_TYPES\s*=\s*listOf\(([^)]*)\)", text)
    assert m, "в ChatModels.kt нет EVENT_TYPES = listOf(...)"
    kotlin = re.findall(r'"([a-z_]+)"', m.group(1))
    assert kotlin == list(EVENT_TYPES)


def test_inbox_notifies_answers_not_stops_and_cursor_moves(chat_settings):
    """Шторка телефона: законченный ответ — да; «Стоп» и уже нажатая кнопка — нет.
    Курсор проходит и мимо событий без уведомления, иначе их перебирали бы вечно."""
    store = Store(chat_settings.db_path)
    cid = store.create_chat("Ноды")["id"]
    store.add_event(cid, "user", {"text": "?"})
    store.add_event(cid, "text", {"text": "Нода de-1 под баном."})
    store.add_event(cid, "done", {"ended": "ok"})
    store.add_event(cid, "approval", {"approval_id": "a", "title": "x"})
    store.add_event(cid, "done", {"ended": "stopped"})
    last = store.add_event(cid, "text", {"text": "хвост"})

    async def go():
        runner = Runner(store, chat_settings, client_factory=lambda o: None)
        app = build_app(runner, start_background=False)
        client = httpx.AsyncClient(transport=httpx.ASGITransport(app=app), base_url="http://hub")
        body = (await client.get("/chat/api/inbox", headers=AUTH)).json()
        assert [(i["type"], i["text"], i["chat_title"]) for i in body["items"]] == \
            [("done", "Нода de-1 под баном.", "Ноды")]
        assert body["last_seq"] == last
        again = (await client.get("/chat/api/inbox", params={"after": body["last_seq"]}, headers=AUTH)).json()
        assert again["items"] == [] and again["last_seq"] == last

    asyncio.run(go())


def test_paid_sim_check_needs_button_only_for_the_run(chat_settings):
    """Preview SIM-проверки бесплатен и идёт сразу; запуск — деньги, ждёт кнопку
    с ценой в заголовке."""
    async def go():
        runner, client, _ = _setup(chat_settings, None)
        cid = runner.store.create_chat()["id"]
        inp = {"node": "de-1", "units": ["*|цфо|on"], "dpi": "on"}
        ok, val = await runner._decide(cid, "mcp__nexus__sim_probe", inp)
        assert ok and val == inp and runner.store.pending_approvals() == []

        task = asyncio.create_task(runner._decide(cid, "mcp__nexus__sim_probe",
                                                  {**inp, "confirm": True, "max_credits": 240}))
        ev = await _wait_type(client, cid, "approval")
        assert ev["data"]["title"] == "SIM-проверка: de-1 · *|цфо|on · с БС · не дороже 2.40 ₽"
        assert not task.done()
        await client.post(f"/chat/api/approvals/{ev['data']['approval_id']}", json={"allow": False}, headers=AUTH)
        ok, _ = await task
        assert not ok

    asyncio.run(go())
