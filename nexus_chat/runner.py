"""Ход разговора: вопрос → Claude с инструментами хаба → события в ленту.

Claude запускается через Claude Agent SDK (это Claude Code как библиотека) на
подписке владельца: `CLAUDE_CODE_OAUTH_TOKEN` из `claude setup-token`. Каждый
ответ — отдельный запуск с `resume` на сессию диалога, поэтому контекст
разговора живёт между вопросами и переживает перезапуск сервиса.

Разрешения: встроенных инструментов Claude Code нет вовсе (`tools=[]` — на
хабе лежит ключ ко всем нодам, шелла тут быть не должно), инструменты хаба на
чтение идут сразу, а действия (ACTION_TOOLS) ждут кнопки в приложении.
"""

from __future__ import annotations

import asyncio
import json
import logging
import time
from collections.abc import Callable
from datetime import datetime
from typing import Any

from nexus_chat import prompts
from nexus_chat.config import ChatSettings
from nexus_chat.store import Store, StoreError

logger = logging.getLogger("nexus_chat")

MCP_NAME = "nexus"
MCP_PREFIX = f"mcp__{MCP_NAME}__"

# Инструменты хаба, которые что-то меняют. Остальные только читают.
ACTION_TOOLS = ("node_action", "panel_action")
# Платные SIM-проверки bschekbot: preview (без confirm) бесплатен и идёт сразу,
# запуск с confirm=true — деньги, поэтому тоже ждёт кнопки.
PAID_TOOLS = ("sim_probe", "sim_vless", "sim_geo")

EFFORTS = ("low", "medium", "high", "xhigh", "max")


def panel_names() -> list[str]:
    """Панели хаба — те же, что видит Claude в panels_list."""
    from nexus_mcp import panels

    try:
        return [p["name"] for p in panels.all_panels()]
    except Exception:  # noqa: BLE001 — битый panels.json не должен ронять чат
        return []


def with_panel(text: str, panel: str) -> str:
    """Выбранная в приложении панель — указанием для Claude перед вопросом."""
    if not panel:
        return text
    return (f"[Выбрана панель «{panel}»: работай с ней — panel=\"{panel}\" у инструментов панели; "
            f"при нескольких панелях её ноды называются «{panel}/имя». Другие панели не трогай, "
            f"если вопрос прямо не про них.]\n\n{text}")


def short_tool(name: str) -> str:
    return name[len(MCP_PREFIX):] if name.startswith(MCP_PREFIX) else name


def describe_action(tool: str, inp: dict) -> str:
    """Одна строка для кнопки «Разрешить»: что именно произойдёт."""
    if tool == "node_action":
        action = inp.get("action", "?")
        node = inp.get("node", "?")
        if action == "restart":
            return f"Перезапустить {inp.get('service') or 'vpn-cell'} на ноде {node}"
        if action == "update_agent":
            return f"Обновить агент на ноде {node}"
        if action == "use_relay":
            return f"Перевести ноду {node} на реле хаба: обновить агент и слать панели через хаб"
        if action == "set_brain_url":
            return f"Прописать адрес панели на ноде {node}" + (
                f": {inp['brain_url']}" if inp.get("brain_url") else "")
        return f"{action} на ноде {node}"
    if tool in PAID_TOOLS:
        cap = inp.get("max_credits")
        price = f"не дороже {int(cap) / 100:.2f} ₽" if isinstance(cap, (int, float)) and cap > 0 else "цена не указана"
        what = inp.get("node") or ", ".join(map(str, (inp.get("targets") or inp.get("links") or [])[:3])) or "?"
        units = inp.get("units") or []
        where = {"sim_probe": "SIM-проверка", "sim_vless": "SIM-тест туннеля", "sim_geo": "Проверка по городам"}[tool]
        scope = ", ".join(map(str, units[:4])) if units else ("все округа" if tool != "sim_geo" else
                                                              inp.get("district") or inp.get("isp") or "опорные города")
        dpi = {"on": "с БС", "off": "без БС", "any": "с БС и без"}.get(str(inp.get("dpi") or "on"), "")
        tail = f" · {dpi}" if tool != "sim_geo" and dpi else ""
        return f"{where}: {what} · {scope}{tail} · {price}"
    if tool == "panel_action":
        panel = inp.get("panel") or "единственная"
        params = inp.get("params")
        tail = f" {json.dumps(params, ensure_ascii=False)}" if params else ""
        return f"Панель {panel}: POST {inp.get('path', '?')}{tail}"
    return tool


def summarize_result(content: Any, is_error: bool | None) -> tuple[bool, str]:
    """Результат инструмента коротко: ok и строка для карточки в ленте."""
    if isinstance(content, list):
        text = "\n".join(str(c.get("text", "")) for c in content if isinstance(c, dict))
    else:
        text = str(content or "")
    ok = not is_error
    summary = text.strip()
    try:
        parsed = json.loads(summary)
    except (ValueError, TypeError):
        parsed = None
    if isinstance(parsed, dict):
        if parsed.get("ok") is False:
            ok = False
            summary = str(parsed.get("detail") or parsed.get("error") or summary)
        elif isinstance(parsed.get("summary"), str):
            summary = parsed["summary"]
    return ok, summary[:400]


class Live:
    """То, чего нет в ленте: идёт ли ответ, недописанный текст, чем занят."""

    def __init__(self, last_seq: int = 0):
        self.running = False
        self.partial = ""
        self.activity = ""
        self.version = 0
        self.last_seq = last_seq

    def as_dict(self) -> dict:
        return {"running": self.running, "partial": self.partial,
                "activity": self.activity, "v": self.version}


class Runner:
    def __init__(self, store: Store, settings: ChatSettings,
                 client_factory: Callable[[Any], Any] | None = None):
        self.store = store
        self.settings = settings
        # Фабрика клиента Claude: по умолчанию ClaudeSDKClient. В тестах —
        # заглушка, отдающая заранее заданные сообщения.
        self._factory = client_factory or _sdk_client
        self._live: dict[str, Live] = {}
        self._cond = asyncio.Condition()
        self._sem = asyncio.Semaphore(max(1, settings.max_parallel))
        self._tasks: dict[str, asyncio.Task] = {}
        self._clients: dict[str, Any] = {}
        self._waiting: dict[str, tuple[str, asyncio.Future]] = {}

    # ── Живое состояние и ожидание ─────────────────────────────────────────

    def live(self, chat_id: str) -> Live:
        lv = self._live.get(chat_id)
        if lv is None:
            lv = self._live[chat_id] = Live(self.store.chat_last_seq(chat_id))
        return lv

    async def _notify(self, chat_id: str) -> None:
        self.live(chat_id).version += 1
        async with self._cond:
            self._cond.notify_all()

    async def emit(self, chat_id: str, etype: str, data: dict) -> int:
        seq = self.store.add_event(chat_id, etype, data)
        self.live(chat_id).last_seq = seq
        await self._notify(chat_id)
        return seq

    async def wait(self, chat_id: str, after: int, version: int, timeout: float) -> None:
        """Long-poll: вернуться, когда в ленте есть что-то после `after` или
        сменилось живое состояние; иначе — по таймауту."""
        lv = self.live(chat_id)

        def ready() -> bool:
            return lv.last_seq > after or lv.version != version

        if ready():
            return
        try:
            async with self._cond:
                await asyncio.wait_for(self._cond.wait_for(ready), timeout)
        except (asyncio.TimeoutError, TimeoutError):
            return
        # Дописывающийся текст меняет версию на каждом слове. Короткая пауза
        # собирает несколько слов в один ответ вместо десятков запросов в секунду.
        if lv.last_seq <= after:
            await asyncio.sleep(0.35)

    # ── Вопрос ─────────────────────────────────────────────────────────────

    def busy(self) -> list[str]:
        return [cid for cid, lv in self._live.items() if lv.running]

    async def send(self, chat_id: str, text: str, *, fresh: bool = False,
                   notice: str = "", panel: str = "") -> None:
        text = (text or "").strip()
        if not text:
            raise StoreError("пустое сообщение")
        panel = (panel or "").strip()
        if panel:
            names = panel_names()
            if panel not in names:
                raise StoreError(f"на хабе нет панели «{panel}». Есть: {', '.join(names) or 'ни одной'}")
        chat = self.store.get_chat(chat_id)
        lv = self.live(chat_id)
        if lv.running:
            raise StoreError("Claude ещё отвечает в этом диалоге — дождитесь или нажмите «Стоп»", 409)
        if not self.settings.logged_in:
            raise StoreError("Claude на хабе не вошёл в подписку: на хабе выполните nexus-chat-login", 503)
        if notice:
            await self.emit(chat_id, "notice", {"text": notice})
        else:
            if chat["title"] == "Новый диалог":
                self.store.rename_chat(chat_id, text.splitlines()[0][:48])
            await self.emit(chat_id, "user", {"text": text, **({"panel": panel} if panel else {})})
        lv.running, lv.partial, lv.activity = True, "", "думает"
        await self._notify(chat_id)
        prompt = with_panel(text, panel)
        self._tasks[chat_id] = asyncio.create_task(self._turn(chat_id, prompt, fresh))

    async def _turn(self, chat_id: str, text: str, fresh: bool) -> None:
        lv = self.live(chat_id)
        start_seq = lv.last_seq
        ended = "ok"
        try:
            if self._sem.locked():
                lv.activity = "ждёт очереди: Claude отвечает в другом диалоге"
                await self._notify(chat_id)
            async with self._sem:
                resume = None if fresh else self.store.session_id(chat_id)
                got = await self._run(chat_id, text, resume)
                if resume and got == 0:
                    # Сессии на диске нет (стёрли каталог, другая машина) — не
                    # ронять диалог, а начать контекст заново и сказать об этом.
                    self.store.set_session(chat_id, None)
                    await self.emit(chat_id, "notice", {
                        "text": "Контекст прошлого разговора на хабе не нашёлся — отвечаю без него"})
                    await self._run(chat_id, text, None)
        except asyncio.CancelledError:
            ended = "stopped"
        except Exception as e:  # noqa: BLE001 — причина уходит на экран, не в лог
            logger.exception("ответ в диалоге %s упал", chat_id)
            ended = "error"
            await self.emit(chat_id, "error", {"text": f"{type(e).__name__}: {e}"})
        finally:
            self._clients.pop(chat_id, None)
            self._tasks.pop(chat_id, None)
            await self._cancel_approvals(chat_id, "ответ закончился")
            # Каждый ответ кончается событием done — по нему приложение знает,
            # что ждать больше нечего, даже если Claude оборвали на полуслове.
            if not any(e["type"] == "done" for e in self.store.events(chat_id, start_seq)):
                if ended == "ok":
                    ended = "stopped"
                if ended == "stopped":
                    await self.emit(chat_id, "notice", {"text": "Остановлено"})
                await self.emit(chat_id, "done", {"ended": ended})
            lv.running, lv.partial, lv.activity = False, "", ""
            await self._notify(chat_id)

    async def _run(self, chat_id: str, text: str, resume: str | None) -> int:
        """Один запуск Claude. Возвращает число полученных сообщений: ноль при
        resume — признак потерянной сессии."""
        got = 0
        try:
            async with self._factory(self._options(chat_id, resume)) as client:
                self._clients[chat_id] = client
                await client.query(text)
                async for msg in client.receive_response():
                    kind = type(msg).__name__
                    if resume and got == 0 and kind == "ResultMessage" and msg.is_error:
                        # Отказ до первого слова при resume — сессии нет на диске.
                        logger.warning("resume %s: %s", resume, msg.result or msg.errors)
                        return 0
                    if kind not in ("SystemMessage", "RateLimitEvent", "StreamEvent"):
                        got += 1
                    await self._on_message(chat_id, msg)
        except Exception:
            if resume and got == 0:
                logger.warning("resume %s не удался — начну заново", resume, exc_info=True)
                return 0
            raise
        return got

    def _options(self, chat_id: str, resume: str | None) -> dict:
        s = self.settings

        async def can_use_tool(name: str, tool_input: dict, _ctx: Any = None):
            return await self.decide_tool(chat_id, name, tool_input)

        return {
            "mcp_servers": {MCP_NAME: {"type": "http", "url": s.mcp_url,
                                       "headers": {"Authorization": f"Bearer {s.mcp_secret}"}}},
            "system_prompt": prompts.SYSTEM_PROMPT,
            "resume": resume,
            "cwd": str(s.work_dir),
            "model": s.model or None,
            "effort": s.effort if s.effort in EFFORTS else None,
            "can_use_tool": can_use_tool,
        }

    # ── Сообщения Claude → лента ───────────────────────────────────────────

    async def _on_message(self, chat_id: str, msg: Any) -> None:
        kind = type(msg).__name__
        lv = self.live(chat_id)
        if kind == "StreamEvent":
            ev = msg.event or {}
            if ev.get("type") == "content_block_delta":
                delta = ev.get("delta") or {}
                if delta.get("type") == "text_delta":
                    lv.partial += delta.get("text", "")
                    lv.activity = "пишет"
                    await self._notify(chat_id)
            elif ev.get("type") == "content_block_start":
                block = ev.get("content_block") or {}
                if block.get("type") == "tool_use":
                    lv.activity = "вызывает " + short_tool(block.get("name", ""))
                    await self._notify(chat_id)
            return
        if kind == "AssistantMessage":
            if getattr(msg, "parent_tool_use_id", None):
                return
            for block in msg.content or []:
                bkind = type(block).__name__
                if bkind == "TextBlock" and (block.text or "").strip():
                    lv.partial = ""
                    await self.emit(chat_id, "text", {"text": block.text.strip()})
                elif bkind == "ToolUseBlock":
                    lv.activity = "вызывает " + short_tool(block.name)
                    await self.emit(chat_id, "tool", {"id": block.id, "name": short_tool(block.name),
                                                      "input": block.input or {}})
            if getattr(msg, "error", None):
                await self.emit(chat_id, "error", {"text": f"Claude: {msg.error}"})
            return
        if kind == "UserMessage":
            content = msg.content if isinstance(msg.content, list) else []
            for block in content:
                if type(block).__name__ == "ToolResultBlock":
                    ok, summary = summarize_result(block.content, block.is_error)
                    await self.emit(chat_id, "tool_result", {"id": block.tool_use_id, "ok": ok,
                                                             "summary": summary})
            lv.activity = "думает"
            await self._notify(chat_id)
            return
        if kind == "SystemMessage":
            data = msg.data or {}
            if msg.subtype == "init" and data.get("session_id"):
                self.store.set_session(chat_id, data["session_id"])
            if msg.subtype == "init" and isinstance(data.get("tools"), list):
                # Без инструментов хаба Claude отвечает догадками — сказать
                # об этом сразу и с причиной, а не ждать «No such tool».
                if not any(str(t).startswith(MCP_PREFIX) for t in data["tools"]):
                    st = [f"{m.get('name')}: {m.get('status')}" for m in data.get("mcp_servers") or []
                          if isinstance(m, dict)]
                    await self.emit(chat_id, "error", {
                        "text": "Claude не получил инструменты хаба" +
                                (f" ({'; '.join(st)})" if st else "") +
                                " — ответ будет без проверок. На хабе: journalctl -u nexus-chat -n 50"})
            return
        if kind == "RateLimitEvent":
            info = msg.rate_limit_info
            if info.status in ("allowed_warning", "rejected"):
                await self.emit(chat_id, "notice", {"text": _rate_limit_text(info)})
            return
        if kind == "ResultMessage":
            if msg.session_id:
                self.store.set_session(chat_id, msg.session_id)
            if msg.is_error:
                why = msg.result or "; ".join(msg.errors or []) or msg.subtype
                if getattr(msg, "api_error_status", None):
                    why = f"HTTP {msg.api_error_status}: {why}"
                await self.emit(chat_id, "error", {"text": str(why)})
            ended = "error" if msg.is_error else (
                "stopped" if str(getattr(msg, "terminal_reason", "") or "").startswith("aborted") else "ok")
            await self.emit(chat_id, "done", {"ended": ended, "cost_usd": msg.total_cost_usd,
                                              "duration_ms": msg.duration_ms,
                                              "turns": msg.num_turns})

    # ── Разрешения ─────────────────────────────────────────────────────────

    async def decide_tool(self, chat_id: str, name: str, tool_input: dict):
        """Вызывается Claude Code перед каждым инструментом."""
        ok, value = await self._decide(chat_id, name, tool_input)
        return _permission(ok, value)

    async def _decide(self, chat_id: str, name: str, tool_input: dict) -> tuple[bool, Any]:
        if not name.startswith(MCP_PREFIX):
            return False, "В чате доступны только инструменты хаба nexus"
        tool = short_tool(name)
        paid = tool in PAID_TOOLS and bool(tool_input.get("confirm"))
        if tool not in ACTION_TOOLS and not paid:
            return True, tool_input
        title = describe_action(tool, tool_input)
        aid = self.store.create_approval(chat_id, tool, title, tool_input)
        fut: asyncio.Future = asyncio.get_running_loop().create_future()
        self._waiting[aid] = (chat_id, fut)
        lv = self.live(chat_id)
        lv.activity = "ждёт вашего подтверждения"
        await self.emit(chat_id, "approval", {"approval_id": aid, "tool": tool, "title": title,
                                              "input": tool_input})
        try:
            allow, reason = await asyncio.wait_for(fut, self.settings.approval_timeout_s)
        except (asyncio.TimeoutError, TimeoutError):
            self.store.decide(aid, "expired")
            mins = self.settings.approval_timeout_s // 60
            reason = f"не подтверждено за {mins} мин"
            await self.emit(chat_id, "approval_done", {"approval_id": aid, "allow": False,
                                                       "reason": reason})
            return False, f"Человек не подтвердил действие ({reason}). Не повторяй без новой просьбы."
        finally:
            self._waiting.pop(aid, None)
        lv.activity = "выполняет" if allow else "думает"
        if allow:
            return True, {**tool_input, "confirm": True}
        return False, (reason or "Человек отклонил это действие в приложении.") + \
            " Не повторяй его без новой просьбы."

    async def approve(self, approval_id: str, allow: bool) -> dict:
        a = self.store.approval(approval_id)
        if a["status"] != "pending":
            raise StoreError(f"запрос уже закрыт: {a['status']}", 409)
        waiting = self._waiting.get(approval_id)
        if waiting is None or waiting[1].done():
            self.store.decide(approval_id, "expired")
            raise StoreError("Claude уже не ждёт ответа на этот запрос", 409)
        self.store.decide(approval_id, "allowed" if allow else "denied")
        reason = "" if allow else "Отклонено в приложении."
        await self.emit(a["chat_id"], "approval_done", {"approval_id": approval_id, "allow": allow,
                                                        "reason": reason})
        waiting[1].set_result((allow, reason))
        return self.store.approval(approval_id)

    async def _cancel_approvals(self, chat_id: str, reason: str) -> None:
        for aid, (cid, fut) in list(self._waiting.items()):
            if cid != chat_id or fut.done():
                continue
            self.store.decide(aid, "denied")
            await self.emit(chat_id, "approval_done", {"approval_id": aid, "allow": False,
                                                       "reason": reason})
            fut.set_result((False, reason))

    async def stop(self, chat_id: str) -> None:
        self.store.get_chat(chat_id)
        await self._cancel_approvals(chat_id, "остановлено")
        client = self._clients.get(chat_id)
        if client is not None:
            try:
                await client.interrupt()
                return
            except Exception:  # noqa: BLE001 — не вышло мягко, гасим задачу
                logger.warning("interrupt не прошёл", exc_info=True)
        task = self._tasks.get(chat_id)
        if task is not None:
            task.cancel()

    # ── Плановый аудит ─────────────────────────────────────────────────────

    async def run_audit(self, label: str = "") -> dict:
        chat = self.store.find_chat("audit") or self.store.create_chat("Аудит", kind="audit")
        # Каждый аудит — с чистого контекста: вчерашний осмотр не должен
        # подсказывать сегодняшний вывод. Вопросы вдогонку — уже с контекстом.
        await self.send(chat["id"], prompts.AUDIT_PROMPT, fresh=True,
                        notice=f"Плановый аудит{' ' + label if label else ''}")
        return self.store.get_chat(chat["id"])

    async def audit_loop(self) -> None:
        if not self.settings.audit_at:
            return
        try:
            from zoneinfo import ZoneInfo
            tz = ZoneInfo(self.settings.tz)
        except Exception:  # noqa: BLE001
            logger.warning("часовой пояс %s не найден — аудит по UTC", self.settings.tz)
            tz = None
        while True:
            await asyncio.sleep(20)
            now = datetime.now(tz)
            hm = now.strftime("%H:%M")
            if hm not in self.settings.audit_at:
                continue
            key = f"audit:{now.date().isoformat()} {hm}"
            if self.store.kv_get(key):
                continue
            self.store.kv_set(key, str(time.time()))
            try:
                await self.run_audit(hm)
            except StoreError as e:
                chat = self.store.find_chat("audit")
                if chat:
                    await self.emit(chat["id"], "error", {"text": f"Аудит {hm} не начат: {e.message}"})


def _rate_limit_text(info: Any) -> str:
    used = f"{round(info.utilization * 100)}%" if info.utilization is not None else ""
    when = ""
    if info.resets_at:
        when = datetime.fromtimestamp(info.resets_at).strftime("%d.%m %H:%M")
    if info.status == "rejected":
        return "Лимит подписки исчерпан" + (f", сброс {when}" if when else "")
    return "Лимит подписки близко" + (f": израсходовано {used}" if used else "") + \
        (f", сброс {when}" if when else "")


def _permission(ok: bool, value: Any):
    try:
        from claude_agent_sdk import PermissionResultAllow, PermissionResultDeny
    except ImportError:  # тесты без SDK
        return {"behavior": "allow", "updated_input": value} if ok else \
            {"behavior": "deny", "message": value}
    if ok:
        return PermissionResultAllow(updated_input=value)
    return PermissionResultDeny(message=value)


def _sdk_client(opts: dict):
    from claude_agent_sdk import ClaudeAgentOptions, ClaudeSDKClient

    def _stderr(line: str) -> None:
        logger.info("claude: %s", line.rstrip())

    options = ClaudeAgentOptions(
        tools=[],                      # ни Bash, ни файлов: только инструменты хаба
        mcp_servers=opts["mcp_servers"],
        strict_mcp_config=True,
        system_prompt=opts["system_prompt"],
        resume=opts["resume"],
        cwd=opts["cwd"],
        model=opts["model"],
        effort=opts["effort"],
        can_use_tool=opts["can_use_tool"],
        include_partial_messages=True,
        setting_sources=[],            # чужие settings.json и CLAUDE.md сюда не попадают
        # Поиск инструментов Claude Code прячет MCP-инструменты за ToolSearch и
        # подгружает по запросу — а встроенных инструментов (и ToolSearch с ними)
        # у чата нет. На официальном API он включён по умолчанию: модель видела
        # только имена и звала «panels_list» → «No such tool available».
        env={"ENABLE_TOOL_SEARCH": "false"},
        stderr=_stderr,
    )
    return ClaudeSDKClient(options)
