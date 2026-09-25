"""Диалоги, события и запросы подтверждения — SQLite на диске хаба.

Разговор хранится как лента событий с растущим `seq`: приложение просит
«всё после N» и не теряет ни строчки, даже если закрылось посреди ответа или
связь с телефона моргнула. Недописанный текст в ленту не пишется — он живёт
в памяти процесса (runner.Live) и отдаётся отдельным полем.

Типы событий — контракт с приложением (`EVENT_TYPES`, сторож в тестах
сверяет их с Kotlin-клиентом: инвариант 25 vgx3d).
"""

from __future__ import annotations

import json
import sqlite3
import threading
import time
import uuid
from pathlib import Path

EVENT_TYPES = (
    "user",           # {text} — вопрос человека
    "text",           # {text} — законченный кусок ответа Claude
    "tool",           # {id, name, input} — Claude зовёт инструмент хаба
    "tool_result",    # {id, ok, summary} — что инструмент вернул (коротко)
    "approval",       # {approval_id, tool, title, input} — ждёт кнопки «Разрешить»
    "approval_done",  # {approval_id, allow, reason}
    "done",           # {ended: ok|stopped|error, cost_usd, duration_ms, turns} — ответ закончен
    "error",          # {text} — причина отказа как есть (инвариант 26)
    "notice",         # {text} — лимиты подписки, аудит по расписанию
)

_SCHEMA = """
CREATE TABLE IF NOT EXISTS chats (
    id TEXT PRIMARY KEY,
    title TEXT NOT NULL,
    kind TEXT NOT NULL DEFAULT 'chat',
    session_id TEXT,
    created REAL NOT NULL,
    updated REAL NOT NULL,
    preview TEXT NOT NULL DEFAULT ''
);
CREATE TABLE IF NOT EXISTS events (
    seq INTEGER PRIMARY KEY AUTOINCREMENT,
    chat_id TEXT NOT NULL,
    type TEXT NOT NULL,
    data TEXT NOT NULL,
    ts REAL NOT NULL
);
CREATE INDEX IF NOT EXISTS events_chat ON events(chat_id, seq);
CREATE TABLE IF NOT EXISTS approvals (
    id TEXT PRIMARY KEY,
    chat_id TEXT NOT NULL,
    tool TEXT NOT NULL,
    title TEXT NOT NULL,
    input TEXT NOT NULL,
    status TEXT NOT NULL DEFAULT 'pending',
    created REAL NOT NULL,
    decided REAL
);
CREATE TABLE IF NOT EXISTS kv (k TEXT PRIMARY KEY, v TEXT NOT NULL);
"""


class StoreError(Exception):
    def __init__(self, message: str, status: int = 400):
        super().__init__(message)
        self.message = message
        self.status = status


class Store:
    def __init__(self, path: Path):
        path.parent.mkdir(parents=True, exist_ok=True)
        self._db = sqlite3.connect(str(path), check_same_thread=False, isolation_level=None)
        self._db.row_factory = sqlite3.Row
        self._lock = threading.Lock()
        with self._lock:
            self._db.executescript(_SCHEMA)
            self._db.execute("PRAGMA journal_mode=WAL")
            # Процесс перезапустился — ожидания кнопок в памяти потеряны. Висящий
            # «Разрешить», который уже ничего не разрешит, хуже честного «истёк».
            self._db.execute("UPDATE approvals SET status='expired', decided=? WHERE status='pending'",
                             (time.time(),))

    def _q(self, sql: str, args: tuple = ()) -> list[sqlite3.Row]:
        with self._lock:
            return self._db.execute(sql, args).fetchall()

    def _x(self, sql: str, args: tuple = ()) -> sqlite3.Cursor:
        with self._lock:
            return self._db.execute(sql, args)

    # ── Диалоги ────────────────────────────────────────────────────────────

    @staticmethod
    def _chat(r: sqlite3.Row) -> dict:
        return {"id": r["id"], "title": r["title"], "kind": r["kind"], "created": r["created"],
                "updated": r["updated"], "preview": r["preview"],
                "has_session": bool(r["session_id"])}

    def create_chat(self, title: str = "", kind: str = "chat") -> dict:
        now = time.time()
        cid = uuid.uuid4().hex[:12]
        title = (title or "").strip()[:80] or "Новый диалог"
        self._x("INSERT INTO chats(id, title, kind, created, updated) VALUES (?,?,?,?,?)",
                (cid, title, kind, now, now))
        return self.get_chat(cid)

    def get_chat(self, chat_id: str) -> dict:
        rows = self._q("SELECT * FROM chats WHERE id=?", (chat_id,))
        if not rows:
            raise StoreError("нет такого диалога", 404)
        return self._chat(rows[0])

    def find_chat(self, kind: str) -> dict | None:
        rows = self._q("SELECT * FROM chats WHERE kind=? ORDER BY created LIMIT 1", (kind,))
        return self._chat(rows[0]) if rows else None

    def list_chats(self) -> list[dict]:
        rows = self._q("SELECT * FROM chats ORDER BY updated DESC")
        out = []
        for r in rows:
            c = self._chat(r)
            last = self._q("SELECT MAX(seq) AS s FROM events WHERE chat_id=?", (r["id"],))
            c["last_seq"] = last[0]["s"] or 0
            out.append(c)
        return out

    def rename_chat(self, chat_id: str, title: str) -> dict:
        self.get_chat(chat_id)
        self._x("UPDATE chats SET title=? WHERE id=?", ((title or "").strip()[:80] or "Диалог", chat_id))
        return self.get_chat(chat_id)

    def delete_chat(self, chat_id: str) -> None:
        self.get_chat(chat_id)
        self._x("DELETE FROM events WHERE chat_id=?", (chat_id,))
        self._x("DELETE FROM approvals WHERE chat_id=?", (chat_id,))
        self._x("DELETE FROM chats WHERE id=?", (chat_id,))

    def session_id(self, chat_id: str) -> str | None:
        rows = self._q("SELECT session_id FROM chats WHERE id=?", (chat_id,))
        return rows[0]["session_id"] if rows else None

    def set_session(self, chat_id: str, session_id: str | None) -> None:
        self._x("UPDATE chats SET session_id=? WHERE id=?", (session_id, chat_id))

    # ── События ────────────────────────────────────────────────────────────

    def add_event(self, chat_id: str, etype: str, data: dict) -> int:
        if etype not in EVENT_TYPES:
            raise ValueError(f"неизвестный тип события: {etype}")
        now = time.time()
        cur = self._x("INSERT INTO events(chat_id, type, data, ts) VALUES (?,?,?,?)",
                      (chat_id, etype, json.dumps(data, ensure_ascii=False), now))
        preview = ""
        if etype in ("user", "text", "error", "notice"):
            preview = str(data.get("text", ""))[:160]
        elif etype == "approval":
            preview = "Ждёт подтверждения: " + str(data.get("title", ""))[:120]
        if preview:
            self._x("UPDATE chats SET updated=?, preview=? WHERE id=?", (now, preview, chat_id))
        else:
            self._x("UPDATE chats SET updated=? WHERE id=?", (now, chat_id))
        return int(cur.lastrowid)

    @staticmethod
    def _event(r: sqlite3.Row) -> dict:
        return {"seq": r["seq"], "chat_id": r["chat_id"], "type": r["type"],
                "data": json.loads(r["data"]), "ts": r["ts"]}

    def events(self, chat_id: str, after: int = 0, limit: int = 500) -> list[dict]:
        rows = self._q("SELECT * FROM events WHERE chat_id=? AND seq>? ORDER BY seq LIMIT ?",
                       (chat_id, after, limit))
        return [self._event(r) for r in rows]

    def chat_last_seq(self, chat_id: str) -> int:
        rows = self._q("SELECT MAX(seq) AS s FROM events WHERE chat_id=?", (chat_id,))
        return rows[0]["s"] or 0

    def last_seq(self) -> int:
        rows = self._q("SELECT MAX(seq) AS s FROM events")
        return rows[0]["s"] or 0

    def inbox(self, after: int = 0, limit: int = 50) -> list[dict]:
        """Что показать уведомлением: законченные ответы и ошибки.

        Для законченного ответа берётся последний кусок текста перед ним —
        именно его человек и хочет увидеть в шторке. Запросы кнопки сюда не
        входят: о них говорит `pending_approvals()` — событие в ленте остаётся и
        после того, как кнопку нажали, а звать нажимать уже нажатое незачем.
        """
        rows = self._q(
            "SELECT e.*, c.title AS chat_title FROM events e JOIN chats c ON c.id=e.chat_id "
            "WHERE e.seq>? AND e.type IN ('done','error') ORDER BY e.seq LIMIT ?",
            (after, limit))
        out = []
        for r in rows:
            data = json.loads(r["data"])
            if r["type"] == "done" and data.get("ended", "ok") != "ok":
                continue  # остановленный или упавший ответ — о нём скажет error/сам человек
            if r["type"] == "done":
                last = self._q("SELECT data FROM events WHERE chat_id=? AND seq<? AND type='text' "
                               "ORDER BY seq DESC LIMIT 1", (r["chat_id"], r["seq"]))
                text = json.loads(last[0]["data"]).get("text", "") if last else ""
            else:
                text = str(data.get("text", ""))
            out.append({"seq": r["seq"], "chat_id": r["chat_id"], "chat_title": r["chat_title"],
                        "type": r["type"], "text": text[:600]})
        return out

    # ── Подтверждения ──────────────────────────────────────────────────────

    def create_approval(self, chat_id: str, tool: str, title: str, tool_input: dict) -> str:
        aid = uuid.uuid4().hex[:16]
        self._x("INSERT INTO approvals(id, chat_id, tool, title, input, created) VALUES (?,?,?,?,?,?)",
                (aid, chat_id, tool, title, json.dumps(tool_input, ensure_ascii=False), time.time()))
        return aid

    def approval(self, approval_id: str) -> dict:
        rows = self._q("SELECT * FROM approvals WHERE id=?", (approval_id,))
        if not rows:
            raise StoreError("нет такого запроса подтверждения", 404)
        r = rows[0]
        return {"id": r["id"], "chat_id": r["chat_id"], "tool": r["tool"], "title": r["title"],
                "input": json.loads(r["input"]), "status": r["status"], "created": r["created"]}

    def decide(self, approval_id: str, status: str) -> None:
        self._x("UPDATE approvals SET status=?, decided=? WHERE id=? AND status='pending'",
                (status, time.time(), approval_id))

    def pending_approvals(self) -> list[dict]:
        rows = self._q("SELECT id FROM approvals WHERE status='pending' ORDER BY created")
        return [self.approval(r["id"]) for r in rows]

    # ── Прочее ─────────────────────────────────────────────────────────────

    def kv_get(self, k: str) -> str | None:
        rows = self._q("SELECT v FROM kv WHERE k=?", (k,))
        return rows[0]["v"] if rows else None

    def kv_set(self, k: str, v: str) -> None:
        self._x("INSERT INTO kv(k, v) VALUES (?,?) ON CONFLICT(k) DO UPDATE SET v=excluded.v", (k, v))
