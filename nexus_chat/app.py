"""HTTP для приложения: /chat/api/* под Bearer NEXUS_CHAT_TOKEN.

Caddy хаба отдаёт сюда /chat/* как есть (с префиксом). Ответ Claude идёт
long-poll'ом: приложение спрашивает «события после N» и держит запрос до 25
секунд. Это переживает мобильную сеть лучше открытого потока: оборвалось —
переспросило с тем же N и ничего не потеряло.
"""

from __future__ import annotations

import asyncio
import contextlib
import hmac
import json
import logging

from starlette.applications import Starlette
from starlette.requests import Request
from starlette.responses import JSONResponse
from starlette.routing import Route

from nexus_chat import config
from nexus_chat.runner import Runner
from nexus_chat.store import Store, StoreError

logger = logging.getLogger("nexus_chat")

API_VERSION = 1


def _eq(a: str, b: str) -> bool:
    return bool(a) and bool(b) and hmac.compare_digest(a.encode(), b.encode())


def _err(status: int, detail: str) -> JSONResponse:
    return JSONResponse({"ok": False, "detail": detail}, status_code=status)


async def _body(request: Request) -> dict:
    try:
        data = await request.json()
    except (ValueError, json.JSONDecodeError):
        return {}
    return data if isinstance(data, dict) else {}


def build_app(runner: Runner | None = None, *, start_background: bool = True) -> Starlette:
    s = config.settings
    if len(s.token) < 32:
        raise SystemExit("NEXUS_CHAT_TOKEN не задан или короче 32 символов: чат открывает всё, "
                         "что умеет хаб, и без токена не запускается")
    if runner is None:
        s.work_dir.mkdir(parents=True, exist_ok=True)
        runner = Runner(Store(s.db_path), s)
    store = runner.store

    def guarded(fn):
        async def handler(request: Request):
            auth = request.headers.get("authorization", "")
            tok = auth[7:].strip() if auth.lower().startswith("bearer ") else ""
            if not _eq(tok, s.token):
                return _err(401, "неверный токен чата")
            try:
                return await fn(request)
            except StoreError as e:
                return _err(e.status, e.message)
        return handler

    async def state(request: Request):
        return JSONResponse({
            "ok": True, "api": API_VERSION,
            "logged_in": s.logged_in,
            "model": s.model or "", "effort": s.effort or "",
            "audit_at": s.audit_at, "tz": s.tz,
            "busy": runner.busy(),
            "pending_approvals": store.pending_approvals(),
            "last_seq": store.last_seq(),
        })

    async def chats(request: Request):
        if request.method == "POST":
            body = await _body(request)
            return JSONResponse({"ok": True, "chat": store.create_chat(str(body.get("title") or ""))})
        items = store.list_chats()
        for c in items:
            lv = runner.live(c["id"])
            c["running"] = lv.running
        return JSONResponse({"ok": True, "chats": items})

    async def chat(request: Request):
        cid = request.path_params["cid"]
        if request.method == "DELETE":
            if runner.live(cid).running:
                raise StoreError("Claude ещё отвечает — сначала «Стоп»", 409)
            store.delete_chat(cid)
            return JSONResponse({"ok": True})
        if request.method == "PATCH":
            body = await _body(request)
            return JSONResponse({"ok": True, "chat": store.rename_chat(cid, str(body.get("title") or ""))})
        return JSONResponse({"ok": True, "chat": store.get_chat(cid)})

    async def events(request: Request):
        cid = request.path_params["cid"]
        store.get_chat(cid)
        q = request.query_params
        try:
            after = int(q.get("after") or 0)
            version = int(q.get("v") or -1)
            wait = min(max(float(q.get("wait") or 0), 0.0), 25.0)
        except ValueError:
            raise StoreError("after, v и wait — числа") from None
        if wait:
            await runner.wait(cid, after, version, wait)
        evs = store.events(cid, after)
        return JSONResponse({"ok": True, "events": evs,
                             "last_seq": evs[-1]["seq"] if evs else after,
                             "live": runner.live(cid).as_dict()})

    async def send(request: Request):
        cid = request.path_params["cid"]
        body = await _body(request)
        await runner.send(cid, str(body.get("text") or ""))
        return JSONResponse({"ok": True}, status_code=202)

    async def stop(request: Request):
        await runner.stop(request.path_params["cid"])
        return JSONResponse({"ok": True})

    async def approve(request: Request):
        body = await _body(request)
        if not isinstance(body.get("allow"), bool):
            raise StoreError("нужно allow: true | false")
        a = await runner.approve(request.path_params["aid"], body["allow"])
        return JSONResponse({"ok": True, "approval": a})

    async def inbox(request: Request):
        try:
            after = int(request.query_params.get("after") or 0)
        except ValueError:
            raise StoreError("after — число") from None
        top = store.last_seq()  # до выборки: всё, что позже, попадёт в следующий раз
        items = store.inbox(after, limit=50)
        # Курсор идёт и мимо событий, о которых не уведомляют, иначе телефон
        # перебирал бы их на каждой проверке.
        last = items[-1]["seq"] if len(items) >= 50 else max(top, items[-1]["seq"] if items else 0, after)
        return JSONResponse({"ok": True, "items": items, "last_seq": last,
                             "pending_approvals": store.pending_approvals()})

    async def audit(request: Request):
        return JSONResponse({"ok": True, "chat": await runner.run_audit("по кнопке")}, status_code=202)

    async def healthz(request: Request):
        return JSONResponse({"ok": True, "service": "nexus-chat", "logged_in": s.logged_in})

    @contextlib.asynccontextmanager
    async def lifespan(app):
        task = asyncio.create_task(runner.audit_loop()) if start_background else None
        yield
        if task:
            task.cancel()

    routes = [
        Route("/chat/healthz", healthz, methods=["GET"]),
        Route("/chat/api/state", guarded(state), methods=["GET"]),
        Route("/chat/api/chats", guarded(chats), methods=["GET", "POST"]),
        Route("/chat/api/chats/{cid}", guarded(chat), methods=["GET", "PATCH", "DELETE"]),
        Route("/chat/api/chats/{cid}/events", guarded(events), methods=["GET"]),
        Route("/chat/api/chats/{cid}/send", guarded(send), methods=["POST"]),
        Route("/chat/api/chats/{cid}/stop", guarded(stop), methods=["POST"]),
        Route("/chat/api/approvals/{aid}", guarded(approve), methods=["POST"]),
        Route("/chat/api/inbox", guarded(inbox), methods=["GET"]),
        Route("/chat/api/audit", guarded(audit), methods=["POST"]),
    ]
    app = Starlette(routes=routes, lifespan=lifespan)
    app.state.runner = runner
    return app


def main() -> None:
    import uvicorn

    logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(name)s: %(message)s")
    s = config.settings
    uvicorn.run(build_app(), host=s.host, port=s.port, proxy_headers=True,
                forwarded_allow_ips="127.0.0.1", log_level="info")


if __name__ == "__main__":
    main()
