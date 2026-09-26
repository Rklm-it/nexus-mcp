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
import time

from starlette.applications import Starlette
from starlette.requests import Request
from starlette.responses import JSONResponse
from starlette.routing import Route

from nexus_chat import config, devices, usage
from nexus_chat.runner import Runner, panel_names
from nexus_chat.store import Store, StoreError

logger = logging.getLogger("nexus_chat")

API_VERSION = 1

# Транспорт к nexus-mcp (127.0.0.1). Тесты подставляют ASGI самого хаба —
# проверяется связка целиком, а не заглушка ответа.
_hub_transport = None


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

    sim_cache: dict = {"at": 0.0, "data": None}

    async def sim_state() -> dict:
        """Баланс bschekbot для экрана — раз в минуту, не на каждый опрос."""
        from nexus_mcp import bsbord

        if not bsbord.enabled():
            return {"enabled": False}
        now = time.monotonic()
        if sim_cache["data"] is None or now - sim_cache["at"] > 60:
            try:
                acc = await bsbord.account()
                sim_cache["data"] = {"enabled": True, "balance_rub": acc.get("balance_rub"),
                                     "spent_today_rub": acc.get("spent_today_rub"),
                                     "daily_cap_rub": acc.get("daily_cap_rub")}
            except Exception as e:  # noqa: BLE001 — причина на экран
                sim_cache["data"] = {"enabled": True, "error": str(e)[:200], **bsbord.budget()}
            sim_cache["at"] = now
        return sim_cache["data"]

    async def state(request: Request):
        return JSONResponse({
            "sim": await sim_state(),
            "panels": panel_names(),
            "ok": True, "api": API_VERSION,
            "logged_in": s.logged_in,
            "model": s.model or "", "effort": s.effort or "",
            "audit_at": s.audit_at, "tz": s.tz,
            "busy": runner.busy(),
            "pending_approvals": store.pending_approvals(),
            "last_seq": store.last_seq(),
            "usage": _usage_short(),
        })

    def _usage_short() -> dict:
        """Коротко для шапки приложения: токены за сегодня / 7 дней / месяц."""
        try:
            sm = usage.summary(store, s.tz)
        except Exception as e:  # noqa: BLE001 — учёт не повод ронять state
            return {"error": str(e)[:200]}
        out = {k: {"tokens": v["tokens"], "answers": v["answers"], "cost_usd": v["cost_usd"]}
               for k, v in sm["periods"].items()}
        out["limits"] = [{"title": x["title"], "utilization": x.get("utilization"),
                          "resets_at": x.get("resets_at")} for x in sm["limits"]]
        return out

    async def usage_full(request: Request):
        return JSONResponse({"ok": True, **usage.summary(store, s.tz)})

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
        await runner.send(cid, str(body.get("text") or ""), panel=str(body.get("panel") or ""))
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

    async def panels(request: Request):
        return JSONResponse({"ok": True, "panels": devices.listing()})

    async def panel_enroll(request: Request):
        body = await _body(request)
        return JSONResponse(await devices.enroll(request.path_params["name"],
                                                 str(body.get("public_key") or ""),
                                                 str(body.get("label") or "")))

    # ── Проверка подписки с пробников (домашний роутер) ──
    # Реестр пробников живёт в процессе nexus-mcp: ходим к нему по 127.0.0.1
    # с секретом MCP. Приложение секрета не знает — только токен чата.

    async def _hub(method: str, path: str, **kw) -> JSONResponse:
        import httpx

        try:
            async with httpx.AsyncClient(timeout=20, transport=_hub_transport) as c:
                r = await c.request(method, s.hub_url + path, **kw,
                                    headers={"Authorization": f"Bearer {s.mcp_secret}"})
        except httpx.HTTPError as e:
            return _err(502, f"хаб (nexus-mcp) не отвечает на 127.0.0.1: {type(e).__name__} — "
                             "systemctl status nexus-mcp")
        try:
            data = r.json()
        except ValueError:
            return _err(502, f"хаб ответил {r.status_code} не JSON: {r.text[:120]}")
        if r.status_code == 404 and isinstance(data, dict) and data.get("detail") == "not found":
            return _err(404, "хаб старый: нет /hub/* — обновите хаб установщиком nexus-mcp")
        return JSONResponse(data, status_code=r.status_code)

    async def probes(request: Request):
        return await _hub("GET", "/hub/probes")

    async def probe_sweep(request: Request):
        if request.method == "POST":
            return await _hub("POST", "/hub/sweep", json=await _body(request))
        return await _hub("GET", "/hub/sweep", params={"probe": request.query_params.get("probe") or "hub"})

    async def probe_setup(request: Request):
        """Команда установки пробника на роутер OpenWrt — готовая к копированию."""
        if not s.probe_token:
            return _err(409, "на хабе нет токена пробников (NEXUS_PROBE_TOKENS в /etc/nexus-mcp.env)")
        hub = str(request.base_url).rstrip("/")
        name = (request.query_params.get("name") or "роутер-дом").strip()[:40]
        name = "".join(c for c in name if c.isalnum() or c in "-_") or "router"
        xray = "tmp" if request.query_params.get("xray", "1") != "0" else "no"
        cmd = (f"wget -qO- {s.probe_src}/probe/openwrt/install.sh | sh -s -- "
               f"--hub {hub} --token {s.probe_token} --name {name} --xray {xray} --src {s.probe_src}")
        return JSONResponse({"ok": True, "hub": hub, "name": name, "command": cmd,
                             "remove": f"wget -qO- {s.probe_src}/probe/openwrt/install.sh | sh -s -- --remove"})

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
        Route("/chat/api/usage", guarded(usage_full), methods=["GET"]),
        Route("/chat/api/audit", guarded(audit), methods=["POST"]),
        Route("/chat/api/panels", guarded(panels), methods=["GET"]),
        Route("/chat/api/panels/{name}/enroll", guarded(panel_enroll), methods=["POST"]),
        Route("/chat/api/probes", guarded(probes), methods=["GET"]),
        Route("/chat/api/probes/sweep", guarded(probe_sweep), methods=["GET", "POST"]),
        Route("/chat/api/probes/setup", guarded(probe_setup), methods=["GET"]),
    ]
    app = Starlette(routes=routes, lifespan=lifespan)
    app.state.runner = runner
    return app


def main() -> None:
    import uvicorn

    logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(name)s: %(message)s")
    s = config.settings
    # Приложение держит long-poll до 25 с и тут же открывает следующий: без
    # потолка остановка ждала бы их вечно, и `systemctl restart` висел до
    # SIGKILL через 90 с. Оборванный опрос приложение просто повторит.
    uvicorn.run(build_app(), host=s.host, port=s.port, proxy_headers=True,
                forwarded_allow_ips="127.0.0.1", log_level="info", timeout_graceful_shutdown=3)


if __name__ == "__main__":
    main()
