"""MCP-сервер хаба: инструменты для диагностики нод + приём пробников.

Подключение в claude.ai: Настройки → Коннекторы → свой коннектор с адресом
`https://<хаб>/mcp/<NEXUS_MCP_SECRET>`. Секрет в пути — потому что
коннектор без OAuth не умеет слать свой заголовок; клиенты, которые умеют
(Claude Code CLI), могут звать `/mcp` с `Authorization: Bearer <секрет>`.
"""

from __future__ import annotations

import asyncio
import hmac
import json
import logging

from mcp.server.mcpserver import MCPServer
from mcp.server.transport_security import TransportSecuritySettings
from starlette.requests import Request
from starlette.responses import JSONResponse

from nexus_mcp import audit, config, diagnose, inventory, playbook, recipes, ssh
from nexus_mcp.inventory import InventoryError
from nexus_mcp.probes import HUB, ProbeError, registry

logger = logging.getLogger("nexus_mcp")

INSTRUCTIONS = """\
Хаб диагностики нод Nexus (VPN). Ноды — зарубежные VPS для клиентов на домашнем
интернете в РФ. Панель (brain) стоит на российском IP, и её путь к нодам режется
фильтром: TCP открывается, пакеты с данными пропадают. Поэтому нода бывает красной
в панели при живой ноде, и наоборот.

Как разбирать:
1. nodes_list(only_problems=True) — какие ноды красные/без heartbeat.
2. node_diagnose(node) — панель + SSH-обзор + доступность IP + сквозная проверка.
   Для домашних нод добавляй probes=[имена домашних пробников] (probes_list):
   дата-центр хаба видит РФ не так, как домашние провайдеры.
3. Уточнять: node_logs, node_run(recipe=...), probe_check.
4. Действия (node_action) — только после согласия человека, с confirm=true.
   Смена порта/транспорта/IP уезжает в подписки всех юзеров ноды — это предлагать,
   а не делать.

Находки упорядочены: crit → warn → info → ok; у каждой есть fix, а в next_steps —
приёмы починки из справочника (fix_playbook) с источником и степенью доверия:
ours (проверено у нас) > measured > repeated > anecdote. Авторы роликов противоречат
друг другу — у операторов разные ТСПУ; решает сквозная проверка с домашних пробников.
"""

mcp = MCPServer(name="nexus-nodes", instructions=INSTRUCTIONS, version="1.0.0")


def _err(e: Exception) -> dict:
    """Отказ — с причиной, а не «ошибка» (инвариант 26)."""
    return {"ok": False, "error": type(e).__name__, "detail": str(e)}


# ── Чтение ─────────────────────────────────────────────────────────────────

@mcp.tool()
async def nodes_list(only_problems: bool = False) -> dict:
    """Ноды: статус в панели, возраст heartbeat, версия агента, доступность из РФ.

    only_problems=True — только красные в панели или без свежего heartbeat.
    """
    try:
        nodes, warnings = await inventory.load_nodes()
    except InventoryError as e:
        return _err(e)
    rows = []
    for n in nodes:
        if only_problems and n.get("panel_online") and n.get("heartbeat_fresh"):
            continue
        rows.append({k: n.get(k) for k in (
            "name", "ip", "country", "active", "panel_online", "heartbeat_age_s",
            "agent_version", "rf_status", "ssh_host", "ssh_port", "source")})
    return {"ok": True, "count": len(rows), "nodes": rows, "warnings": warnings}


@mcp.tool()
async def node_diagnose(node: str, probes: list[str] | None = None, e2e: bool = True) -> dict:
    """Полный диагноз ноды: панель, SSH-обзор, доступность IP с каждой точки
    обзора, сквозная проверка протоколов.

    node — имя, IP или id ноды. probes — точки обзора: "hub" (сам хаб) и имена
    домашних пробников из probes_list. По умолчанию только hub.
    e2e=False — без сквозной проверки (быстрее).
    """
    try:
        n = await inventory.find_node(node)
    except InventoryError as e:
        return _err(e)
    report = await diagnose.diagnose(n, probes or [HUB], with_e2e=e2e)
    audit.record("node_diagnose", {"node": n["name"], "probes": probes, "e2e": e2e}, True,
                 report.get("summary", ""))
    return report


@mcp.tool()
async def fleet_check(only_problems: bool = True, probes: list[str] | None = None,
                      e2e: bool = False, limit: int = 30) -> dict:
    """Диагноз по многим нодам сразу, коротко: главная находка и что делать.

    По умолчанию — только проблемные ноды, без сквозной проверки.
    """
    try:
        nodes, warnings = await inventory.load_nodes()
    except InventoryError as e:
        return _err(e)
    targets = [n for n in nodes if n.get("active", True)]
    if only_problems:
        targets = [n for n in targets if not (n.get("panel_online") and n.get("heartbeat_fresh"))]
    targets = targets[:max(1, min(limit, 100))]
    sem = asyncio.Semaphore(4)

    async def one(n: dict) -> dict:
        async with sem:
            try:
                r = await diagnose.diagnose(n, probes or [HUB], with_e2e=e2e)
            except Exception as e:  # noqa: BLE001
                return {"node": n["name"], "summary": f"диагноз упал: {e}"}
            crit = [f["code"] for f in r["findings"] if f["level"] == diagnose.CRIT]
            return {"node": n["name"], "ip": n.get("ip"), "summary": r["summary"], "crit": crit}

    results = await asyncio.gather(*[one(n) for n in targets])
    audit.record("fleet_check", {"only_problems": only_problems, "probes": probes, "n": len(targets)}, True)
    return {"ok": True, "checked": len(results), "results": results, "warnings": warnings}


@mcp.tool()
async def node_logs(node: str, service: str = "vpn-cell", lines: int = 100, since_min: int = 60) -> dict:
    """Журнал сервиса на ноде: vpn-cell (агент), xray, hysteria-server."""
    return await node_run(node, "logs", service=service, lines=lines, since_min=since_min)


READ_RECIPES = ("overview", "logs", "listening", "firewall", "xray_test", "env", "capture", "brain_path")


@mcp.tool()
async def node_run(node: str, recipe: str, service: str = "vpn-cell", lines: int = 100,
                   since_min: int = 60, client_ip: str = "", seconds: int = 20) -> dict:
    """Выполнить на ноде готовый рецепт (только чтение):

    overview — сервисы, версия агента, адрес панели, путь нода→панель, heartbeat;
    logs — журнал service; listening — открытые порты; firewall — правила;
    xray_test — проверка конфига xray; env — .env без секретов;
    capture — видит ли нода пакеты от client_ip за seconds (пусто = не доходят);
    brain_path — подробно путь нода→панель.
    """
    try:
        n = await inventory.find_node(node)
        if recipe == "overview":
            script = recipes.overview()
        elif recipe == "logs":
            script = recipes.logs(service, lines, since_min)
        elif recipe == "listening":
            script = recipes.listening()
        elif recipe == "firewall":
            script = recipes.firewall()
        elif recipe == "xray_test":
            script = recipes.xray_test()
        elif recipe == "env":
            script = recipes.env_redacted()
        elif recipe == "capture":
            script = recipes.capture(client_ip, seconds)
        elif recipe == "brain_path":
            script = recipes.brain_path(config.settings.brain_url)
        else:
            return {"ok": False, "error": "unknown_recipe", "detail": f"есть: {', '.join(READ_RECIPES)}"}
    except (InventoryError, recipes.RecipeError) as e:
        return _err(e)
    timeout = 45 + (seconds if recipe == "capture" else 0)
    res = await ssh.run_script(n, script, timeout=timeout)
    audit.record("node_run", {"node": n["name"], "recipe": recipe}, res.ok, res.failure or "")
    out = res.as_dict()
    if recipe == "overview" and res.ok:
        out["parsed"] = recipes.parse_overview(res.stdout)
    return out


@mcp.tool()
async def probes_list() -> dict:
    """Точки обзора: hub (сам хаб) и домашние пробники — на связи ли, есть ли xray."""
    return {"ok": True, "probes": registry.list()}


@mcp.tool()
async def probe_check(probe: str, target: str, kind: str = "tls", port: int = 443,
                      sni: str = "", url: str = "") -> dict:
    """Одна проба с выбранной точки обзора.

    target — имя ноды или хост. kind: tcp | banner | tls | http.
    Для http target не нужен — передайте url.
    """
    host = target
    try:
        n = await inventory.find_node(target)
        host = n.get("ip") or n.get("ssh_host")
    except InventoryError:
        pass
    if kind == "http":
        args = {"url": url}
    elif kind in ("tcp", "banner", "tls"):
        args = {"host": host, "port": int(port)}
        if kind == "tls" and sni:
            args["sni"] = sni
    else:
        return {"ok": False, "error": "bad_kind", "detail": "kind: tcp | banner | tls | http"}
    try:
        res = await registry.run(probe, kind, args)
    except ProbeError as e:
        return _err(e)
    return {"probe": probe, "kind": kind, "target": host, **res}


@mcp.tool()
async def panel_reachability(node: str) -> dict:
    """Что думает сама панель: её вердикт «почему красная» (refused / filtered /
    path_blocked / bad_token / slow / ok) и видит ли она heartbeat."""
    try:
        n = await inventory.find_node(node)
        if not n.get("id"):
            return {"ok": False, "error": "not_in_panel", "detail": "ноды нет в панели"}
        return {"ok": True, **(await inventory.brain_get(f"/api/v1/servers/{n['id']}/reachability", timeout=40))}
    except Exception as e:  # noqa: BLE001
        return _err(e)


@mcp.tool()
async def check_from_russia(node: str) -> dict:
    """Проверка ноды с российских узлов check-host (запускает панель, ~30 с).
    Это дата-центры РФ: для домашних нод правду говорят домашние пробники."""
    try:
        n = await inventory.find_node(node)
        if not n.get("id"):
            return {"ok": False, "error": "not_in_panel", "detail": "ноды нет в панели"}
        return {"ok": True, **(await inventory.brain_post(f"/api/v1/admin/nodes/{n['id']}/rf-check", timeout=90))}
    except Exception as e:  # noqa: BLE001
        return _err(e)


@mcp.tool()
async def fix_playbook(symptom: str = "") -> dict:
    """Что делать при симптоме — справочник из нашего журнала и опыта владельцев
    VPN-сервисов (ролики 2026 года), со ссылками и степенью доверия.

    symptom — код находки из node_diagnose (payload_filtered, some_protocols_dead,
    old_agent, …). Пусто — весь справочник и общие правила.
    """
    return playbook.lookup(symptom)


@mcp.tool()
async def audit_tail(n: int = 30) -> dict:
    """Последние вызовы хаба — кто что делал с нодами."""
    return {"ok": True, "entries": audit.tail(max(1, min(n, 500)))}


# ── Действия ───────────────────────────────────────────────────────────────

ACTIONS = ("restart", "set_brain_url", "update_agent")


@mcp.tool()
async def node_action(node: str, action: str, confirm: bool = False, service: str = "vpn-cell",
                      brain_url: str = "") -> dict:
    """Изменить что-то на ноде. Только с согласия человека и confirm=true.

    restart — перезапустить service (vpn-cell | xray | hysteria-server);
    set_brain_url — прописать адрес панели в .env агента и перезапустить его;
    update_agent — обновить агент штатным cell-update.sh (и прописать адрес панели).
    brain_url по умолчанию — адрес панели из настроек хаба.
    """
    s = config.settings
    if not s.allow_actions:
        return {"ok": False, "error": "actions_disabled",
                "detail": "действия выключены на хабе (NEXUS_ALLOW_ACTIONS=1 чтобы включить)"}
    if not confirm:
        return {"ok": False, "error": "need_confirm",
                "detail": "действие меняет ноду: спросите человека и повторите с confirm=true"}
    try:
        n = await inventory.find_node(node)
        url = brain_url or s.brain_url
        if action == "restart":
            script, timeout = recipes.restart(service), 60
        elif action == "set_brain_url":
            if not url:
                return {"ok": False, "error": "no_brain_url", "detail": "адрес панели не задан"}
            script, timeout = recipes.set_brain_url(url), 60
        elif action == "update_agent":
            script, timeout = recipes.update_agent(s.repo_raw, s.repo_url, url or None), 900
        else:
            return {"ok": False, "error": "unknown_action", "detail": f"есть: {', '.join(ACTIONS)}"}
    except (InventoryError, recipes.RecipeError) as e:
        return _err(e)
    res = await ssh.run_script(n, script, timeout=timeout)
    out = res.as_dict()
    if action == "update_agent":
        # rc=0 без отметки конца — не успех: скрипт мог оборваться.
        done = recipes.UPDATE_DONE_MARK in res.stdout
        out["update_finished"] = done
        out["ok"] = res.ok and done
        if res.ok and not done:
            out["detail"] = "скрипт обновления не дошёл до конца — см. stdout"
    audit.record("node_action", {"node": n["name"], "action": action, "service": service},
                 out["ok"], res.failure or "")
    return out


# ── HTTP: пробники и здоровье ──────────────────────────────────────────────

@mcp.custom_route("/probe/poll", methods=["POST"])
async def probe_poll(request: Request) -> JSONResponse:
    name = (request.query_params.get("name") or "").strip()[:64]
    if not name:
        return JSONResponse({"detail": "нужен ?name=имя-пробника"}, status_code=400)
    try:
        body = await request.json()
    except (ValueError, json.JSONDecodeError):
        body = {}
    client = request.client.host if request.client else ""
    fwd = request.headers.get("x-forwarded-for", "").split(",")[0].strip()
    try:
        jobs = await registry.poll(name, (body or {}).get("info"), fwd or client)
    except ProbeError as e:
        return JSONResponse({"detail": str(e)}, status_code=400)
    return JSONResponse({"jobs": jobs})


@mcp.custom_route("/probe/result", methods=["POST"])
async def probe_result(request: Request) -> JSONResponse:
    try:
        body = await request.json()
    except (ValueError, json.JSONDecodeError):
        return JSONResponse({"detail": "тело не JSON"}, status_code=400)
    accepted = registry.result(str(body.get("name", "")), str(body.get("id", "")), body.get("result") or {})
    return JSONResponse({"accepted": accepted})


@mcp.custom_route("/healthz", methods=["GET"])
async def healthz(request: Request) -> JSONResponse:
    return JSONResponse({"ok": True, "service": "nexus-mcp"})


# ── Авторизация ────────────────────────────────────────────────────────────

def _eq(a: str, b: str) -> bool:
    return bool(a) and bool(b) and hmac.compare_digest(a.encode(), b.encode())


class AuthMiddleware:
    """/mcp/<секрет> или Bearer <секрет> — MCP; Bearer <токен пробника> — /probe/*.

    Всё остальное, кроме /healthz, — 404: хаб не должен выдавать, что он такое.
    """

    def __init__(self, app, secret: str, probe_tokens: list[str]):
        self.app = app
        self.secret = secret
        self.probe_tokens = probe_tokens

    def _bearer(self, scope) -> str:
        for k, v in scope.get("headers") or []:
            if k == b"authorization":
                val = v.decode("latin-1")
                if val.lower().startswith("bearer "):
                    return val[7:].strip()
        return ""

    async def __call__(self, scope, receive, send):
        if scope["type"] != "http":
            return await self.app(scope, receive, send)
        path = scope.get("path", "")
        if path == "/healthz":
            return await self.app(scope, receive, send)
        if path.startswith("/probe/"):
            tok = self._bearer(scope)
            if any(_eq(tok, t) for t in self.probe_tokens) or _eq(tok, self.secret):
                return await self.app(scope, receive, send)
            return await _deny(send, 401, "неверный токен пробника")
        if path == "/mcp" or path == "/mcp/":
            if _eq(self._bearer(scope), self.secret):
                return await self.app(scope, receive, send)
            return await _deny(send, 401, "нужен секрет")
        if path.startswith("/mcp/"):
            rest = path[len("/mcp/"):].strip("/")
            if _eq(rest, self.secret):
                scope = dict(scope, path="/mcp", raw_path=b"/mcp")
                return await self.app(scope, receive, send)
        return await _deny(send, 404, "not found")


async def _deny(send, code: int, detail: str) -> None:
    body = json.dumps({"detail": detail}, ensure_ascii=False).encode()
    await send({"type": "http.response.start", "status": code,
                "headers": [(b"content-type", b"application/json; charset=utf-8"),
                            (b"content-length", str(len(body)).encode())]})
    await send({"type": "http.response.body", "body": body})


def build_app():
    s = config.settings
    if len(s.secret) < 24:
        raise SystemExit("NEXUS_MCP_SECRET не задан или короче 24 символов: хаб держит ключи "
                         "ко всем нодам и без секрета не запускается")
    hosts = list(s.public_hosts)
    security = TransportSecuritySettings(
        enable_dns_rebinding_protection=bool(hosts),
        allowed_hosts=hosts + [f"{h}:*" for h in hosts] + ["127.0.0.1:*", "localhost:*"],
        allowed_origins=[f"https://{h}" for h in hosts],
    )
    app = mcp.streamable_http_app(streamable_http_path="/mcp", transport_security=security,
                                  host=s.host)
    return AuthMiddleware(app, s.secret, s.probe_tokens)


def main() -> None:
    import uvicorn

    logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(name)s: %(message)s")
    s = config.settings
    uvicorn.run(build_app(), host=s.host, port=s.port, proxy_headers=True,
                forwarded_allow_ips="127.0.0.1", log_level="info")


if __name__ == "__main__":
    main()
