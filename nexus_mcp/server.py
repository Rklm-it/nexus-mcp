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

from urllib.parse import urlparse

from nexus_mcp import audit, bsbord, config, diagnose, inventory, panels, playbook, recipes, ssh
from nexus_mcp import links as sublinks
from nexus_mcp import panel as panel_api
from nexus_mcp.inventory import InventoryError
from nexus_mcp.probes import HUB, ProbeError, registry

logger = logging.getLogger("nexus_mcp")

INSTRUCTIONS = """\
Хаб диагностики нод Nexus (VPN). Ноды — зарубежные VPS для клиентов на домашнем
интернете в РФ. Панель (brain) стоит на российском IP, и её путь к нодам режется
фильтром: TCP открывается, пакеты с данными пропадают. Поэтому нода бывает красной
в панели при живой ноде, и наоборот.

Панель: panel_health — проверка всего одной ручкой (ядро, контейнеры, боты, ноды,
мониторинг, платежи), с неё начинать общий осмотр. panel_findings — находки центра
состояния. Дальше panel_users / panel_user_diagnose (почему у юзера нет пинга),
panel_inbound_diagnose, panel_logs, panel_payments, panel_get для любой админской ручки.
Секреты в ответах панели замаскированы — так и задумано.
Панелей может быть несколько (panels_list): тогда у инструментов панели указывай
panel=<имя>, а ноды называются «панель/имя».

Как разбирать ноды:
1. nodes_list(only_problems=True) — какие ноды красные/без heartbeat.
2. node_diagnose(node) — панель + SSH-обзор + доступность IP + сквозная проверка.
   Для домашних нод добавляй probes=[имена домашних пробников] (probes_list):
   дата-центр хаба видит РФ не так, как домашние провайдеры.
3. Уточнять: node_logs, node_run(recipe=...), probe_check.
4. Действия (node_action) — только после согласия человека, с confirm=true.
   Смена порта/транспорта/IP уезжает в подписки всех юзеров ноды — это предлагать,
   а не делать.

IP ноды режется (payload_filtered / ip_unreachable) — первое средство панели:
Cloudflare-фронт («Включить Cloudflare», VLESS+WS через Cloudflare). Если он
включён, node_diagnose проверяет его адрес (cf_reachable / cf_blocked) и строку
«· CF» сквозной проверкой отдельно от IP. «Только через CF» советовать, лишь когда
«· CF» прошла с домашних пробников: Cloudflare в РФ местами тоже режут.

SIM-проверки (bschekbot, если задан ключ): хаб и пробники на проводном интернете,
а клиенты сидят и на мобильном — с белыми списками (БС) операторов. sim_probe —
доступность IP/домена/SNI с SIM каждого оператора в каждом округе, с БС и без;
sim_vless — поднимается ли туннель; sim_geo — из каких городов открывается.
ПЛАТНО: сначала вызов без confirm (бесплатный preview с ценой), цену — человеку,
запуск — с confirm=true и max_credits из preview. Единицы — sim_units.

Находки упорядочены: crit → warn → info → ok; у каждой есть fix, а в next_steps —
приёмы починки из справочника (fix_playbook) с источником и степенью доверия:
ours (проверено у нас) > measured > repeated > anecdote. Авторы роликов противоречат
друг другу — у операторов разные ТСПУ; решает сквозная проверка с домашних пробников.
"""

mcp = MCPServer(name="nexus-nodes", instructions=INSTRUCTIONS, version="1.0.0")


def _node_panel_url(n: dict) -> str:
    """Адрес панели, к которой относится нода: туда она шлёт heartbeat."""
    p = inventory.node_panel(n)
    return p["url"] if p else ""


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
            script = recipes.brain_path(_node_panel_url(n))
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
        return {"ok": True, "panel": n.get("panel"), **(await inventory.brain_get(
            f"/api/v1/servers/{n['id']}/reachability", panels.resolve(n["panel"]), timeout=40))}
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
        return {"ok": True, "panel": n.get("panel"), **(await inventory.brain_post(
            f"/api/v1/admin/nodes/{n['id']}/rf-check", panels.resolve(n["panel"]), timeout=90))}
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


# ── SIM-проверки: операторы и города РФ (bschekbot) ────────────────────────

def _bs_err(e: Exception) -> dict:
    if isinstance(e, bsbord.BsError):
        return e.as_dict()
    return _err(e)


async def _node_targets(node: str) -> dict:
    """Что проверять у ноды: IP:порты клиентов, адрес CF-фронта, SNI и ссылки
    тестовой подписки — то же, что смотрит node_diagnose."""
    n = await inventory.find_node(node)
    node_links: list[str] = []
    cf_links: list[str] = []
    cf = await diagnose.cf_front(n)
    cft = diagnose.cf_target(cf)
    if config.settings.test_sub_url:
        try:
            all_links = await sublinks.fetch_links()
            node_links = await asyncio.to_thread(sublinks.links_for_node, all_links, n)
            if cft:
                cf_links = [u for u in all_links if (urlparse(u).hostname or "") == cft[0]]
        except sublinks.LinksError:
            pass
    ip = n.get("ip") or n.get("ssh_host")
    targets = [f"{ip}:{p}" for p in diagnose.client_ports(n, node_links)]
    if cft:
        targets.append(f"{cft[0]}:{cft[1]}")
    snis = []
    for u in node_links + cf_links:
        sni = sublinks.describe(u).get("sni")
        if sni and sni not in snis:
            snis.append(sni)
    if cft and cft[0] not in snis:
        snis.append(cft[0])
    return {"node": n["name"], "targets": targets[:10], "sni_hosts": snis[:10],
            "links": (node_links + cf_links)[:20]}


@mcp.tool()
async def sim_units(dpi: str = "any", operator: str = "", region: str = "") -> dict:
    """Единицы SIM-проверки bschekbot: оператор × федеральный округ × белый
    список (БС). Бесплатно. dpi: on — только с включённым БС, off — без БС,
    any — все. operator/region — фильтр через запятую (mts,beeline / цфо,пфо).
    Ключ единицы op_key ("mts|цфо|on") — для units у sim_probe/sim_vless;
    селекторы: "mts" (все округа), "*|цфо|on" (все операторы ЦФО с БС)."""
    try:
        return await bsbord.units(dpi, operator, region)
    except Exception as e:  # noqa: BLE001 — причина уходит в ответ
        return _bs_err(e)


@mcp.tool()
async def sim_account() -> dict:
    """Баланс bschekbot, тариф и дневной потолок трат хаба (сколько уже
    потрачено сегодня). Бесплатно."""
    try:
        return await bsbord.account()
    except Exception as e:  # noqa: BLE001
        return _bs_err(e)


@mcp.tool()
async def sim_probe(targets: list[str] | None = None, node: str = "", units: list[str] | None = None,
                    dpi: str = "on", probes: list[str] | None = None, sni_hosts: list[str] | None = None,
                    max_credits: int = 0, confirm: bool = False) -> dict:
    """Доступность цели с SIM-карт мобильных операторов РФ (ICMP / TCP / TLS-SNI),
    в т.ч. с ВКЛЮЧЁННЫМИ БЕЛЫМИ СПИСКАМИ — то, чего не видят хаб и домашние
    пробники. ПЛАТНО (1 кредит = 1 копейка).

    Два шага: без confirm — бесплатный preview (цена, какие единицы поедут);
    покажите цену человеку и с его согласия повторите тем же вызовом с
    confirm=true и max_credits = cost_credits из preview.

    targets — до 10 целей (IP, IP:порт, домен, URL). node — взять цели ноды
    (IP:порты клиентов, адрес CF-фронта) и её SNI сами. units — op_key или
    селекторы из sim_units; пусто — все доступные единицы. dpi: on (деф.) —
    только единицы с БС, off — без БС, any — обе группы. probes: icmp, tcp, sni
    (деф. icmp+tcp, +sni при заданных sni_hosts). reachable = icmp или tcp прошли;
    http-ответ может быть заглушкой оператора — смотрите status/location/body_head.
    """
    try:
        t, snis = list(targets or []), list(sni_hosts or [])
        if node:
            nt = await _node_targets(node)
            t = t or nt["targets"]
            snis = snis or nt["sni_hosts"]
        pr = list(probes or (["icmp", "tcp"] + (["sni"] if snis else [])))
        res = await bsbord.probe(t, list(units or []), dpi, pr, snis, int(max_credits or 0), bool(confirm))
    except Exception as e:  # noqa: BLE001
        res = _bs_err(e)
    if confirm:
        audit.record("sim_probe", {"targets": targets, "node": node, "units": units, "dpi": dpi},
                     bool(res.get("ok")), f"{res.get('cost_rub')} ₽" if res.get("ok") else str(res.get("detail", ""))[:200])
    return res


@mcp.tool()
async def sim_vless(node: str = "", links: list[str] | None = None, units: list[str] | None = None,
                    dpi: str = "on", core: str = "", max_credits: int = 0, confirm: bool = False,
                    wait: bool = True) -> dict:
    """Сквозной тест протокола (VLESS/Reality, VMess, Trojan, SS, Hysteria2) с
    SIM-карт операторов РФ: поднимается ли туннель и где режет DPI/ТСПУ.
    ПЛАТНО: n_servers × n_units проверок. Preview у API нет — без confirm хаб
    показывает, что поедет; с confirm=true и max_credits запускает, а если
    цена при постановке выше потолка — сразу отменяет (бесплатно).

    node — ссылки ноды из тестовой подписки; links — свои ссылки (до 20).
    ⚠ Ссылки уходят сервису целиком — берите тестового юзера, не клиентов.
    units/dpi — как у sim_probe. core: "" авто, stable, prerelease (xhttp,
    VLESS Encryption). wait=false — вернуть test_id, результат — sim_result.
    """
    try:
        lk = list(links or [])
        if node and not lk:
            lk = (await _node_targets(node))["links"]
        res = await bsbord.vless(lk, list(units or []), dpi, core, int(max_credits or 0), bool(confirm), bool(wait))
    except Exception as e:  # noqa: BLE001
        res = _bs_err(e)
    if confirm:
        audit.record("sim_vless", {"node": node, "n_links": len(links or []), "units": units, "dpi": dpi},
                     bool(res.get("ok")), str(res.get("cost_rub") or res.get("detail", ""))[:200])
    return res


@mcp.tool()
async def sim_geo(targets: list[str] | None = None, node: str = "", network: str = "mob",
                  district: str = "", region: str = "", isp: str = "", cities: list | None = None,
                  city_limit: int = 0, probe_mode: str = "tls", heavy: bool = False, core: str = "",
                  max_credits: int = 0, confirm: bool = False, wait: bool = True) -> dict:
    """FULL GEO: из каких ГОРОДОВ РФ открывается цель — домашние (network=res)
    или мобильные (mob) провайдеры в самих городах. ПЛАТНО по трафику.

    Без confirm — бесплатный preview: число городов, время и reserve_credits
    (ПОТОЛОК, списывается факт). С confirm=true и max_credits = reserve_credits —
    запуск. targets — домены/URL/IP и/или ОДНА ссылка vless:// / hysteria2://;
    node — взять первую ссылку ноды из тестовой подписки. district: ЦФО…ДФО
    (8 округов), region/isp/cities — токены из каталога сервиса; isp="__ALL__" —
    каждый провайдер города. city_limit — потолок проб. heavy — детект троттлинга
    (только домены). Вердикты: blocked — подтверждённая блокировка, throttled —
    режут скорость; exit_bad/no_ru_node — шум сервиса, не результат.
    """
    try:
        t = list(targets or [])
        if node and not any("://" in x and x.split("://")[0] in ("vless", "hysteria2") for x in t):
            nl = [u for u in (await _node_targets(node))["links"] if u.startswith(("vless://", "hysteria2://"))]
            if nl:
                t.append(nl[0])
        res = await bsbord.geo(t, network, district, region, isp, list(cities or []), int(city_limit or 0),
                               probe_mode, bool(heavy), core, int(max_credits or 0), bool(confirm), bool(wait))
    except Exception as e:  # noqa: BLE001
        res = _bs_err(e)
    if confirm:
        audit.record("sim_geo", {"targets_n": len(targets or []), "node": node, "network": network,
                                 "district": district, "isp": isp}, bool(res.get("ok")),
                     str(res.get("charged_rub") or res.get("reserve_rub") or res.get("detail", ""))[:200])
    return res


@mcp.tool()
async def sim_result(kind: str, id: str) -> dict:
    """Статус и результат долгой SIM-проверки: kind = vless | geo | scan, id —
    test_id / run_id / scan_id. Бесплатно, можно звать сколько угодно."""
    try:
        return await bsbord.result(kind, str(id))
    except Exception as e:  # noqa: BLE001
        return _bs_err(e)


@mcp.tool()
async def sim_cancel(kind: str, id: str) -> dict:
    """Остановить долгую SIM-проверку (vless | geo | scan). Бесплатно:
    несделанная часть не оплачивается, готовые вердикты остаются."""
    try:
        return await bsbord.cancel(kind, str(id))
    except Exception as e:  # noqa: BLE001
        return _bs_err(e)


# ── Панель ─────────────────────────────────────────────────────────────────

async def _panel(call, *args, **kwargs) -> dict:
    try:
        data = await call(*args, **kwargs)
    except (panel_api.PanelError, InventoryError) as e:
        return _err(e)
    return {"ok": True, "data": data}


@mcp.tool()
async def panels_list() -> dict:
    """Панели, к которым подключён хаб (без токенов). Имя — параметр panel у
    инструментов панели; ноды при нескольких панелях называются «панель/имя»."""
    try:
        return {"ok": True, "panels": [panels.public_view(p) for p in panels.all_panels()]}
    except panels.PanelConfigError as e:
        return _err(e)


@mcp.tool()
async def panel_health(fresh: bool = False, panel: str = "") -> dict:
    """Проверка всей панели одной ручкой: ядро, контейнеры, боты, ноды,
    мониторинг, платежи — то же, что видит приложение администратора.
    fresh=True — мимо 20-секундного кэша.
    panel — имя панели (panels_list); при одной панели можно не указывать.
    """
    return await _panel(panel_api.get, "/api/v1/admin/app/health", {"fresh": fresh or None},
                        panel_name=panel, compact=panel_api.compact_health)


@mcp.tool()
async def panel_overview(panel: str = "") -> dict:
    """Цифры главного экрана: юзеры (всего/активные/заблокированные), онлайн,
    выручка, версия панели.
    panel — имя панели (panels_list); при одной панели можно не указывать.
    """
    return await _panel(panel_api.get, "/api/v1/admin/app/overview", panel_name=panel)


@mcp.tool()
async def panel_findings(fresh: bool = False, panel: str = "") -> dict:
    """Находки центра состояния (что панель сама считает проблемой) с
    объяснениями. Требует фичу monitoring_pro в лицензии.
    panel — имя панели (panels_list); при одной панели можно не указывать.
    """
    return await _panel(panel_api.get, "/api/v1/admin/monitoring/overview", {"fresh": fresh or None}, panel_name=panel)


@mcp.tool()
async def panel_regions(hours: int = 6, panel: str = "") -> dict:
    """Регионы и операторы клиентов: у кого из провайдеров проблемы.
    panel — имя панели (panels_list); при одной панели можно не указывать.
    """
    return await _panel(panel_api.get, "/api/v1/admin/monitoring/regions", {"hours": hours}, panel_name=panel)


@mcp.tool()
async def panel_versions(panel: str = "") -> dict:
    """Версии панели и агентов на всех нодах — кто отстал.
    panel — имя панели (panels_list); при одной панели можно не указывать.
    """
    return await _panel(panel_api.get, "/api/v1/admin/nodes/versions", panel_name=panel)


@mcp.tool()
async def panel_users(search: str = "", status: str = "", limit: int = 20, panel: str = "") -> dict:
    """Найти юзеров: search — ник, имя, telegram_id или часть UUID;
    status — active | inactive | paid_inactive.
    panel — имя панели (panels_list); при одной панели можно не указывать.
    """
    return await _panel(panel_api.get, "/api/v1/admin/users",
                        {"search": search, "status": status, "limit": max(1, min(limit, 100))}, panel_name=panel)


@mcp.tool()
async def panel_user_diagnose(user_id: str, panel: str = "") -> dict:
    """Почему у юзера нет пинга: панель проверяет каждую ссылку его подписки
    и объясняет. user_id — UUID из panel_users.
    panel — имя панели (panels_list); при одной панели можно не указывать.
    """
    return await _panel(panel_api.get, f"/api/v1/admin/users/{user_id}/diagnose-links", timeout=90, panel_name=panel)


@mcp.tool()
async def panel_inbound_diagnose(inbound_id: str, panel: str = "") -> dict:
    """Разбор инбаунда: конфиг в панели против того, что реально на ноде.
    panel — имя панели (panels_list); при одной панели можно не указывать.
    """
    return await _panel(panel_api.get, f"/api/v1/admin/inbounds/{inbound_id}/diagnose", timeout=90, panel_name=panel)


@mcp.tool()
async def panel_logs(source: str = "brain", service: str = "", lines: int = 150, panel: str = "") -> dict:
    """Логи через панель. source="brain" — сервисы панели (service: brain | bot |
    admin-bot | dealer-bot | support-bot | postgres | redis); source=<имя ноды> —
    логи ноды через ЕЁ панель (service: vpn-cell | xray | hysteria-server; идёт через панель,
    поэтому для красной ноды используйте node_logs по SSH).
    panel — имя панели (panels_list); при одной панели можно не указывать.
    """
    lines = max(10, min(lines, 500))
    if source == "brain":
        return await _panel(panel_api.get, "/api/v1/admin/logs/brain",
                            {"service": service or "brain", "lines": lines}, panel_name=panel)
    try:
        n = await inventory.find_node(source)
    except InventoryError as e:
        return _err(e)
    if not n.get("id"):
        return {"ok": False, "error": "not_in_panel", "detail": "ноды нет в панели — node_logs по SSH"}
    return await _panel(panel_api.get, f"/api/v1/admin/logs/node/{n['id']}",
                        {"service": service or "vpn-cell", "lines": lines}, timeout=60,
                        panel_name=n.get("panel") or "")


@mcp.tool()
async def panel_payments(limit: int = 25, status: str = "", panel: str = "") -> dict:
    """Последние платежи (status — фильтр, например pending | paid | failed).
    panel — имя панели (panels_list); при одной панели можно не указывать.
    """
    return await _panel(panel_api.get, "/api/v1/admin/payments",
                        {"limit": max(1, min(limit, 100)), "status": status}, panel_name=panel)


@mcp.tool()
async def panel_get(path: str, params: dict | None = None, panel: str = "") -> dict:
    """Любая админская GET-ручка панели, когда нет готового инструмента.

    path — например "/api/v1/admin/dashboard", "/api/v1/servers/<id>",
    "/api/v1/admin/expiring", "/api/v1/admin/users/<id>/connection-log".
    Разрешены /api/v1/admin/*, /api/v1/servers*, /api/v1/inbounds*,
    /api/v1/outbounds*, /api/v1/users*, /api/v1/traffic*, /health.
    panel — имя панели (panels_list); при одной панели можно не указывать.
    """
    return await _panel(panel_api.get, path, params or {}, timeout=60, panel_name=panel)


@mcp.tool()
async def panel_action(path: str, confirm: bool = False, params: dict | None = None, panel: str = "") -> dict:
    """Действие в панели из короткого списка (проверить/перезапустить/обновить
    ноду, прогон центра состояния, пересинхронизация). Только с согласия
    человека: NEXUS_ALLOW_ACTIONS=1 на хабе и confirm=true.
    panel — имя панели (panels_list); при одной панели можно не указывать.
    """
    if not config.settings.allow_actions:
        return {"ok": False, "error": "actions_disabled",
                "detail": "действия выключены на хабе (NEXUS_ALLOW_ACTIONS=1 чтобы включить)"}
    try:
        panel_api.check_action_path(path)
    except panel_api.PanelError as e:
        return _err(e)
    if not confirm:
        return {"ok": False, "error": "need_confirm",
                "detail": "действие меняет панель или ноду: спросите человека и повторите с confirm=true"}
    res = await _panel(panel_api.post_action, path, params or {}, panel_name=panel)
    audit.record("panel_action", {"path": path, "params": params, "panel": panel}, res.get("ok", False),
                 res.get("detail", ""), panel_name=panel)
    return res


# ── Действия ───────────────────────────────────────────────────────────────

ACTIONS = ("restart", "set_brain_url", "update_agent")


@mcp.tool()
async def node_action(node: str, action: str, confirm: bool = False, service: str = "vpn-cell",
                      brain_url: str = "") -> dict:
    """Изменить что-то на ноде. Только с согласия человека и confirm=true.

    restart — перезапустить service (vpn-cell | xray | hysteria-server);
    set_brain_url — прописать адрес панели в .env агента и перезапустить его;
    update_agent — обновить агент скриптом панели <панель>/install/cell-update.sh
    (он же прописывает адрес панели в .env агента).
    brain_url по умолчанию — адрес панели, к которой относится нода.
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
        url = brain_url or _node_panel_url(n)
        if action == "restart":
            script, timeout = recipes.restart(service), 60
        elif action in ("set_brain_url", "update_agent") and not url:
            return {"ok": False, "error": "no_brain_url", "detail": "адрес панели не задан"}
        elif action == "set_brain_url":
            script, timeout = recipes.set_brain_url(url), 60
        elif action == "update_agent":
            script, timeout = recipes.update_agent(url), 900
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
