"""Диагноз ноды: от «почему красная в панели» до «какой протокол жив дома».

Порядок проверки — сверху вниз, как в разборе 22.09.2026:
  1. что думает панель (online, heartbeat, версия агента);
  2. что на самой ноде (SSH-обзор: сервисы, адрес панели, путь нода→панель);
  3. доступен ли IP с каждой точки обзора (TCP → данные → TLS);
  4. работает ли каждый протокол на самом деле (сквозная проверка xray).

Каждая находка — код, текст и что делать. Коды стабильны: по ним удобно
сравнивать прогоны и писать тесты. Текст — для человека.
"""

from __future__ import annotations

import asyncio
from urllib.parse import urlparse

from nexus_mcp import config, inventory, links, playbook, recipes, ssh
from nexus_mcp.probes import HUB, registry

CRIT, WARN, INFO, OK = "crit", "warn", "info", "ok"

# Транспорты поверх UDP: TCP-пробы к ним ничего не говорят.
UDP_SCHEMES = {"hysteria2", "hy2", "tuic"}


def finding(level: str, code: str, text: str, fix: str = "") -> dict:
    d = {"level": level, "code": code, "text": text}
    if fix:
        d["fix"] = fix
    return d


# ── 1–2. Панель и нода ─────────────────────────────────────────────────────

def panel_findings(node: dict) -> list[dict]:
    out = []
    if node.get("source") == "file":
        return [finding(INFO, "not_in_panel", "Ноды нет в панели — статус панели не проверяется.")]
    age = node.get("heartbeat_age_s")
    if node.get("panel_online"):
        out.append(finding(OK, "panel_green", "В панели нода зелёная."))
    else:
        out.append(finding(WARN, "panel_red", "В панели нода красная."))
    if age is None:
        out.append(finding(WARN, "never_heartbeat",
                           "Нода ни разу не приходила к панели сама (heartbeat): панель видит её "
                           "только своим звонком, а он режется фильтром."))
    elif not node.get("heartbeat_fresh"):
        out.append(finding(WARN, "stale_heartbeat",
                           f"Последний heartbeat {int(age // 60)} мин назад — нода перестала "
                           "приходить к панели."))
    return out


def node_findings(ov: dict, brain_url: str) -> list[dict]:
    """Разбор SSH-обзора ноды (recipes.overview)."""
    out = []
    svc = lambda s: ov.get(f"svc_{s}", "")  # noqa: E731
    if svc("vpn-cell") != "active":
        out.append(finding(CRIT, "agent_down", f"Агент vpn-cell: {svc('vpn-cell') or 'нет'}.",
                           "node_logs(service='vpn-cell'), затем node_action(action='restart', "
                           "service='vpn-cell')."))
    if svc("xray") != "active":
        out.append(finding(CRIT, "xray_down", f"xray: {svc('xray') or 'нет'} — клиенты не подключатся.",
                           "node_run(recipe='xray_test') и node_logs(service='xray'); откат на "
                           "config.json.good, если конфиг битый (инвариант 9)."))
    if svc("hysteria-server") not in ("active", ""):
        out.append(finding(INFO, "hy2_not_active", f"hysteria-server: {svc('hysteria-server')} "
                           "(на CDN-нодах его нет — это нормально)."))
    if ov.get("has_uplink") == "no":
        out.append(finding(CRIT, "old_agent",
                           f"Агент старый (версия {ov.get('agent_version') or '?'}): нет heartbeat и "
                           "обратного канала, поэтому панель видит ноду только своим звонком — а он "
                           "режется. Это и есть «красная в панели».",
                           "node_action(action='update_agent') — обновит агент и пропишет адрес панели."))
    if not ov.get("brain_url"):
        out.append(finding(CRIT, "no_brain_url",
                           "В .env ноды нет CELL_BRAIN_URL — heartbeat выключен молча.",
                           f"node_action(action='set_brain_url'{', brain_url=' + repr(brain_url) if brain_url else ''})."))
    else:
        hb = ov.get("brain_heartbeat_path", "")
        if hb.startswith("000") or hb == "":
            out.append(finding(CRIT, "node_cant_reach_panel",
                               f"Нода не достаёт до панели ({ov.get('brain_url')}): путь нода→панель "
                               "тоже режется. Heartbeat не дойдёт, пока нет обходного пути.",
                               "node_run(recipe='brain_path') для подробностей; обходной путь — "
                               "адрес панели за CDN/другим IP или relay через живую ноду."))
        elif ov.get("brain_basic_auth") == "yes":
            out.append(finding(CRIT, "heartbeat_behind_basic_auth",
                               "Ручка heartbeat закрыта basic_auth в Caddy панели: нода стучится, а "
                               "панель её не пускает.",
                               "Открыть /api/v1/agent/* мимо basic_auth в Caddyfile панели (инвариант 4)."))
        elif hb in ("401", "403", "422", "405", "400"):
            out.append(finding(OK, "panel_reachable", f"Нода достаёт до панели (heartbeat-ручка: {hb})."))
        else:
            out.append(finding(WARN, "heartbeat_route_broken",
                               f"До адреса панели нода доходит, но ручка heartbeat ответила {hb}: панель "
                               "лежит (502/503) или адрес не тот (404).",
                               "Проверить CELL_BRAIN_URL ноды и маршрут /api/v1/agent/* в Caddy панели."))
    logs_hb = "\n".join(ov.get("logs", {}).get("heartbeat", []))
    if "401" in logs_hb:
        out.append(finding(CRIT, "bad_token",
                           "Панель не принимает токен ноды (401): ноду переустановили, а запись в "
                           "панели осталась со старым ключом.",
                           "Сверить CELL_API_TOKEN ноды с токеном сервера в панели."))
    elif "Обратный канал открыт" in logs_hb:
        out.append(finding(OK, "uplink_open", "Обратный канал к панели открыт."))
    if ov.get("local_health") not in ("200", None, ""):
        out.append(finding(WARN, "agent_not_answering",
                           f"Агент локально ответил {ov.get('local_health')} на /health — завис или "
                           "занят (инвариант 11).",
                           "node_logs(service='vpn-cell')."))
    try:
        if int(ov.get("disk_pct") or 0) >= 90:
            out.append(finding(WARN, "disk_full", f"Диск занят на {ov['disk_pct']}%."))
        if int(ov.get("mem_pct") or 0) >= 95:
            out.append(finding(WARN, "mem_full", f"Память занята на {ov['mem_pct']}%."))
    except ValueError:
        pass
    return out


# ── 3. Доступность IP с точек обзора ───────────────────────────────────────

def client_ports(node: dict, node_links: list[str]) -> list[int]:
    ports = []
    for uri in node_links:
        u = urlparse(uri)
        if u.scheme in UDP_SCHEMES or not u.port:
            continue
        if u.port not in ports:
            ports.append(u.port)
    return ports[:3] or [443]


async def reach(probe: str, node: dict, ports: list[int]) -> dict:
    """TCP и данные к SSH-порту + TLS к клиентским портам с одной точки."""
    host = node.get("ip") or node.get("ssh_host")
    sp = int(node.get("ssh_port") or 22)
    tasks = {
        "tcp_ssh": registry.run(probe, "tcp", {"host": host, "port": sp}),
        "banner_ssh": registry.run(probe, "banner", {"host": host, "port": sp}),
    }
    for p in ports:
        tasks[f"tls_{p}"] = registry.run(probe, "tls", {"host": host, "port": p})
    keys = list(tasks)
    vals = await asyncio.gather(*tasks.values(), return_exceptions=True)
    res = {}
    for k, v in zip(keys, vals):
        res[k] = v if isinstance(v, dict) else {"ok": False, "error": "probe_error", "detail": str(v)}
    return res


def reach_verdict(probe: str, r: dict) -> dict:
    tcp, banner = r.get("tcp_ssh", {}), r.get("banner_ssh", {})
    tls = {k: v for k, v in r.items() if k.startswith("tls_")}
    tls_ok = [k for k, v in tls.items() if v.get("ok") or v.get("error") == "ssl_error"]
    tls_frozen = [k for k, v in tls.items()
                  if v.get("stage") == "handshake" and v.get("error") in ("timeout", "reset")]
    if tcp.get("error") == "probe_timeout" or banner.get("error") == "probe_timeout":
        return finding(WARN, "probe_silent", f"[{probe}] пробник не ответил — проверка не состоялась.")
    if not tcp.get("ok") and not any(v.get("stage") == "handshake" for v in tls.values()) and not tls_ok:
        kind = tcp.get("error", "?")
        if kind == "refused":
            return finding(WARN, "ssh_closed", f"[{probe}] IP отвечает, но SSH-порт закрыт (refused).")
        return finding(CRIT, "ip_unreachable",
                       f"[{probe}] до IP не открывается ни одно TCP-соединение ({kind}): нода лежит "
                       "или IP закрыт с этой сети целиком.",
                       "Сверить с другими точками: у всех — нода/хостер; у одной сети — блок IP у "
                       "провайдера → RU-вход перед нодой или новый IP.")
    if (tcp.get("ok") and banner.get("stage") == "data") or tls_frozen:
        what = []
        if banner.get("stage") == "data":
            what.append("SSH-баннер не пришёл")
        if tls_frozen:
            what.append("TLS не завершился на " + ", ".join(k[4:] for k in tls_frozen))
        return finding(CRIT, "payload_filtered",
                       f"[{probe}] TCP открывается, но данные режутся ({'; '.join(what)}). Это фильтр "
                       "по IP на пути, а не поломка ноды — настройками протокола не лечится.",
                       "RU-вход перед нодой (relay) или смена IP у хостера.")
    if not tcp.get("ok"):
        return finding(WARN, "ssh_port_closed",
                       f"[{probe}] клиентские порты отвечают, а SSH-порт нет ({tcp.get('error', '?')}): "
                       "закрыт файрволом или sshd на другом порту (ssh_port в nodes.json).")
    return finding(OK, "ip_reachable",
                   f"[{probe}] IP доступен: TCP, данные" + (", TLS" if tls_ok else "") + " проходят.")


# ── 4. Сквозная проверка протоколов ────────────────────────────────────────

async def e2e(probe: str, uri: str) -> dict:
    d = links.describe(uri)
    cfg = links.config_for(uri)
    label = f"{d['scheme']} {d['type'] or 'tcp'}/{d['security'] or 'none'} :{d['port']} {d['remark']}".strip()
    if cfg is None:
        return {"link": label, "ok": None, "skipped": "формат не переносится в xray-конфиг"}
    r = await registry.run(probe, "e2e", {"config": cfg}, timeout=45)
    return {"link": label, **r}


# ── Сборка ─────────────────────────────────────────────────────────────────

async def diagnose(node: dict, probes: list[str] | None = None, with_e2e: bool = True,
                   with_ssh: bool = True) -> dict:
    probes = probes or [HUB]
    report: dict = {"node": {k: node.get(k) for k in (
        "name", "panel", "ip", "ssh_host", "country", "panel_online", "heartbeat_age_s",
        "agent_version", "rf_status", "source")}}
    findings: list[dict] = panel_findings(node)

    node_links: list[str] = []
    links_note = ""
    if config.settings.test_sub_url:
        try:
            all_links = await links.fetch_links()
            node_links = await asyncio.to_thread(links.links_for_node, all_links, node)
            if not node_links:
                links_note = "в подписке тестового юзера нет ссылок на эту ноду"
        except links.LinksError as e:
            links_note = str(e)
    else:
        links_note = "NEXUS_TEST_SUB_URL не задан — сквозная проверка и порты клиентов недоступны"
    if links_note:
        report["links_note"] = links_note

    ports = client_ports(node, node_links)

    async def ssh_part():
        if not with_ssh:
            return None
        return await ssh.run_script(node, recipes.overview(), timeout=60)

    ssh_res, *reaches = await asyncio.gather(ssh_part(), *[reach(p, node, ports) for p in probes])

    if ssh_res is not None:
        if ssh_res.ok:
            ov = recipes.parse_overview(ssh_res.stdout)
            report["node_overview"] = ov
            p = inventory.node_panel(node)
            findings += node_findings(ov, p["url"] if p else "")
        else:
            report["ssh"] = ssh_res.as_dict()
            findings.append(finding(CRIT if ssh_res.failure != "no_key" else WARN, f"ssh_{ssh_res.failure}",
                                    f"SSH с хаба не удался: {ssh.FAILURE_HINTS.get(ssh_res.failure, ssh_res.stderr[:200])}"))

    report["reach"] = {}
    for probe, r in zip(probes, reaches):
        report["reach"][probe] = r
        findings.append(reach_verdict(probe, r))

    if with_e2e and node_links:
        report["e2e"] = {}
        for probe in probes:
            results = await asyncio.gather(*[e2e(probe, u) for u in node_links[:6]])
            report["e2e"][probe] = results
            alive = [x["link"] for x in results if x.get("ok")]
            dead = [x["link"] for x in results if x.get("ok") is False]
            if dead and alive:
                findings.append(finding(WARN, "some_protocols_dead",
                                        f"[{probe}] работают: {', '.join(alive)}; не работают: {', '.join(dead)} "
                                        "— режут конкретный протокол/транспорт, IP жив.",
                                        "Оставить живые, мёртвые перевести на другой транспорт/порт/fingerprint."))
            elif dead:
                findings.append(finding(CRIT, "all_protocols_dead",
                                        f"[{probe}] ни один протокол ноды не открыл сайт: {', '.join(dead)}."))
            elif alive:
                findings.append(finding(OK, "protocols_ok", f"[{probe}] все протоколы ноды работают."))

    order = {CRIT: 0, WARN: 1, INFO: 2, OK: 3}
    findings.sort(key=lambda f: order.get(f["level"], 9))
    report["findings"] = findings
    report["summary"] = summarize(findings)
    # Что делать — из справочника (наш журнал + чужой опыт), по каждому
    # критичному симптому один раз.
    steps = {}
    for f in findings:
        code = f["code"]
        if f["level"] in (CRIT, WARN) and code in playbook.PLAYBOOK and code not in steps:
            steps[code] = playbook.lookup(code)["steps"]
    if steps:
        report["next_steps"] = steps
    return report


def summarize(findings: list[dict]) -> str:
    crit = [f for f in findings if f["level"] == CRIT]
    if not crit:
        warn = [f for f in findings if f["level"] == WARN]
        return "Критичного не найдено." + (f" Обратить внимание: {warn[0]['text']}" if warn else "")
    head = crit[0]
    return f"{head['text']}" + (f" → {head['fix']}" if head.get("fix") else "")
