"""Прогон подписки с точки обзора: какие строки подписки открываются из дома.

Вопрос владельца — «доступны ли ноды в подписке с моего интернета», а не
«что с конкретной нодой». Поэтому единица здесь — строка подписки (то, что
клиент видит в списке серверов), сгруппированная по ноде.

Две ступени:
  1. доступность: TLS-рукопожатие (reality/tls) или TCP до адреса строки —
     одной пачкой (`batch` у пробника), параллельно, за секунды;
  2. сквозная (e2e=True, нужен xray у пробника): поднять клиент с конфигом
     строки и открыть сайт — по одной, это минуты.

Первая ступень отличает «IP режут» (TCP есть, рукопожатие пропало) от «нода
лежит» (refused / нет TCP), но не видит, что режут сам протокол: это вторая.
UDP-строки (hysteria2) первой ступенью не проверяются вовсе — честно
«не проверено», а не зелёное.

Прогон идёт фоном на хабе: приложение запускает его и спрашивает состояние.
Последний итог по каждому пробнику лежит на диске — после рестарта хаба
экран не пустой.
"""

from __future__ import annotations

import asyncio
import ipaddress
import json
import time
import uuid
from urllib.parse import urlparse

from nexus_mcp import config, inventory, links, panels, singbox
from nexus_mcp.probes import HUB, ProbeError, registry

# Статус строки. Порядок — от хорошего к плохому; приложение держит копию
# (SweepModels.kt, сторож в tests/test_sweep.py — инвариант 25 vgx3d).
LINK_STATUSES = ("ok", "reachable", "unchecked", "unknown", "via_vpn", "broken", "refused", "filtered", "down",
                 "dns")
# Статус ноды: все строки ok — ok, ни одной — bad, вперемешку — partial.
NODE_STATUSES = ("ok", "partial", "bad", "unchecked")

TLS_SECURITIES = {"tls", "reality", "xtls"}
UDP_SCHEMES = {"hysteria2", "hy2", "tuic", "wireguard"}
MAX_LINKS = 120
MAX_E2E = 40
BATCH_PARALLEL = 8
REACH_TIMEOUT = 7.0
E2E_JOB_TIMEOUT = 45.0

# Что значит каждый отказ — коротко, для экрана.
REASONS = {
    "ok": "открывается",
    "reachable": "адрес доступен (сквозная проверка не запускалась)",
    "unchecked": "не проверялось",
    "unknown": "пробник не ответил",
    "via_vpn": "проверка ушла в VPN роутера (podkop: адрес подменён FakeIP 198.18.x.x) — это картина VPN, "
               "а не провайдера. Уберите домен из списков podkop или проверяйте с другой точки",
    "broken": "адрес доступен, но через протокол сайт не открылся — режут протокол или нода не пускает",
    "refused": "порт закрыт (refused): служба на ноде не слушает",
    "filtered": "TCP открывается, данные режутся: фильтр по IP на пути",
    "down": "до адреса не открывается ни одно соединение: нода лежит или IP закрыт целиком",
    "dns": "имя не резолвится с этой сети",
}


# Строка за Cloudflare: проба первой ступени доходит до CF, а не до ноды.
CDN_REASONS = {
    "reachable": "Cloudflare доступен с этой сети; дойдёт ли до ноды — покажет сквозная проверка",
    "ok": "открывается (через Cloudflare)",
}
# https://www.cloudflare.com/ips-v4 и ips-v6 (хаб часто ходит к CF по IPv6)
CLOUDFLARE_NETS = tuple(ipaddress.ip_network(n) for n in (
    "173.245.48.0/20", "103.21.244.0/22", "103.22.200.0/22", "103.31.4.0/22", "141.101.64.0/18",
    "108.162.192.0/18", "190.93.240.0/20", "188.114.96.0/20", "197.234.240.0/22", "198.41.128.0/17",
    "162.158.0.0/15", "104.16.0.0/13", "104.24.0.0/14", "172.64.0.0/13", "131.0.72.0/22",
    "2400:cb00::/32", "2606:4700::/32", "2803:f800::/32", "2405:b500::/32", "2405:8100::/32",
    "2a06:98c0::/29", "2c0f:f248::/32",
))


def is_cloudflare(ip: str) -> bool:
    try:
        a = ipaddress.ip_address(ip)
    except ValueError:
        return False
    return any(a in n for n in CLOUDFLARE_NETS if n.version == a.version)


class SweepError(Exception):
    pass


# ── Откуда брать подписку ──────────────────────────────────────────────────

def sources(panel: str = "") -> list[tuple[str, str]]:
    """(имя панели, ссылка подписки). Панель в panels.json со своим sub_url —
    её подписка; иначе NEXUS_TEST_SUB_URL. Пустой список — отказ с причиной."""
    env_url = config.settings.test_sub_url
    try:
        all_p = panels.all_panels()
    except panels.PanelConfigError:
        all_p = []
    if panel:
        p = next((x for x in all_p if x["name"] == panel), None)
        if p is None and all_p:
            raise SweepError(f"панели «{panel}» нет. Есть: {', '.join(x['name'] for x in all_p)}")
        url = (p or {}).get("sub_url") or env_url
        if not url:
            raise SweepError(no_sub_hint(panel))
        return [(panel, url)]
    out: list[tuple[str, str]] = []
    for p in all_p:
        if p.get("sub_url") and all(u != p["sub_url"] for _, u in out):
            out.append((p["name"], p["sub_url"]))
    if env_url and all(u != env_url for _, u in out):
        out.insert(0, (all_p[0]["name"] if len(all_p) == 1 else "", env_url))
    if not out:
        raise SweepError(no_sub_hint(""))
    return out


def no_sub_hint(panel: str) -> str:
    who = panel or "<панель>"
    return ("Нет подписки для проверки. Хаб заведёт её сам: probe_subscription"
            f"(panel='{panel}') в чате или «Завести» в приложении (Проверка из дома) — "
            "служебный юзер nexus-probe на всех нодах. Или свою ссылку: "
            f"nexus-mcp-panels sub {who} https://…/sub/<токен>")


# ── Строки подписки ────────────────────────────────────────────────────────

def link_row(uri: str) -> dict:
    d = links.describe(uri)
    scheme = (d["scheme"] or "").lower()
    security = (d["security"] or "").lower()
    if scheme == "trojan" and not security:
        security = "tls"  # trojan без security= — это TLS по умолчанию
    return {
        "uri": uri,
        "remark": d["remark"] or f"{d['host']}:{d['port']}",
        "scheme": scheme,
        "transport": d["type"] or "tcp",
        "security": security,
        "host": d["host"] or "",
        "port": d["port"] or (443 if security in TLS_SECURITIES else 0),
        "sni": d["sni"] or "",
        "udp": scheme in UDP_SCHEMES,
    }


def reach_job(row: dict) -> dict | None:
    """Проба доступности строки. None — нечего пробовать по TCP (UDP, без порта)."""
    if row["udp"] or not row["host"] or not row["port"]:
        return None
    if row["security"] in TLS_SECURITIES:
        args = {"host": row["host"], "port": row["port"], "timeout": REACH_TIMEOUT}
        # Reality отвечает рукопожатием чужого сайта по своему SNI: без него
        # часть нод рвёт соединение, и живая строка выглядела бы мёртвой.
        if row["sni"]:
            args["sni"] = row["sni"]
        return {"kind": "tls", "args": args}
    return {"kind": "tcp", "args": {"host": row["host"], "port": row["port"], "timeout": REACH_TIMEOUT}}


def reach_status(kind: str, r: dict) -> str:
    """Итог пробы → статус строки (LINK_STATUSES)."""
    if r.get("fakeip"):
        return "via_vpn"  # что бы ни вышло — это не про провайдера
    if r.get("ok"):
        return "reachable"
    err = r.get("error") or ""
    if err in ("probe_timeout", "probe_error", "probe_offline"):
        return "unknown"
    if kind == "tls" and err == "ssl_error":
        return "reachable"  # сервер ответил, пусть и не тем — дорога живая
    if err == "dns":
        return "dns"
    if err == "refused":
        return "refused"
    if r.get("stage") in ("handshake", "data"):
        return "filtered"
    return "down"  # timeout / unreachable / reset на соединении


def node_status(rows: list[dict]) -> str:
    checked = [r["status"] for r in rows if r["status"] not in ("unchecked", "unknown", "via_vpn")]
    if not checked:
        return "unchecked"
    good = [s for s in checked if s in ("ok", "reachable")]
    if len(good) == len(checked):
        return "ok"
    return "partial" if good else "bad"


# ── Прогон ─────────────────────────────────────────────────────────────────

async def _run_batch(probe: str, jobs: list[dict]) -> list[dict]:
    """Пачка проб на пробнике. Старый пробник (1.0) пачек не знает — тогда
    по одной, но параллельно: у нового он всё равно их выполнит по очереди."""
    rounds = -(-len(jobs) // BATCH_PARALLEL)
    timeout = 15 + rounds * (REACH_TIMEOUT + 3)
    r = await registry.run(probe, "batch", {"jobs": jobs, "parallel": BATCH_PARALLEL}, timeout=timeout)
    if r.get("ok") and isinstance(r.get("results"), list) and len(r["results"]) == len(jobs):
        return r["results"]
    if r.get("error") != "unknown_kind":
        return [dict(r) for _ in jobs]
    sem = asyncio.Semaphore(4)

    async def one(j: dict) -> dict:
        async with sem:
            return await registry.run(probe, j["kind"], j["args"], timeout=timeout)
    return list(await asyncio.gather(*[one(j) for j in jobs]))


async def _load_nodes() -> list[dict]:
    try:
        nodes, _errors = await inventory.load_nodes()
    except Exception:  # noqa: BLE001 — без панели группируем по адресу
        return []
    return nodes


def node_by_name(host: str, panel: str, nodes: list[dict]) -> dict | None:
    """Строка за CDN: адрес — edge Cloudflare, по IP ноду не найти. Имя в
    домене — имя ноды (eng41s2.pablo.stream → JonyX/eng41s2): сперва в панели
    строки, потом в любой. Двусмысленность — не угадываем."""
    label = (host or "").split(".", 1)[0].lower()
    if not label or label.replace(".", "").isdigit():
        return None

    def short(n: dict) -> str:
        return str(n.get("name") or "").rsplit("/", 1)[-1].lower()

    hits = [n for n in nodes if label in (short(n), short(n).split("-", 1)[0])]
    same = [n for n in hits if str(n.get("name") or "").startswith(f"{panel}/")] if panel else []
    for group in (same, hits):
        if len(group) == 1:
            return group[0]
    return None


def _resolve_all(hosts: list[str]) -> dict[str, list[str]]:
    return {h: sorted(links._resolve(h)) for h in hosts}  # noqa: SLF001


async def sweep(probe: str = HUB, panel: str = "", e2e: bool = False,
                progress: dict | None = None) -> dict:
    t0 = time.time()
    progress = progress if progress is not None else {}
    progress.update(stage="subscription", done=0, total=0)

    srcs = sources(panel)
    uris: list[tuple[str, str]] = []
    errors: list[str] = []
    # Ноды, появившиеся после заведения тестового юзера, — в его подписку.
    from nexus_mcp import probe_sub

    errors += await probe_sub.refresh_all(panel)
    for pname, url in srcs:
        try:
            got = await links.fetch_links(url)
        except links.LinksError as e:
            errors.append(f"{pname or 'подписка'}: {e}")
            continue
        for u in got:
            if all(u != x for _, x in uris):
                uris.append((pname, u))
    if not uris:
        raise SweepError("; ".join(errors) or "в подписке нет ссылок")
    truncated = len(uris) > MAX_LINKS
    uris = uris[:MAX_LINKS]

    rows = []
    for pname, u in uris:
        row = link_row(u)
        row["panel"] = pname
        rows.append(row)

    # Имя ноды по IP (домен строки резолвим тут же, на хабе: для группировки,
    # не для проверки — проба идёт по имени с точки обзора).
    all_nodes = await _load_nodes()
    index = {str(n["ip"]): n for n in all_nodes if n.get("ip")}
    resolved = await asyncio.to_thread(_resolve_all, sorted({r["host"] for r in rows if r["host"]}))
    for r in rows:
        node = index.get(r["host"])
        if node is None:
            node = next((index[ip] for ip in resolved.get(r["host"], []) if ip in index), None)
        if any(is_cloudflare(ip) for ip in resolved.get(r["host"], [])):
            r["cdn"] = "Cloudflare"
        r["node"] = node["name"] if node else ""

    # 1. Доступность — одной пачкой.
    progress.update(stage="reach", total=len(rows))
    jobs = [(i, reach_job(r)) for i, r in enumerate(rows)]
    todo = [(i, j) for i, j in jobs if j is not None]
    results = await _run_batch(probe, [j for _, j in todo]) if todo else []
    for (i, j), res in zip(todo, results):
        rows[i]["reach"] = _short(res)
        rows[i]["status"] = reach_status(j["kind"], res)
        rows[i]["ms"] = res.get("ms")
        if res.get("peer"):
            rows[i]["peer"] = res["peer"]
            # CF видит пробник, а не хаб: у провайдера мог быть свой DNS
            if is_cloudflare(res["peer"]):
                rows[i]["cdn"] = "Cloudflare"
    for r in rows:
        r.setdefault("status", "unchecked")
        # За CDN по IP ноду не найти — по имени в домене (CF мог увидеть только пробник).
        if not r["node"] and r.get("cdn"):
            node = node_by_name(r["host"], r["panel"], all_nodes)
            r["node"] = node["name"] if node else ""
    progress.update(done=len(rows))

    # 2. Сквозная — по одной, только если попросили и у пробника есть xray.
    e2e_note = ""
    e2e_ran = False
    if e2e:
        e2e_note = _e2e_unavailable(probe)
        if not e2e_note:
            e2e_ran = True
            cand = [r for r in rows if r["status"] in ("reachable", "unchecked") and links.config_for(r["uri"])]
            if len(cand) > MAX_E2E:
                e2e_note = f"сквозная проверка — первые {MAX_E2E} строк из {len(cand)}"
                cand = cand[:MAX_E2E]
            progress.update(stage="e2e", done=0, total=len(cand))
            not_run: list[str] = []
            for r in cand:
                cfg = links.config_for(r["uri"])
                res = await registry.run(probe, "e2e", {"config": cfg, "singbox": singbox.config(cfg)},
                                         timeout=E2E_JOB_TIMEOUT)
                r["e2e"] = _short(res)
                if res.get("ok"):
                    r["status"] = "ok"
                    r["ms"] = res.get("ms")
                elif res.get("error") in ("probe_timeout", "no_xray", "low_memory", "xray_failed"):
                    # проверка не состоялась — статус первой ступени остаётся
                    not_run.append(f"{r['remark']}: {res.get('detail') or res.get('error')}")
                else:
                    r["status"] = "broken"
                progress["done"] = progress.get("done", 0) + 1
            if not_run:
                e2e_note = (f"сквозная не состоялась для {len(not_run)} из {len(cand)} строк — "
                            + "; ".join(not_run[:3]) + (" …" if len(not_run) > 3 else ""))

    for r in rows:
        r["reason"] = REASONS.get(r["status"], "")
        if r.get("cdn"):
            r["reason"] = CDN_REASONS.get(r["status"], r["reason"] + " (адрес — Cloudflare)")
        r.pop("uri", None)  # в ссылке UUID юзера: на экран и в лог не нужно

    groups: dict[str, dict] = {}
    for r in rows:
        key = r["node"] or r["host"] or r["remark"]
        g = groups.setdefault(key, {"name": key, "panel": r["panel"], "known": bool(r["node"]),
                                    "host": r["host"], "links": []})
        g["links"].append(r)
    nodes = list(groups.values())
    for g in nodes:
        g["status"] = node_status(g["links"])
    order = {s: i for i, s in enumerate(("bad", "partial", "unchecked", "ok"))}
    nodes.sort(key=lambda g: (order.get(g["status"], 9), g["name"]))

    summary = {s: sum(1 for g in nodes if g["status"] == s) for s in NODE_STATUSES}
    summary["links"] = len(rows)
    info = next((p for p in registry.list() if p["name"] == probe), {})
    out = {
        "ok": True, "probe": probe, "probe_addr": info.get("remote_addr", ""),
        "e2e": e2e_ran,
        "finished_at": int(time.time()), "took_s": round(time.time() - t0, 1),
        "summary": summary, "nodes": nodes,
    }
    notes = [n for n in (e2e_note, *errors) if n]
    via_vpn = sum(1 for r in rows if r["status"] == "via_vpn")
    if via_vpn:
        notes.append(f"{via_vpn} строк ушли в VPN роутера (FakeIP) — для них проверка не про провайдера")
    if info.get("router_vpn"):
        notes.append(f"на роутере включён {info['router_vpn']}: подмену имён (FakeIP) пробник видит и "
                     "помечает, а заворот по спискам ПОДСЕТЕЙ — нет. Если в его списках есть подсети "
                     "хостеров нод (Hetzner, OVH, DigitalOcean…), такие строки проверены через VPN")
    if truncated:
        notes.append(f"в подписке больше {MAX_LINKS} строк — проверены первые {MAX_LINKS}")
    if notes:
        out["notes"] = notes
    return out


def _e2e_unavailable(probe: str) -> str:
    """Почему сквозная невозможна; пусто — возможна."""
    if probe == HUB:
        from nexus_mcp.probes import probe_lib

        if probe_lib().find_xray(config.settings.xray_bin or None):
            return ""
        return "у хаба нет xray (NEXUS_XRAY) — проверена только доступность"
    info = next((p for p in registry.list() if p["name"] == probe), None)
    if info and not info.get("xray") and not info.get("singbox"):
        return (f"у пробника {probe} нет ни xray, ни sing-box — проверена только доступность "
                "(на роутере: установщик с --xray tmp)")
    return ""


def _short(r: dict) -> dict:
    """Результат пробы без лишнего: лог xray — только хвост."""
    keep = ("ok", "ms", "error", "stage", "detail", "status", "connect_ms", "xray_log", "engine")
    out = {k: r[k] for k in keep if k in r}
    if "xray_log" in out:
        out["xray_log"] = str(out["xray_log"])[-300:]
    return out


# ── Фоновые прогоны: один на пробник ───────────────────────────────────────

class Sweeps:
    def __init__(self) -> None:
        self.running: dict[str, dict] = {}

    def _file(self, probe: str):
        safe = "".join(c if c.isalnum() or c in "-_" else "_" for c in probe)[:64] or "_"
        return config.settings.state_dir / "sweeps" / f"{safe}.json"

    def last(self, probe: str) -> dict | None:
        try:
            return json.loads(self._file(probe).read_text(encoding="utf-8"))
        except (OSError, ValueError):
            return None

    def _save(self, probe: str, result: dict) -> None:
        path = self._file(probe)
        try:
            path.parent.mkdir(parents=True, exist_ok=True)
            tmp = path.with_suffix(".tmp")
            tmp.write_text(json.dumps(result, ensure_ascii=False), encoding="utf-8")
            tmp.replace(path)
        except OSError:
            pass  # итог в памяти всё равно отдадим; диск — только для рестарта

    def state(self, probe: str) -> dict:
        cur = self.running.get(probe)
        out: dict = {"ok": True, "probe": probe, "running": False}
        if cur and not cur["task"].done():
            out.update(running=True, id=cur["id"], started_at=int(cur["started"]),
                       e2e=cur["e2e"], panel=cur["panel"], progress=dict(cur["progress"]))
        elif cur and cur.get("error"):
            out["error"] = cur["error"]
        last = self.last(probe)
        if last:
            out["last"] = last
        return out

    def start(self, probe: str, panel: str = "", e2e: bool = False) -> dict:
        """Запустить прогон; идущий не перезапускаем — отдаём его состояние."""
        cur = self.running.get(probe)
        if cur and not cur["task"].done():
            return self.state(probe)
        if probe != HUB:
            info = next((p for p in registry.list() if p["name"] == probe), None)
            if info is None:
                raise SweepError(f"пробник «{probe}» ни разу не подключался — установите его на роутер")
            if not info.get("online"):
                raise SweepError(f"пробник «{probe}» не на связи {info.get('last_seen_s')} с — "
                                 "роутер выключен или служба nexus-probe остановлена (logread -e nexus-probe)")
        sources(panel)  # нет подписки — отказ сразу, а не через фон
        entry = {"id": uuid.uuid4().hex[:10], "started": time.time(), "e2e": bool(e2e),
                 "panel": panel, "progress": {}, "error": ""}

        async def work():
            try:
                res = await sweep(probe, panel, e2e, entry["progress"])
                res["panel"] = panel
                self._save(probe, res)
                return res
            except (SweepError, ProbeError, links.LinksError) as e:
                entry["error"] = str(e)
            except Exception as e:  # noqa: BLE001 — причина на экран, не в лог
                entry["error"] = f"{type(e).__name__}: {str(e)[:200]}"
            return None

        entry["task"] = asyncio.create_task(work())
        self.running[probe] = entry
        return self.state(probe)


sweeps = Sweeps()
