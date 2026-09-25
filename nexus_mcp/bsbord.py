"""bschekbot (bsbord.com): проверки глазами мобильных операторов и городов РФ.

Хаб и домашние пробники стоят на проводном интернете и не видят того, что
делает с трафиком мобильный оператор, — тем более с включёнными белыми
списками (БС). У bschekbot стоят SIM-карты каждого оператора в каждом
федеральном округе, с БС и без: единица проверки = оператор × округ × БС
(`op_key` вида "mts|цфо|on"). Плюс FULL GEO — из каких ГОРОДОВ открывается
цель (домашние и мобильные провайдеры).

Деньги. Всё платное (1 кредит = 1 копейка) идёт в два шага:
1. без `confirm` — бесплатный preview: цена и какие единицы поедут;
2. с `confirm=true` и `max_credits` не ниже цены из preview — запуск.
Сверху — дневной потолок хаба `NEXUS_BSBORD_DAILY_RUB` по журналу расходов
на диске (`bsbord_spend.jsonl`): Claude не должен суметь потратить больше,
чем владелец разрешил на день, даже по ошибке в цикле.

Idempotency-Key на каждый платный POST обязателен (контракт API): тот же
ключ при 409 request_in_progress отдаёт результат ТОЙ ЖЕ проверки, новый
ключ оплатил бы вторую. Повторы ниже держат ключ неизменным.
"""

from __future__ import annotations

import asyncio
import json
import time
import uuid
from datetime import datetime, timezone
from typing import Any

import httpx

from nexus_mcp import config

# Тесты подменяют транспорт на httpx.MockTransport.
_TRANSPORT: httpx.AsyncBaseTransport | None = None

KINDS = ("probe", "vless", "geo")


class BsError(Exception):
    """Отказ bschekbot с причиной как есть: код, текст, request_id для поддержки."""

    def __init__(self, code: str, message: str, status: int = 0, details: dict | None = None):
        self.code = code
        self.message = message
        self.status = status
        self.details = details or {}
        rid = self.details.get("request_id")
        super().__init__(f"{code}: {message}" + (f" (request_id {rid})" if rid else ""))

    @property
    def retryable(self) -> bool:
        return bool(self.details.get("retryable"))

    def as_dict(self) -> dict:
        out = {"ok": False, "error": self.code, "detail": self.message, "http": self.status}
        for k in ("request_id", "retryable", "retry_after", "skipped_dpi_off", "fields", "unknown", "allowed"):
            if k in self.details:
                out[k] = self.details[k]
        return out


def enabled() -> bool:
    return bool(config.settings.bsbord_key)


def rub(credits: Any) -> float | None:
    try:
        return round(int(credits) / 100, 2)
    except (TypeError, ValueError):
        return None


async def _req(method: str, path: str, body: dict | None = None, *, idem: str | None = None,
               params: dict | None = None, timeout: float = 30) -> dict:
    s = config.settings
    if not s.bsbord_key:
        raise BsError("not_configured", "ключ bschekbot не задан: NEXUS_BSBORD_KEY=bsk_live_… в /etc/nexus-mcp.env")
    headers = {"Authorization": f"Bearer {s.bsbord_key}", "Accept": "application/json"}
    if idem:
        headers["Idempotency-Key"] = idem
    try:
        async with httpx.AsyncClient(base_url=s.bsbord_url, timeout=timeout, transport=_TRANSPORT) as c:
            r = await c.request(method, path, json=body, params=params, headers=headers)
    except httpx.TimeoutException:
        raise BsError("timeout", f"bsbord.com не ответил за {int(timeout)} с") from None
    except httpx.HTTPError as e:
        raise BsError("network", f"bsbord.com недоступен: {e}") from None
    try:
        data = r.json()
    except ValueError:
        data = None
    if r.status_code >= 400:
        err = (data or {}).get("error") if isinstance(data, dict) else None
        if isinstance(err, dict):
            raise BsError(str(err.get("code") or r.status_code), str(err.get("message") or ""),
                          r.status_code, err.get("details") or {})
        raise BsError(str(r.status_code), (r.text or "")[:300], r.status_code)
    if not isinstance(data, dict):
        raise BsError("bad_reply", f"ответ не JSON-объект: {(r.text or '')[:200]}", r.status_code)
    return data


async def _paid(path: str, body: dict, *, timeout: float = 150, max_wait: float = 240) -> dict:
    """Платный POST: один Idempotency-Key на всю жизнь запроса.

    429 — лимит 1 запрос/с на аккаунт, проверка ещё не начиналась: ждём и
    повторяем тем же ключом. 409 request_in_progress — наша же проверка ещё
    идёт: повтор С ТЕМ ЖЕ ключом отдаст её результат, новый — оплатил бы
    вторую.
    """
    key = str(uuid.uuid4())
    deadline = time.monotonic() + max_wait
    while True:
        try:
            return await _req("POST", path, body, idem=key, timeout=timeout)
        except BsError as e:
            if time.monotonic() > deadline:
                raise
            if e.code == "rate_limited":
                await asyncio.sleep(float(e.details.get("retry_after") or 1))
                continue
            if e.code == "request_in_progress":
                await asyncio.sleep(3)
                continue
            raise


# ── Журнал расходов и дневной потолок ─────────────────────────────────────

def _today() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%d")


def spent_today() -> int:
    path = config.settings.bsbord_ledger
    if not path.exists():
        return 0
    total, day = 0, _today()
    for ln in path.read_text(encoding="utf-8").splitlines():
        try:
            e = json.loads(ln)
        except ValueError:
            continue
        if str(e.get("ts", "")).startswith(day):
            total += int(e.get("credits") or 0)
    return total


def _spend(kind: str, ref: Any, credits: Any, note: str = "") -> None:
    try:
        c = int(credits or 0)
    except (TypeError, ValueError):
        c = 0
    path = config.settings.bsbord_ledger
    path.parent.mkdir(parents=True, exist_ok=True)
    entry = {"ts": datetime.now(timezone.utc).isoformat(timespec="seconds"), "kind": kind,
             "ref": ref, "credits": c}
    if note:
        entry["note"] = note[:200]
    with path.open("a", encoding="utf-8") as f:
        f.write(json.dumps(entry, ensure_ascii=False) + "\n")


def _settle_geo(run_id: Any, charged: Any) -> None:
    """GEO списывает ФАКТ по трафику, а в журнал при запуске ушёл резерв:
    по завершении — одна поправка на разницу (возврат идёт минусом)."""
    if charged is None:
        return
    path = config.settings.bsbord_ledger
    reserve, settled = None, False
    if path.exists():
        for ln in path.read_text(encoding="utf-8").splitlines():
            try:
                e = json.loads(ln)
            except ValueError:
                continue
            if str(e.get("ref")) != str(run_id):
                continue
            if e.get("kind") == "geo":
                reserve = int(e.get("credits") or 0)
            elif e.get("kind") == "geo_settle":
                settled = True
    if reserve is None or settled:
        return
    _spend("geo_settle", run_id, int(charged) - reserve, "факт минус резерв")


def budget() -> dict:
    cap = int(round(config.settings.bsbord_daily_rub * 100))
    spent = spent_today()
    return {"daily_cap_rub": rub(cap), "spent_today_rub": rub(spent),
            "left_today_rub": rub(max(cap - spent, 0)) if cap else None}


def _check_budget(credits: int) -> None:
    cap = int(round(config.settings.bsbord_daily_rub * 100))
    if cap <= 0:
        return
    spent = spent_today()
    if spent + credits > cap:
        raise BsError("daily_cap", f"дневной потолок хаба {rub(cap)} ₽: сегодня уже {rub(spent)} ₽, "
                                   f"эта проверка — {rub(credits)} ₽. Поднять: NEXUS_BSBORD_DAILY_RUB")


def _gate(cost: int, max_credits: int) -> None:
    """Цена из preview против того, что человек разрешил потратить."""
    if max_credits <= 0:
        raise BsError("need_max_credits", "укажите max_credits — не меньше цены из preview "
                                          "(запуск без потолка цены хаб не делает)")
    if cost > max_credits:
        raise BsError("price_changed", f"цена {rub(cost)} ₽ выше разрешённой {rub(max_credits)} ₽ — "
                                       "покажите человеку новую цену")
    _check_budget(cost)


# ── Единицы и аккаунт ──────────────────────────────────────────────────────

async def units(dpi: str = "any", operator: str = "", region: str = "", only_probeable: bool = True) -> dict:
    params: dict[str, Any] = {"dpi": dpi or "any"}
    if operator:
        params["operator"] = operator
    if region:
        params["region"] = region
    if only_probeable:
        params["probeable"] = "true"
    data = await _req("GET", "/operators", params=params)
    rows = [{k: u.get(k) for k in ("op_key", "operator", "name", "region", "dpi", "channel_state", "probeable")}
            for u in data.get("units") or []]
    by_op: dict[str, list[str]] = {}
    for u in rows:
        mark = "БС" if u["dpi"] == "on" else "без БС"
        by_op.setdefault(str(u["operator"]), []).append(f"{u['region']} ({mark})")
    return {"ok": True, "n_units": data.get("n_units", len(rows)), "n_probeable": data.get("n_probeable"),
            "by_operator": {k: sorted(v) for k, v in sorted(by_op.items())}, "units": rows}


async def account() -> dict:
    a = await _req("GET", "/account")
    return {"ok": True, "balance_rub": rub(a.get("balance_total")), "tier": a.get("tier"),
            "tier_expires_at": a.get("tier_expires_at"), **budget()}


# ── Проба: ICMP / TCP / SNI (синхронно) ──────────────────────────────────

def _probe_body(targets: list[str], unit_keys: list[str], dpi: str, probes: list[str],
                sni_hosts: list[str]) -> dict:
    if not targets:
        raise BsError("no_targets", "нужна хотя бы одна цель (IP, IP:порт, домен или URL)")
    if len(targets) > 10:
        raise BsError("too_many_targets", "целей больше 10 — разбейте на несколько проверок")
    kinds = {p.strip().lower() for p in (probes or ["tcp"]) if p.strip()}
    body: dict = {"targets": targets, "dpi": dpi or "on",
                  "probes": {"icmp": "icmp" in kinds, "tcp": "tcp" in kinds, "sni": "sni" in kinds and bool(sni_hosts)}}
    if not any(body["probes"].values()):
        raise BsError("no_probes", "не выбрано ни одной пробы: icmp, tcp или sni (sni — вместе с sni_hosts)")
    if unit_keys:
        body["operators"] = unit_keys
    if body["probes"]["sni"]:
        body["sni_hosts"] = sni_hosts
    return body


def _leg(op_key: str, leg: dict) -> dict:
    icmp, tcp, http = leg.get("icmp"), leg.get("tcp"), leg.get("http")
    reachable = bool((icmp or {}).get("ok")) or bool((tcp or {}).get("ok"))
    out: dict[str, Any] = {"unit": op_key, "dpi": leg.get("dpi"), "reachable": reachable}
    if leg.get("error"):
        out["error"] = leg["error"]
    if icmp:
        out["icmp"] = f"{'ok' if icmp.get('ok') else 'нет'} · потери {icmp.get('loss_pct')}% · " \
                      f"rtt {icmp.get('rtt_avg_ms') or icmp.get('rtt_ms')} мс"
    if tcp:
        t = "ok" if tcp.get("ok") else f"нет ({tcp.get('error') or tcp.get('verdict') or '?'})"
        if leg.get("tcp_is_tls"):
            t += f" · TLS с проверкой сертификата: {tcp.get('verdict')}"
        out["tcp"] = t
    if leg.get("sni"):
        out["sni"] = {str(x.get("host") or x.get("sni") or i): bool(x.get("ok"))
                      for i, x in enumerate(leg["sni"]) if isinstance(x, dict)}
    if http:
        # http.ok = «ответ получен», а не «сайт работает»: заглушку оператора
        # видно по статусу, location и началу тела.
        out["http"] = {k: http.get(k) for k in ("status", "location", "server", "body_head", "error")
                       if http.get(k) not in (None, "")}
    return out


def _compact_probe(res: dict) -> dict:
    out: dict[str, Any] = {"ok": True, "cost_rub": rub(res.get("cost_credits")),
                           "refunded_rub": rub(res.get("refunded")), "targets": {}}
    lines = []
    for target, t in (res.get("by_target") or {}).items():
        legs = [_leg(k, v) for k, v in (t.get("by_operator") or {}).items()]
        up = [l["unit"] for l in legs if l["reachable"]]
        down = [l["unit"] for l in legs if not l["reachable"]]
        out["targets"][target] = {"resolved": t.get("target_resolved"), "legs": legs}
        lines.append(f"{target}: доступна {len(up)}/{len(legs)}" + (f"; НЕ доступна: {', '.join(down)}" if down else ""))
    out["summary"] = lines
    for k in ("skipped", "skipped_dpi_off", "skipped_unavailable"):
        if res.get(k):
            out[k] = res[k]
    return out


async def probe(targets: list[str], unit_keys: list[str], dpi: str, probes: list[str],
                sni_hosts: list[str], max_credits: int, confirm: bool) -> dict:
    body = _probe_body(targets, unit_keys, dpi, probes, sni_hosts)
    pv = await _req("POST", "/probe/preview", body)
    cost = int(pv.get("cost_credits") or 0)
    if not confirm:
        return {"ok": True, "preview": True, "cost_credits": cost, "cost_rub": rub(cost),
                "units": pv.get("selected_units"), "n_targets": pv.get("n_targets"), **budget(),
                "next": "покажите цену человеку; запуск — тем же вызовом с confirm=true и max_credits=cost_credits"}
    _gate(cost, max_credits)
    res = await _paid("/probe", body)
    if res.get("outcome") == "no_dpi_on":
        return {"ok": False, "error": "no_dpi_on", "detail": "выбранные единицы ушли из режима БС перед стартом — "
                "списания нет; повторите с dpi=any или другими единицами", "skipped_dpi_off": res.get("skipped_dpi_off")}
    _spend("probe", ",".join(targets)[:120], res.get("cost_credits"))
    return _compact_probe(res)


# ── VLESS и прочие протоколы (асинхронно) ────────────────────────────────

def _compact_vless(st: dict) -> dict:
    out: dict[str, Any] = {"ok": True, "test_id": st.get("test_id"), "state": st.get("state"),
                           "queue_pos": st.get("queue_pos"), "used_core": st.get("used_core")}
    if isinstance(st.get("result"), list):
        rows = []
        for r in st["result"]:
            row = {"server": r.get("server_name") or r.get("server_addr"), "unit": f"{r.get('operator')}|{r.get('region')}",
                   "channel": r.get("channel_state"), "ok": r.get("ok"), "stage": r.get("stage"),
                   "tunnel_up": r.get("tunnel_up"), "tcp_ms": r.get("tcp_latency_ms"),
                   "speed_mbps": r.get("speed_mbps")}
            for k in ("fail_reason", "diagnosis", "sni_check_error"):
                if r.get(k):
                    row[k] = r[k]
            rows.append(row)
        out["results"] = rows
        bad = [f"{r['server']} @ {r['unit']}: {r.get('fail_reason') or r.get('stage')}" for r in rows if not r["ok"]]
        out["summary"] = f"работает {len(rows) - len(bad)}/{len(rows)}" + (f"; не работает: {'; '.join(bad[:12])}" if bad else "")
    return out


async def vless(links: list[str], unit_keys: list[str], dpi: str, core: str, max_credits: int,
                confirm: bool, wait: bool) -> dict:
    if not links:
        raise BsError("no_configs", "нет ссылок: передайте vless://… или ноду (ссылки возьмутся из тестовой подписки)")
    if len(links) > 20:
        raise BsError("too_many_configs", "больше 20 ссылок за раз")
    if not confirm:
        # У VLESS-теста нет preview: цена известна только после постановки.
        return {"ok": True, "preview": True, "n_links": len(links),
                "servers": [l.split("#", 1)[-1] if "#" in l else l.split("@", 1)[-1].split("?", 1)[0] for l in links],
                "units": unit_keys or "все подключённые единицы", **budget(),
                "note": "цену API называет только при постановке: n_servers × n_units единиц. "
                        "Запуск — с confirm=true и max_credits; дороже потолка — хаб отменит тест сразу (бесплатно, пока в очереди)."}
    if max_credits <= 0:
        raise BsError("need_max_credits", "укажите max_credits — потолок цены теста")
    _check_budget(0)
    body: dict = {"raw_input": "\n".join(links), "dpi": dpi or "on", "core": core or ""}
    if unit_keys:
        body["selected_modems"] = unit_keys
    sub = await _paid("/vless", body, timeout=60, max_wait=60)
    tid, cost = sub.get("test_id"), int(sub.get("cost_credits") or 0)
    if cost > max_credits or spent_today() + cost > int(round(config.settings.bsbord_daily_rub * 100) or 10**12):
        c = await _req("POST", f"/vless/{tid}/cancel")
        return {"ok": False, "error": "over_limit", "test_id": tid, "cost_rub": rub(cost),
                "detail": f"тест стоил бы {rub(cost)} ₽ — выше потолка ({rub(max_credits)} ₽) или дневного лимита; "
                          f"отменён, возврат {rub(c.get('refunded_credits'))} ₽"}
    _spend("vless", tid, cost)
    out: dict[str, Any] = {"test_id": tid, "cost_rub": rub(cost), "n_servers": sub.get("n_servers"),
                           "n_units": sub.get("n_modems")}
    for k in ("skipped_unavailable", "skipped_dpi_off"):
        if sub.get(k):
            out[k] = sub[k]
    if not wait:
        return {"ok": True, "state": "queued", **out,
                "next": "результат — sim_result(kind='vless', id=test_id), бесплатно"}
    st = await _poll(f"/vless/{tid}", lambda d: d.get("result_ready") or d.get("state") in ("done", "cancelled"), 240)
    return {**_compact_vless(st), **out}


# ── FULL GEO: из каких городов открывается цель ───────────────────────────

def _geo_body(targets: list[str], network: str, district: str, region: str, isp: str,
              cities: list, city_limit: int, probe_mode: str, heavy: bool, core: str) -> dict:
    if not targets:
        raise BsError("no_targets", "нужна цель: домен/URL/IP и/или одна ссылка vless:// / hysteria2://")
    body: dict[str, Any] = {"targets": targets, "network": network or "mob", "probe_mode": probe_mode or "tls"}
    for k, v in (("district", district), ("region", region), ("isp", isp), ("core", core)):
        if v:
            body[k] = v
    if cities:
        body["cities"] = cities
    if city_limit:
        body["city_limit"] = int(city_limit)
    if heavy:
        body["heavy"] = True
    return body


def _compact_geo(st: dict) -> dict:
    rows = st.get("rows") or []
    order = {"blocked": 0, "throttled": 1, "partial": 2, "unconfirmed": 3, "target_error": 4,
             "port_blocked": 5, "ok": 6}
    compact = []
    for r in sorted(rows, key=lambda x: order.get(str(x.get("verdict")), 9)):
        v = r.get("verdict")
        if v in ("exit_bad", "no_ru_node", "no_udp"):
            continue  # шум сервиса, не результат (контракт API)
        bad = {k: (t.get("err_code") or t.get("err")) for k, t in (r.get("targets") or {}).items()
               if isinstance(t, dict) and not t.get("ok")}
        row = {"city": r.get("city"), "region": r.get("region"), "provider": r.get("provider"), "verdict": v}
        if bad:
            row["failed"] = bad
        compact.append(row)
    out = {"ok": True, "run_id": st.get("run_id") or st.get("id"), "state": st.get("state"),
           "progress": st.get("progress"), "by_verdict": st.get("by_verdict"),
           "conclusion": st.get("conclusion"), "charged_rub": rub(st.get("charged_credits")),
           "rows": compact[:80]}
    if len(compact) > 80:
        out["rows_truncated"] = len(compact) - 80
    return out


async def geo(targets: list[str], network: str, district: str, region: str, isp: str, cities: list,
              city_limit: int, probe_mode: str, heavy: bool, core: str, max_credits: int,
              confirm: bool, wait: bool) -> dict:
    body = _geo_body(targets, network, district, region, isp, cities, city_limit, probe_mode, heavy, core)
    pv = await _req("POST", "/geo/preview", body)
    reserve = int(pv.get("reserve_credits") or 0)
    if not confirm:
        return {"ok": True, "preview": True, "reserve_credits": reserve, "reserve_rub": rub(reserve),
                "n_cities": pv.get("n_nodes"), "estimated_sec": pv.get("estimated_sec"),
                "max_cities": pv.get("max_nodes"), **budget(),
                "note": "reserve — ПОТОЛОК; списывается факт по трафику, разница возвращается. "
                        "Запуск — с confirm=true и max_credits=reserve_credits"}
    _gate(reserve, max_credits)
    sub = await _paid("/geo/runs", body, timeout=60, max_wait=60)
    rid = sub.get("run_id")
    # В журнал — резерв: факт узнаем по завершении, до того считаем по потолку.
    _spend("geo", rid, reserve, "резерв")
    if not wait:
        return {"ok": True, "run_id": rid, "state": "running", "reserve_rub": rub(reserve),
                "estimated_sec": sub.get("estimated_sec"),
                "next": "результат — sim_result(kind='geo', id=run_id), бесплатно"}
    limit = min(float(sub.get("estimated_sec") or 120) + 60, 420)
    st = await _poll(f"/geo/runs/{rid}", lambda d: d.get("state") != "running", limit)
    if st.get("state") != "running":
        _settle_geo(rid, st.get("charged_credits"))
    return _compact_geo(st)


# ── Статус и отмена ────────────────────────────────────────────────────────

async def _poll(path: str, done, limit: float) -> dict:
    deadline = time.monotonic() + limit
    while True:
        st = await _req("GET", path)
        if done(st) or time.monotonic() > deadline:
            return st
        await asyncio.sleep(5)


async def result(kind: str, ref: str) -> dict:
    if kind == "vless":
        return _compact_vless(await _req("GET", f"/vless/{ref}"))
    if kind == "geo":
        st = await _req("GET", f"/geo/runs/{ref}")
        if st.get("state") != "running":
            _settle_geo(ref, st.get("charged_credits"))
        return _compact_geo(st)
    if kind == "scan":
        return await _req("GET", f"/scans/{ref}")
    raise BsError("bad_kind", "kind: vless | geo | scan (проба синхронная — её результат приходит сразу)")


async def cancel(kind: str, ref: str) -> dict:
    paths = {"vless": f"/vless/{ref}/cancel", "geo": f"/geo/runs/{ref}/cancel", "scan": f"/scans/{ref}/cancel"}
    if kind not in paths:
        raise BsError("bad_kind", "kind: vless | geo | scan")
    return {"ok": True, **await _req("POST", paths[kind])}
