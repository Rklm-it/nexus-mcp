"""SIM-проверки bschekbot: деньги под контролем и честный разбор ответа.

bsbord.com подменён httpx.MockTransport по контракту API v1.1. Проверяется
поведение: сколько платных запросов ушло и с каким Idempotency-Key, что
попало в журнал расходов, что увидит Claude (инвариант 28).
"""

from __future__ import annotations

import asyncio
import json

import httpx
import pytest

from nexus_mcp import bsbord

PREVIEW = {"cost_credits": 240, "full_credits": 240, "n_targets": 1,
           "selected_units": ["mts|цфо|on", "beeline|цфо|on"], "breakdown": {}}

PROBE = {
    "outcome": "done", "cost_credits": 240, "refunded": 0, "n_targets": 1,
    "operators": ["mts|цфо|on", "beeline|цфо|on"],
    "by_target": {"203.0.113.7:443": {"target_resolved": "203.0.113.7", "is_domain": False, "by_operator": {
        "mts|цфо|on": {"ok": True, "operator": "mts", "region": "ЦФО", "dpi": "on", "channel_state": "DPI_ON",
                       "error": None, "tcp_is_tls": True,
                       "icmp": {"ok": False, "sent": 4, "received": 0, "loss_pct": 100},
                       "tcp": {"ok": False, "received": 0, "total": 3, "verdict": "reset_after_handshake"},
                       "sni": None, "http": None},
        "beeline|цфо|on": {"ok": True, "operator": "beeline", "region": "ЦФО", "dpi": "on", "channel_state": "DPI_ON",
                           "error": None, "tcp_is_tls": False,
                           "icmp": {"ok": True, "sent": 4, "received": 4, "loss_pct": 0, "rtt_avg_ms": 41},
                           "tcp": {"ok": True, "received": 3, "total": 3, "error": None},
                           "sni": None,
                           "http": {"ok": True, "url": "http://203.0.113.7", "status": 302,
                                    "location": "http://warning.rt.ru", "body_head": ""}},
    }}},
}


class Fake:
    """bsbord.com по контракту: считает запросы и ключи идемпотентности."""

    def __init__(self):
        self.calls: list[tuple[str, str, dict, str | None]] = []
        self.in_progress = 0
        self.rate_limited = 0
        self.vless_cost = 300

    def handler(self, request: httpx.Request) -> httpx.Response:
        body = json.loads(request.content or b"{}")
        idem = request.headers.get("idempotency-key")
        self.calls.append((request.method, request.url.path, body, idem))
        assert request.headers["authorization"] == "Bearer bsk_live_test"
        path = request.url.path.removeprefix("/v1")
        if path == "/probe/preview":
            return httpx.Response(200, json=PREVIEW)
        if path == "/probe":
            if not idem:
                return _err(400, "idempotency_key_required")
            if self.rate_limited:
                self.rate_limited -= 1
                return _err(429, "rate_limited", retry_after=0.01, retryable=True)
            if self.in_progress:
                self.in_progress -= 1
                return _err(409, "request_in_progress", retryable=False)
            return httpx.Response(200, json=PROBE)
        if path == "/vless":
            return httpx.Response(200, json={"outcome": "queued", "test_id": 88, "cost_credits": self.vless_cost,
                                             "n_servers": 1, "n_modems": 3, "configs": []})
        if path == "/vless/88/cancel":
            return httpx.Response(200, json={"test_id": 88, "cancelled": True, "stopped_legs": 0,
                                             "refunded_credits": self.vless_cost})
        if path == "/vless/88":
            return httpx.Response(200, json={"test_id": 88, "state": "done", "result_ready": True, "result": [
                {"ok": False, "stage": "tls", "server_name": "de-1", "operator": "mts", "region": "ЦФО",
                 "channel_state": "DPI_ON", "tunnel_up": False, "fail_reason": "reset после ClientHello"}]})
        if path == "/geo/preview":
            return httpx.Response(200, json={"n_nodes": 30, "reserve_credits": 500, "estimated_sec": 50, "max_nodes": 300})
        if path == "/geo/runs":
            return httpx.Response(200, json={"outcome": "queued", "run_id": 812, "state": "running",
                                             "n_nodes": 30, "reserve_credits": 500, "estimated_sec": 1})
        if path == "/geo/runs/812":
            return httpx.Response(200, json={"run_id": 812, "state": "done", "charged_credits": 120,
                                             "by_verdict": {"ok": 1, "blocked": 1, "exit_bad": 1}, "rows": [
                {"city": "moscow", "region": "moscow", "provider": "mts", "verdict": "ok", "targets": {}},
                {"city": "kazan", "region": "tatarstan", "provider": "beeline", "verdict": "blocked",
                 "targets": {"203.0.113.7:443": {"ok": False, "err_code": "tls_reset"}}},
                {"city": "omsk", "region": "omsk", "provider": "x", "verdict": "exit_bad", "targets": {}}]})
        if path == "/operators":
            return httpx.Response(200, json={"units": [
                {"op_key": "mts|цфо|on", "operator": "mts", "name": "МТС", "region": "ЦФО", "dpi": "on",
                 "channel_state": "DPI_ON", "probeable": True},
                {"op_key": "mts|цфо|off", "operator": "mts", "name": "МТС", "region": "ЦФО", "dpi": "off",
                 "channel_state": "DPI_OFF", "probeable": True}], "n_units": 2, "n_probeable": 2})
        return _err(404, "not_found")

    def paid(self, path: str) -> list:
        return [c for c in self.calls if c[0] == "POST" and c[1] == "/v1" + path]


def _err(status: int, code: str, **details) -> httpx.Response:
    return httpx.Response(status, json={"error": {"code": code, "message": code.replace("_", " "),
                                                  "details": {"request_id": "req-1", **details}}})


@pytest.fixture
def fake(hub_settings, monkeypatch):
    hub_settings.bsbord_key = "bsk_live_test"
    hub_settings.bsbord_url = "https://bsbord.test/v1"
    hub_settings.bsbord_daily_rub = 10.0
    f = Fake()
    monkeypatch.setattr(bsbord, "_TRANSPORT", httpx.MockTransport(f.handler))
    return f


def _probe(**kw):
    args = dict(targets=["203.0.113.7:443"], unit_keys=["*|цфо|on"], dpi="on", probes=["icmp", "tcp"],
                sni_hosts=[], max_credits=0, confirm=False)
    args.update(kw)
    return asyncio.run(bsbord.probe(**args))


def test_preview_spends_nothing(fake):
    r = _probe()
    assert r["preview"] and r["cost_rub"] == 2.4
    assert fake.paid("/probe") == []
    assert bsbord.spent_today() == 0


def test_confirm_without_cap_is_refused_before_paying(fake):
    with pytest.raises(bsbord.BsError) as e:
        _probe(confirm=True)
    assert e.value.code == "need_max_credits"
    assert fake.paid("/probe") == []


def test_price_above_cap_is_refused(fake):
    with pytest.raises(bsbord.BsError) as e:
        _probe(confirm=True, max_credits=100)
    assert e.value.code == "price_changed"
    assert fake.paid("/probe") == []


def test_daily_cap_blocks_run(fake, hub_settings):
    hub_settings.bsbord_daily_rub = 3.0
    _probe(confirm=True, max_credits=240)           # 2.40 ₽ из 3 ₽
    with pytest.raises(bsbord.BsError) as e:
        _probe(confirm=True, max_credits=240)       # ещё 2.40 — сверх потолка
    assert e.value.code == "daily_cap"
    assert len(fake.paid("/probe")) == 1
    assert bsbord.spent_today() == 240


def test_run_reports_blocked_operator_and_stub(fake):
    r = _probe(confirm=True, max_credits=240)
    legs = {l["unit"]: l for l in r["targets"]["203.0.113.7:443"]["legs"]}
    assert legs["mts|цфо|on"]["reachable"] is False
    assert "reset_after_handshake" in legs["mts|цфо|on"]["tcp"]
    assert legs["beeline|цфо|on"]["reachable"] is True
    # «Ответ получен» — не «сайт работает»: заглушку оператора видно.
    assert legs["beeline|цфо|on"]["http"]["location"] == "http://warning.rt.ru"
    assert r["summary"] == ["203.0.113.7:443: доступна 1/2; НЕ доступна: mts|цфо|on"]
    assert bsbord.spent_today() == 240


def test_retries_keep_the_same_idempotency_key(fake):
    """429 и «запрос ещё идёт» — повтор тем же ключом: новый ключ оплатил бы
    вторую проверку."""
    fake.rate_limited = 1
    fake.in_progress = 1
    orig_sleep = asyncio.sleep

    async def fast(_s):
        await orig_sleep(0)

    bsbord.asyncio.sleep = fast
    try:
        r = _probe(confirm=True, max_credits=240)
    finally:
        bsbord.asyncio.sleep = orig_sleep
    calls = fake.paid("/probe")
    assert len(calls) == 3
    assert len({c[3] for c in calls}) == 1 and calls[0][3]
    assert r["ok"] and bsbord.spent_today() == 240


def test_error_envelope_reaches_claude(fake, hub_settings):
    hub_settings.bsbord_key = ""
    with pytest.raises(bsbord.BsError) as e:
        _probe()
    assert "NEXUS_BSBORD_KEY" in e.value.message
    hub_settings.bsbord_key = "bsk_live_test"
    with pytest.raises(bsbord.BsError) as e:
        asyncio.run(bsbord.result("geo", "999"))
    d = e.value.as_dict()
    assert d["error"] == "not_found" and d["http"] == 404 and d["request_id"] == "req-1"


def test_vless_over_cap_is_cancelled_at_once(fake):
    fake.vless_cost = 900
    r = asyncio.run(bsbord.vless(["vless://u@203.0.113.7:443?security=reality#de-1"], [], "on", "",
                                 max_credits=500, confirm=True, wait=True))
    assert r["error"] == "over_limit"
    assert fake.paid("/vless/88/cancel")
    assert bsbord.spent_today() == 0


def test_vless_result_names_the_failure(fake):
    r = asyncio.run(bsbord.vless(["vless://u@203.0.113.7:443?security=reality#de-1"], ["mts|цфо|on"], "on", "",
                                 max_credits=500, confirm=True, wait=True))
    assert r["summary"].startswith("работает 0/1")
    assert "reset после ClientHello" in r["summary"]
    assert bsbord.spent_today() == 300


def test_geo_settles_reserve_to_fact_and_hides_noise(fake):
    r = asyncio.run(bsbord.geo(["https://example.com"], "mob", "ЦФО", "", "", [], 30, "tls", False, "",
                               max_credits=500, confirm=True, wait=True))
    assert [x["verdict"] for x in r["rows"]] == ["blocked", "ok"]   # exit_bad — шум, не результат
    assert r["rows"][0]["failed"] == {"203.0.113.7:443": "tls_reset"}
    assert bsbord.spent_today() == 120                                # резерв 500 → факт 120
    asyncio.run(bsbord.result("geo", "812"))                          # повторный опрос не правит дважды
    assert bsbord.spent_today() == 120


def test_units_grouped_for_reading(fake):
    r = asyncio.run(bsbord.units())
    assert r["by_operator"] == {"mts": ["ЦФО (БС)", "ЦФО (без БС)"]}
    assert fake.calls[-1][1] == "/v1/operators"
