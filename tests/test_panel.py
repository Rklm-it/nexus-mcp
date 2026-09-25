"""Инструменты панели: маскировка секретов, белые списки, отказы с причиной,
и сторож на то, что каждая ручка, в которую ходит хаб, есть в коде панели."""

import asyncio
import json
import re

import httpx
import pytest

from nexus_mcp import panel

UUID = "11111111-2222-3333-4444-555555555555"


# ── Маскировка ─────────────────────────────────────────────────────────────

def test_redact_hides_secrets_but_keeps_shape():
    data = {
        "name": "de-1", "ip_address": "203.0.113.7",
        "api_token": "abcdefghijklmnopqrstuvwxyz",
        "reality_private_key": "PRIVATEKEYVALUE1234567890",
        "ss2022_password": "short",
        "has_api_token": True,
        "inbounds": [{"config": {"pbk": "PUBKEY-long-value-xxxx", "port": 443}}],
        "sub_url": "https://panel.ru/sub/AbCdEf123456789xyz",
    }
    out = panel.redact(data)
    dump = json.dumps(out)
    for secret in ("abcdefghijklmnopqrstuvwxyz", "PRIVATEKEYVALUE1234567890", "short",
                   "PUBKEY-long-value-xxxx", "123456789xyz"):
        assert secret not in dump, secret
    assert out["api_token"] == "abcd…"
    assert out["has_api_token"] is True          # метаданные не трогаем
    assert out["inbounds"][0]["config"]["port"] == 443
    assert out["sub_url"] == "https://panel.ru/sub/AbCdEf…"
    assert out["name"] == "de-1"


# ── Белые списки путей ─────────────────────────────────────────────────────

@pytest.mark.parametrize("path", [
    "/api/v1/admin/app/health", "api/v1/admin/dashboard", "/api/v1/servers",
    f"/api/v1/servers/{UUID}", "/health",
])
def test_read_paths_allowed(path):
    assert panel.check_read_path(path).startswith("/")


@pytest.mark.parametrize("path", [
    "/api/v1/sub/abc", "/sub/abc", "/api/v1/webhook/platega", "/api/v1/bot/x",
    "/api/v1/admin/../sub/x", "/api/v1/admin//x", "/api/v1/admin/x;rm",
])
def test_read_paths_denied(path):
    with pytest.raises(panel.PanelError):
        panel.check_read_path(path)


def test_action_allowlist():
    assert panel.check_action_path(f"/api/v1/admin/nodes/{UUID}/rf-check")
    assert panel.check_action_path(f"/api/v1/admin/nodes/{UUID}/restart/xray")
    for bad in (f"/api/v1/admin/nodes/{UUID}/restart/sshd", f"/api/v1/admin/users/{UUID}",
                "/api/v1/admin/users/bulk", "/api/v1/admin/system/update",
                "/api/v1/admin/payments/cleanup"):
        with pytest.raises(panel.PanelError):
            panel.check_action_path(bad)


# ── Запросы: настоящий httpx на подменном транспорте ───────────────────────

def _mock(monkeypatch, handler):
    real = httpx.AsyncClient

    def factory(*a, **kw):
        kw["transport"] = httpx.MockTransport(handler)
        return real(*a, **kw)

    monkeypatch.setattr(panel.httpx, "AsyncClient", factory)


def test_request_sends_admin_token_and_redacts(hub_settings, monkeypatch):
    hub_settings.brain_url = "https://panel.example.ru"
    hub_settings.brain_admin_token = "ADMIN"
    seen = {}

    def handler(req: httpx.Request):
        seen["token"] = req.headers.get("x-admin-token")
        seen["url"] = str(req.url)
        return httpx.Response(200, json={"servers": [{"name": "n", "api_token": "x" * 40}]})

    _mock(monkeypatch, handler)
    out = asyncio.run(panel.get("/api/v1/admin/app/health", {"fresh": True, "empty": ""}))
    assert seen["token"] == "ADMIN"
    assert seen["url"] == "https://panel.example.ru/api/v1/admin/app/health?fresh=true"
    assert out["servers"][0]["api_token"] == "xxxx…"


def test_basic_auth_refusal_names_the_fix(hub_settings, monkeypatch):
    hub_settings.brain_url = "https://p.ru"
    hub_settings.brain_admin_token = "A"
    _mock(monkeypatch, lambda req: httpx.Response(
        401, text="Unauthorized", headers={"www-authenticate": 'Basic realm="x"'}))
    with pytest.raises(panel.PanelError, match="VPN_PANEL_GATE_SECRET"):
        asyncio.run(panel.get("/api/v1/admin/dashboard"))


def test_big_list_is_truncated_with_note(hub_settings, monkeypatch):
    hub_settings.brain_url = "https://p.ru"
    hub_settings.brain_admin_token = "A"
    rows = [{"id": i, "note": "x" * 500} for i in range(1000)]
    _mock(monkeypatch, lambda req: httpx.Response(200, json=rows))
    out = asyncio.run(panel.get("/api/v1/admin/users"))
    assert "truncated" in out and len(out["items"]) < 1000
    assert len(json.dumps(out)) <= panel.MAX_CHARS * 1.2


def test_health_keeps_every_check_when_logs_are_huge(hub_settings, monkeypatch):
    """Мегабайт хвостов логов в /app/health вытеснял все группы («обрезано»),
    и модель не видела, какая проверка красная. Проверки остаются, хвосты —
    только у не-ok и короткие."""
    from nexus_mcp import server

    hub_settings.brain_url = "https://p.ru"
    hub_settings.brain_admin_token = "A"
    log = ["x" * 2000] * 400
    body = {"status": "error", "counts": {"error": 1, "ok": 1}, "groups": [
        {"key": "containers", "title": "Контейнеры", "status": "error", "checks": [
            {"key": "bot", "title": "bot", "status": "error", "detail": "упал", "lines": log},
            {"key": "api", "title": "api", "status": "ok", "detail": "ok", "lines": log},
        ]},
    ]}
    _mock(monkeypatch, lambda req: httpx.Response(200, json=body))
    r = asyncio.run(server.panel_health())
    checks = r["data"]["groups"][0]["checks"]
    assert [c["key"] for c in checks] == ["bot", "api"]
    assert len(checks[0]["lines"]) == panel.HEALTH_LINES
    assert len(checks[0]["lines"][0]) == panel.HEALTH_LINE_CHARS
    assert "lines" not in checks[1]
    assert len(json.dumps(r, ensure_ascii=False)) < panel.MAX_CHARS


def test_health_fields_match_panel(vgx3d):
    """compact_health опирается на поля ответа панели — сверяем с её кодом."""
    text = (vgx3d / "brain/app/services/app_health.py").read_text(encoding="utf-8")
    for field in ('"groups"', '"checks"', "lines: list[str]", "status: str"):
        assert field in text, field


def test_panel_not_configured_is_a_reason(hub_settings):
    from nexus_mcp import server

    r = asyncio.run(server.panel_health())
    assert r["ok"] is False and "nexus-mcp-panels add" in r["detail"]


def test_panel_action_gated(hub_settings, monkeypatch):
    from nexus_mcp import server

    path = f"/api/v1/admin/nodes/{UUID}/rf-check"
    assert asyncio.run(server.panel_action(path, confirm=True))["error"] == "actions_disabled"
    hub_settings.allow_actions = True
    assert asyncio.run(server.panel_action(path))["error"] == "need_confirm"
    assert asyncio.run(server.panel_action("/api/v1/admin/system/update", confirm=True))["ok"] is False


# ── Сторож: ручки существуют в панели ──────────────────────────────────────

# (файл роутера в vgx3d, префикс роутера, путь ручки) — всё, что хаб зовёт
# по фиксированному адресу. Переименуют в панели — упадёт здесь, а не 404 у хаба.
ROUTES = [
    ("brain/app/api/v1/admin/mobile.py", "/app", "/health"),
    ("brain/app/api/v1/admin/mobile.py", "/app", "/overview"),
    ("brain/app/api/v1/admin/monitoring.py", "/monitoring", "/overview"),
    ("brain/app/api/v1/admin/monitoring.py", "/monitoring", "/regions"),
    ("brain/app/api/v1/admin/nodes.py", "/nodes", "/versions"),
    ("brain/app/api/v1/admin/nodes.py", "/nodes", "/{server_id}/rf-check"),
    ("brain/app/api/v1/admin/nodes.py", "/nodes", "/{server_id}/restart/{service}"),
    ("brain/app/api/v1/admin/user_diagnose.py", "/users", "/{user_id}/diagnose-links"),
    ("brain/app/api/v1/admin/inbound_diagnose.py", "/inbounds", "/{inbound_id}/diagnose"),
    ("brain/app/api/v1/admin/logs.py", "", "/logs/brain"),
    ("brain/app/api/v1/admin/logs.py", "", "/logs/node/{server_id}"),
    ("brain/app/api/v1/admin/payments.py", "", "/payments"),
    ("brain/app/api/v1/admin/resync.py", "/resync", "/run"),
    ("brain/app/api/v1/servers.py", "", "/{server_id}/reachability"),
]


@pytest.mark.parametrize("fname,prefix,route", ROUTES)
def test_panel_routes_exist(vgx3d, fname, prefix, route):
    text = (vgx3d / fname).read_text(encoding="utf-8")
    if prefix:
        assert f'prefix="{prefix}"' in text, f"{fname}: префикс {prefix} сменился"
    assert re.search(r'@router\.(get|post)\(\s*"' + re.escape(route) + '"', text), \
        f"{fname}: нет ручки {route}"


def test_restart_services_match_panel(vgx3d):
    """Панель перезапускает только xray и hysteria-server — список хаба тот же."""
    text = (vgx3d / "brain/app/api/v1/admin/nodes.py").read_text(encoding="utf-8")
    m = re.search(r'if service not in \{([^}]*)\}', text)
    panel_set = set(re.findall(r'"([^"]+)"', m.group(1)))
    hub = re.search(r"restart/\(([^)]*)\)", "".join(panel.ACTION_PATTERNS)).group(1)
    assert set(hub.split("|")) == panel_set
