"""Обслуживание нод Remnawave: разбор, действия, служебный юзер, подписка,
запасной путь. Мок панели — тот же, что у test_remna_edit (со состоянием)."""

import base64
import json
import urllib.parse

import pytest

from nexus_mcp import remna_ops as ops
from nexus_mcp import ssh
from test_remna_edit import ENTRY_IP, PROBE_VLESS, do, make_env, run


@pytest.fixture
def env(monkeypatch, hub_settings):
    """Мок панели — тот же, что у test_remna_edit."""
    return make_env(monkeypatch, hub_settings)


# ── X25519 ────────────────────────────────────────────────────────────────

def test_x25519_rfc7748_vector():
    """Публичный ключ Reality из приватного — вектор RFC 7748 (Алиса)."""
    priv = bytes.fromhex("77076d0a7318a57d3c16c17251b26645df4c2f87ebc0992ab177fba51db92c2a")
    pub = bytes.fromhex("8520f0098930a754748b7ddcb43ef75a0dbf3a0d26381af4eba4a98eaa9b4e6a")
    b64 = base64.urlsafe_b64encode(priv).decode().rstrip("=")
    assert ops.x25519_public(b64) == base64.urlsafe_b64encode(pub).decode().rstrip("=")


# ── служебный юзер и ссылки ───────────────────────────────────────────────

def _probe(panel):
    return next((u for u in panel.users.values() if u["username"] == ops.PROBE_USER), None)


def test_probe_user_in_client_squads_not_relay(env):
    panel, cf, sent = env
    do("nl01s1", "cf_exit", {})                       # появился сквад hub-relay-nl01s1
    pl = run(ops.probe_plan("pablo"))
    assert not pl["exists"] and "PabloWD" in pl["todo"] and "hub-relay" not in pl["todo"]
    assert run(ops.ensure_probe_user("pablo"))["ok"]
    u = _probe(panel)
    assert [x["uuid"] for x in u["activeInternalSquads"]] == ["sq-main"]
    assert u["expireAt"].startswith("2099")
    # Новый сквад клиентов — досыпается, старые не снимаются.
    panel.squads["sq-vip"] = {"uuid": "sq-vip", "name": "VIP", "info": {}, "inbounds": []}
    assert "VIP" in run(ops.probe_plan("pablo"))["todo"]
    run(ops.ensure_probe_user("pablo"))
    assert [x["uuid"] for x in _probe(panel)["activeInternalSquads"]] == ["sq-main", "sq-vip"]


def test_node_links_include_hidden_entry_with_real_pbk(env):
    panel, cf, sent = env
    do("nl01s1", "cf_exit", {})
    do("ru01s3", "cascade_entry", {"exit": "nl01s1", "sni": "ads.x5.ru"})   # строка скрыта
    with pytest.raises(ops.OpsError, match="hub-probe"):
        run(ops.node_links("pablo", "ru01s3"))
    run(ops.ensure_probe_user("pablo"))
    res = run(ops.node_links("pablo", "ru01s3"))
    assert len(res["links"]) == 2 and f"{ENTRY_IP}:8443" in res["targets"]
    entry = next(x for x in res["links"] if ":8443" in x)
    q = dict(urllib.parse.parse_qsl(urllib.parse.urlsplit(entry).query))
    assert entry.startswith(f"vless://{PROBE_VLESS}@{ENTRY_IP}:8443?")
    assert q["security"] == "reality" and q["fp"] == "firefox" and q["flow"] == "xtls-rprx-vision"
    priv = next(i for i in panel.profiles["p-ru"]["config"]["inbounds"]
                if i["tag"] == "HUB_CASCADE_NL01S1")["streamSettings"]["realitySettings"]
    assert q["pbk"] == ops.x25519_public(priv["privateKey"]) and q["sid"] == priv["shortIds"][0]
    # Ноды Remnawave — в SIM-проверке по имени «remna:панель/нода».
    assert ops.parse_remna_node("remna:pablo/ru01s3") == ("pablo", "ru01s3")
    assert ops.parse_remna_node("de-1") is None


def test_hysteria_link(env):
    panel, cf, sent = env
    run(ops.ensure_probe_user("pablo"))
    link = run(ops.node_links("pablo", "nl01s1"))["links"][0]
    assert link.startswith(f"hysteria2://{PROBE_VLESS}@nl01s1.pablo.support:443?")
    assert "alpn=h3" in link and "sni=nl01s1.pablo.support" in link


def test_sub_check_via_bot_page_without_links_in_answer(env, monkeypatch):
    panel, cf, sent = env
    run(ops.ensure_probe_user("pablo"))
    seen = {}
    good = f"vless://{PROBE_VLESS}@{ENTRY_IP}:443?security=reality&sni=ads.x5.ru&type=tcp#RU"
    hy = f"hysteria2://{PROBE_VLESS}@nl01s1.pablo.support:443?sni=nl01s1.pablo.support#NL"

    async def fetch_links(url=""):
        seen["url"] = url
        return [good, hy]

    async def batch(probe, jobs):
        seen["jobs"] = jobs
        return [{"ok": False, "error": "timeout", "stage": "handshake"}]

    from nexus_mcp import links, sweep
    monkeypatch.setattr(links, "fetch_links", fetch_links)
    monkeypatch.setattr(sweep, "_run_batch", batch)
    res = run(ops.sub_check("pablo", "home"))
    assert seen["url"] == "https://auth.pablovpn.com/sub/" + _probe(panel)["shortUuid"]
    assert res["lines"] == 2 and res["problems"] == 1
    assert [r["status"] for r in res["rows"]] == ["filtered", "udp_unchecked"]
    assert seen["jobs"][0]["args"]["sni"] == "ads.x5.ru"
    assert PROBE_VLESS not in json.dumps(res, ensure_ascii=False)


# ── разбор ноды ───────────────────────────────────────────────────────────

def test_diagnose_finds_what_breaks_silently(env, monkeypatch):
    panel, cf, sent = env
    rs = panel.profiles["p-ru"]["config"]["inbounds"][0]["streamSettings"]["realitySettings"]
    rs.pop("minClientVer")
    panel.hosts["h-ru"]["fingerprint"] = "chrome"

    async def run_script(node, script, timeout=45):
        sent["diag"] = script
        return ssh.SshResult(True, 0, "container=Up 3 hours\nrestarts=7\nlisten=tcp:2222,\n"
                                      "errors=failed to start: x|\nufw=active\ndisk_use=95%\n", "", 1.0)

    async def probe_run(probe, kind, args, timeout=40):
        return {"ok": probe == "hub", "error": None if probe == "hub" else "timeout", "stage": "connect"}

    from nexus_mcp.probes import registry
    monkeypatch.setattr(ssh, "run_script", run_script)
    monkeypatch.setattr(registry, "run", probe_run)
    res = run(ops.diagnose("pablo", "ru01s3", ["home"]))
    codes = {f["code"] for f in res["findings"]}
    assert res["verdict"] == "bad"
    assert {"min_client_ver", "fp_chrome", "not_listening", "restarts", "xray_errors", "disk",
            "unreachable"} <= codes
    assert res["findings"][0]["level"] == "bad"                 # плохое — первым
    assert [r["status"] for r in res["reach"]] == ["reachable", "down"]


def test_diagnose_checks_cascade_front_and_cert(env, monkeypatch):
    panel, cf, sent = env
    do("nl01s1", "cf_exit", {})

    async def run_script(node, script, timeout=45):
        return ssh.SshResult(True, 0, "container=Up 1 day\nrestarts=0\nlisten=udp:443,tcp:2087,\n"
                                      "cert_0=2\ncert_1=3000\n", "", 1.0)

    monkeypatch.setattr(ssh, "run_script", run_script)
    sent["handshake"] = 526
    res = run(ops.diagnose("pablo", "nl01s1"))
    texts = " | ".join(f["text"] for f in res["findings"])
    assert any(f["code"] == "cert_expiry" and f["level"] == "bad" for f in res["findings"])
    assert any(f["code"] == "cascade" for f in res["findings"]) and "526" in texts
    assert res["cascade"][0]["target"] == "nl01s1.pablo.stream:2087"


# ── действия ──────────────────────────────────────────────────────────────

def test_node_actions(env, hub_settings):
    panel, cf, sent = env
    pv = run(ops.action_plan("pablo", "ru01s3", "delete"))
    assert "необратимо" in pv["does"]
    with pytest.raises(ops.OpsError):
        run(ops.action_plan("pablo", "ru01s3", "reboot"))
    assert run(ops.action_run("pablo", "ru01s3", "disable"))["now"]["isDisabled"] is True
    assert ("POST", "/api/nodes/n-ru/actions/disable", None) in panel.calls
    assert run(ops.action_run("pablo", "ru01s3", "delete"))["ok"] and "n-ru" not in panel.nodes
    hub_settings.allow_actions = False
    assert run(ops.action_run("pablo", "ru02s3", "restart"))["error"] == "actions_disabled"


# ── запасной путь ─────────────────────────────────────────────────────────

def test_get_masks_links_and_trims(env):
    panel, cf, sent = env
    run(ops.ensure_probe_user("pablo"))
    for i in range(60):
        panel.hosts[f"x{i}"] = {"uuid": f"x{i}", "remark": str(i)}
    res = run(ops.get("pablo", "/api/users/by-username/hub-probe"))
    dump = json.dumps(res, ensure_ascii=False)
    assert PROBE_VLESS not in dump and "short-" not in dump
    hosts = run(ops.get("pablo", "api/hosts"))
    assert len(hosts) == ops.LIST_LIMIT + 1 and "ещё" in hosts[-1]
    with pytest.raises(ops.OpsError):
        run(ops.get("pablo", "/api/tokens"))
    with pytest.raises(ops.OpsError):
        run(ops.get("pablo", "/etc/passwd"))


def test_call_preview_then_run(env):
    panel, cf, sent = env
    pv = run(ops.call_plan("pablo", "patch", "/api/hosts", {"uuid": "h-ru", "remark": "RU new"}))
    assert pv["method"] == "PATCH" and not any(m == "PATCH" for m, _, _ in panel.calls)
    with pytest.raises(ops.OpsError):
        run(ops.call_plan("pablo", "GET", "/api/hosts"))
    with pytest.raises(ops.OpsError):
        run(ops.call_plan("pablo", "POST", "/api/auth/login", {}))
    res = run(ops.call_run("pablo", "PATCH", "/api/hosts", {"uuid": "h-ru", "remark": "RU new"}))
    assert res["ok"] and panel.hosts["h-ru"]["remark"] == "RU new"


def test_probe_speed_takes_remna_node_link_without_leaking_it(env, monkeypatch):
    """Замер по ноде Remnawave: ссылка hub-probe (и на скрытый вход каскада)
    уходит пробнику, но не в ответ; при нескольких строках нужен host."""
    from nexus_mcp import server, speed

    panel, cf, sent = env
    do("nl01s1", "cf_exit", {})
    do("ru01s3", "cascade_entry", {"exit": "nl01s1", "sni": "ads.x5.ru"})   # строка скрыта
    run(ops.ensure_probe_user("pablo"))
    started = {}

    def fake_start(probe, uri, *a, **k):
        started["uri"] = uri
        return {"running": False}

    monkeypatch.setattr(speed.runs, "start", fake_start)
    monkeypatch.setattr(speed.runs, "state", lambda probe: {"ok": True, "probe": probe, "host": "x"})
    res = run(server.probe_speed("hub", node="remna:pablo/ru01s3"))
    assert not res["ok"] and "host" in res["detail"] and f"{ENTRY_IP}:8443" in res["detail"]
    res = run(server.probe_speed("hub", node="remna:pablo/ru01s3", host=f"{ENTRY_IP}:8443"))
    assert res["ok"] and started["uri"].startswith(f"vless://{PROBE_VLESS}@{ENTRY_IP}:8443?")
    assert PROBE_VLESS not in json.dumps(res, ensure_ascii=False)
    res = run(server.probe_speed("hub", node="remna:pablo/ru01s3", host="8443"))
    assert res["ok"]


# ── приложение: панели Remnawave через чат хаба ──────────────────────────

def test_app_sees_remna_panels_through_chat(env, monkeypatch, hub_settings, tmp_path):
    """Приложение → nexus-chat → nexus-mcp → Remnawave: список, ноды, клиент.
    Токены панели в ответ не едут; чат принимает панель Remnawave и говорит
    Claude работать инструментами remna_*."""
    import asyncio

    import httpx

    from nexus_chat import app as chat_app
    from nexus_chat import config as chat_config
    from nexus_chat.runner import Runner, with_panel
    from nexus_chat.store import Store
    from nexus_mcp import server

    run(ops.ensure_probe_user("pablo"))
    cs = chat_config.ChatSettings()
    cs.token = "t" * 40
    cs.state_dir = tmp_path / "chat"
    cs.mcp_secret = "s" * 32
    cs.audit_at = []
    monkeypatch.setattr(chat_config, "settings", cs)
    hub_settings.public_hosts = []
    monkeypatch.setattr(chat_app, "_hub_transport", httpx.ASGITransport(app=server.build_app()))
    auth = {"authorization": "Bearer " + "t" * 40}

    async def go():
        cs.state_dir.mkdir(parents=True)
        app = chat_app.build_app(Runner(Store(cs.db_path), cs), start_background=False)
        async with httpx.AsyncClient(transport=httpx.ASGITransport(app=app), base_url="https://hub") as c:
            st = (await c.get("/chat/api/state", headers=auth)).json()
            assert st["remna_panels"] == ["pablo"]
            r = await c.get("/chat/api/remna", headers=auth)
            dump = r.text
            assert r.status_code == 200 and r.json()["panels"][0]["name"] == "pablo"
            assert "tok" not in json.loads(dump)["panels"][0].values() and "CF-TOKEN-SECRET" not in dump
            r = await c.get("/chat/api/remna/pablo/nodes", headers=auth)
            assert r.status_code == 200 and {n["name"] for n in r.json()["nodes"]} >= {"ru01s3", "nl01s1"}
            r = await c.get("/chat/api/remna/pablo/users", params={"q": "hub-probe"}, headers=auth)
            assert r.status_code == 200 and r.json()["users"][0]["username"] == "hub-probe"
            r = await c.get("/chat/api/remna/ghost/nodes", headers=auth)
            assert r.status_code == 404 and "pablo" in r.json()["detail"]
            r = await c.get("/chat/api/remna/pablo/tokens", headers=auth)
            assert r.status_code == 404
            r = await c.get("/chat/api/remna/pablo/nodes")
            assert r.status_code == 401

    asyncio.run(go())
    hint = with_panel("что с нодами?", "pablo")
    assert "remna_*" in hint and 'panel="pablo"' in hint and hint.endswith("что с нодами?")


def test_app_fields_contract(env):
    """Поля, которые читает приложение (admin_app/.../chat/RemnaModels.kt в
    vgx3d, сторож там — RemnaModelsTest). Переименование здесь не падает
    нигде: экран просто покажет прочерки (инвариант 25 vgx3d)."""
    from nexus_mcp import remna

    node = remna.node_view({"name": "x", "configProfile": {}})
    assert {"name", "address", "country", "connected", "disabled", "users_online",
            "traffic_used_gb", "status_message", "inbounds"} <= set(node)
    user = remna.user_view({"username": "u", "shortUuid": "s"}, "https://sub/")
    assert {"username", "telegram_id", "status", "expire_at", "device_limit", "traffic_used_gb",
            "traffic_limit_gb", "online_at", "squads", "sub_link"} <= set(user)
    assert {"name", "url", "sub_url", "cf_zone"} <= set(remna.public_view(
        {"name": "p", "url": "https://p", "token": "t"}))
    panel, cf, sent = env
    panel.stats = {"users": {"statusCounts": {"ACTIVE": 1}, "totalUsers": 1},
                   "onlineStats": {"onlineNow": 0, "lastDay": 1}}
    ov = run(remna.overview(remna.resolve("pablo")))
    assert {"panel", "version", "users", "users_total", "online_now", "online_day",
            "nodes_total", "nodes_online", "nodes_down"} <= set(ov)


def test_panel_findings_folds_per_client_items():
    """Сотня «клиент не подключался» — одна строка со счётчиком: иначе ответ
    центра состояния не влезает в контекст Claude (63–87 КБ на живых панелях)."""
    from nexus_mcp.server import compact_findings

    data = {"findings": [{"code": "node.offline", "scope": "node", "target_name": "nl"}],
            "signals": [{"code": "client.zero_traffic", "scope": "client", "severity": "warning",
                         "title": f"«u{i}» ни разу не подключился", "target_name": f"u{i}"} for i in range(70)]
            + [{"code": "node.rf_blocked", "scope": "node", "target_name": "fi"}],
            "nodes": [{"name": "nl", "link_history": [1] * 500, "stats": {"disk_percent": 40}}]}
    out = compact_findings(data)
    assert out["findings"] == data["findings"]
    folded = [s for s in out["signals"] if s.get("scope") == "clients"]
    assert len(out["signals"]) == 2 and folded[0]["count"] == 70 and len(folded[0]["examples"]) == 5
    assert "link_history" not in out["nodes"][0] and out["nodes"][0]["stats"]
