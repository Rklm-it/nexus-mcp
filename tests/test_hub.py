"""Хаб диагностики: авторизация, рецепты, находки, пробники, инвентарь.

Проверяется поведение, а не факт вызова (инвариант 28): настоящие сокеты
для проб, настоящий bash для рецептов, настоящий ASGI для авторизации.
"""

import asyncio
import base64
import json
import re
import socket
import subprocess
import threading
from pathlib import Path

import pytest

from nexus_mcp import diagnose, inventory, links, recipes, ssh
from nexus_mcp.probes import HUB, Registry, probe_lib



# ── Авторизация ────────────────────────────────────────────────────────────

async def _asgi(app, path, headers=None):
    sent = []

    async def receive():
        return {"type": "http.request", "body": b"", "more_body": False}

    async def send(msg):
        sent.append(msg)

    scope = {"type": "http", "path": path, "raw_path": path.encode(), "method": "GET",
             "headers": [(k.encode(), v.encode()) for k, v in (headers or {}).items()],
             "query_string": b""}
    await app(scope, receive, send)
    return sent[0]["status"], scope


def _auth_app():
    from nexus_mcp.server import AuthMiddleware

    seen = {}

    async def inner(scope, receive, send):
        seen["path"] = scope["path"]
        await send({"type": "http.response.start", "status": 200, "headers": []})
        await send({"type": "http.response.body", "body": b"ok"})

    return AuthMiddleware(inner, "s" * 32, ["probe-token"]), seen


def test_auth_secret_in_path_rewrites_to_mcp():
    app, seen = _auth_app()
    status, _ = asyncio.run(_asgi(app, "/mcp/" + "s" * 32))
    assert status == 200
    assert seen["path"] == "/mcp"


def test_auth_rejects_wrong_secret_and_hides_itself():
    app, seen = _auth_app()
    assert asyncio.run(_asgi(app, "/mcp/" + "x" * 32))[0] == 404
    assert asyncio.run(_asgi(app, "/mcp"))[0] == 401
    assert asyncio.run(_asgi(app, "/"))[0] == 404
    assert "path" not in seen


def test_auth_bearer_and_probe_tokens_are_separate():
    app, _ = _auth_app()
    assert asyncio.run(_asgi(app, "/mcp", {"authorization": "Bearer " + "s" * 32}))[0] == 200
    # Токен пробника открывает только /probe/*, но не MCP.
    assert asyncio.run(_asgi(app, "/probe/poll", {"authorization": "Bearer probe-token"}))[0] == 200
    assert asyncio.run(_asgi(app, "/mcp", {"authorization": "Bearer probe-token"}))[0] == 401
    assert asyncio.run(_asgi(app, "/probe/poll", {"authorization": "Bearer nope"}))[0] == 401


def test_hub_refuses_to_start_without_secret(hub_settings):
    from nexus_mcp import server

    hub_settings.secret = "short"
    with pytest.raises(SystemExit):
        server.build_app()


# ── Рецепты ────────────────────────────────────────────────────────────────

@pytest.mark.parametrize("call", [
    lambda: recipes.logs("sshd"),
    lambda: recipes.logs("xray", lines=100000),
    lambda: recipes.capture("1.2.3.4; rm -rf /"),
    lambda: recipes.set_brain_url("https://x.ru/$(id)"),
    lambda: recipes.restart("docker"),
])
def test_recipes_reject_bad_params(call):
    with pytest.raises(recipes.RecipeError):
        call()


def _run_local(script: str, cell: Path) -> str:
    script = script.replace(f"CELL={recipes.CELL_DIR}", f"CELL={cell}")
    return subprocess.run(["bash", "-c", script], capture_output=True, text=True, timeout=60).stdout


def test_overview_runs_and_never_prints_token(tmp_path):
    cell = tmp_path / "cell"
    (cell / "agent").mkdir(parents=True)
    (cell / "agent" / "VERSION").write_text("3.1.4\n")
    (cell / "agent" / "uplink.py").write_text("")
    (cell / ".env").write_text('CELL_API_TOKEN="top-secret-token"\nCELL_API_PORT=9\n')
    out = _run_local(recipes.overview(), cell)
    assert "top-secret-token" not in out
    ov = recipes.parse_overview(out)
    assert ov["agent_version"] == "3.1.4"
    assert ov["has_uplink"] == "yes"
    assert ov["has_api_token"] == "yes"
    assert ov["brain_url"] == ""
    assert "heartbeat" in ov["logs"]


def test_env_redacted_masks_secrets(tmp_path):
    cell = tmp_path / "cell"
    cell.mkdir()
    (cell / ".env").write_text("CELL_API_TOKEN=abc\nCELL_BRAIN_TOKEN=def\nCELL_API_PORT=9090\n")
    out = _run_local(recipes.env_redacted(), cell)
    assert "abc" not in out and "def" not in out
    assert "CELL_API_PORT=9090" in out


def test_set_brain_url_rewrites_env(tmp_path):
    cell = tmp_path / "cell"
    (cell / "agent").mkdir(parents=True)
    (cell / ".env").write_text("CELL_BRAIN_URL=http://old\nCELL_API_PORT=9090\n")
    script = recipes.set_brain_url("https://panel.example.ru").replace("systemctl", "true")
    out = _run_local(script, cell)
    env = (cell / ".env").read_text()
    assert env.count("CELL_BRAIN_URL=") == 1
    assert "CELL_BRAIN_URL=https://panel.example.ru" in env
    assert "WARN_OLD_AGENT" in out  # uplink.py нет — предупреждает


def test_update_script_is_downloaded_before_run():
    s = recipes.update_agent("https://panel.example.ru/")
    # Инвариант 32: не `bash <(curl …)`, а скачать целиком и потом выполнить.
    assert "<(curl" not in s
    assert s.index("curl -fsSL") < s.index("bash $F")
    # Скрипт — с панели (открытый путь, как у «Обновить агент» в панели),
    # не из GitHub: репозиторий панели приватный.
    assert "https://panel.example.ru/install/cell-update.sh" in s
    assert "github" not in s
    assert subprocess.run(["bash", "-n"], input=s, text=True).returncode == 0


def test_update_agent_rejects_bad_panel_url():
    with pytest.raises(recipes.RecipeError):
        recipes.update_agent("https://p.ru; rm -rf /")


def test_update_done_mark_matches_update_scripts(vgx3d):
    """Отметка конца — из настоящих скриптов обновления: панельного (его хаб
    и запускает) и cell/cell-update.sh. Разойдутся — хаб будет считать
    успешное обновление оборванным (или наоборот)."""
    panel = (vgx3d / "brain/app/api/v1/cell_update.py").read_text(encoding="utf-8")
    assert '@router.get("/install/cell-update.sh"' in panel
    assert recipes.UPDATE_DONE_MARK in panel
    assert recipes.UPDATE_DONE_MARK in (vgx3d / "cell/cell-update.sh").read_text(encoding="utf-8")


def test_xray_json_copy_matches_panel(vgx3d):
    """Сборщик конфигов в хабе — побайтовая копия панельного (инвариант 25).
    Упало — скопируйте brain/app/services/xray_json.py в nexus_mcp/."""
    hub = Path(__file__).resolve().parents[1] / "nexus_mcp" / "xray_json.py"
    assert hub.read_bytes() == (vgx3d / "brain/app/services/xray_json.py").read_bytes()


def test_recipe_paths_match_cell_installer(vgx3d):
    text = (vgx3d / "cell" / "cell-setup.sh").read_text(encoding="utf-8")
    assert f'CELL_DIR="{recipes.CELL_DIR}"' in text
    assert recipes.XRAY_CONFIG.rsplit("/", 1)[0] in text
    for svc in recipes.SERVICES:
        assert f"{svc}.service" in text or f"enable {svc}" in text


# ── SSH: классификация отказов ─────────────────────────────────────────────

@pytest.mark.parametrize("stderr,rc,expected", [
    ("ssh: connect to host 1.2.3.4 port 22: Connection timed out", 255, "timeout"),
    ("ssh: connect to host 1.2.3.4 port 22: Connection refused", 255, "refused"),
    ("root@1.2.3.4: Permission denied (publickey).", 255, "auth"),
    ("Host key verification failed.", 255, "hostkey"),
    ("kex_exchange_identification: read: Connection reset by peer", 255, "timeout"),
    ("ssh: connect to host x port 22: No route to host", 255, "unreachable"),
    ("что-то новое", 255, "ssh_error"),
    ("", 1, "remote_error"),
    ("", 0, None),
])
def test_ssh_classify(stderr, rc, expected):
    assert ssh.classify(stderr, rc) == expected


# ── Находки по ноде ────────────────────────────────────────────────────────

def _ov(**kw):
    base = {"svc_vpn-cell": "active", "svc_xray": "active", "svc_hysteria-server": "active",
            "has_uplink": "yes", "brain_url": "https://p.ru", "brain_heartbeat_path": "422",
            "brain_basic_auth": "no", "local_health": "200", "disk_pct": "20", "mem_pct": "30",
            "logs": {"heartbeat": ["Обратный канал открыт: wss://p.ru"]}}
    base.update(kw)
    return base


def _codes(findings):
    return {f["code"] for f in findings}


def test_node_healthy_has_no_crit():
    f = diagnose.node_findings(_ov(), "https://p.ru")
    assert not [x for x in f if x["level"] == diagnose.CRIT]
    assert {"panel_reachable", "uplink_open"} <= _codes(f)


@pytest.mark.parametrize("override,code", [
    ({"has_uplink": "no"}, "old_agent"),
    ({"brain_url": ""}, "no_brain_url"),
    ({"brain_heartbeat_path": "000"}, "node_cant_reach_panel"),
    ({"brain_heartbeat_path": "401", "brain_basic_auth": "yes"}, "heartbeat_behind_basic_auth"),
    ({"brain_heartbeat_path": "502"}, "heartbeat_route_broken"),
    ({"svc_vpn-cell": "failed"}, "agent_down"),
    ({"svc_xray": "inactive"}, "xray_down"),
    ({"logs": {"heartbeat": ["heartbeat: панель не приняла токен ноды (401)"]}}, "bad_token"),
])
def test_node_findings_name_the_cause(override, code):
    assert code in _codes(diagnose.node_findings(_ov(**override), "https://p.ru"))


def test_every_crit_has_fix():
    for override in ({"has_uplink": "no"}, {"brain_url": ""}, {"brain_heartbeat_path": "000"},
                     {"svc_vpn-cell": "failed"}, {"svc_xray": "failed"}):
        for f in diagnose.node_findings(_ov(**override), "https://p.ru"):
            if f["level"] == diagnose.CRIT:
                assert f.get("fix"), f["code"]


# ── Настоящие сокеты: баннер, фильтр данных, TLS ───────────────────────────

class _Server:
    """Локальный TCP-сервер: `banner` — шлёт первым; `silent` — молчит,
    как нода за фильтром, режущим пакеты с данными."""

    def __init__(self, mode: str):
        self.sock = socket.socket()
        self.sock.bind(("127.0.0.1", 0))
        self.sock.listen(5)
        self.port = self.sock.getsockname()[1]
        self.mode = mode
        self.conns = []
        threading.Thread(target=self._loop, daemon=True).start()

    def _loop(self):
        while True:
            try:
                c, _ = self.sock.accept()
            except OSError:
                return
            self.conns.append(c)
            if self.mode == "banner":
                c.sendall(b"SSH-2.0-OpenSSH_9.6\r\n")

    def close(self):
        for c in self.conns:
            c.close()
        self.sock.close()


def test_banner_distinguishes_payload_filter_from_live_sshd():
    lib = probe_lib()
    live, silent = _Server("banner"), _Server("silent")
    try:
        ok = lib.probe_banner("127.0.0.1", live.port, timeout=2)
        cut = lib.probe_banner("127.0.0.1", silent.port, timeout=1)
    finally:
        live.close()
        silent.close()
    assert ok["ok"] and ok["banner"].startswith("SSH-2.0")
    assert not cut["ok"] and cut["stage"] == "data" and cut["error"] == "timeout"


def test_tls_timeout_is_reported_as_frozen_handshake():
    lib = probe_lib()
    silent = _Server("silent")
    try:
        r = lib.probe_tls("127.0.0.1", silent.port, timeout=1)
    finally:
        silent.close()
    assert r["stage"] == "handshake" and r["error"] == "timeout"
    assert "ClientHello" in r["detail"]


def test_refused_port():
    lib = probe_lib()
    s = socket.socket()
    s.bind(("127.0.0.1", 0))
    port = s.getsockname()[1]
    s.close()
    assert lib.probe_tcp("127.0.0.1", port, timeout=1)["error"] == "refused"


def test_reach_verdict_payload_filtered():
    r = {"tcp_ssh": {"ok": True}, "banner_ssh": {"ok": False, "stage": "data", "error": "timeout"},
         "tls_443": {"ok": False, "stage": "handshake", "error": "timeout"}}
    v = diagnose.reach_verdict("hub", r)
    assert v["code"] == "payload_filtered" and v["level"] == diagnose.CRIT


def test_reach_verdict_unreachable_and_ok():
    dead = {"tcp_ssh": {"ok": False, "error": "timeout"},
            "banner_ssh": {"ok": False, "stage": "connect", "error": "timeout"},
            "tls_443": {"ok": False, "stage": "connect", "error": "timeout"}}
    assert diagnose.reach_verdict("hub", dead)["code"] == "ip_unreachable"
    live = {"tcp_ssh": {"ok": True}, "banner_ssh": {"ok": True, "banner": "SSH-2.0"},
            "tls_443": {"ok": False, "stage": "handshake", "error": "ssl_error"}}
    assert diagnose.reach_verdict("hub", live)["code"] == "ip_reachable"
    ssh_closed = {"tcp_ssh": {"ok": False, "error": "timeout"},
                  "banner_ssh": {"ok": False, "stage": "connect", "error": "timeout"},
                  "tls_443": {"ok": True}}
    assert diagnose.reach_verdict("hub", ssh_closed)["code"] == "ssh_port_closed"


# ── Пробники ───────────────────────────────────────────────────────────────

def test_probe_roundtrip_through_registry():
    reg = Registry()

    async def scenario():
        poll = asyncio.create_task(reg.poll("home", {"xray": None}, "10.0.0.1", hold=5))
        await asyncio.sleep(0.05)
        run = asyncio.create_task(reg.run("home", "tcp", {"host": "x", "port": 1}, timeout=5))
        jobs = await poll
        assert jobs and jobs[0]["kind"] == "tcp"
        assert reg.result("home", jobs[0]["id"], {"ok": True, "ms": 1})
        return await run

    assert asyncio.run(scenario()) == {"ok": True, "ms": 1}


def test_probe_timeout_is_a_result_not_a_hang():
    reg = Registry()

    async def scenario():
        await reg.poll("home", None, "", hold=0.01)  # пробник отметился
        return await reg.run("home", "tcp", {"host": "x", "port": 1}, timeout=0.2)

    r = asyncio.run(scenario())
    assert r["error"] == "probe_timeout"


def test_hub_name_is_reserved_and_unknown_probe_named():
    reg = Registry()
    from nexus_mcp.probes import ProbeError

    with pytest.raises(ProbeError):
        asyncio.run(reg.poll(HUB, None, ""))
    with pytest.raises(ProbeError, match="ни разу не подключался"):
        asyncio.run(reg.run("ghost", "tcp", {}))


def test_probe_file_is_stdlib_only():
    """Пробник кладут на роутеры и домашние Windows — никаких pip-зависимостей."""
    text = (Path(__file__).resolve().parents[1] / "probe" / "probe.py").read_text(encoding="utf-8")
    imports = set(re.findall(r"^\s*(?:import|from)\s+([a-zA-Z_]+)", text, re.M))
    stdlib = {"argparse", "json", "os", "platform", "shutil", "socket", "ssl", "subprocess", "sys",
              "tempfile", "time", "urllib", "__future__"}
    assert imports <= stdlib, imports - stdlib


# ── Инвентарь ──────────────────────────────────────────────────────────────

def test_heartbeat_grace_matches_brain(vgx3d):
    """Инвариант 25: константа живёт и в brain, и здесь — сторож на расхождение."""
    text = (vgx3d / "brain" / "app" / "services" / "health.py").read_text(encoding="utf-8")
    m = re.search(r"^HEARTBEAT_GRACE_S\s*=\s*(\d+)", text, re.M)
    assert m and int(m.group(1)) == inventory.HEARTBEAT_GRACE_S


def test_merge_panel_and_file(hub_settings):
    rows = [{"id": "u1", "name": "de-1", "ip_address": "1.1.1.1", "is_online": False,
             "last_heartbeat_at": None, "api_host": None, "is_active": True}]
    file_data = {"defaults": {"ssh_port": 2222},
                 "nodes": [{"name": "de-1", "ssh_user": "admin"}, {"name": "extra", "ip": "2.2.2.2"}]}
    nodes = {n["name"]: n for n in inventory.merge({"main": rows}, file_data)}
    assert nodes["de-1"]["ssh_port"] == 2222 and nodes["de-1"]["ssh_user"] == "admin"
    assert nodes["de-1"]["ssh_host"] == "1.1.1.1" and nodes["de-1"]["heartbeat_fresh"] is False
    assert nodes["extra"]["source"] == "file"


def test_ssh_goes_to_management_address():
    """Инвариант 37: SSH — на адрес управления (api_host), если он задан."""
    rows = [{"id": "u", "name": "n", "ip_address": "1.1.1.1", "api_host": "10.9.9.9"}]
    assert inventory.merge({"main": rows}, {})[0]["ssh_host"] == "10.9.9.9"


def test_heartbeat_age_handles_naive_utc():
    from datetime import datetime, timezone

    now = datetime(2026, 9, 25, 12, 0, 0, tzinfo=timezone.utc)
    assert inventory.heartbeat_age_s("2026-09-25T11:59:00", now) == 60
    assert inventory.heartbeat_age_s("2026-09-25T11:59:00Z", now) == 60
    assert inventory.heartbeat_age_s(None, now) is None


# ── Ссылки подписки ────────────────────────────────────────────────────────

VLESS = ("vless://11111111-2222-3333-4444-555555555555@203.0.113.7:443?type=tcp&security=reality"
         "&pbk=abc&sid=01&sni=www.example.com&fp=chrome&flow=xtls-rprx-vision#DE%20Reality")


def test_config_built_by_brain_code():
    cfg = links.config_for(VLESS)
    out = cfg["outbounds"][0]
    assert out["protocol"] == "vless"
    assert out["streamSettings"]["security"] == "reality"


def test_subscription_decoding_and_node_match():
    body = base64.b64encode((VLESS + "\nss://x@198.51.100.1:8388#other\n").encode()).decode()
    uris = links.decode_subscription(body)
    assert len(uris) == 2
    assert links.links_for_node(uris, {"ip": "203.0.113.7"}) == [VLESS]


def test_e2e_rewrites_inbounds_and_reports_missing_xray():
    lib = probe_lib()
    r = lib.probe_e2e({"inbounds": [], "outbounds": []}, xray_bin="/nonexistent/xray")
    # Без xray — внятная причина, а не трейсбек.
    if r.get("error") == "no_xray":
        assert "xray" in r["detail"]


# ── Действия ───────────────────────────────────────────────────────────────

def test_actions_need_flag_and_confirm(hub_settings, monkeypatch):
    from nexus_mcp import server

    hub_settings.inventory_file.write_text(json.dumps({"nodes": [{"name": "n", "ip": "1.2.3.4"}]}))
    r = asyncio.run(server.node_action("n", "restart", confirm=True))
    assert r["error"] == "actions_disabled"
    hub_settings.allow_actions = True
    r = asyncio.run(server.node_action("n", "restart", confirm=False))
    assert r["error"] == "need_confirm"


def test_update_without_finish_mark_is_not_success(hub_settings, monkeypatch):
    from nexus_mcp import server

    hub_settings.allow_actions = True
    hub_settings.brain_url = "https://p.ru"
    hub_settings.brain_admin_token = "A"

    async def no_servers(path, panel, timeout=15.0):
        return []

    monkeypatch.setattr(inventory, "brain_get", no_servers)
    # Нода из файла, но относится к панели main — адрес heartbeat берётся у неё.
    hub_settings.inventory_file.write_text(json.dumps({"nodes": [{"name": "n", "ip": "1.2.3.4", "panel": "main"}]}))

    async def fake_run(node, script, timeout=45):
        assert "https://p.ru/install/cell-update.sh" in script
        return ssh.SshResult(True, 0, "качаем…\nrc=0\n", "", 10.0)

    monkeypatch.setattr(ssh, "run_script", fake_run)
    r = asyncio.run(server.node_action("n", "update_agent", confirm=True))
    assert r["ok"] is False and r["update_finished"] is False

    async def fake_done(node, script, timeout=45):
        return ssh.SshResult(True, 0, f"…\n  {recipes.UPDATE_DONE_MARK} ✅\nrc=0\n", "", 10.0)

    monkeypatch.setattr(ssh, "run_script", fake_done)
    r = asyncio.run(server.node_action("n", "update_agent", confirm=True))
    assert r["ok"] is True
    # И каждое действие — в журнале.
    from nexus_mcp import audit

    assert [e["tool"] for e in audit.tail()][-2:] == ["node_action", "node_action"]


# ── Справочник приёмов ─────────────────────────────────────────────────────

def test_playbook_keys_are_real_finding_codes():
    """Переименовали код находки — справочник молча перестал бы
    подсказывать. Каждый ключ обязан встречаться в diagnose.py."""
    from nexus_mcp import playbook

    src = (Path(__file__).resolve().parents[1] / "nexus_mcp" / "diagnose.py").read_text(encoding="utf-8")
    missing = [k for k in playbook.PLAYBOOK if k != "docker_pull_hangs" and f'"{k}"' not in src]
    assert not missing, missing


def test_playbook_entries_have_source_and_evidence():
    from nexus_mcp import playbook

    for code, steps in playbook.PLAYBOOK.items():
        for st in steps:
            assert st["evidence"] in ("ours", "measured", "repeated", "anecdote"), code
            assert st["src"] and all(s in playbook.SOURCES for s in st["src"]), code


def test_diagnose_attaches_next_steps(hub_settings, monkeypatch):
    """Критичная находка в отчёте приходит вместе с приёмами починки."""
    from nexus_mcp import probes as probes_mod

    async def fake_run(probe, kind, args, timeout=40.0):
        if kind == "tcp":
            return {"ok": True}
        return {"ok": False, "stage": "data" if kind == "banner" else "handshake", "error": "timeout"}

    monkeypatch.setattr(probes_mod.registry, "run", fake_run)
    node = {"name": "n", "ip": "203.0.113.7", "ssh_host": "203.0.113.7", "source": "file"}
    r = asyncio.run(diagnose.diagnose(node, with_e2e=False, with_ssh=False))
    assert r["findings"][0]["code"] == "payload_filtered"
    steps = r["next_steps"]["payload_filtered"]
    # Первым — свой инструмент панели, затем чужой опыт.
    assert "Включить Cloudflare" in steps[0]["do"]
    assert any("RU-вход" in s["do"] for s in steps)


# ── Cloudflare-фронт ───────────────────────────────────────────────────────

CF = {"enabled": True, "hostname": "nl1.example.com", "port": 2087, "cf_only": False}
CF_LINK = ("vless://11111111-2222-3333-4444-555555555555@nl1.example.com:2087?type=ws&security=tls"
           "&sni=nl1.example.com&host=nl1.example.com&path=%2Fx#NL%20%7C%20VLESS%20WS%20%C2%B7%20CF")


def _panel_node(hub_settings):
    hub_settings.brain_url = "https://p.ru"
    hub_settings.brain_admin_token = "A"
    return {"id": "00383c6f-9853-484b-8f16-d6023c734291", "name": "nl", "ip": "203.0.113.7",
            "ssh_host": "203.0.113.7", "source": "panel", "panel": "main"}


def _blocked_ip_probes(monkeypatch, cf_ok: bool):
    from nexus_mcp import probes as probes_mod

    seen = []

    async def fake_run(probe, kind, args, timeout=40.0):
        seen.append((kind, args))
        if args.get("sni"):
            return {"ok": True} if cf_ok else {"ok": False, "stage": "handshake", "error": "timeout"}
        return {"ok": False, "stage": "connect", "error": "timeout"}

    monkeypatch.setattr(probes_mod.registry, "run", fake_run)
    return seen


def test_cf_front_checked_from_every_probe(hub_settings, monkeypatch):
    """IP режется, фронт включён — адрес фронта проверяется отдельно (TLS с SNI)."""
    node = _panel_node(hub_settings)

    async def status(path, panel, timeout=15.0):
        assert path == f"/api/v1/admin/cloudflare/servers/{node['id']}"
        return {**CF, "inbound_id": "x"}

    monkeypatch.setattr(inventory, "brain_get", status)
    seen = _blocked_ip_probes(monkeypatch, cf_ok=True)
    r = asyncio.run(diagnose.diagnose(node, with_e2e=False, with_ssh=False))
    assert r["cf_front"] == CF
    assert ("tls", {"host": "nl1.example.com", "port": 2087, "sni": "nl1.example.com"}) in seen
    codes = _codes(r["findings"])
    assert "ip_unreachable" in codes and "cf_reachable" in codes and "cf_front_off" not in codes
    assert r["reach"]["hub"]["cf_tls"]["target"] == "nl1.example.com:2087"


def test_cf_blocked_is_critical(hub_settings, monkeypatch):
    node = _panel_node(hub_settings)

    async def status(path, panel, timeout=15.0):
        return CF

    monkeypatch.setattr(inventory, "brain_get", status)
    _blocked_ip_probes(monkeypatch, cf_ok=False)
    r = asyncio.run(diagnose.diagnose(node, with_e2e=False, with_ssh=False))
    assert "cf_blocked" in _codes(r["findings"])
    assert "cf_blocked" in r["next_steps"]


def test_cf_front_off_suggested_when_ip_blocked(hub_settings, monkeypatch):
    node = _panel_node(hub_settings)

    async def status(path, panel, timeout=15.0):
        return {"enabled": False, "cf_only": False}

    monkeypatch.setattr(inventory, "brain_get", status)
    seen = _blocked_ip_probes(monkeypatch, cf_ok=True)
    r = asyncio.run(diagnose.diagnose(node, with_e2e=False, with_ssh=False))
    assert "cf_front_off" in _codes(r["findings"])
    assert not [a for k, a in seen if a.get("sni")]


def test_cf_status_error_does_not_break_diagnose(hub_settings, monkeypatch):
    """Старая панель без ручки (404) — разбор идёт дальше, фронт «неизвестен»."""
    node = _panel_node(hub_settings)

    async def status(path, panel, timeout=15.0):
        raise inventory.InventoryError("панель main ответила 404")

    monkeypatch.setattr(inventory, "brain_get", status)
    _blocked_ip_probes(monkeypatch, cf_ok=True)
    r = asyncio.run(diagnose.diagnose(node, with_e2e=False, with_ssh=False))
    assert r["cf_front"]["enabled"] is None
    assert "cf_front_off" not in _codes(r["findings"])


def test_cf_links_go_to_e2e(hub_settings, monkeypatch):
    """Строка «· CF» ведёт на имя фронта, а не на IP — links_for_node её не
    находит; разбор добавляет её в сквозную проверку сам."""
    node = _panel_node(hub_settings)
    hub_settings.test_sub_url = "https://p.ru/sub/x"

    async def status(path, panel, timeout=15.0):
        return CF

    async def fetch():
        return [VLESS.replace("203.0.113.7", "198.51.100.9"), CF_LINK]

    monkeypatch.setattr(inventory, "brain_get", status)
    monkeypatch.setattr(links, "fetch_links", fetch)
    _blocked_ip_probes(monkeypatch, cf_ok=True)
    tested = []

    async def fake_e2e(probe, uri):
        tested.append(uri)
        return {"link": uri, "ok": True}

    monkeypatch.setattr(diagnose, "e2e", fake_e2e)
    r = asyncio.run(diagnose.diagnose(node, with_ssh=False))
    assert tested == [CF_LINK]
    assert "links_note" not in r
