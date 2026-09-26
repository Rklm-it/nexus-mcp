"""Правка конфигурации ноды (node_edit): план → подтверждение → применение →
откат, против фальшивой панели с состоянием. Сценарий — живой разбор
25.09.2026: CDN-нода вела весь зарубежный трафик в relay на мёртвую nl41s2."""

import asyncio
import copy
import json
import os
import re
import stat

import httpx
import pytest

from nexus_mcp import inventory, node_edit, panel

YA = "a0eba836-b718-4f69-9a11-46afe4698997"
GER = "49341184-93ca-491b-972a-4bdfe424d4ff"
NL = "00383c6f-9853-484b-8f16-d6023c734291"
OB_NL = "7537d3d8-4531-4464-a961-e3b9303784d2"
IB = "620d9b99-8708-4763-81ca-6691ffd1f4a5"

TG = {"type": "field", "domain": ["geosite:telegram"], "outboundTag": "relay-00383c6f"}
RU = {"type": "field", "ip": ["geoip:ru"], "outboundTag": "direct"}


class FakePanel:
    """Панель с состоянием: серверы, выходы, инбаунды. Пишет журнал запросов."""

    def __init__(self):
        self.servers = {
            YA: {"id": YA, "name": "ru41s2-YA-CDN", "display_name": "#1 Обход", "is_active": True,
                 "warp_enabled": False, "cf_only": False,
                 "dns_settings": {"servers": ["8.8.8.8"], "final_outbound": "relay-00383c6f"},
                 "routing_rules": [copy.deepcopy(TG), copy.deepcopy(RU)], "custom_routes": None},
        }
        self.outbounds = {YA: [{"id": OB_NL, "tag": "relay-00383c6f", "protocol": "vless_reality",
                                "target_address": "144.124.249.249", "target_port": 443,
                                "config": {"uuid": "b7827f8f-7476-5ef0-aee5-e979f1ff5c98",
                                           "public_key": "ZE37hMfz_f7784g4im14X_UEfpmjHnYIU_tUpyYFIiU",
                                           "short_id": "a552ab47", "password": "REAL-SECRET-VALUE-123"},
                                "is_enabled": True, "relay_mode": "xray", "listen_port": None}]}
        self.inbounds = {YA: [{"id": IB, "tag": "vless-xhttp-cdn", "protocol": "vless_xhttp_cdn",
                               "listen_port": 8080, "display_name": "🇷🇺 Россия LTE 4G",
                               "is_enabled": True, "display_order": 0,
                               "config": {"path": "/assets/api/v2", "cdn_host": "cdn-1.example",
                                          "password": "INBOUND-SECRET-9999"}}]}
        self.log = []
        self.n = 0
        # Cloudflare-фронт (vgx3d api/v1/admin/cloudflare.py).
        self.cf_settings = {"api_token": "✓ задано", "zone": "nexus-front.net", "port": 2087,
                            "https_ports": [2053, 2083, 2087, 2096, 8443], "configured": True}
        self.cf = {}                 # server_id → {"hostname", "port"}
        self.cf_enable_fail = None   # тело 400 от enable
        self.cf_verify_ok = True
        self.active_users = {YA: 37}

    def cloudflare(self, req, path, body):
        if path == "/api/v1/admin/cloudflare/settings" and req.method == "GET":
            return httpx.Response(200, json=self.cf_settings)
        m = re.fullmatch(r"/api/v1/admin/cloudflare/servers/([0-9a-f-]{36})(/\w+)?", path)
        if not m:
            return httpx.Response(404, json={"detail": "Not Found"})
        sid, act = m.group(1), m.group(2) or ""
        srv, front = self.servers[sid], self.cf.get(sid)
        if act == "" and req.method == "GET":
            if not front:
                return httpx.Response(200, json={"enabled": False, "cf_only": srv["cf_only"]})
            return httpx.Response(200, json={"enabled": True, **front, "cf_only": srv["cf_only"]})
        if act == "/enable" and req.method == "POST":
            if self.cf_enable_fail:
                return httpx.Response(400, json=self.cf_enable_fail)
            self.cf[sid] = {"hostname": "ru41s2-ya-cdn.nexus-front.net", "port": 2087}
            return httpx.Response(200, json={"ok": True, "hostname": self.cf[sid]["hostname"], "port": 2087,
                                             "inbound_id": IB, "steps": [{"step": "DNS", "ok": True}]})
        if act == "/verify" and req.method == "POST":
            if not front:
                return httpx.Response(409, json={"detail": "Cloudflare на этой ноде не включён"})
            if self.cf_verify_ok:
                return httpx.Response(200, json={"ok": True, "code": 101, "attempts": 1})
            return httpx.Response(200, json={"ok": False, "code": 0, "error": "Cloudflare 522"})
        if act == "/disable" and req.method == "POST":
            self.cf.pop(sid, None)
            srv["cf_only"] = False
            return httpx.Response(200, json={"ok": True, "steps": []})
        return httpx.Response(405, json={"detail": f"нет {req.method} {path}"})

    def handler(self, req: httpx.Request) -> httpx.Response:
        path = req.url.path
        body = json.loads(req.content) if req.content else None
        self.log.append((req.method, path, body))
        m = re.fullmatch(r"/api/v1/servers/([0-9a-f-]{36})(/.*)?", path)
        if path.startswith("/api/v1/admin/cloudflare/"):
            return self.cloudflare(req, path, body)
        if path == "/api/v1/servers" and req.method == "GET":
            stats = req.url.params.get("with_stats") == "true"
            return httpx.Response(200, json=[{**s, **({"active_users": self.active_users.get(i, 0)}
                                                       if stats else {})} for i, s in self.servers.items()])
        m2 = re.fullmatch(r"/api/v1/admin/nodes/([0-9a-f-]{36})/relay-node", path)
        if m2 and req.method == "POST":
            sid = m2.group(1)
            tag = f"relay-{body['relay_server_id'][:8]}"
            self.n += 1
            self.outbounds[sid].append({"id": f"00000000-0000-0000-0000-{self.n:012d}", "tag": tag,
                                        "protocol": "vless_reality", "target_address": "111.235.151.78",
                                        "target_port": 443, "config": {}, "is_enabled": True,
                                        "relay_mode": body["relay_mode"], "listen_port": None})
            return httpx.Response(200, json={"status": "ok", "tag": tag, "relay_server": "ger41s2"})
        if not m:
            return httpx.Response(404, json={"detail": "Not Found"})
        sid, rest = m.group(1), m.group(2) or ""
        srv = self.servers[sid]
        if rest == "" and req.method == "GET":
            return httpx.Response(200, json=srv)
        if rest == "" and req.method == "PATCH":
            if body.get("cf_only") and not srv["cf_only"] and sid not in self.cf:
                return httpx.Response(409, json={"detail": "Сначала включите Cloudflare на этой ноде"})
            srv.update(body)
            return httpx.Response(200, json=srv)
        if rest == "/outbounds" and req.method == "GET":
            return httpx.Response(200, json=self.outbounds[sid])
        if rest == "/outbounds" and req.method == "POST":
            self.n += 1
            ob = {**body, "id": f"00000000-0000-0000-0000-{self.n:012d}"}
            self.outbounds[sid].append(ob)
            return httpx.Response(201, json=ob)
        mo = re.fullmatch(r"/outbounds/([0-9a-f-]{36})", rest)
        if mo and req.method == "DELETE":
            self.outbounds[sid] = [o for o in self.outbounds[sid] if o["id"] != mo.group(1)]
            return httpx.Response(204)
        if rest == "/inbounds" and req.method == "GET":
            return httpx.Response(200, json=self.inbounds[sid])
        mi = re.fullmatch(r"/inbounds/([0-9a-f-]{36})", rest)
        if mi and req.method == "PATCH":
            ib = next(i for i in self.inbounds[sid] if i["id"] == mi.group(1))
            for k, v in body.items():
                if k == "config":
                    ib["config"] = {**ib["config"], **v}
                elif k != "force":
                    ib[k] = v
            return httpx.Response(200, json=ib)
        return httpx.Response(405, json={"detail": f"нет {req.method} {path} в фальшивой панели"})


NODES = {
    "ru41s2-YA-CDN": {"name": "ru41s2-YA-CDN", "id": YA, "panel": "", "ip": "217.18.62.16", "panel_online": True},
    "ger41s2": {"name": "ger41s2", "id": GER, "panel": "", "ip": "111.235.151.78", "panel_online": True},
    "nl41s2": {"name": "nl41s2", "id": NL, "panel": "", "ip": "144.124.249.249", "panel_online": False},
}


@pytest.fixture
def fake(hub_settings, monkeypatch):
    hub_settings.brain_url = "https://panel.example.ru"
    hub_settings.brain_admin_token = "ADMIN"
    hub_settings.allow_actions = True
    fp = FakePanel()
    real = httpx.AsyncClient

    def factory(*a, **kw):
        kw["transport"] = httpx.MockTransport(fp.handler)
        return real(*a, **kw)

    monkeypatch.setattr(panel.httpx, "AsyncClient", factory)

    async def find_node(name):
        if name not in NODES:
            raise inventory.InventoryError(f"нода «{name}» не найдена")
        return dict(NODES[name])

    monkeypatch.setattr(inventory, "find_node", find_node)
    return fp


def writes(fp):
    return [(m, p) for m, p, _ in fp.log if m != "GET"]


def run(coro):
    return asyncio.run(coro)


# ── Главный сценарий ───────────────────────────────────────────────────────

def test_swap_to_missing_relay_is_refused(fake):
    """relay-49341184 на YA-CDN нет — панель такое пропустила бы (нода ger41s2
    существует), а xray на ноде не поднялся бы вовсе."""
    from nexus_mcp import server

    r = run(server.node_edit("ru41s2-YA-CDN", "swap_outbound",
                             {"from": "relay-00383c6f", "to": "relay-49341184"}))
    assert r["ok"] is False and "relay-49341184" in r["detail"] and "relay_add" in r["detail"]
    assert writes(fake) == []


def test_batch_fixes_cdn_node_and_rolls_back(fake):
    from nexus_mcp import server

    args = {"ops": [
        {"op": "relay_add", "args": {"via": "ger41s2"}},
        {"op": "swap_outbound", "args": {"from": "relay-00383c6f", "to": "relay-49341184"}},
        {"op": "relay_remove", "args": {"tag": "relay-00383c6f"}},
    ]}
    pv = run(server.node_edit("ru41s2-YA-CDN", "batch", args))
    assert pv["ok"] and pv["preview"] and writes(fake) == []
    assert any("relay-00383c6f → relay-49341184" in ln for ln in pv["changes"])
    # Секреты в предпросмотре замаскированы.
    dump = json.dumps(pv, ensure_ascii=False)
    assert "REAL-SECRET-VALUE-123" not in dump and "INBOUND-SECRET-9999" not in dump

    # Без plan_hash — не применяется.
    r = run(server.node_edit("ru41s2-YA-CDN", "batch", args, confirm=True))
    assert r["error"] == "plan_changed" and writes(fake) == []

    r = run(server.node_edit("ru41s2-YA-CDN", "batch", args, confirm=True, plan_hash=pv["plan_hash"]))
    assert r["ok"], r
    assert [m for m, _ in writes(fake)] == ["POST", "PATCH", "DELETE"]
    srv = fake.servers[YA]
    assert srv["dns_settings"]["final_outbound"] == "relay-49341184"
    assert srv["routing_rules"][0]["outboundTag"] == "relay-49341184"
    assert srv["routing_rules"][1]["outboundTag"] == "direct"
    assert [o["tag"] for o in fake.outbounds[YA]] == ["relay-49341184"]

    # Запись правки — только владельцу, с настоящими значениями для отката.
    f = hub_path(r["edit"])
    assert stat.S_IMODE(os.stat(f).st_mode) == 0o600

    fake.log.clear()
    rb = {"edit": r["edit"]}
    pv2 = run(server.node_edit("", "rollback", rb))
    assert pv2["ok"], pv2
    r2 = run(server.node_edit("", "rollback", rb, confirm=True, plan_hash=pv2["plan_hash"]))
    assert r2["ok"], r2
    # Обратный порядок: вернуть старый relay → вернуть маршрутизацию → убрать новый.
    assert [m for m, _ in writes(fake)] == ["POST", "PATCH", "DELETE"]
    assert srv["dns_settings"]["final_outbound"] == "relay-00383c6f"
    assert srv["routing_rules"][0]["outboundTag"] == "relay-00383c6f"
    tags = [o["tag"] for o in fake.outbounds[YA]]
    assert tags == ["relay-00383c6f"]
    restored = fake.outbounds[YA][0]
    # Вернулся настоящий ключ, а не маска из ответа панели.
    assert restored["config"]["password"] == "REAL-SECRET-VALUE-123"

    # Второй откат той же правки — отказ.
    again = run(server.node_edit("", "rollback", rb))
    assert again["ok"] is False and "уже откачена" in again["detail"]


def hub_path(edit_id):
    from nexus_mcp import config

    return config.settings.state_dir / "edits" / f"{edit_id}.json"


def test_plan_hash_catches_change_between_plan_and_confirm(fake):
    from nexus_mcp import server

    run(server.node_edit("ru41s2-YA-CDN", "relay_add", {"via": "ger41s2"},
                         confirm=True, plan_hash=run(server.node_edit(
                             "ru41s2-YA-CDN", "relay_add", {"via": "ger41s2"}))["plan_hash"]))
    pv = run(server.node_edit("ru41s2-YA-CDN", "swap_outbound",
                              {"from": "relay-00383c6f", "to": "relay-49341184"}))
    assert pv["ok"]
    # Кто-то поменял правила в панели после плана.
    fake.servers[YA]["routing_rules"].append({"type": "field", "ip": ["1.1.1.1"],
                                              "outboundTag": "relay-00383c6f"})
    before = len(writes(fake))
    r = run(server.node_edit("ru41s2-YA-CDN", "swap_outbound",
                             {"from": "relay-00383c6f", "to": "relay-49341184"},
                             confirm=True, plan_hash=pv["plan_hash"]))
    assert r["error"] == "plan_changed" and len(writes(fake)) == before


def test_relay_remove_refused_while_used(fake):
    r = run(_plan("relay_remove", {"tag": "relay-00383c6f"}))
    assert "ещё ссылаются" in r


def _plan(op, args, node="ru41s2-YA-CDN"):
    async def go():
        try:
            await node_edit.plan(node, op, args)
        except node_edit.EditError as e:
            return str(e)
        return ""
    return go()


def test_masked_value_is_never_written(fake):
    """Маска из ответа панели («REAL…») вместо ключа — отказ до панели."""
    msg = run(_plan("inbound_update", {"inbound": "vless-xhttp-cdn",
                                       "changes": {"config": {"password": "INBO…"}}}))
    assert "маск" in msg


def test_inbound_update_merges_and_rolls_back_only_changed_keys(fake):
    from nexus_mcp import server

    args = {"inbound": "🇷🇺 Россия LTE 4G", "changes": {"display_name": "LTE 1.1",
                                                          "config": {"path": "/new"}}}
    pv = run(server.node_edit("ru41s2-YA-CDN", "inbound_update", args))
    assert pv["affects_clients"], pv
    r = run(server.node_edit("ru41s2-YA-CDN", "inbound_update", args, confirm=True,
                             plan_hash=pv["plan_hash"]))
    assert r["ok"]
    sent = [b for m, p, b in fake.log if m == "PATCH"][0]
    assert sent == {"display_name": "LTE 1.1", "config": {"path": "/new"}}   # только меняемое
    ib = fake.inbounds[YA][0]
    assert ib["config"]["password"] == "INBOUND-SECRET-9999"
    pv2 = run(server.node_edit("", "rollback", {"edit": r["edit"]}))
    run(server.node_edit("", "rollback", {"edit": r["edit"]}, confirm=True, plan_hash=pv2["plan_hash"]))
    assert ib["display_name"] == "🇷🇺 Россия LTE 4G" and ib["config"]["path"] == "/assets/api/v2"


def test_settings_rejects_unknown_fields_and_warns_clients(fake):
    assert "ip_address" in run(_plan("settings", {"ip_address": "1.2.3.4"}))

    async def go():
        return node_edit.preview(await node_edit.plan("ru41s2-YA-CDN", "settings", {"is_active": False}))
    pv = run(go())
    assert any("is_active" in w for w in pv["affects_clients"])


def test_unknown_op_lists_ops(fake):
    msg = run(_plan("drop_node", {}))
    assert "swap_outbound" in msg and "rollback" in msg


def test_gated_by_allow_actions(fake, hub_settings):
    from nexus_mcp import server

    hub_settings.allow_actions = False
    r = run(server.node_edit("ru41s2-YA-CDN", "settings", {"note": "x"}))
    assert r["error"] == "actions_disabled"


@pytest.mark.parametrize("method,path", [
    ("DELETE", f"/api/v1/servers/{YA}"),
    ("PATCH", f"/api/v1/users/{YA}"),
    ("POST", "/api/v1/admin/users/bulk"),
    ("DELETE", "/api/v1/admin/payments/x"),
    ("POST", f"/api/v1/servers/{YA}/../../admin/system/update"),
])
def test_write_allowlist_denies(method, path):
    with pytest.raises(panel.PanelError):
        panel.check_write(method, path)


def test_history_lists_edits(fake):
    from nexus_mcp import server

    pv = run(server.node_edit("ru41s2-YA-CDN", "settings", {"note": "проверка"}))
    r = run(server.node_edit("ru41s2-YA-CDN", "settings", {"note": "проверка"}, confirm=True,
                             plan_hash=pv["plan_hash"]))
    h = run(server.node_edits())["edits"]
    assert h[0]["edit"] == r["edit"] and h[0]["can_rollback"] is True


# ── Cloudflare-фронт ───────────────────────────────────────────────────────

CF = f"/api/v1/admin/cloudflare/servers/{YA}"


def test_cf_front_plan_writes_nothing_and_needs_its_own_hash(fake):
    from nexus_mcp import server

    args = {"enable": True, "cf_only": True}
    pv = run(server.node_edit("ru41s2-YA-CDN", "cf_front", args))
    assert pv["ok"] and pv["preview"], pv
    assert writes(fake) == []                       # план не зовёт ни одного POST/PATCH
    dump = json.dumps(pv, ensure_ascii=False)
    assert "ru41s2-ya-cdn.nexus-front.net" in dump and "2087" in dump
    assert any("37 юзеров" in c and "VLESS WS · CF" in c for c in pv["affects_clients"]), pv
    assert any("уйдут ВСЕ ссылки с IP ноды" in c for c in pv["affects_clients"]), pv

    # plan_hash другого плана (без cf_only) — отказ, в панель ничего не ушло.
    other = run(server.node_edit("ru41s2-YA-CDN", "cf_front", {"enable": True}))["plan_hash"]
    assert other != pv["plan_hash"]
    r = run(server.node_edit("ru41s2-YA-CDN", "cf_front", args, confirm=True, plan_hash=other))
    assert r["error"] == "plan_changed" and writes(fake) == []

    r = run(server.node_edit("ru41s2-YA-CDN", "cf_front", args, confirm=True, plan_hash=pv["plan_hash"]))
    assert r["ok"], r
    assert writes(fake) == [("POST", f"{CF}/enable"), ("POST", f"{CF}/verify"),
                            ("PATCH", f"/api/v1/servers/{YA}")]
    assert r["cf_check"]["ok"] is True and r["cf_front"]["hostname"] == "ru41s2-ya-cdn.nexus-front.net"
    assert fake.servers[YA]["cf_only"] is True

    # Откат: сначала вернуть cf_only, потом снять фронт.
    fake.log.clear()
    pv2 = run(server.node_edit("", "rollback", {"edit": r["edit"]}))
    r2 = run(server.node_edit("", "rollback", {"edit": r["edit"]}, confirm=True, plan_hash=pv2["plan_hash"]))
    assert r2["ok"], r2
    assert writes(fake) == [("PATCH", f"/api/v1/servers/{YA}"), ("POST", f"{CF}/disable")]
    assert [b for m, _, b in fake.log if m == "PATCH"] == [{"cf_only": False}]
    assert YA not in fake.cf


def test_cf_front_refused_when_panel_not_configured(fake):
    from nexus_mcp import server

    fake.cf_settings.update(api_token="", configured=False)
    r = run(server.node_edit("ru41s2-YA-CDN", "cf_front", {"enable": True}))
    assert r["ok"] is False and "не настроен" in r["detail"] and "токен API" in r["detail"], r
    assert writes(fake) == []


def test_cf_front_refuses_token_in_args(fake):
    msg = run(_plan("cf_front", {"enable": True, "api_token": "cf-secret"}))
    assert "api_token" in msg


def test_cf_front_enable_400_reaches_answer_with_step(fake):
    from nexus_mcp import server

    steps = [{"step": "DNS-запись", "ok": True, "detail": "ru41s2-ya-cdn.nexus-front.net → 217.18.62.16"},
             {"step": "Файрвол", "ok": False, "detail": "нода не ответила: timeout"}]
    fake.cf_enable_fail = {"detail": "Файрвол: нода не ответила: timeout", "step": "Файрвол", "steps": steps}
    pv = run(server.node_edit("ru41s2-YA-CDN", "cf_front", {"enable": True}))
    r = run(server.node_edit("ru41s2-YA-CDN", "cf_front", {"enable": True}, confirm=True,
                             plan_hash=pv["plan_hash"]))
    assert r["ok"] is False and r["step"] == "Файрвол" and r["steps"] == steps, r
    assert "Файрвол: нода не ответила: timeout" in r["detail"]
    assert writes(fake) == [("POST", f"{CF}/enable")]    # проверка после отказа не идёт
    # На «Файрвол» панель оставляет инбаунд и DNS — откат (disable) обязан быть.
    fake.log.clear()
    pv2 = run(server.node_edit("", "rollback", {"edit": r["edit"]}))
    assert pv2["ok"], pv2
    r2 = run(server.node_edit("", "rollback", {"edit": r["edit"]}, confirm=True, plan_hash=pv2["plan_hash"]))
    assert r2["ok"] and writes(fake) == [("POST", f"{CF}/disable")], r2


def test_cf_only_waits_for_path_check(fake):
    """Проверка пути не прошла — «только через CF» не включается: у юзеров
    осталась бы одна неработающая строка."""
    from nexus_mcp import server

    fake.cf_verify_ok = False
    args = {"enable": True, "cf_only": True}
    pv = run(server.node_edit("ru41s2-YA-CDN", "cf_front", args))
    r = run(server.node_edit("ru41s2-YA-CDN", "cf_front", args, confirm=True, plan_hash=pv["plan_hash"]))
    assert r["ok"] is False and r["cf_check"]["error"] == "Cloudflare 522", r
    assert ("PATCH", f"/api/v1/servers/{YA}") not in writes(fake)
    assert fake.servers[YA]["cf_only"] is False


def test_cf_front_disable_and_rollback_restores_cf_only(fake):
    from nexus_mcp import server

    fake.cf[YA] = {"hostname": "ru41s2-ya-cdn.nexus-front.net", "port": 2087}
    fake.servers[YA]["cf_only"] = True
    assert "без фронта" in run(_plan("cf_front", {"enable": False, "cf_only": True}))
    pv = run(server.node_edit("ru41s2-YA-CDN", "cf_front", {"enable": False}))
    assert any("пропадёт из подписок 37" in c for c in pv["affects_clients"]), pv
    r = run(server.node_edit("ru41s2-YA-CDN", "cf_front", {"enable": False}, confirm=True,
                             plan_hash=pv["plan_hash"]))
    assert r["ok"] and writes(fake)[-1] == ("POST", f"{CF}/disable"), r
    fake.log.clear()
    pv2 = run(server.node_edit("", "rollback", {"edit": r["edit"]}))
    run(server.node_edit("", "rollback", {"edit": r["edit"]}, confirm=True, plan_hash=pv2["plan_hash"]))
    assert writes(fake) == [("POST", f"{CF}/enable"), ("PATCH", f"/api/v1/servers/{YA}")]
    assert fake.servers[YA]["cf_only"] is True and YA in fake.cf


def test_cf_front_not_enabled_nothing_to_disable(fake):
    assert "не включён" in run(_plan("cf_front", {"enable": False}))


# ── Чат: план идёт сразу, применение — кнопкой ─────────────────────────────

def test_chat_gates_only_confirmed_edit():
    from nexus_chat import runner

    title = runner.describe_action("node_edit", {"node": "ru41s2-YA-CDN", "op": "batch", "args": {"ops": [
        {"op": "relay_add"}, {"op": "swap_outbound"}, {"op": "relay_remove"}]}})
    assert "ru41s2-YA-CDN" in title and "добавить relay → переключить выход → удалить relay" in title
    assert "relay-00383c6f → relay-49341184" in runner.describe_action(
        "node_edit", {"node": "x", "op": "swap_outbound", "args": {"from": "relay-00383c6f",
                                                                   "to": "relay-49341184"}})
    assert "node_edit" in runner.EDIT_TOOLS and "node_edit" not in runner.ACTION_TOOLS
    assert "Cloudflare-фронт · включить, только через CF" in runner.describe_action(
        "node_edit", {"node": "x", "op": "cf_front", "args": {"enable": True, "cf_only": True}})
    assert set(runner.EDIT_OPS) == set(node_edit.OPS)


# ── Сторожа: хаб и панель говорят об одном (инвариант 25) ──────────────────

def test_write_routes_exist_in_panel(vgx3d):
    srv = (vgx3d / "brain/app/api/v1/servers.py").read_text(encoding="utf-8")
    ib = (vgx3d / "brain/app/api/v1/inbounds.py").read_text(encoding="utf-8")
    ob = (vgx3d / "brain/app/api/v1/outbounds.py").read_text(encoding="utf-8")
    nodes = (vgx3d / "brain/app/api/v1/admin/nodes.py").read_text(encoding="utf-8")
    assert '@router.patch("/{server_id}"' in srv
    assert '@router.post("/{server_id}/push-network")' in srv
    assert '@router.post("/{server_id}/relay-node")' in nodes
    for route, text in (('"/servers/{server_id}/inbounds"', ib), ('"/servers/{server_id}/inbounds/{inbound_id}"', ib),
                        ('"/servers/{server_id}/inbounds/{inbound_id}/push"', ib),
                        ('"/servers/{server_id}/outbounds"', ob),
                        ('"/servers/{server_id}/outbounds/{outbound_id}"', ob)):
        assert route in text, route
    assert '@router.put("/servers/{server_id}/inbounds/order")' in ib
    assert "inbound_ids: list[uuid.UUID]" in ib[ib.index("class InboundReorder"):]


def test_fields_match_panel(vgx3d):
    srv = (vgx3d / "brain/app/api/v1/servers.py").read_text(encoding="utf-8")
    block = srv[srv.index("_ALLOWED_SERVER_FIELDS = {"):]
    block = block[:block.index("}")]
    allowed = set(re.findall(r'"([a-z_]+)"', block))
    assert set(node_edit.SETTINGS_FIELDS) <= allowed, set(node_edit.SETTINGS_FIELDS) - allowed
    assert set(node_edit.ROUTING_FIELDS) <= allowed
    sys_tags = set(re.findall(r'"([a-z-]+)"', re.search(r"_SYSTEM_OUTBOUND_TAGS = \{([^}]*)\}", srv).group(1)))
    assert node_edit.SYSTEM_OUTBOUNDS | {"warp-out"} == sys_tags
    schema = (vgx3d / "brain/app/schemas/inbound.py").read_text(encoding="utf-8")
    upd = schema[schema.index("class InboundUpdate"):schema.index("class InboundOut")]
    for f in node_edit.INBOUND_FIELDS:
        assert re.search(rf"^\s+{f}:", upd, re.M), f
    prov = (vgx3d / "brain/app/services/provisioning.py").read_text(encoding="utf-8")
    assert 'tag = f"relay-{str(relay_node.id)[:8]}"' in prov
    rq = (vgx3d / "brain/app/api/v1/admin/nodes.py").read_text(encoding="utf-8")
    req = rq[rq.index("class RelayByNodeRequest"):]
    for f in ("relay_server_id", "relay_mode", "listen_port", "protocol"):
        assert f"{f}:" in req[:1500], f


def test_cf_front_matches_panel(vgx3d):
    """Ручки, поля и имя фронта — те же, что у панели."""
    api = (vgx3d / "brain/app/api/v1/admin/cloudflare.py").read_text(encoding="utf-8")
    assert 'APIRouter(prefix="/cloudflare"' in api
    for route in ('@router.get("/settings")', '@router.get("/servers/{server_id}")',
                  '@router.post("/servers/{server_id}/enable")', '@router.post("/servers/{server_id}/verify")',
                  '@router.post("/servers/{server_id}/disable")'):
        assert route in api, route
    # Отказ enable — 400 с detail, step, steps: хаб отдаёт их как есть.
    assert re.search(r'status_code=400,\s*content=\{"detail": [^\n]*"step": e\.step, "steps": e\.steps\}', api)
    front = (vgx3d / "brain/app/services/cf_front.py").read_text(encoding="utf-8")
    pub = front[front.index("def public_settings"):front.index("def _cf(")]
    for key in ('"configured"', '"zone"', '"port"'):
        assert key in pub, key
    st = front[front.index("async def status"):]
    assert '"enabled": False, "cf_only"' in st and '"hostname"' in st
    slug = front[front.index("def _slug"):front.index("async def hostname_for")]
    assert 're.sub(r"[^a-z0-9-]+", "-", (text or "").lower()).strip("-")' in slug and "[:40]" in slug
    assert 'candidate = f"{base}.{zone}"' in front and '_slug(server.name) or "node"' in front
    assert node_edit._cf_slug("ru41s2-YA-CDN") == "ru41s2-ya-cdn"
    schema = (vgx3d / "brain/app/schemas/server.py").read_text(encoding="utf-8")
    assert re.search(r"^\s+active_users:", schema[schema.index("class ServerOut"):], re.M)
    srv = (vgx3d / "brain/app/api/v1/servers.py").read_text(encoding="utf-8")
    lst = srv[srv.index("async def list_servers"):srv.index("async def list_servers") + 300]
    assert "with_stats: bool" in lst and "with_online: bool | None" in lst
