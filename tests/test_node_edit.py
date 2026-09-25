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
                 "warp_enabled": False,
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

    def handler(self, req: httpx.Request) -> httpx.Response:
        path = req.url.path
        body = json.loads(req.content) if req.content else None
        self.log.append((req.method, path, body))
        m = re.fullmatch(r"/api/v1/servers/([0-9a-f-]{36})(/.*)?", path)
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
