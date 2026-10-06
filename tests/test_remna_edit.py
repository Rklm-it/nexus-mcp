"""Перенастройка нод Remnawave и каскад RU → Cloudflare → EU с хаба.

Remnawave — httpx.MockTransport со СВОИМ состоянием (профили, ноды, хосты,
сквады, юзеры меняются от PATCH/POST/DELETE), Cloudflare — так же; SSH и
WebSocket-рукопожатие подменены. Проверяем то, что ломается молча:
* каскад: реле смотрит на фронт выхода с юзером реле, Рунет и DNS — напрямую,
  правила встают ПЕРЕД общими, но после блокировок; Reality — firefox и
  minClientVer 1.0.0; ключи настоящие, а не заглушки;
* секреты (vlessUuid реле, privateKey) не попадают в ответ;
* фронт не отвечает или нода не вышла на связь — панель и Cloudflare
  возвращены как были (сверяем состояние, а не факт вызова);
* план детерминирован и устаревает от чужой правки.
"""

import asyncio
import copy
import json
import re

import httpx
import pytest

from nexus_mcp import remna, ssh
from nexus_mcp import remna_edit as re_

RELAY_VLESS = "9f1c2d3e-aaaa-4bbb-8ccc-0123456789ab"
PRIV = "PRIVATE-X25519-KEY-abcdef"
EXIT_IP = "45.141.118.7"
ENTRY_IP = "185.22.1.10"


def run(coro):
    return asyncio.new_event_loop().run_until_complete(coro)


def hy_inbound(tag, dom):
    return {"tag": tag, "port": 443, "protocol": "hysteria",
            "settings": {"clients": [], "version": 2},
            "streamSettings": {"network": "hysteria", "security": "tls", "tlsSettings": {
                "alpn": ["h3"], "certificates": [{
                    "certificateFile": f"/etc/letsencrypt/live/{dom}/fullchain.pem",
                    "keyFile": f"/etc/letsencrypt/live/{dom}/privkey.pem"}]}}}


def re_inbound(tag, sni, port=443):
    return {"tag": tag, "port": port, "protocol": "vless",
            "settings": {"clients": [], "decryption": "none"},
            "streamSettings": {"network": "tcp", "security": "reality", "realitySettings": {
                "privateKey": "OLD-PK", "serverNames": [sni], "dest": f"{sni}:443",
                "shortIds": ["ab"], "minClientVer": "1.0.0"}}}


BASE_RULES = [{"ip": ["geoip:private"], "outboundTag": "BLOCK"},
              {"protocol": ["bittorrent"], "outboundTag": "BLOCK"},
              {"domain": ["geosite:openai"], "outboundTag": "DIRECT"}]


def base_cfg(inbounds):
    return {"log": {"loglevel": "none"}, "inbounds": inbounds,
            "outbounds": [{"tag": "DIRECT", "protocol": "freedom"}, {"tag": "BLOCK", "protocol": "blackhole"}],
            "routing": {"rules": copy.deepcopy(BASE_RULES)}}


class Panel:
    """Remnawave с состоянием по контракту remnawave/backend 3.x."""

    def __init__(self):
        self.calls = []
        self.n = 0
        self.connected_after_patch = True
        self.profiles = {
            "p-nl": {"uuid": "p-nl", "name": "profile-nl",
                     "config": base_cfg([hy_inbound("HY_NL", "nl01s1.pablo.support")])},
            "p-ru": {"uuid": "p-ru", "name": "profile-ru",
                     "config": base_cfg([re_inbound("RE_RU", "ads.x5.ru")])},
        }
        self.inb_uuids = {}
        self.nodes = {
            "n-nl": {"uuid": "n-nl", "name": "nl01s1", "address": "nl01s1.pablo.support", "port": 2222,
                     "countryCode": "NL", "isConnected": True,
                     "configProfile": {"activeConfigProfileUuid": "p-nl", "activeInbounds": []}},
            "n-ru": {"uuid": "n-ru", "name": "ru01s3", "address": ENTRY_IP, "port": 2222,
                     "countryCode": "RU", "isConnected": True,
                     "configProfile": {"activeConfigProfileUuid": "p-ru", "activeInbounds": []}},
            "n-ru2": {"uuid": "n-ru2", "name": "ru02s3", "address": "185.22.1.11", "port": 2222,
                      "countryCode": "RU", "isConnected": True,
                      "configProfile": {"activeConfigProfileUuid": "p-ru", "activeInbounds": []}},
        }
        for nid, tag in (("n-nl", "HY_NL"), ("n-ru", "RE_RU"), ("n-ru2", "RE_RU")):
            self.nodes[nid]["configProfile"]["activeInbounds"] = [{"uuid": self.iu(tag), "tag": tag}]
        self.hosts = {
            "h-nl": {"uuid": "h-nl", "remark": "🇳🇱 Нидерланды", "address": "nl01s1.pablo.support",
                     "port": 443, "sni": "nl01s1.pablo.support", "fingerprint": None, "isDisabled": False,
                     "inbound": {"configProfileUuid": "p-nl", "configProfileInboundUuid": self.iu("HY_NL")}},
            "h-ru": {"uuid": "h-ru", "remark": "🇷🇺 Россия", "address": ENTRY_IP, "port": 443,
                     "sni": "ads.x5.ru", "fingerprint": "firefox", "isDisabled": False,
                     "inbound": {"configProfileUuid": "p-ru", "configProfileInboundUuid": self.iu("RE_RU")}},
        }
        self.squads = {
            "sq-main": {"uuid": "sq-main", "name": "PabloWD", "info": {"membersCount": 16000},
                        "inbounds": [{"uuid": self.iu("HY_NL")}, {"uuid": self.iu("RE_RU")}]},
        }
        self.users = {}

    def iu(self, tag):
        return self.inb_uuids.setdefault(tag, f"inb-{tag.lower()}")

    def new_id(self, prefix):
        self.n += 1
        return f"{prefix}-{self.n}"

    def profile_view(self, uid):
        pr = self.profiles[uid]
        return {**copy.deepcopy(pr), "inbounds": [{"uuid": self.iu(i["tag"]), "tag": i["tag"]}
                                                  for i in pr["config"]["inbounds"]]}

    def snapshot(self):
        return copy.deepcopy({"profiles": self.profiles, "nodes": self.nodes, "hosts": self.hosts,
                              "squads": self.squads, "users": self.users})

    def handler(self, req: httpx.Request) -> httpx.Response:
        body = json.loads(req.content) if req.content else None
        m, path = req.method, req.url.path
        self.calls.append((m, path, body))
        w = lambda v: httpx.Response(200, json={"response": v})  # noqa: E731
        nf = httpx.Response(404, json={"message": "not found"})
        if m == "GET" and path == "/api/nodes":
            return w(list(copy.deepcopy(self.nodes).values()))
        if m == "GET" and path.startswith("/api/nodes/"):
            n = self.nodes.get(path.rsplit("/", 1)[1])
            return w(copy.deepcopy(n)) if n else nf
        if m == "PATCH" and path == "/api/nodes":
            n = self.nodes[body["uuid"]]
            cp = body["configProfile"]
            by = {v: k for k, v in self.inb_uuids.items()}
            n["configProfile"] = {"activeConfigProfileUuid": cp["activeConfigProfileUuid"],
                                  "activeInbounds": [{"uuid": u, "tag": by[u]} for u in cp["activeInbounds"]]}
            n["isConnected"] = self.connected_after_patch
            return w(copy.deepcopy(n))
        if m == "GET" and path.startswith("/api/config-profiles/"):
            uid = path.rsplit("/", 1)[1]
            return w(self.profile_view(uid)) if uid in self.profiles else nf
        if m == "PATCH" and path == "/api/config-profiles":
            self.profiles[body["uuid"]]["config"] = copy.deepcopy(body["config"])
            for n in self.nodes.values():
                if n["configProfile"]["activeConfigProfileUuid"] == body["uuid"]:
                    n["isConnected"] = self.connected_after_patch
            return w(self.profile_view(body["uuid"]))
        if m == "GET" and path == "/api/hosts":
            return w(list(copy.deepcopy(self.hosts).values()))
        if m == "POST" and path == "/api/hosts":
            uid = self.new_id("host")
            self.hosts[uid] = {"uuid": uid, **body}
            return w(copy.deepcopy(self.hosts[uid]))
        if m == "PATCH" and path == "/api/hosts":
            self.hosts[body["uuid"]].update({k: v for k, v in body.items() if k != "uuid"})
            return w(copy.deepcopy(self.hosts[body["uuid"]]))
        if m == "GET" and path == "/api/internal-squads":
            return w({"total": len(self.squads), "internalSquads": list(copy.deepcopy(self.squads).values())})
        if m == "POST" and path == "/api/internal-squads":
            uid = self.new_id("sq")
            self.squads[uid] = {"uuid": uid, "name": body["name"], "info": {"membersCount": 0},
                                "inbounds": [{"uuid": u} for u in body["inbounds"]]}
            return w(copy.deepcopy(self.squads[uid]))
        if m == "PATCH" and path == "/api/internal-squads":
            self.squads[body["uuid"]]["inbounds"] = [{"uuid": u} for u in body["inbounds"]]
            return w(copy.deepcopy(self.squads[body["uuid"]]))
        if m == "GET" and path.startswith("/api/users/by-username/"):
            name = path.rsplit("/", 1)[1]
            u = next((u for u in self.users.values() if u["username"] == name), None)
            return w(copy.deepcopy(u)) if u else nf
        if m == "POST" and path == "/api/users":
            uid = self.new_id("user")
            self.users[uid] = {"uuid": uid, "vlessUuid": RELAY_VLESS, **body}
            return w(copy.deepcopy(self.users[uid]))
        if m == "GET" and path == "/api/system/tools/x25519/generate":
            return w({"keypairs": [{"publicKey": "PUB", "privateKey": PRIV}]})
        if m == "DELETE":
            for coll, prefix in ((self.hosts, "/api/hosts/"), (self.users, "/api/users/"),
                                 (self.squads, "/api/internal-squads/")):
                if path.startswith(prefix):
                    coll.pop(path[len(prefix):], None)
                    return w({"isDeleted": True})
        return httpx.Response(404, json={"message": f"no route {m} {path}"})


class Cloudflare:
    def __init__(self, ssl_mode="full"):
        self.ssl_mode = ssl_mode
        self.records = {}
        self.calls = []

    def handler(self, req):
        m, path = req.method, req.url.path.replace("/client/v4", "")
        body = json.loads(req.content) if req.content else None
        self.calls.append((m, path, body))
        ok = lambda r: httpx.Response(200, json={"success": True, "result": r})  # noqa: E731
        if path == "/zones":
            return ok([{"id": "z1", "name": req.url.params.get("name")}])
        if path == "/zones/z1/settings/ssl":
            return ok({"id": "ssl", "value": self.ssl_mode})
        if path == "/zones/z1/dns_records" and m == "GET":
            return ok([r for r in self.records.values() if r["name"] == req.url.params.get("name")])
        if path == "/zones/z1/dns_records" and m == "POST":
            rid = f"rec{len(self.records) + 1}"
            self.records[rid] = {"id": rid, **body}
            return ok(self.records[rid])
        if path.startswith("/zones/z1/dns_records/") and m == "DELETE":
            self.records.pop(path.rsplit("/", 1)[1], None)
            return ok({"id": "x"})
        return httpx.Response(404, json={"success": False, "errors": [{"code": 7003, "message": "no route"}]})


PRECHECK_OK = ("mounts=/etc/letsencrypt,/opt/remnanode,\ncontainer=Up 2 days\nhubcert=absent\n"
               "openssl=ok\nufw=active\nbusy=no\n")


@pytest.fixture
def env(monkeypatch, hub_settings):
    remna.add("pablo", "https://panelpablo.mooo.com", "tok", "https://auth.pablovpn.com/sub/")
    remna.set_cf("pablo", "pablo.stream", "CF-TOKEN-SECRET")
    panel, cf = Panel(), Cloudflare()
    monkeypatch.setattr(remna, "_TRANSPORT", httpx.MockTransport(panel.handler))
    monkeypatch.setattr(re_, "_CF_TRANSPORT", httpx.MockTransport(cf.handler))
    monkeypatch.setattr(re_, "_resolve", lambda h: [EXIT_IP] if h.startswith("nl01s1") else [])
    sent = {"scripts": [], "pre": PRECHECK_OK, "handshake": 101}

    async def run_script(node, script, timeout=45):
        sent["scripts"].append((node, script))
        if "busy=yes" in script:
            return ssh.SshResult(True, 0, sent["pre"], "", 1.0)
        return ssh.SshResult(True, 0, "cert=ok\nufw=opened\n" + re_.DONE_MARK + "\n", "", 2.0)

    async def handshake(host, port, path, timeout=12):
        sent.setdefault("hs", []).append((host, port, path))
        return sent["handshake"]

    monkeypatch.setattr(ssh, "run_script", run_script)
    monkeypatch.setattr(re_, "ws_handshake", handshake)
    monkeypatch.setattr(re_, "SETTLE_S", 0)
    monkeypatch.setattr(re_, "HEALTH_WAIT_S", 5)
    monkeypatch.setattr(re_, "VERIFY_PAUSE_S", 0)
    monkeypatch.setattr(asyncio, "sleep", _nosleep)
    hub_settings.allow_actions = True
    return panel, cf, sent


async def _nosleep(*a, **k):
    return None


def do(node, op, args):
    pl = run(re_.plan("pablo", node, op, args))
    assert pl["ok"], pl["problems"]
    return pl, run(re_.apply("pablo", node, op, args, pl["plan_hash"]))


# ── простые правки ────────────────────────────────────────────────────────

def test_reality_sni_profile_and_hosts(env):
    panel, cf, sent = env
    pl, res = do("ru01s3", "reality_sni", {"sni": "dl.google.com"})
    assert res["ok"], res
    assert any("ru02s3" in w for w in pl["warnings"])        # общий профиль — правка у обеих
    rs = panel.profiles["p-ru"]["config"]["inbounds"][0]["streamSettings"]["realitySettings"]
    assert rs["serverNames"] == ["dl.google.com"] and rs["dest"] == "dl.google.com:443"
    assert rs["privateKey"] == "OLD-PK" and rs["minClientVer"] == "1.0.0"
    assert panel.hosts["h-ru"]["sni"] == "dl.google.com"


def test_host_fields_and_guards(env):
    panel, cf, sent = env
    pl = run(re_.plan("pablo", "ru01s3", "host", {"host": "Россия", "set": {"bogus": 1}}))
    assert not pl["ok"] and "bogus" in pl["problems"][0]
    pl = run(re_.plan("pablo", "ru01s3", "host", {"host": "Россия", "set": {"fingerprint": "chrome"}}))
    assert any("инвариант 56" in w for w in pl["warnings"])
    _, res = do("ru01s3", "host", {"host": "Россия", "set": {"isDisabled": "true", "port": "8443"}})
    assert res["ok"]
    assert panel.hosts["h-ru"]["isDisabled"] is True and panel.hosts["h-ru"]["port"] == 8443


def test_squad_remove_keeps_other_inbounds(env):
    panel, cf, sent = env
    _, res = do("ru01s3", "squad", {"inbound": "RE_RU", "action": "remove"})
    assert res["ok"]
    assert [i["uuid"] for i in panel.squads["sq-main"]["inbounds"]] == ["inb-hy_nl"]


def test_plan_is_stable_and_goes_stale(env):
    panel, cf, sent = env
    args = {"sni": "dl.google.com"}
    a = run(re_.plan("pablo", "ru01s3", "reality_sni", args))
    b = run(re_.plan("pablo", "ru01s3", "reality_sni", args))
    assert a["plan_hash"] == b["plan_hash"]
    panel.hosts["h-ru"]["remark"] = "переименовал бот"
    res = run(re_.apply("pablo", "ru01s3", "reality_sni", args, a["plan_hash"]))
    assert res["error"] == "plan_changed"
    assert not any(m in ("PATCH", "POST") for m, _, _ in panel.calls)


def test_node_down_after_edit_rolls_back(env):
    panel, cf, sent = env
    before = panel.snapshot()["profiles"]
    panel.connected_after_patch = False
    pl = run(re_.plan("pablo", "ru01s3", "reality_sni", {"sni": "dl.google.com"}))
    res = run(re_.apply("pablo", "ru01s3", "reality_sni", {"sni": "dl.google.com"}, pl["plan_hash"]))
    assert not res["ok"] and res["error"] == "edit_failed"
    assert panel.profiles == before
    assert panel.hosts["h-ru"]["sni"] == "ads.x5.ru"


def test_actions_disabled(env, hub_settings):
    hub_settings.allow_actions = False
    assert run(re_.apply("pablo", "ru01s3", "host", {}, "x"))["error"] == "actions_disabled"


# ── каскад: выход ─────────────────────────────────────────────────────────

def test_cf_exit_builds_front_and_relay(env):
    panel, cf, sent = env
    pl, res = do("nl01s1", "cf_exit", {})
    assert res["ok"], res
    # Cloudflare: A-запись с облаком на IP ноды (адрес ноды — домен).
    rec = next(iter(cf.records.values()))
    assert (rec["type"], rec["name"], rec["content"], rec["proxied"]) == ("A", "nl01s1.pablo.stream", EXIT_IP, True)
    # Профиль: WS+TLS на CF-порту, имя фронта в wsSettings.host, свой сертификат.
    ib = next(i for i in panel.profiles["p-nl"]["config"]["inbounds"] if i["tag"].startswith("HUB_CF_"))
    ss = ib["streamSettings"]
    assert ib["port"] == 2087 and ss["network"] == "ws" and ss["security"] == "tls"
    assert ss["wsSettings"]["host"] == "nl01s1.pablo.stream"
    assert ss["tlsSettings"]["alpn"] == ["http/1.1"]
    assert ss["tlsSettings"]["certificates"][0]["certificateFile"].startswith(re_.CF_CERT_DIR)
    # Включён только на этой ноде, сквад реле — только с фронтом, юзер — в нём.
    active = [a["tag"] for a in panel.nodes["n-nl"]["configProfile"]["activeInbounds"]]
    assert active == ["HY_NL", ib["tag"]]
    relay_sq = next(s for s in panel.squads.values() if s["name"] == "hub-relay-nl01s1")
    assert [i["uuid"] for i in relay_sq["inbounds"]] == [panel.iu(ib["tag"])]
    user = next(iter(panel.users.values()))
    assert user["username"] == "hub-relay-nl01s1" and user["activeInternalSquads"] == [relay_sq["uuid"]]
    assert user["trafficLimitBytes"] == 0 and user["expireAt"].startswith("2099")
    # Публичной строки не просили — главный сквад и хосты не тронуты.
    assert [i["uuid"] for i in panel.squads["sq-main"]["inbounds"]] == ["inb-hy_nl", "inb-re_ru"]
    assert len(panel.hosts) == 2
    # Сервер: сертификат + порт только сетям Cloudflare; проверка — через фронт.
    script = sent["scripts"][-1][1]
    assert "openssl req -x509" in script and "173.245.48.0/20" in script and "port 2087" in script
    assert sent["hs"][-1] == ("nl01s1.pablo.stream", 2087, ss["wsSettings"]["path"])
    assert RELAY_VLESS not in json.dumps(res, ensure_ascii=False)
    assert "CF-TOKEN-SECRET" not in json.dumps(pl, ensure_ascii=False)


def test_cf_exit_rolls_back_everything_when_front_is_dead(env):
    panel, cf, sent = env
    before = panel.snapshot()
    sent["handshake"] = 522
    pl = run(re_.plan("pablo", "nl01s1", "cf_exit", {}))
    res = run(re_.apply("pablo", "nl01s1", "cf_exit", {}, pl["plan_hash"]))
    assert not res["ok"] and "522" in res["detail"]
    assert cf.records == {}
    assert panel.snapshot() == before


def test_cf_exit_refuses_strict_zone_and_busy_record(env):
    panel, cf, sent = env
    cf.ssl_mode = "strict"
    pl = run(re_.plan("pablo", "nl01s1", "cf_exit", {}))
    assert not pl["ok"] and any("526" in p for p in pl["problems"])
    cf.ssl_mode = "full"
    cf.records["r"] = {"id": "r", "type": "A", "name": "nl01s1.pablo.stream", "content": "1.1.1.1",
                       "proxied": True}
    pl = run(re_.plan("pablo", "nl01s1", "cf_exit", {}))
    assert not pl["ok"] and any("уже есть" in p for p in pl["problems"])


# ── каскад: вход ──────────────────────────────────────────────────────────

def test_cascade_entry_needs_front_first(env):
    pl = run(re_.plan("pablo", "ru01s3", "cascade_entry", {"exit": "nl01s1", "sni": "ads.x5.ru"}))
    assert not pl["ok"] and "cf_exit" in pl["problems"][0]


def test_cascade_entry_full_path(env):
    panel, cf, sent = env
    do("nl01s1", "cf_exit", {})
    front = next(i for i in panel.profiles["p-nl"]["config"]["inbounds"] if i["tag"].startswith("HUB_CF_"))
    pl, res = do("ru01s3", "cascade_entry", {"exit": "nl01s1", "sni": "ads.x5.ru"})
    assert res["ok"], res
    cfg = panel.profiles["p-ru"]["config"]
    entry = next(i for i in cfg["inbounds"] if i["tag"] == "HUB_CASCADE_NL01S1")
    rs = entry["streamSettings"]["realitySettings"]
    assert entry["port"] == 8443                                  # 443 занят RE_RU
    assert rs["privateKey"] == PRIV and rs["minClientVer"] == "1.0.0"
    assert all(re.fullmatch(r"[0-9a-f]{8}|", s) for s in rs["shortIds"])
    # Реле: на фронт выхода, юзер реле, WS+TLS http/1.1, mux с UDP мимо.
    relay = next(o for o in cfg["outbounds"] if o["tag"] == "HUB_RELAY_NL01S1")
    vn = relay["settings"]["vnext"][0]
    assert (vn["address"], vn["port"], vn["users"][0]["id"]) == ("nl01s1.pablo.stream", 2087, RELAY_VLESS)
    assert relay["streamSettings"]["wsSettings"]["path"] == front["streamSettings"]["wsSettings"]["path"]
    assert relay["streamSettings"]["tlsSettings"]["alpn"] == ["http/1.1"]
    assert relay["mux"]["xudpConcurrency"] == -1
    # Правила: блокировки клиента первыми, затем DNS, Рунет напрямую, реле; общие — после.
    rules = cfg["routing"]["rules"]
    assert rules[:2] == BASE_RULES[:2]
    assert rules[2] == {"type": "field", "network": "udp", "port": "53", "outboundTag": "DIRECT"}
    assert rules[3]["inboundTag"] == ["HUB_CASCADE_NL01S1"] and rules[3]["outboundTag"] == "DIRECT"
    assert "domain:gosuslugi.ru" in rules[3]["domain"] and not any(
        d.startswith("geosite:") for d in rules[3]["domain"])
    assert rules[4] == {"type": "field", "inboundTag": ["HUB_CASCADE_NL01S1"], "outboundTag": "HUB_RELAY_NL01S1"}
    assert rules[5:] == BASE_RULES[2:]
    # Вход включён только на ru01s3 (профиль общий с ru02s3).
    assert [a["tag"] for a in panel.nodes["n-ru"]["configProfile"]["activeInbounds"]] == ["RE_RU", "HUB_CASCADE_NL01S1"]
    assert [a["tag"] for a in panel.nodes["n-ru2"]["configProfile"]["activeInbounds"]] == ["RE_RU"]
    # Строка: скрыта, firefox, на IP входа, в главном скваде.
    host = next(h for h in panel.hosts.values() if h["remark"].endswith("через РФ"))
    assert host["isDisabled"] is True and host["fingerprint"] == "firefox"
    assert (host["address"], host["port"], host["sni"]) == (ENTRY_IP, 8443, "ads.x5.ru")
    assert panel.iu("HUB_CASCADE_NL01S1") in [i["uuid"] for i in panel.squads["sq-main"]["inbounds"]]
    # Секреты — ни в плане, ни в итоге.
    dump = json.dumps([pl, res], ensure_ascii=False)
    assert RELAY_VLESS not in dump and PRIV not in dump


def test_cascade_entry_failure_restores_entry_profile(env):
    panel, cf, sent = env
    do("nl01s1", "cf_exit", {})
    before = panel.snapshot()
    panel.connected_after_patch = False
    pl = run(re_.plan("pablo", "ru01s3", "cascade_entry", {"exit": "nl01s1", "sni": "ads.x5.ru"}))
    res = run(re_.apply("pablo", "ru01s3", "cascade_entry", {"exit": "nl01s1", "sni": "ads.x5.ru"},
                        pl["plan_hash"]))
    assert not res["ok"]
    after = panel.snapshot()
    after["nodes"] = {k: {**v, "isConnected": True} for k, v in after["nodes"].items()}
    assert after == before
    assert PRIV not in json.dumps(res, ensure_ascii=False)


# ── сторож копии (инвариант 25) ───────────────────────────────────────────

def test_ru_direct_lists_match_panel(vgx3d):
    """Наборы Рунета — копия vgx3d services/service_domains.py."""
    text = (vgx3d / "brain/app/services/service_domains.py").read_text(encoding="utf-8")
    ns: dict = {}
    for name in ("YANDEX_DOMAINS", "VK_DOMAINS", "GOSUSLUGI_DOMAINS"):
        m = re.search(rf"^{name} = (\[.*?^\])", text, re.S | re.M)
        assert m, name
        ns[name] = eval(m.group(1), {})  # noqa: S307 — литерал списка из нашего же репо
        assert getattr(re_, name) == ns[name], name
