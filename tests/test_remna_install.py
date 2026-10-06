"""Новая нода Remnawave с хаба: план, установка, откат.

SSH подменён (как в test_node_install), Remnawave — httpx.MockTransport по
контракту remnawave/backend 3.x. Проверяем то, что ломается молча:
* секрет ноды не попадает в вывод, но доходит до сервера;
* профиль повторяет рабочие ноды клиента (Hysteria2 TLS h3 BBR) и Reality
  с minClientVer 1.0.0 и отпечатком firefox;
* инбаунд дописывается в сквад, а не заменяет его инбаунды;
* упало в панели — созданное этим запуском удалено;
* план изменился — установка не идёт.
"""

import asyncio
import json
import subprocess

import httpx
import pytest

from nexus_mcp import remna, ssh
from nexus_mcp import remna_install as ri

SECRET = "SECRETKEY-abcdef-0123456789"
DONE = "docker=ok\ncert=ok\ncontainer=Up 3 seconds\n" + ri.DONE_MARK + "\n"


def run(coro):
    return asyncio.new_event_loop().run_until_complete(coro)


class Panel:
    def __init__(self, fail_host=False):
        self.calls = []
        self.fail_host = fail_host
        self.squad_inbounds = [{"uuid": "old-inb-1"}, {"uuid": "old-inb-2"}]

    def handler(self, req: httpx.Request) -> httpx.Response:
        body = json.loads(req.content) if req.content else None
        self.calls.append((req.method, req.url.path, body))
        w = lambda v: httpx.Response(200, json={"response": v})  # noqa: E731
        m, path = req.method, req.url.path
        if m == "GET" and path == "/api/nodes":
            return w([{"uuid": "n0", "name": "ger01s3", "address": "ger01s3.pablo.support"}])
        if m == "GET" and path == "/api/internal-squads":
            return w({"total": 2, "internalSquads": [
                {"uuid": "sq-small", "name": "Test", "info": {"membersCount": 3}, "inbounds": []},
                {"uuid": "sq-main", "name": "PabloWD", "info": {"membersCount": 16000},
                 "inbounds": self.squad_inbounds},
            ]})
        if m == "GET" and path == "/api/keygen":
            return w({"secretKey": SECRET})
        if m == "GET" and path == "/api/system/tools/x25519/generate":
            return w({"keypairs": [{"publicKey": "PUB", "privateKey": "PRIVATE-X25519"}]})
        if m == "POST" and path == "/api/config-profiles":
            tag = body["config"]["inbounds"][0]["tag"]
            return w({"uuid": "prof-new", "name": body["name"],
                      "inbounds": [{"uuid": "inb-new", "tag": tag}]})
        if m == "POST" and path == "/api/nodes":
            return w({"uuid": "node-new", "name": body["name"]})
        if m == "POST" and path == "/api/hosts":
            if self.fail_host:
                return httpx.Response(400, json={"message": "Host validation failed"})
            return w({"uuid": "host-new", "remark": body["remark"]})
        if m == "PATCH" and path == "/api/internal-squads":
            return w({"uuid": body["uuid"]})
        if m == "GET" and path == "/api/nodes/node-new":
            return w({"uuid": "node-new", "isConnected": True})
        if m == "DELETE":
            return w({"isDeleted": True})
        return httpx.Response(404, json={"message": f"no route {m} {path}"})


@pytest.fixture
def setup(monkeypatch, hub_settings):
    remna.add("pablo", "https://panelpablo.mooo.com", "tok", "https://auth.pablovpn.com/sub/")
    panel = Panel()
    monkeypatch.setattr(remna, "_TRANSPORT", httpx.MockTransport(panel.handler))
    monkeypatch.setattr(ri, "_resolve_ip", lambda host: ["45.141.118.7"] if "pablo.support" in host
                        else ["45.67.58.40"])
    sent = {}

    async def run_script(node, script, timeout=45):
        if "busy=" in script and "docker_get" in script:
            sent["precheck"] = script
            return ssh.SshResult(True, 0, sent.get("pre_out", "os=Ubuntu 24.04\ndocker=absent\n"
                                 "remnanode=absent\nbusy=22:sshd,\nufw=active\ndocker_get=ok\nregistry=ok\n"), "", 5.0)
        sent["install"] = script
        return ssh.SshResult(True, 0, sent.get("install_out", DONE + f"echo {SECRET}\n"), "", 30.0)

    monkeypatch.setattr(ssh, "run_script", run_script)
    monkeypatch.setattr(ri, "CONNECT_WAIT_S", 5)
    hub_settings.allow_actions = True
    return panel, sent


def hy_params(**kw):
    return ri.check_params("45.141.118.7", "nl05s1", "nl", domain="nl05s1.pablo.support", **kw)


# ── параметры, шаблоны, скрипты ───────────────────────────────────────────

def test_params_validation():
    with pytest.raises(ri.InstallError, match="domain"):
        ri.check_params("45.141.118.7", "nl05s1", "NL", template="hysteria2")
    with pytest.raises(ri.InstallError, match="reality_sni"):
        ri.check_params("45.141.118.7", "nl05s1", "NL", template="reality")
    with pytest.raises(ri.InstallError, match="внутренний"):
        ri.check_params("10.0.0.1", "nl05s1", "NL", domain="a.example.com")
    with pytest.raises(ri.InstallError, match="node_port"):
        ri.check_params("45.141.118.7", "nl05s1", "NL", domain="a.example.com", node_port=443)
    p = hy_params()
    assert p["country"] == "NL" and p["remark"] == "🇳🇱 nl05s1"


def test_hysteria_profile_like_clients_nodes():
    p = hy_params()
    cfg = ri.profile_config(p, "HYSTERIA_BBR_ABC123")
    ib = cfg["inbounds"][0]
    assert (ib["protocol"], ib["port"], ib["settings"]["version"]) == ("hysteria", 443, 2)
    ss = ib["streamSettings"]
    assert ss["finalmask"]["quicParams"]["congestion"] == "bbr"
    assert ss["tlsSettings"]["alpn"] == ["h3"]
    assert ss["tlsSettings"]["certificates"][0]["certificateFile"] == \
        "/etc/letsencrypt/live/nl05s1.pablo.support/fullchain.pem"
    assert {"ip": ["geoip:private"], "outboundTag": "BLOCK"} in cfg["routing"]["rules"]
    host = ri.host_body(p, "pr", "ib", "nd")
    assert (host["address"], host["sni"], host["alpn"], host["securityLayer"]) == \
        ("nl05s1.pablo.support", "nl05s1.pablo.support", "h3", "TLS")


def test_reality_profile_open_to_old_clients_and_firefox():
    p = ri.check_params("45.141.118.7", "ru02", "RU", template="reality", reality_sni="ads.x5.ru")
    rs = ri.profile_config(p, "VLESS_REALITY_X", {"privateKey": "PK"})["inbounds"][0]["streamSettings"]["realitySettings"]
    assert rs["minClientVer"] == "1.0.0" and rs["privateKey"] == "PK"
    assert rs["serverNames"] == ["ads.x5.ru"] and rs["dest"] == "ads.x5.ru:443"
    assert ri.host_body(p, "pr", "ib", "nd")["fingerprint"] == "firefox"


def test_scripts_are_valid_bash():
    p = hy_params()
    for script in (ri.precheck_script(p), ri.install_script(p, SECRET, "45.67.58.40")):
        assert subprocess.run(["bash", "-n"], input=script, text=True).returncode == 0
    inst = ri.install_script(p, SECRET, "45.67.58.40")
    assert "/etc/letsencrypt:/etc/letsencrypt:ro" in inst
    assert 'docker restart remnanode' in inst
    assert "ufw allow from 45.67.58.40 to any port 2222" in inst
    assert ri.DONE_MARK in inst


# ── план ──────────────────────────────────────────────────────────────────

def test_plan_ok_picks_biggest_squad(setup):
    panel, sent = setup
    pl = run(ri.plan("pablo", hy_params()))
    assert pl["ok"], pl["problems"]
    assert pl["will_create"]["squad"] == "PabloWD"
    assert pl["plan_hash"]
    assert not any(c[0] != "GET" for c in panel.calls)      # план ничего не меняет


def test_plan_problems(setup):
    panel, sent = setup
    sent["pre_out"] = ("os=Ubuntu\ndocker=absent\nremnanode=present\nbusy=443:nginx,\n"
                       "docker_get=ok\nregistry=ok\n")
    p = ri.check_params("45.141.118.9", "ger01s3", "DE", domain="other.example.com")
    pl = run(ri.plan("pablo", p))
    text = " | ".join(pl["problems"])
    assert not pl["ok"]
    assert "remnanode" in text and "443" in text
    assert "уже есть" in text                       # имя ноды занято
    assert "смотрит на" in text                     # домен не на этот IP


# ── установка ─────────────────────────────────────────────────────────────

def test_install_happy_path(setup):
    panel, sent = setup
    p = hy_params()
    pl = run(ri.plan("pablo", p))
    res = run(ri.install("pablo", p, pl["plan_hash"]))
    assert res["ok"] and res["connected"], res
    # Секрет ушёл на сервер, но не в ответ.
    assert SECRET in sent["install"]
    assert SECRET not in json.dumps(res, ensure_ascii=False)
    writes = [(m, path) for m, path, _ in panel.calls if m != "GET"]
    assert writes == [("POST", "/api/config-profiles"), ("POST", "/api/nodes"),
                      ("POST", "/api/hosts"), ("PATCH", "/api/internal-squads")]
    squad_body = next(b for m, path, b in panel.calls if m == "PATCH")
    assert squad_body == {"uuid": "sq-main", "inbounds": ["old-inb-1", "old-inb-2", "inb-new"]}
    node_body = next(b for m, path, b in panel.calls if (m, path) == ("POST", "/api/nodes"))
    assert node_body["configProfile"] == {"activeConfigProfileUuid": "prof-new",
                                          "activeInbounds": ["inb-new"]}


def test_install_rejects_changed_plan(setup):
    panel, sent = setup
    res = run(ri.install("pablo", hy_params(), "stale-hash"))
    assert res["error"] == "plan_changed"
    assert not any(m != "GET" for m, _, _ in panel.calls)


def test_install_rolls_back_panel_objects(setup, monkeypatch):
    panel, sent = setup
    panel.fail_host = True
    p = hy_params()
    pl = run(ri.plan("pablo", p))
    res = run(ri.install("pablo", p, pl["plan_hash"]))
    assert not res["ok"] and res["error"] == "install_failed"
    deletes = [path for m, path, _ in panel.calls if m == "DELETE"]
    assert deletes == ["/api/nodes/node-new", "/api/config-profiles/prof-new"]
    assert not any(m == "PATCH" for m, _, _ in panel.calls)


def test_install_server_failure_stops_before_panel(setup):
    panel, sent = setup
    # Сервер упал и вывел секрет (например, set -x) — в ответ он попасть не должен.
    sent["install_out"] = f"+ SECRET_KEY={SECRET}\nRN_ERR=сертификат не выдан: too many requests\n"
    p = hy_params()
    pl = run(ri.plan("pablo", p))
    res = run(ri.install("pablo", p, pl["plan_hash"]))
    assert res["error"] == "server_failed" and "сертификат" in res["detail"]
    assert SECRET not in json.dumps(res, ensure_ascii=False)
    assert not any(m in ("POST", "PATCH") for m, _, _ in panel.calls)


def test_install_needs_actions_enabled(setup, hub_settings):
    hub_settings.allow_actions = False
    res = run(ri.install("pablo", hy_params(), "x"))
    assert res["error"] == "actions_disabled"
