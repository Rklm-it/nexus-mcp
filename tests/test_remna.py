"""Связка Remnawave (+ бот 3XUIStore) в хабе: реестр, клиент API, чтение.

Remnawave подменён httpx.MockTransport по контракту remnawave/backend 3.x:
ответы обёрнуты в {"response": ...}, списки — массивом или {total, <ключ>}.
"""

import asyncio
import json
import os
import stat

import httpx
import pytest

from nexus_mcp import remna

USER = {
    "id": 7, "username": "u7_abc", "telegramId": 111, "status": "ACTIVE",
    "expireAt": "2026-12-01T00:00:00.000Z", "hwidDeviceLimit": 2,
    "shortUuid": "aaaaaaaa-0000-4000-8000-000000000001",
    "vlessUuid": "aaaaaaaa-0000-4000-8000-000000000001",
    "trafficLimitBytes": 0, "activeInternalSquads": [{"name": "PabloWD"}],
    "userTraffic": {"usedTrafficBytes": 5_000_000_000, "onlineAt": None,
                    "lastConnectedNodeUuid": "n1"},
}
NODE = {
    "uuid": "n1", "name": "nl01s1", "address": "nl01s1.pablo.support", "port": 2222,
    "countryCode": "NL", "isConnected": True, "isDisabled": False, "usersOnline": 30,
    "trafficUsedBytes": 2_000_000_000_000, "trafficLimitBytes": 0, "lastStatusMessage": "",
    "configProfile": {"activeConfigProfileUuid": "cp1", "activeInbounds": [{"tag": "HY"}]},
}
DOWN = {**NODE, "uuid": "n2", "name": "ger01s3", "isConnected": False}
PROFILE = {
    "uuid": "cp1", "name": "profile-nl",
    "config": {
        "inbounds": [
            {"tag": "HY", "protocol": "hysteria", "port": 443,
             "settings": {"clients": [{"auth": "x"}, {"auth": "y"}], "version": 2},
             "streamSettings": {"network": "hysteria", "security": "tls", "tlsSettings": {
                 "alpn": ["h3"], "certificates": [{
                     "certificateFile": "/etc/letsencrypt/live/nl01s1.pablo.support/fullchain.pem",
                     "keyFile": "/etc/letsencrypt/live/nl01s1.pablo.support/privkey.pem"}]}}},
            {"tag": "RE", "protocol": "vless", "port": 8443,
             "settings": {"clients": [], "decryption": "none"},
             "streamSettings": {"network": "tcp", "security": "reality", "realitySettings": {
                 "privateKey": "SECRET-PRIVATE-KEY", "serverNames": ["ads.x5.ru"],
                 "dest": "ads.x5.ru:443", "shortIds": ["ab", ""]}}},
        ],
        "outbounds": [{"tag": "DIRECT", "protocol": "freedom"}],
        "routing": {"rules": [{"outboundTag": "DIRECT", "password": "leak"}]},
    },
}


class Fake:
    def __init__(self):
        self.calls = []

    def handler(self, req: httpx.Request) -> httpx.Response:
        self.calls.append(req)
        path = req.url.path
        if req.headers.get("authorization") != "Bearer tok":
            return httpx.Response(401, json={"message": "Unauthorized"})
        wrap = lambda v: httpx.Response(200, json={"response": v})  # noqa: E731
        if path == "/api/nodes":
            return wrap([NODE, DOWN])
        if path == "/api/system/stats":
            return wrap({"users": {"statusCounts": {"ACTIVE": 1}, "totalUsers": 1},
                         "onlineStats": {"onlineNow": 5, "lastDay": 9}})
        if path == "/api/system/metadata":
            return wrap({"version": "3.2.1"})
        if path == "/api/users":
            flt = json.loads(req.url.params.get("filters") or "[]")
            tg = flt[0]["value"] if flt else None
            return wrap({"users": [USER] if tg == "111" else [], "total": 1})
        if path.startswith("/api/users/by-short-uuid/"):
            return wrap(USER) if path.endswith(USER["shortUuid"]) else httpx.Response(404, json={"message": "nf"})
        if path.startswith("/api/users/by-username/"):
            return httpx.Response(404, json={"message": "nf"})
        if path == "/api/hwid/devices/7":
            return wrap({"devices": [{"platform": "Android", "deviceModel": "Pixel", "hwid": "SECRETHW"}],
                         "total": 1})
        if path == "/api/config-profiles/cp1":
            return wrap(PROFILE)
        return httpx.Response(404, json={"message": "no route"})


@pytest.fixture
def fake(monkeypatch):
    f = Fake()
    monkeypatch.setattr(remna, "_TRANSPORT", httpx.MockTransport(f.handler))
    remna.add("pablo", "https://panelpablo.mooo.com", "tok", "https://auth.pablovpn.com/sub")
    return f


def run(coro):
    return asyncio.new_event_loop().run_until_complete(coro)


# ── реестр ────────────────────────────────────────────────────────────────

def test_registry_file_private_and_no_token_in_view(hub_settings):
    v = remna.add("pablo", "https://panelpablo.mooo.com/", "SECRET-TOKEN-123", "https://auth.pablovpn.com/sub")
    assert v == {"name": "pablo", "url": "https://panelpablo.mooo.com", "token": True,
                 "sub_url": "https://auth.pablovpn.com/sub/", "cf_zone": "", "cf_token": False}
    mode = stat.S_IMODE(os.stat(hub_settings.remna_file).st_mode)
    assert mode == 0o600
    assert "SECRET-TOKEN-123" not in json.dumps(remna.public_view(remna.resolve("pablo")))


def test_registry_validation(hub_settings):
    with pytest.raises(remna.RemnaError):
        remna.add("bad name", "https://x.ru", "t")
    with pytest.raises(remna.RemnaError):
        remna.add("ok", "ftp://x", "t")
    with pytest.raises(remna.RemnaError):
        remna.add("ok", "https://x.ru", "")


def test_resolve_single_and_ambiguous(hub_settings):
    remna.add("a", "https://a.ru", "t")
    assert remna.resolve("")["name"] == "a"
    remna.add("b", "https://b.ru", "t")
    with pytest.raises(remna.RemnaError, match="несколько"):
        remna.resolve("")
    assert remna.resolve("B")["name"] == "b"


def test_cli_add_list_remove(hub_settings, capsys):
    assert remna.main(["add", "p", "https://p.ru", "secret-tok", "--sub", "https://b.ru/sub/"]) == 0
    assert remna.main(["list"]) == 0
    out = capsys.readouterr().out
    assert "https://p.ru" in out and "secret-tok" not in out
    assert remna.main(["remove", "p"]) == 0
    assert remna.main(["remove", "p"]) == 1


# ── клиент и чтение ───────────────────────────────────────────────────────

def test_sends_forwarded_headers(fake):
    run(remna.nodes(remna.resolve()))
    req = fake.calls[0]
    assert req.headers["x-forwarded-proto"] == "https"
    assert req.headers["authorization"] == "Bearer tok"


def test_401_is_explained(fake):
    remna.add("other", "https://x.ru", "wrong")
    with pytest.raises(remna.RemnaError, match="401"):
        run(remna.nodes(remna.resolve("other")))


def test_overview_counts_down_nodes(fake):
    o = run(remna.overview(remna.resolve()))
    assert o["version"] == "3.2.1" and o["nodes_total"] == 2 and o["nodes_online"] == 1
    assert o["nodes_down"] == ["ger01s3"] and o["online_now"] == 5


def test_user_by_telegram_uses_filter_and_builds_sub_link(fake):
    users = run(remna.find_user(remna.resolve(), "111"))
    assert len(users) == 1
    u = users[0]
    assert u["sub_link"] == "https://auth.pablovpn.com/sub/" + USER["shortUuid"]
    assert u["key_equals_link"] is True
    assert "vlessUuid" not in json.dumps(u) and USER["vlessUuid"] not in json.dumps(
        {k: v for k, v in u.items() if k not in ("short_uuid", "sub_link")})
    flt = json.loads(fake.calls[0].url.params["filters"])
    assert flt == [{"id": "telegramId", "value": "111"}]


def test_user_by_short_uuid_and_not_found(fake):
    assert run(remna.find_user(remna.resolve(), USER["shortUuid"]))[0]["username"] == "u7_abc"
    assert run(remna.find_user(remna.resolve(), "nobody")) == []


def test_devices_hide_hwid(fake):
    devs = run(remna.user_devices(remna.resolve(), 7))
    assert devs == [{"platform": "Android", "osVersion": None, "deviceModel": "Pixel",
                     "userAgent": None, "createdAt": None, "updatedAt": None}]


def test_profile_masks_secrets(fake):
    pr = run(remna.profile(remna.resolve(), "nl01s1"))
    dump = json.dumps(pr, ensure_ascii=False)
    assert "SECRET-PRIVATE-KEY" not in dump and "leak" not in dump
    hy, re_ = pr["inbounds"]
    assert hy["protocol"] == "hysteria" and hy["cert_domain"] == "nl01s1.pablo.support"
    assert re_["reality_sni"] == ["ads.x5.ru"] and re_["short_ids"] == 2


def test_node_lookup_errors(fake):
    with pytest.raises(remna.RemnaError, match="нет"):
        run(remna.profile(remna.resolve(), "zz"))
