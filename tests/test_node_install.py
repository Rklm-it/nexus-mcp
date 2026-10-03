"""node_install: хаб ставит ноду на чистый сервер и добавляет её в панель.

Скрипт установки гоняется настоящим bash с поддельным установщиком: так
видно, что значения доезжают окружением, вывод чистится от секретов и код
выхода установщика не теряется.
"""

import asyncio
import json
import subprocess

import pytest

from nexus_mcp import inventory, node_install as ni, ssh

INSTALLER = ('#!/usr/bin/env bash\nMASTER_BRAIN_URL="${MASTER_BRAIN_URL:-https://p.ru}"\n'
             'echo "url=$MASTER_BRAIN_URL name=$NODE_NAME country=$COUNTRY ip=$NODE_IP"\n'
             'echo "tok=$ADMIN_TOKEN"\n'
             "echo \"quote: it's $ \\\"x\\\"\"\n"
             'read -r x && echo "STDIN_EATEN"\n'
             'echo -e "  API-Key:         \\033[0;32mCELLSECRET\\033[0m"\n'
             'echo "|    Server PSK:       SSPSKSECRET"\n'
             'echo "|    ShortID:          SHORTSECRET"\n'
             'echo "|    PubKey:           PUBLICKEYOK"\n'
             'exit 7\n')

PARAMS = {"ip": "45.141.118.7", "name": "de 1 «тест»", "country": "DE", "ssh_port": 22,
          "cdn_domain": "", "route": "auto"}


@pytest.fixture
def panel(hub_settings):
    hub_settings.allow_actions = True
    hub_settings.brain_url = "https://p.ru"
    hub_settings.brain_admin_token = "ADMINTOKEN123"
    hub_settings.public_hosts = ["hub.example"]
    return hub_settings


def _run(script: str) -> str:
    r = subprocess.run(["bash", "-s"], input=script, text=True, capture_output=True, timeout=30)
    assert r.returncode == 0, r.stderr
    return r.stdout


# ── Параметры ──────────────────────────────────────────────────────────────

@pytest.mark.parametrize("kw,bad", [
    ({"ip": "1.2.3"}, "IP"),
    ({"ip": "10.0.0.5"}, "внутренний"),
    ({"name": ""}, "имя"),
    ({"name": "a\nb"}, "имя"),
    ({"country": "Германия"}, "код"),
    ({"ssh_port": 0}, "ssh_port"),
    ({"cdn_domain": "x; rm -rf /"}, "домен"),
    ({"route": "via"}, "route"),
])
def test_params_are_checked(kw, bad):
    args = {"ip": "45.141.118.7", "name": "de-1", "country": "de", **kw}
    with pytest.raises(ni.InstallError, match=bad):
        ni.check_params(**args)


def test_params_normalized():
    p = ni.check_params(" 45.141.118.7 ", " de-1 ", "de", 2222, "Origin.Example.com.")
    assert p == {"ip": "45.141.118.7", "name": "de-1", "country": "DE", "ssh_port": 2222,
                 "cdn_domain": "origin.example.com", "route": "auto"}


# ── Скрипты на сервере ─────────────────────────────────────────────────────

def test_install_script_passes_values_and_hides_secrets():
    out = _run(ni.install_script(INSTALLER, PARAMS, "ADM'IN$TOK"))
    assert "url=https://p.ru name=de 1 «тест» country=DE ip=45.141.118.7" in out
    assert "tok=ADM'IN$TOK" in out                          # значение доехало как есть
    assert "quote: it's $ \"x\"" in out                     # скрипт не покорёжен heredoc'ом
    assert "STDIN_EATEN" not in out                         # stdin установщика — /dev/null
    assert "CELLSECRET" not in out and "API-Key" not in out  # строка с ключом агента вырезана
    assert "SSPSKSECRET" not in out and "SHORTSECRET" not in out  # ключ SS-2022 и short_id — тоже
    assert "PUBLICKEYOK" in out                             # публичный ключ Reality — не секрет
    assert "\x1b[" not in out
    assert out.strip().endswith("rc=7")                     # код установщика, а не хвоста трубы


def test_install_script_relay_overrides_panel_url():
    s = ni.install_script(INSTALLER, PARAMS, "T", brain_url="https://hub.example/relay/main")
    assert "url=https://hub.example/relay/main" in _run(s)


def test_install_script_refuses_non_installer():
    with pytest.raises(ni.InstallError):
        ni.install_script("<html>login</html>", PARAMS, "T")


def test_precheck_script_is_valid_bash_and_parses():
    s = ni.precheck_script("https://p.ru", "https://hub.example/relay/main")
    assert subprocess.run(["bash", "-n"], input=s, text=True).returncode == 0
    kv = ni.parse_kv("os=Ubuntu 24.04 LTS\nuser=root\ncell=absent\nports=22,53,\npanel_direct=000\n")
    assert kv["os"] == "Ubuntu 24.04 LTS" and kv["panel_direct"] == "000"


def _fake_bin(tmp_path):
    """ss с «чужим» xray на 443 и 3x-ui на 2053; curl: ru-зеркало молчит."""
    b = tmp_path / "bin"
    b.mkdir()
    (b / "ss").write_text(
        "#!/bin/bash\n"
        "echo 'tcp LISTEN 0 4096 *:443 *:* users:((\"xray\",pid=11,fd=3))'\n"
        "echo 'tcp LISTEN 0 4096 0.0.0.0:2053 0.0.0.0:* users:((\"x-ui\",pid=12,fd=7))'\n"
        "echo 'tcp LISTEN 0 128 0.0.0.0:22 0.0.0.0:* users:((\"sshd\",pid=1,fd=3))'\n")
    (b / "curl").write_text('#!/bin/bash\nfor a; do u="$a"; done\n'
                            'case "$u" in *ru.archive*) echo -n 000; exit 28 ;; *) echo -n 200 ;; esac\n')
    for f in b.iterdir():
        f.chmod(0o755)
    return b


def _apt_dir(tmp_path):
    d = tmp_path / "apt"
    (d / "sources.list.d").mkdir(parents=True)
    (d / "sources.list.d" / "ubuntu.sources").write_text(
        "Types: deb\nURIs: http://ru.archive.ubuntu.com/ubuntu/\nSuites: noble noble-updates\n\n"
        "Types: deb\nURIs: http://security.ubuntu.com/ubuntu/\nSuites: noble-security\n")
    (d / "sources.list").write_text("# пусто\n")
    return d


def test_precheck_finds_dead_mirror_and_port_owners(tmp_path):
    """Прогон настоящим bash: зеркало и владельцы портов, как на польском VPS 03.10."""
    import os

    b, d = _fake_bin(tmp_path), _apt_dir(tmp_path)
    s = ni.precheck_script("https://p.ru", apt_sources=f"{d}/sources.list {d}/sources.list.d/*.sources")
    r = subprocess.run(["bash", "-s"], input=s, text=True, capture_output=True, timeout=30,
                       env={**os.environ, "PATH": f"{b}:{os.environ['PATH']}"})
    pre = ni.parse_kv(r.stdout)
    assert ni.parse_pairs(pre["port_owners"]) == {"443": "xray", "2053": "x-ui", "22": "sshd"}
    assert ni.parse_pairs(pre["apt_mirrors"]) == {"ru.archive.ubuntu.com": "000", "security.ubuntu.com": "200"}
    assert ni.dead_mirrors(pre) == ["ru.archive.ubuntu.com"]


def test_apt_fix_switches_only_dead_mirror(tmp_path):
    import os

    b, d = _fake_bin(tmp_path), _apt_dir(tmp_path)
    s = ni.apt_fix_script(["ru.archive.ubuntu.com"], force_ipv4=True, apt_dir=str(d),
                          backup_dir=str(tmp_path / "bak"))
    r = subprocess.run(["bash", "-s"], input=s, text=True, capture_output=True, timeout=30,
                       env={**os.environ, "PATH": f"{b}:{os.environ['PATH']}"})
    src = (d / "sources.list.d" / "ubuntu.sources").read_text()
    assert "URIs: http://archive.ubuntu.com/ubuntu/" in src and "ru.archive" not in src
    assert "http://security.ubuntu.com/ubuntu/" in src                 # чужое не тронуто
    assert 'ForceIPv4 "true"' in (d / "apt.conf.d" / "99nexus-force-ipv4").read_text()
    backups = list((tmp_path / "bak").glob("*/ubuntu.sources"))
    assert backups and "ru.archive" in backups[0].read_text()           # копия — до правки, не рядом
    assert not list((d / "sources.list.d").glob("*.bak"))
    assert "apt_fix=switched:ru.archive.ubuntu.com->archive.ubuntu.com:200" in r.stdout
    with pytest.raises(ni.InstallError):
        ni.apt_fix_script(["x; rm -rf /"], force_ipv4=False)


DEAD_MIRROR = ("user=root\ncell=absent\nports=22,443\nport_owners=443:xray,22:sshd,\npanel_direct=200\n"
               "apt_mirrors=ru.archive.ubuntu.com:000,security.ubuntu.com:200,\nipv6=no\n")


def test_preview_names_port_owner_and_dead_mirror(panel, monkeypatch):
    from nexus_mcp import server

    hub = FakeHub(monkeypatch, precheck=DEAD_MIRROR)
    r = asyncio.run(server.node_install("main", "45.141.118.7", "de-1", "DE"))
    assert r["ready"] and r["apt_fix"] == ["ru.archive.ubuntu.com"]
    text = " ".join(r["warnings"])
    assert "443 (xray)" in text and "ru.archive.ubuntu.com" in text
    assert not any("NEXUS_APT_FIX" in s for s in hub.scripts)          # план ничего не меняет


def test_install_fixes_mirror_before_installer(panel, monkeypatch):
    from nexus_mcp import server

    hub = FakeHub(monkeypatch, precheck=DEAD_MIRROR)
    r = asyncio.run(server.node_install("main", "45.141.118.7", "de-1", "DE", confirm=True))
    assert r["ok"] and r["apt_fix"].startswith("switched:ru.archive.ubuntu.com")
    order = [("fix" if "NEXUS_APT_FIX" in s else "install" if "NEXUS_INSTALLER_B64" in s else "other")
             for s in hub.scripts]
    assert order.index("fix") < order.index("install")
    assert "ForceIPv4" in next(s for s in hub.scripts if "NEXUS_APT_FIX" in s)   # ipv6=no


def test_install_stops_when_no_mirror_answers(panel, monkeypatch):
    from nexus_mcp import server

    hub = FakeHub(monkeypatch, precheck=DEAD_MIRROR)
    hub.apt_fix_result = "switched:ru.archive.ubuntu.com->archive.ubuntu.com:000 backup=/x"
    r = asyncio.run(server.node_install("main", "45.141.118.7", "de-1", "DE", confirm=True))
    assert r["ok"] is False and r["error"] == "apt_mirror_dead"
    assert not any("NEXUS_INSTALLER_B64" in s for s in hub.scripts)    # восемь минут впустую не тратим


@pytest.mark.parametrize("route,pre,relay,expect", [
    ("auto", {"panel_direct": "200"}, "R", ("direct", False)),
    ("auto", {"panel_direct": "000", "panel_relay": "200"}, "R", ("relay", False)),
    ("auto", {"panel_direct": "000", "panel_relay": "000"}, "R", ("direct", True)),
    ("direct", {"panel_direct": "000", "panel_relay": "200"}, "R", ("direct", True)),
    ("relay", {"panel_direct": "200", "panel_relay": "200"}, "R", ("relay", False)),
    ("relay", {"panel_direct": "200"}, "", ("relay", True)),
])
def test_route_choice(route, pre, relay, expect):
    r, _why, blocking = ni.pick_route(route, pre, relay)
    assert (r, blocking) == expect


# ── План и установка ───────────────────────────────────────────────────────

class FakeHub:
    """Сервер за SSH и панель: что выполнено и что зарегистрировано."""

    def __init__(self, monkeypatch, *, precheck="user=root\ncell=absent\nports=22\npanel_direct=200\npanel_relay=200\n",
                 installer_registers=True, servers=None):
        self.scripts: list[str] = []
        self.servers = list(servers or [])
        self.posted: list[dict] = []
        self.precheck = precheck
        self.installer_registers = installer_registers
        self.apt_fix_result = "switched:ru.archive.ubuntu.com->archive.ubuntu.com:200 backup=/var/backups/x"

        async def run_script(node, script, timeout=45):
            self.scripts.append(script)
            assert node["ssh_host"] == "45.141.118.7"
            if "panel_direct" in script:
                return ssh.SshResult(True, 0, self.precheck, "", 5.0)
            if "NEXUS_INSTALLER_B64" in script:
                if self.installer_registers:
                    self.servers.append({"id": "srv-1", "name": "de-1", "ip_address": "45.141.118.7"})
                return ssh.SshResult(True, 0, "шаг… токен ADMINTOKEN123\nrc=0\n", "", 5.0)
            if "CELL_API_TOKEN" in script:
                return ssh.SshResult(True, 0, "CELLTOKEN42\n", "", 5.0)
            if "NEXUS_APT_FIX" in script:
                return ssh.SshResult(True, 0, f"apt_fix={self.apt_fix_result}\n", "", 2.0)
            raise AssertionError(script[:200])

        async def brain_get(path, p, timeout=15.0):
            assert path == "/api/v1/servers"
            return list(self.servers)

        async def fetch_installer(p):
            return INSTALLER

        async def request(method, path, params=None, timeout=30.0, panel_name="", compact=None,
                          body=None, raw=False):
            assert (method, path) == ("POST", "/api/v1/servers")
            self.posted.append(body)
            row = {"id": "srv-2", "name": body["name"], "ip_address": body["ip_address"]}
            self.servers.append(row)
            return row

        monkeypatch.setattr(ssh, "run_script", run_script)
        monkeypatch.setattr(inventory, "brain_get", brain_get)
        monkeypatch.setattr(ni, "fetch_installer", fetch_installer)
        monkeypatch.setattr(ni.panel_api, "request", request)


def test_needs_actions_flag(hub_settings):
    from nexus_mcp import server

    r = asyncio.run(server.node_install("main", "45.141.118.7", "de-1", "DE"))
    assert r["error"] == "actions_disabled"


def test_preview_changes_nothing(panel, monkeypatch):
    from nexus_mcp import server

    hub = FakeHub(monkeypatch)
    r = asyncio.run(server.node_install("main", "45.141.118.7", "de-1", "DE"))
    assert r["preview"] and r["ready"] and r["route"] == "direct"
    assert not any("NEXUS_INSTALLER_B64" in s for s in hub.scripts)
    assert "ADMINTOKEN123" not in json.dumps(r, ensure_ascii=False)


def test_preview_blocks_duplicates_and_dirty_server(panel, monkeypatch):
    from nexus_mcp import server

    FakeHub(monkeypatch, precheck="user=root\ncell=present\nports=22,443\npanel_direct=200\n",
            servers=[{"id": "x", "name": "DE-1", "ip_address": "198.51.100.1"}])
    r = asyncio.run(server.node_install("main", "45.141.118.7", "de-1", "DE"))
    assert r["ready"] is False
    text = " ".join(r["blockers"])
    assert "Cell-агент" in text and "занято" in text
    assert any("443" in w for w in r["warnings"])
    # И установка по такому плану не начнётся.
    r = asyncio.run(server.node_install("main", "45.141.118.7", "de-1", "DE", confirm=True))
    assert r["ok"] is False and r["error"] == "not_ready"


def test_preview_explains_missing_hub_key(panel, monkeypatch):
    from nexus_mcp import server

    async def denied(node, script, timeout=45):
        return ssh.SshResult(False, 255, "", "root@45.141.118.7: Permission denied (publickey).", 5.0, "auth")

    FakeHub(monkeypatch)
    monkeypatch.setattr(ssh, "run_script", denied)
    r = asyncio.run(server.node_install("main", "45.141.118.7", "de-1", "DE"))
    assert r["ready"] is False and "authorized_keys" in r["blockers"][0]


def test_install_registered_by_installer(panel, monkeypatch):
    from nexus_mcp import audit, server

    hub = FakeHub(monkeypatch)
    r = asyncio.run(server.node_install("main", "45.141.118.7", "de-1", "DE", confirm=True))
    assert r["ok"] and r["registered_by"] == "installer" and r["server_id"] == "srv-1"
    assert r["route"] == "direct" and r["installer_rc"] == 0
    assert "ADMINTOKEN123" not in r["output"]                 # токен панели в вывод не попал
    install = next(s for s in hub.scripts if "NEXUS_INSTALLER_B64" in s)
    assert "MASTER_BRAIN_URL" not in install.split("NEXUS_INSTALLER_B64")[-1]  # напрямую — адрес из скрипта
    assert hub.posted == []
    assert audit.tail()[-1]["tool"] == "node_install" and audit.tail()[-1]["ok"] is True


def test_installer_rc_after_registered_node_is_explained(panel, monkeypatch):
    """Первый POST регистрации дошёл, ответ не успел, повтор получил 409 и
    установщик вышел с 1: нода в панели — это успех, с пояснением про код."""
    from nexus_mcp import server

    hub = FakeHub(monkeypatch)
    orig = ssh.run_script

    async def rc1(node, script, timeout=45):
        res = await orig(node, script, timeout)
        if "NEXUS_INSTALLER_B64" in script:
            return ssh.SshResult(True, 0, "HTTP 409 уже есть\nrc=1\n", "", 5.0)
        return res

    monkeypatch.setattr(ssh, "run_script", rc1)
    r = asyncio.run(server.node_install("main", "45.141.118.7", "de-1", "DE", confirm=True))
    assert r["ok"] and r["installer_rc"] == 1 and r["registered_by"] == "installer"
    assert "409" in r["note"] and hub.posted == []


def test_install_via_relay_registers_from_hub(panel, monkeypatch):
    """Сервер не достаёт до панели: агент качается через реле, а регистрацию
    (её через реле нет) делает хаб токеном агента."""
    from nexus_mcp import server

    hub = FakeHub(monkeypatch, precheck="user=root\ncell=absent\nports=22\npanel_direct=000\npanel_relay=200\n",
                  installer_registers=False)
    r = asyncio.run(server.node_install("main", "45.141.118.7", "de-1", "DE", confirm=True))
    assert r["ok"] and r["route"] == "relay" and r["registered_by"] == "hub"
    assert r["relay_url"] == "https://hub.example/relay/main"
    install = next(s for s in hub.scripts if "NEXUS_INSTALLER_B64" in s)
    assert "export MASTER_BRAIN_URL=https://hub.example/relay/main" in install
    assert hub.posted == [{"name": "de-1", "ip_address": "45.141.118.7", "api_port": 9090,
                           "api_token": "CELLTOKEN42", "country": "DE", "sub_type": "vpn",
                           "protocols": ["reality", "reality_grpc", "hysteria2", "shadowsocks"]}]
    assert "CELLTOKEN42" not in json.dumps(r, ensure_ascii=False)


def test_install_without_agent_is_failure(panel, monkeypatch):
    from nexus_mcp import server

    FakeHub(monkeypatch, installer_registers=False)

    async def no_agent(node, script, timeout=45):
        if "panel_direct" in script:
            return ssh.SshResult(True, 0, "user=root\ncell=absent\npanel_direct=200\n", "", 5.0)
        if "NEXUS_INSTALLER_B64" in script:
            return ssh.SshResult(True, 0, "[ОШИБКА] apt сломан\nrc=1\n", "", 5.0)
        return ssh.SshResult(True, 0, "", "", 5.0)

    monkeypatch.setattr(ssh, "run_script", no_agent)
    r = asyncio.run(server.node_install("main", "45.141.118.7", "de-1", "DE", confirm=True))
    assert r["ok"] is False and r["error"] == "no_agent" and r["installer_rc"] == 1


def test_dead_agent_is_not_registered(panel, monkeypatch):
    """Установщик упал посреди cell-setup: .env с токеном есть, агент не
    запущен — в панель такую ноду не заводим."""
    from nexus_mcp import server

    hub = FakeHub(monkeypatch, installer_registers=False)
    orig = ssh.run_script

    async def agent_down(node, script, timeout=45):
        if "CELL_API_TOKEN" in script:
            return ssh.SshResult(True, 0, f"{ni.AGENT_DOWN}\n", "", 5.0)
        return await orig(node, script, timeout)

    monkeypatch.setattr(ssh, "run_script", agent_down)
    r = asyncio.run(server.node_install("main", "45.141.118.7", "de-1", "DE", confirm=True))
    assert r["ok"] is False and r["error"] == "no_agent" and hub.posted == []


def test_cell_token_script_is_valid_bash():
    s = ni.cell_token_script()
    assert subprocess.run(["bash", "-n"], input=s, text=True).returncode == 0
    assert "is-active" in s.split("CELL_API_TOKEN")[0]      # сперва проверка агента


def test_cdn_node_registers_as_bypass():
    body = ni.register_body({**PARAMS, "cdn_domain": "o.example.com"}, "T")
    assert body["sub_type"] == "bypass" and body["protocols"] == ["vless_xhttp_cdn"]


# ── Сверка с кодом панели (инвариант 25) ───────────────────────────────────

def test_installer_contract_matches_panel(vgx3d):
    """Хаб полагается на установщик панели: значения окружением, свой адрес
    панели (реле) важнее вшитого, строка с ключом агента помечена API-Key."""
    text = (vgx3d / "license/dist/install-node.sh").read_text(encoding="utf-8")
    assert ni.INSTALLER_MARK in text
    for var in ("ADMIN_TOKEN", "NODE_NAME", "COUNTRY", "NODE_IP", "CDN_DOMAIN"):
        assert f'{var}="${{{var}:-' in text, var
    assert "--brain-url \"$MASTER_BRAIN_URL\"" in text           # агент получит адрес реле
    assert '"${MASTER_BRAIN_URL}/install/cell-bundle.tar.gz"' in text  # бандл — путь /install/*, есть в реле
    cell_setup_text = (vgx3d / "cell/cell-setup.sh").read_text(encoding="utf-8")
    for label in ni.SECRET_LINES:                          # метки строк с секретами ещё печатаются
        assert f"{label}:" in text or f"{label}:" in cell_setup_text, label
    assert f"--argjson port \"$CELL_PORT\"" in text and f'CELL_PORT="${{CELL_PORT:-{ni.CELL_PORT}}}"' in text
    assert f'PROTOCOLS="${{PROTOCOLS:-{",".join(ni.DEFAULT_PROTOCOLS)}}}"' in text
    assert f'PROTOCOLS="${{PROTOCOLS:-{",".join(ni.CDN_PROTOCOLS)}}}"' in text
    panel = (vgx3d / "brain/app/api/v1/licenses.py").read_text(encoding="utf-8")
    assert f'@router.get("{ni.INSTALLER_PATH.removeprefix("/api/v1")}")' in panel
    cell_setup = (vgx3d / "cell/cell-setup.sh").read_text(encoding="utf-8")
    assert "CELL_API_TOKEN=" in cell_setup


def test_relay_carries_installer_paths():
    from nexus_mcp import relay

    assert "/install/*" in relay.RELAY_PATHS          # brain-ip и cell-bundle идут через реле
