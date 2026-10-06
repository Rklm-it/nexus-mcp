"""Бэкап хаба: что попадает в архив, что нет, ротация, восстановление и
отказ на архиве с чужими путями (восстановление пишет от root в /)."""

import asyncio
import io
import json
import sqlite3
import tarfile

import httpx
import pytest

from nexus_mcp import backup


@pytest.fixture
def hub(tmp_path, monkeypatch, hub_settings):
    env = tmp_path / "etc/nexus-mcp.env"
    etc = tmp_path / "etc/nexus-mcp"
    caddy = tmp_path / "etc/caddy-nexus-mcp"
    state = tmp_path / "var/lib/nexus-mcp"
    for d in (etc, caddy, state / "chat/home/.claude", state / "chat/work"):
        d.mkdir(parents=True)
    env.write_text("NEXUS_MCP_SECRET=s\n")
    (etc / "panels.json").write_text('{"panels": [{"name": "main", "token": "t"}]}')
    (etc / "remnawave.json").write_text('{"panels": []}')
    (etc / "id_ed25519").write_text("KEY")
    (caddy / "relay.caddy").write_text("# relay")
    (state / "audit.jsonl").write_text("{}\n")
    (state / "chat/home/.claude/cache.bin").write_bytes(b"x" * 1000)
    (state / "chat/work/tmp.txt").write_text("junk")
    con = sqlite3.connect(state / "chat/chat.db")
    con.execute("create table t(x)")
    con.execute("insert into t values (42)")
    con.commit()
    con.close()
    monkeypatch.setattr(backup, "ENV_FILE", env)
    monkeypatch.setattr(backup, "ETC_DIR", etc)
    monkeypatch.setattr(backup, "CADDY_DIR", caddy)
    monkeypatch.setattr(hub_settings, "state_dir", state)
    monkeypatch.setenv("NEXUS_BACKUP_DIR", str(tmp_path / "backups"))
    return tmp_path


def _names(path) -> set[str]:
    with tarfile.open(path, "r:gz") as tar:
        return {m.name for m in tar.getmembers()}


def test_archive_has_what_rebuilds_hub_and_nothing_else(hub):
    res = backup.create()
    path = backup.backup_dir() / res["name"]
    names = _names(path)
    root = str(hub).lstrip("/")
    assert {f"{root}/etc/nexus-mcp.env", f"{root}/etc/nexus-mcp/panels.json",
            f"{root}/etc/nexus-mcp/remnawave.json", f"{root}/etc/nexus-mcp/id_ed25519",
            f"{root}/etc/caddy-nexus-mcp/relay.caddy", f"{root}/var/lib/nexus-mcp/audit.jsonl",
            f"{root}/var/lib/nexus-mcp/chat/chat.db", "nexus-hub-backup.json"} == names
    assert oct(path.stat().st_mode & 0o777) == "0o600"
    with tarfile.open(path, "r:gz") as tar:
        db = tar.extractfile(f"{root}/var/lib/nexus-mcp/chat/chat.db").read()
    tmp = hub / "check.db"
    tmp.write_bytes(db)
    assert sqlite3.connect(tmp).execute("select x from t").fetchone() == (42,)


def test_keeps_last_n(hub, monkeypatch):
    monkeypatch.setattr(backup, "KEEP", 3)
    d = backup.backup_dir()
    d.mkdir(parents=True)
    for i in range(5):
        (d / f"hub-2026010{i}-000000.tar.gz").write_bytes(b"old")
    backup.prune(3)
    assert [x["name"] for x in backup.listing()] == [
        "hub-20260104-000000.tar.gz", "hub-20260103-000000.tar.gz", "hub-20260102-000000.tar.gz"]


def test_restore_puts_files_back_and_saves_current_state(hub):
    name = backup.create()["name"]
    panels = hub / "etc/nexus-mcp/panels.json"
    panels.write_text("broken")
    res = backup.restore(backup.path_of(name), restart=False)
    assert json.loads(panels.read_text())["panels"][0]["name"] == "main"
    assert res["safety"].endswith("-before-restore.tar.gz")
    # Сохранённое перед восстановлением — с «broken»: откат тем же restore.
    with tarfile.open(backup.backup_dir() / res["safety"], "r:gz") as tar:
        root = str(hub).lstrip("/")
        assert tar.extractfile(f"{root}/etc/nexus-mcp/panels.json").read() == b"broken"


def test_restore_refuses_foreign_paths(hub):
    evil = hub / "evil.tar.gz"
    with tarfile.open(evil, "w:gz") as tar:
        data = b"root::0:0::/root:/bin/sh\n"
        info = tarfile.TarInfo("etc/passwd")
        info.size = len(data)
        tar.addfile(info, io.BytesIO(data))
    with pytest.raises(backup.BackupError, match="вне хаба"):
        backup.restore(evil, restart=False)
    assert not list(backup.backup_dir().glob("*")) if backup.backup_dir().exists() else True
    for bad in ("../x.tar.gz", "hub-1.tar.gz", "/etc/passwd"):
        with pytest.raises(backup.BackupError):
            backup.path_of(bad)


def test_app_lists_creates_and_downloads(hub, tmp_path, monkeypatch):
    from nexus_chat import app as chat_app
    from nexus_chat import config as chat_config
    from nexus_chat.runner import Runner
    from nexus_chat.store import Store

    cs = chat_config.ChatSettings()
    cs.token = "t" * 40
    cs.state_dir = tmp_path / "chat-state"
    cs.audit_at = []
    monkeypatch.setattr(chat_config, "settings", cs)
    auth = {"authorization": "Bearer " + "t" * 40}

    async def go():
        cs.state_dir.mkdir(parents=True)
        app = chat_app.build_app(Runner(Store(cs.db_path), cs), start_background=False)
        async with httpx.AsyncClient(transport=httpx.ASGITransport(app=app), base_url="https://hub") as c:
            assert (await c.get("/chat/api/backups", headers=auth)).json()["backups"] == []
            r = await c.post("/chat/api/backups", headers=auth)
            name = r.json()["backup"]["name"]
            assert r.status_code == 200 and name.endswith("-app.tar.gz")
            r = await c.get(f"/chat/api/backups/{name}", headers=auth)
            assert r.status_code == 200 and r.content[:2] == b"\x1f\x8b"
            assert (await c.get(f"/chat/api/backups/{name}")).status_code == 401
            assert (await c.get("/chat/api/backups/..%2Fetc%2Fpasswd", headers=auth)).status_code == 404

    asyncio.run(go())
