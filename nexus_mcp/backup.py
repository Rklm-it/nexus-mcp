"""Бэкап хаба: всё, без чего его не поднять заново на чистом сервере.

В архиве — реестры панелей Nexus и Remnawave (с токенами), ключ SSH к
нодам, `/etc/nexus-mcp.env` (секрет MCP, токен чата, пробников), токен
подписки Claude, база чата и журнал действий, маршруты реле Caddy. Не
кладём: сертификаты Caddy (выпустятся заново), кэш и рабочий каталог
Claude, xray и venv (их ставит установщик).

Копии лежат на самом хабе (`/var/backups/nexus-mcp`, только root, последние
`KEEP`), а копию вне сервера приложение скачивает к себе: бэкап на той же
машине не спасает от её потери.

Восстановление: чистый сервер → установщик хаба → `nexus-mcp-backup restore
<архив>`. Перед распаковкой текущее состояние само сохраняется отдельным
архивом — неудачное восстановление откатывается тем же restore.
"""

from __future__ import annotations

import argparse
import io
import json
import os
import re
import sqlite3
import subprocess
import sys
import tarfile
import tempfile
import time
from pathlib import Path

from nexus_mcp import config

KEEP = 14
NAME_RE = re.compile(r"^hub-\d{8}-\d{6}(-[a-z0-9-]{1,20})?\.tar\.gz$")
SERVICES = ("nexus-mcp", "nexus-chat", "nexus-mcp-caddy")

# Корни, которые попадают в архив и только в которые восстановление пишет.
ENV_FILE = Path(os.environ.get("NEXUS_ENV_FILE", "/etc/nexus-mcp.env"))
ETC_DIR = Path(os.environ.get("NEXUS_ETC_DIR", "/etc/nexus-mcp"))
CADDY_DIR = Path(os.environ.get("NEXUS_CADDY_DIR", "/etc/caddy-nexus-mcp"))
# Внутри каталога состояния — мимо: кэш Claude CLI, рабочий каталог, база
# чата (её кладём отдельно, согласованной копией через sqlite).
SKIP_STATE = ("chat/home", "chat/work", "chat/chat.db", "chat/chat.db-wal", "chat/chat.db-shm")


class BackupError(Exception):
    pass


def backup_dir() -> Path:
    return Path(os.environ.get("NEXUS_BACKUP_DIR", "/var/backups/nexus-mcp"))


def _roots() -> list[Path]:
    return [ENV_FILE, ETC_DIR, CADDY_DIR, config.settings.state_dir]


def _arcname(p: Path) -> str:
    return str(p).lstrip("/")


def _skip_state(p: Path) -> bool:
    try:
        rel = p.relative_to(config.settings.state_dir).as_posix()
    except ValueError:
        return False
    return any(rel == s or rel.startswith(s + "/") for s in SKIP_STATE)


def _sqlite_copy(src: Path) -> bytes | None:
    """Согласованная копия базы чата: файл живой, и простое копирование
    может поймать её посреди записи."""
    if not src.is_file():
        return None
    with tempfile.TemporaryDirectory() as tmp:
        dst = Path(tmp) / "chat.db"
        con = sqlite3.connect(f"file:{src}?mode=ro", uri=True)
        try:
            out = sqlite3.connect(dst)
            with out:
                con.backup(out)
            out.close()
        finally:
            con.close()
        return dst.read_bytes()


def create(label: str = "") -> dict:
    """Собрать архив; старые сверх KEEP — удалить. Ответ — без содержимого."""
    label = re.sub(r"[^a-z0-9-]+", "-", (label or "").lower()).strip("-")[:20]
    d = backup_dir()
    d.mkdir(parents=True, exist_ok=True)
    os.chmod(d, 0o700)
    name = time.strftime("hub-%Y%m%d-%H%M%S") + (f"-{label}" if label else "") + ".tar.gz"
    path = d / name
    files: list[str] = []
    tmp = path.with_suffix(".part")
    old_umask = os.umask(0o077)
    try:
        with tarfile.open(tmp, "w:gz") as tar:
            for root in _roots():
                if not root.exists():
                    continue
                items = [root] if root.is_file() else sorted(x for x in root.rglob("*") if x.is_file())
                for f in items:
                    if f.is_symlink() or _skip_state(f) or backup_dir() in f.parents:
                        continue
                    tar.add(f, arcname=_arcname(f), recursive=False)
                    files.append(_arcname(f))
            db = _sqlite_copy(config.settings.state_dir / "chat" / "chat.db")
            if db is not None:
                arc = _arcname(config.settings.state_dir / "chat" / "chat.db")
                info = tarfile.TarInfo(arc)
                info.size, info.mode, info.mtime = len(db), 0o600, int(time.time())
                tar.addfile(info, io.BytesIO(db))
                files.append(arc)
            meta = json.dumps({"created": int(time.time()), "files": files}, ensure_ascii=False).encode()
            info = tarfile.TarInfo("nexus-hub-backup.json")
            info.size, info.mode, info.mtime = len(meta), 0o600, int(time.time())
            tar.addfile(info, io.BytesIO(meta))
        tmp.rename(path)
    finally:
        os.umask(old_umask)
        tmp.unlink(missing_ok=True)
    if not any(f.endswith("panels.json") or f.endswith("nexus-mcp.env") for f in files):
        path.unlink(missing_ok=True)
        raise BackupError("в архив не попало ни реестра панелей, ни /etc/nexus-mcp.env — "
                          "это не установка хаба или нет прав (нужен root)")
    removed = prune()
    return {"name": name, "size": path.stat().st_size, "files": len(files), "removed": removed}


def listing() -> list[dict]:
    d = backup_dir()
    if not d.is_dir():
        return []
    out = []
    for p in sorted(d.iterdir(), reverse=True):
        if NAME_RE.match(p.name) and p.is_file():
            st = p.stat()
            out.append({"name": p.name, "size": st.st_size, "created": int(st.st_mtime)})
    return out


def prune(keep: int = KEEP) -> list[str]:
    """Самые старые сверх `keep`; ручные (с меткой) живут наравне."""
    removed = []
    for item in listing()[keep:]:
        (backup_dir() / item["name"]).unlink(missing_ok=True)
        removed.append(item["name"])
    return removed


def path_of(name: str) -> Path:
    """Архив по имени — только из каталога бэкапов (имя приходит из сети)."""
    if not NAME_RE.match(name or ""):
        raise BackupError(f"нет такого бэкапа: «{name}»")
    p = backup_dir() / name
    if not p.is_file():
        raise BackupError(f"нет такого бэкапа: «{name}»")
    return p


def _allowed(member: str) -> bool:
    target = Path("/" + member)
    if ".." in Path(member).parts or member.startswith("/"):
        return False
    for root in _roots():
        if target == root or root in target.parents:
            return not _skip_state(target) or target == config.settings.state_dir / "chat" / "chat.db"
    return False


def inspect(archive: Path) -> list[str]:
    """Что восстановится. Чужой файл в архиве — отказ целиком, не пропуск."""
    try:
        with tarfile.open(archive, "r:gz") as tar:
            names = [m.name for m in tar.getmembers() if m.isfile()]
            bad = [m.name for m in tar.getmembers()
                   if m.name != "nexus-hub-backup.json" and (not m.isfile() or not _allowed(m.name))]
    except (tarfile.TarError, OSError) as e:
        raise BackupError(f"архив не читается: {e}") from None
    if bad:
        raise BackupError("в архиве файлы вне хаба — не восстанавливаю: " + ", ".join(bad[:5]))
    names = [n for n in names if n != "nexus-hub-backup.json"]
    if not names:
        raise BackupError("архив пустой")
    return names


def restore(archive: Path, *, restart: bool = True) -> dict:
    names = inspect(archive)
    safety = create("before-restore")
    # База чата живая: писать её поверх работающего сервиса — порча. Хаб и
    # чат останавливаем на время распаковки, старые WAL/SHM удаляем.
    if restart:
        subprocess.run(["systemctl", "stop", "nexus-chat", "nexus-mcp"], capture_output=True)
    db = config.settings.state_dir / "chat" / "chat.db"
    if _arcname(db) in names:
        for tail in ("-wal", "-shm"):
            Path(str(db) + tail).unlink(missing_ok=True)
    with tarfile.open(archive, "r:gz") as tar:
        for m in tar.getmembers():
            if m.name == "nexus-hub-backup.json":
                continue
            dst = Path("/" + m.name)
            dst.parent.mkdir(parents=True, exist_ok=True)
            src = tar.extractfile(m)
            tmp = dst.with_name(dst.name + ".restore")
            with open(tmp, "wb") as fh:
                fh.write(src.read() if src else b"")
            os.chmod(tmp, m.mode & 0o777 or 0o600)
            tmp.replace(dst)
    restarted = []
    if restart:
        for svc in SERVICES:
            enabled = subprocess.run(["systemctl", "is-enabled", "--quiet", svc]).returncode == 0
            if enabled and subprocess.run(["systemctl", "restart", svc], capture_output=True).returncode == 0:
                restarted.append(svc)
    return {"restored": len(names), "safety": safety["name"], "restarted": restarted}


def _human(n: int) -> str:
    return f"{n / 1e6:.1f} МБ" if n >= 1e6 else f"{n / 1e3:.0f} КБ"


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(prog="nexus-mcp-backup", description="Бэкап хаба nexus-mcp")
    sub = ap.add_subparsers(dest="cmd", required=True)
    c = sub.add_parser("create", help="сделать бэкап сейчас")
    c.add_argument("--label", default="")
    c.add_argument("--quiet", action="store_true")
    sub.add_parser("list", help="бэкапы на хабе")
    r = sub.add_parser("restore", help="восстановить из архива (файл или имя из list)")
    r.add_argument("archive")
    r.add_argument("--no-restart", action="store_true")
    a = ap.parse_args(argv)
    try:
        if a.cmd == "create":
            res = create(a.label)
            if not a.quiet:
                print(f"✓ {backup_dir() / res['name']} ({_human(res['size'])}, файлов {res['files']})")
                for n in res["removed"]:
                    print(f"  удалён старый: {n}")
        elif a.cmd == "list":
            items = listing()
            if not items:
                print(f"бэкапов нет ({backup_dir()})")
            for i in items:
                print(f"{i['name']}  {_human(i['size'])}  {time.strftime('%d.%m %H:%M', time.localtime(i['created']))}")
        else:
            p = Path(a.archive)
            if not p.is_file():
                p = path_of(a.archive)
            res = restore(p, restart=not a.no_restart)
            print(f"✓ восстановлено файлов: {res['restored']}")
            print(f"  прежнее состояние сохранено: {res['safety']} (откат — restore этого архива)")
            if res["restarted"]:
                print("  перезапущены: " + ", ".join(res["restarted"]))
    except BackupError as e:
        print(f"✗ {e}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
