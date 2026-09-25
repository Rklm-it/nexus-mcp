"""Меню хаба bin/nexus-hub прогоном: поддельное окружение, заглушки
systemctl/curl, ввод пунктов из файла вместо терминала (инвариант 35 vgx3d:
установщики и консольные скрипты проверять прогоном, а не чтением)."""

from __future__ import annotations

import os
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


def _run(tmp: Path, keys: str, *args: str) -> tuple[subprocess.CompletedProcess, str]:
    bin_ = tmp / "bin"
    bin_.mkdir(exist_ok=True)
    (bin_ / "systemctl").write_text('#!/bin/bash\n[ "$1" = is-active ] && exit 0\necho "[systemctl $*]"\n')
    (bin_ / "curl").write_text('#!/bin/bash\necho \'{"ok":true,"logged_in":true}\'\n')
    (bin_ / "nexus-mcp-panels").write_text('#!/bin/bash\necho "main  https://panel.example.ru"\n')
    (bin_ / "clear").write_text("#!/bin/bash\n")
    for f in bin_.iterdir():
        f.chmod(0o755)
    base = tmp / "base"
    base.mkdir(exist_ok=True)
    if not (base / "app").exists():
        (base / "app").symlink_to(ROOT)
        (base / "venv" / "bin").mkdir(parents=True)
        # Обёртка, а не симлинк: через симлинк питон не видит venv и падает на
        # import httpx — меню тогда молча показывало пустые строки.
        py = base / "venv" / "bin" / "python"
        py.write_text(f'#!/bin/sh\nexec "{sys.executable}" "$@"\n')
        py.chmod(0o755)
    (tmp / "etc").mkdir(exist_ok=True)
    (tmp / "input").write_text(keys)
    env = {**os.environ, "PATH": f"{bin_}:{os.environ['PATH']}", "NEXUS_HUB_ENV": str(tmp / "env"),
           "NEXUS_HUB_ETC": str(tmp / "etc"), "NEXUS_HUB_BASE": str(base), "NEXUS_HUB_TTY": str(tmp / "input")}
    r = subprocess.run(["bash", str(ROOT / "bin/nexus-hub"), *args], capture_output=True, text=True,
                       timeout=60, env=env)
    return r, (tmp / "env").read_text()


ENV = ("NEXUS_MCP_SECRET=secretsecretsecretsecretsecret1234\nNEXUS_CHAT_TOKEN=chat_old_token_chat_old_token_12345678\n"
       "NEXUS_PROBE_TOKENS=probe_old\nNEXUS_MCP_PUBLIC_HOSTS=hub.example\nNEXUS_MCP_PUBLIC_PORT=443\n"
       "NEXUS_ALLOW_ACTIONS=0\nNEXUS_CHAT_AUDIT_AT=\nNEXUS_CHAT_TZ=Europe/Moscow\nNEXUS_BSBORD_KEY=\n"
       "NEXUS_BSBORD_DAILY_RUB=300\n")


def test_menu_changes_settings(tmp_path):
    (tmp_path / "env").write_text(ENV)
    # 13: включить действия; 10: аудит; 12: потолок; 10: плохое время — отказ; 0: выход
    r, env = _run(tmp_path, "13\nд\n\n10\n09:00,21:00\n\n12\n150\n\n10\n25:99\n\n0\n")
    assert r.returncode == 0, r.stderr
    assert "NEXUS_ALLOW_ACTIONS=1" in env
    assert "NEXUS_CHAT_AUDIT_AT=09:00,21:00" in env
    assert "NEXUS_BSBORD_DAILY_RUB=150" in env
    assert "формат ЧЧ:ММ" in r.stdout


def test_secrets_are_shown_only_on_yes_and_rotated(tmp_path):
    (tmp_path / "env").write_text(ENV)
    r, _ = _run(tmp_path, "9\nн\n\n0\n")
    assert "chat_old_token" not in r.stdout + r.stderr          # «нет» — секрет не на экране
    r, env = _run(tmp_path, "14\nд\n\n0\n")
    assert "chat_old_token" not in env and "probe_old" not in env and "secretsecretsecret" not in env
    assert "NEXUS_CHAT_TOKEN=" in env and "NEXUS_MCP_SECRET=" in env


def test_status_works_without_tty_and_menu_refuses(tmp_path):
    (tmp_path / "env").write_text(ENV)
    r, _ = _run(tmp_path, "", "status")
    assert "Nexus Hub" in r.stdout and "https://hub.example" in r.stdout
    (tmp_path / "input").unlink()
    env = {**os.environ, "NEXUS_HUB_ENV": str(tmp_path / "env"), "NEXUS_HUB_TTY": str(tmp_path / "nope"),
           "NEXUS_HUB_BASE": str(tmp_path / "base"), "PATH": f"{tmp_path / 'bin'}:{os.environ['PATH']}"}
    r = subprocess.run(["bash", str(ROOT / "bin/nexus-hub")], capture_output=True, text=True, timeout=30, env=env)
    assert r.returncode == 1 and "нет терминала" in r.stderr


def test_usage_and_edits_items(tmp_path):
    """Шапка показывает токены; пункты 19 и 20 работают и без чата/правок."""
    env = ENV + f"NEXUS_STATE_DIR={tmp_path / 'state'}\n"
    (tmp_path / "env").write_text(env)
    r, _ = _run(tmp_path, "19\n\n20\n\n0\n")
    assert r.returncode == 0, r.stderr
    assert "Токены" in r.stdout and "чат ещё не запускался" in r.stdout
    assert "правок ещё не было" in r.stdout

    # Чат поработал: шапка и пункт 19 показывают расход.
    sys.path.insert(0, str(ROOT))
    from nexus_chat.store import Store

    st = Store(tmp_path / "state" / "chat" / "chat.db")
    st.add_usage("chat", "claude-x", input=1500, output=500, cache_read=1_000_000)
    r, _ = _run(tmp_path, "19\n\n0\n")
    assert "сегодня 1 млн" in r.stdout, r.stdout
    assert "Этот месяц" in r.stdout and "claude.ai → Settings → Usage" in r.stdout
