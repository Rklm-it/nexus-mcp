"""Меню хаба bin/nexus-hub прогоном: поддельное окружение, заглушки
systemctl/curl, ввод пунктов из файла вместо терминала (инвариант 35 vgx3d:
установщики и консольные скрипты проверять прогоном, а не чтением)."""

from __future__ import annotations

import os
import re
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
    # Заглушка реестра Remnawave: пишет аргументы и stdin — проверить, что
    # токен ушёл через stdin, а не в командную строку (видна в ps).
    (bin_ / "nexus-mcp-remna").write_text(
        '#!/bin/bash\n'
        f'echo "ARGS $*" >> "{tmp}/remna.log"\n'
        'case "$*" in *" -"|*" - "*) IFS= read -r t; echo "STDIN $t" >> "' + str(tmp) + '/remna.log" ;; esac\n'
        'case "$1" in check) echo "✓ Remnawave 3.2.1 · нод 2, на связи 2" ;; cf-check) echo "✓ зона ok" ;;\n'
        '  count) echo 1 ;; list) echo "pablo  https://panelpablo.mooo.com" ;; *) echo "ok $1" ;; esac\n')
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


def _items() -> list[tuple[str, str, str]]:
    """Пункты меню из ITEMS скрипта: (раздел, функция, подпись) по порядку."""
    text = (ROOT / "bin/nexus-hub").read_text()
    block = text.split("ITEMS=(", 1)[1].split("\n)", 1)[0]
    rows = re.findall(r'^\s*"([^"]+)"\s*$', block, re.M)
    return [tuple(r.split("|")[:3]) for r in rows]


def _num(func: str) -> str:
    return str([f for _s, f, _l in _items()].index(func) + 1)


def test_menu_changes_settings(tmp_path):
    (tmp_path / "env").write_text(ENV)
    acts, audit, cap = _num("a_actions"), _num("a_audit"), _num("a_bsbord_cap")
    # действия вкл; аудит; потолок; плохое время аудита — отказ; 0: выход
    r, env = _run(tmp_path, f"{acts}\nд\n\n{audit}\n09:00,21:00\n\n{cap}\n150\n\n{audit}\n25:99\n\n0\n")
    assert r.returncode == 0, r.stderr
    assert "NEXUS_ALLOW_ACTIONS=1" in env
    assert "NEXUS_CHAT_AUDIT_AT=09:00,21:00" in env
    assert "NEXUS_BSBORD_DAILY_RUB=150" in env
    assert "формат ЧЧ:ММ" in r.stdout


def test_secrets_are_shown_only_on_yes_and_rotated(tmp_path):
    (tmp_path / "env").write_text(ENV)
    r, _ = _run(tmp_path, f"{_num('a_app_line')}\nн\n\n0\n")
    assert "chat_old_token" not in r.stdout + r.stderr          # «нет» — секрет не на экране
    r, env = _run(tmp_path, f"{_num('a_rotate')}\nд\n\n0\n")
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
    r, _ = _run(tmp_path, f"{_num('a_usage')}\n\n{_num('a_edits')}\n\n0\n")
    assert r.returncode == 0, r.stderr
    assert "Токены" in r.stdout and "чат ещё не запускался" in r.stdout
    assert "правок ещё не было" in r.stdout

    # Чат поработал: шапка и пункт 19 показывают расход.
    sys.path.insert(0, str(ROOT))
    from nexus_chat.store import Store

    st = Store(tmp_path / "state" / "chat" / "chat.db")
    st.add_usage("chat", "claude-x", input=1500, output=500, cache_read=1_000_000)
    r, _ = _run(tmp_path, f"{_num('a_usage')}\n\n0\n")
    assert "сегодня 1 млн" in r.stdout, r.stdout
    assert "Этот месяц" in r.stdout and "claude.ai → Settings → Usage" in r.stdout


def test_menu_numbers_follow_the_list(tmp_path):
    """Экран, выбор и подсказки — из одного ITEMS: номера подряд по разделам,
    у каждого пункта есть функция, а «пункт N» в тексте ведёт куда надо."""
    items = _items()
    text = (ROOT / "bin/nexus-hub").read_text()
    for _s, func, _l in items:
        assert re.search(rf"^{func}\(\)", text, re.M), f"нет функции {func}"
    sections = [s for s, _f, _l in items]
    assert sections == sorted(sections, key=sections.index)        # раздел не разорван
    assert not re.search(r"пункт [0-9]", text)                      # номера только через num_of

    (tmp_path / "env").write_text(ENV)
    r, _ = _run(tmp_path, "0\n")
    # Пробелы, а не \s: \s съедал перевод строки, и следующий пункт пропадал.
    shown = re.findall(r"^ +(\d+) {2}(\S.*?)(?: {2,}|$)", r.stdout, re.M)
    assert [int(n) for n, _ in shown][:len(items)] == list(range(1, len(items) + 1))
    assert [lbl.strip() for _n, lbl in shown][:len(items)] == [lbl for _s, _f, lbl in items]
    r, _ = _run(tmp_path, "99\n\n0\n")
    assert "нет такого пункта: 99" in r.stdout


def test_status_box_is_aligned(tmp_path):
    (tmp_path / "env").write_text(ENV)
    r, _ = _run(tmp_path, "", "status")
    lines = [ln for ln in r.stdout.splitlines() if ln and ln[0] in "╭│╰"]
    assert len(lines) >= 5 and len({len(ln) for ln in lines}) == 1, lines   # правая стенка ровная


def test_shell_item_runs_command_with_hub_key(tmp_path):
    (tmp_path / "env").write_text(ENV)
    bin_ = tmp_path / "bin"
    bin_.mkdir()
    (bin_ / "ssh").write_text(f'#!/bin/bash\nprintf "%s\\n" "$@" > {tmp_path}/ssh.args\necho "Reading package lists... Done"\n')
    (bin_ / "ssh").chmod(0o755)
    r, _ = _run(tmp_path, f"{_num('a_ssh_shell')}\n203.0.113.9\n\n\n\napt-get update\n\n0\n")
    args = (tmp_path / "ssh.args").read_text().splitlines()
    assert args[args.index("-i") + 1].endswith("etc/id_ed25519")             # ключ хаба
    assert "root@203.0.113.9" in args and args[-1] == "apt-get update"
    assert "BatchMode=yes" in args and "команда выполнена" in r.stdout


def test_remna_panel_add_keeps_token_off_argv_and_screen(tmp_path):
    """Панель Remnawave из меню: токен скрыт при вводе, в командную строку
    (ps) не попадает — только через stdin; проверка перед добавлением."""
    (tmp_path / "env").write_text(ENV)
    keys = (f"{_num('a_remna_add')}\npablo\nhttps://panelpablo.mooo.com\nRW-SECRET-TOKEN\n"
            "https://auth.pablovpn.com/sub/\n\n"
            f"{_num('a_remna_cf')}\npablo\npablo.stream\nCF-SECRET-TOKEN\n\n0\n")
    r, _ = _run(tmp_path, keys)
    assert r.returncode == 0, r.stderr
    log = (tmp_path / "remna.log").read_text()
    args = [ln for ln in log.splitlines() if ln.startswith("ARGS")]
    assert "ARGS check https://panelpablo.mooo.com -" in args
    assert "ARGS add pablo https://panelpablo.mooo.com - --sub https://auth.pablovpn.com/sub/" in args
    assert "ARGS cf-check pablo.stream -" in args and "ARGS cf pablo pablo.stream -" in args
    assert "STDIN RW-SECRET-TOKEN" in log and "STDIN CF-SECRET-TOKEN" in log
    assert not any("SECRET" in a for a in args)
    assert "SECRET" not in r.stdout + r.stderr
    assert "✓ Remnawave 3.2.1" in r.stdout and "+ Remnawave" in r.stdout
