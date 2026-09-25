"""Фоновая установка хаба (install.sh, секция «Фоном»): прогоном с заглушками
systemd, а не чтением (инвариант 35 vgx3d).

2026-09-26: «Обновить хаб» из меню падал сразу — `systemd-run --unit
nexus-mcp-install` отказывал «Unit … was already loaded or has a fragment
file»: юнит прошлой установки systemd ещё не выгрузил."""

from __future__ import annotations

import os
import subprocess
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


def _section() -> str:
    text = (ROOT / "install.sh").read_text(encoding="utf-8")
    start = text.index("# ── Фоном")
    end = text.index("port_busy() {")
    return text[start:end]


def _run(tmp: Path, loaded: set[str], running: str = "") -> tuple[subprocess.CompletedProcess, list[str]]:
    bin_ = tmp / "bin"
    bin_.mkdir(exist_ok=True)
    calls = tmp / "calls"
    calls.write_text("")
    # systemd-run отказывает на имени, которое «ещё загружено», как настоящий.
    (bin_ / "systemd-run").write_text(f'''#!/bin/bash
echo "run $*" >> {calls}
while [ $# -gt 0 ]; do [ "$1" = --unit ] && u="$2"; shift; done
case " {' '.join(sorted(loaded))} " in *" $u "*)
  echo "Failed to start transient service unit: Unit $u.service was already loaded or has a fragment file." >&2; exit 1;;
esac
exit 0
''')
    (bin_ / "systemctl").write_text(f'''#!/bin/bash
echo "systemctl $*" >> {calls}
if [ "$1" = show ] && [ "$3" = ExecMainStatus ]; then echo 0; exit 0; fi
if [ "$1" = show ]; then
  for a in "$@"; do u="$a"; done
  n=$(cat {tmp}/shows 2>/dev/null || echo 0); echo $((n+1)) > {tmp}/shows
  if [ "$u" = "{running}" ] && [ "$n" -lt 2 ]; then echo running; else echo exited; fi
fi
exit 0
''')
    (bin_ / "tail").write_text("#!/bin/bash\nexit 0\n")
    (bin_ / "sleep").write_text("#!/bin/bash\nexit 0\n")
    for f in bin_.iterdir():
        f.chmod(0o755)
    script = tmp / "install.sh"
    script.write_text("#!/bin/bash\nset -uo pipefail\n"
                      'warn(){ echo "[!] $*"; }\ndie(){ echo "[x] $*" >&2; exit 1; }\n'
                      'CYAN=""; NC=""; FINISHED=0; BRANCH=main; GH_TOKEN=""; FOREGROUND=0; ARGS=()\n'
                      f'UNIT=nexus-mcp-install; LOG={tmp}/install.log\n'
                      'UNITF="${NEXUS_INSTALL_UNITF}"\n' + _section() + '\necho "дошли до конца"\n')
    env = {**os.environ, "PATH": f"{bin_}:{os.environ['PATH']}",
           "NEXUS_INSTALL_UNITF": str(tmp / "unit")}
    env.pop("NEXUS_INSTALL_BG", None)
    r = subprocess.run(["bash", str(script)], capture_output=True, text=True, timeout=30, env=env)
    return r, calls.read_text().splitlines()


def test_leftover_unit_does_not_block_update(tmp_path):
    r, calls = _run(tmp_path, loaded={"nexus-mcp-install"})
    assert r.returncode == 0, r.stdout + r.stderr
    runs = [c for c in calls if c.startswith("run ")]
    assert len(runs) == 1 and "--unit nexus-mcp-install-" in runs[0]
    unit = (tmp_path / "unit").read_text().strip()
    assert unit.startswith("nexus-mcp-install-") and unit in runs[0]
    # Хвост старого общего имени убран.
    assert "systemctl reset-failed nexus-mcp-install" in calls


def test_running_install_is_shown_not_started_twice(tmp_path):
    (tmp_path / "unit").write_text("nexus-mcp-install-111\n")
    r, calls = _run(tmp_path, loaded=set(), running="nexus-mcp-install-111")
    assert "Установка уже идёт" in r.stdout
    assert not [c for c in calls if c.startswith("run ")]
