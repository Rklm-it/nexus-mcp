import os
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))


def _find_vgx3d() -> Path | None:
    """Клон панели: NEXUS_REPO_DIR или соседний каталог ../vgx3d."""
    for cand in (os.environ.get("NEXUS_REPO_DIR"), ROOT.parent / "vgx3d"):
        if cand and (Path(cand) / "brain" / "app" / "services" / "xray_json.py").exists():
            return Path(cand)
    return None


VGX3D = _find_vgx3d()


@pytest.fixture
def vgx3d() -> Path:
    """Сторожа сверяют хаб с кодом панели и ноды (инвариант 25). Без клона
    они не пропускаются молча, а падают: зелёный прогон без сверки врёт."""
    if VGX3D is None:
        pytest.fail("нужен клон vgx3d: NEXUS_REPO_DIR=/путь/к/vgx3d или каталог ../vgx3d рядом")
    return VGX3D


@pytest.fixture(autouse=True)
def hub_settings(tmp_path, monkeypatch):
    """Каждый тест — со своими настройками и своим каталогом состояния."""
    from nexus_mcp import config

    s = config.Settings()
    s.secret = "s" * 32
    s.probe_tokens = ["probe-token"]
    s.state_dir = tmp_path / "state"
    s.inventory_file = tmp_path / "nodes.json"
    s.brain_url = ""
    s.brain_admin_token = ""
    s.test_sub_url = ""
    s.allow_actions = False
    if VGX3D is not None:
        s.repo_dir = VGX3D
    monkeypatch.setattr(config, "settings", s)
    return s
