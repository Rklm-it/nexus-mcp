"""Настройки хаба — только из окружения (`/etc/nexus-mcp.env` у systemd).

Хаб — отдельная машина рядом с нодами, а не часть brain: brain стоит на
российском адресе, и путь от него к нодам режется фильтром (разбор
22.09.2026, docs/journal/MONITORING.md). Хаб ставится туда, откуда до нод
достаётся, и ходит к ним по SSH.
"""

from __future__ import annotations

import os
from dataclasses import dataclass, field
from pathlib import Path


def _env(name: str, default: str = "") -> str:
    return (os.environ.get(name) or default).strip()


def _flag(name: str) -> bool:
    return _env(name).lower() in ("1", "true", "yes", "on")


def _list(name: str) -> list[str]:
    return [x.strip() for x in _env(name).split(",") if x.strip()]


@dataclass
class Settings:
    # Секрет подключения MCP. Его знает только коннектор в claude.ai: адрес
    # вида https://host/mcp/<secret>, либо заголовок Authorization: Bearer.
    secret: str = field(default_factory=lambda: _env("NEXUS_MCP_SECRET"))
    # Токены домашних пробников (через запятую) — отдельно от секрета MCP:
    # пробник лежит у знакомых, и его токен не должен открывать всё.
    probe_tokens: list[str] = field(default_factory=lambda: _list("NEXUS_PROBE_TOKENS"))

    # Brain: откуда брать список нод и их статус в панели. Необязателен —
    # без него ноды берутся из файла.
    brain_url: str = field(default_factory=lambda: _env("NEXUS_BRAIN_URL").rstrip("/"))
    brain_admin_token: str = field(default_factory=lambda: _env("NEXUS_BRAIN_ADMIN_TOKEN"))
    # user:pass, если /api закрыт basic_auth в Caddy панели.
    brain_basic_auth: str = field(default_factory=lambda: _env("NEXUS_BRAIN_BASIC_AUTH"))

    # Панели (несколько на одном хабе) — см. panels.py.
    panels_file: Path = field(
        default_factory=lambda: Path(_env("NEXUS_PANELS", "/etc/nexus-mcp/panels.json")))

    # Файл с нодами и поправками (ssh-порт, пользователь, ноды вне панели).
    inventory_file: Path = field(
        default_factory=lambda: Path(_env("NEXUS_INVENTORY", "/etc/nexus-mcp/nodes.json")))

    ssh_key: str = field(default_factory=lambda: _env("NEXUS_SSH_KEY", "/etc/nexus-mcp/id_ed25519"))
    ssh_user: str = field(default_factory=lambda: _env("NEXUS_SSH_USER", "root"))
    state_dir: Path = field(default_factory=lambda: Path(_env("NEXUS_STATE_DIR", "/var/lib/nexus-mcp")))

    # Действия, меняющие ноду (обновить агент, перезапуск, адрес панели).
    # Выключены, пока их явно не включили: чтение безопасно всегда, запись —
    # только осознанно. Каждый вызов ещё и требует confirm=true.
    allow_actions: bool = field(default_factory=lambda: _flag("NEXUS_ALLOW_ACTIONS"))

    # Подписка тестового юзера — из неё берутся ссылки для сквозной проверки.
    test_sub_url: str = field(default_factory=lambda: _env("NEXUS_TEST_SUB_URL"))
    xray_bin: str = field(default_factory=lambda: _env("NEXUS_XRAY"))

    # Репозиторий, из которого нода обновляет агент.
    repo_url: str = field(
        default_factory=lambda: _env("NEXUS_REPO_URL", "https://github.com/Rklm-it/vgx3d.git"))
    repo_raw: str = field(
        default_factory=lambda: _env(
            "NEXUS_REPO_RAW", "https://raw.githubusercontent.com/Rklm-it/vgx3d/main"))

    # Клон vgx3d (панели): оттуда берётся brain/app/services/xray_json.py —
    # тот же сборщик клиентских конфигов, что у подписки. Установщик кладёт
    # туда разреженный клон; в разработке — соседний каталог ../vgx3d.
    repo_dir: Path = field(
        default_factory=lambda: Path(_env("NEXUS_REPO_DIR", "/opt/nexus-mcp/vgx3d")))

    host: str = field(default_factory=lambda: _env("NEXUS_MCP_HOST", "127.0.0.1"))
    port: int = field(default_factory=lambda: int(_env("NEXUS_MCP_PORT", "8765")))
    # Публичные имена хаба — для защиты от DNS rebinding в MCP-транспорте.
    public_hosts: list[str] = field(default_factory=lambda: _list("NEXUS_MCP_PUBLIC_HOSTS"))

    @property
    def audit_log(self) -> Path:
        return self.state_dir / "audit.jsonl"

    @property
    def known_hosts(self) -> Path:
        return self.state_dir / "known_hosts"


settings = Settings()
