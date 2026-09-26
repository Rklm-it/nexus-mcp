"""Настройки чата — из того же `/etc/nexus-mcp.env`, что и у хаба."""

from __future__ import annotations

import os
from dataclasses import dataclass, field
from pathlib import Path


def _env(name: str, default: str = "") -> str:
    return (os.environ.get(name) or default).strip()


def _list(name: str) -> list[str]:
    return [x.strip() for x in _env(name).split(",") if x.strip()]


@dataclass
class ChatSettings:
    # Токен приложения. Открывает только /chat/api/*, не MCP: но через чат
    # доступно всё, что умеет хаб, поэтому длина — как у секрета MCP.
    token: str = field(default_factory=lambda: _env("NEXUS_CHAT_TOKEN"))

    host: str = field(default_factory=lambda: _env("NEXUS_CHAT_HOST", "127.0.0.1"))
    port: int = field(default_factory=lambda: int(_env("NEXUS_CHAT_PORT", "8766")))

    # Хаб, чьи инструменты получает Claude: тот же процесс nexus-mcp на этой
    # машине, мимо Caddy.
    mcp_url: str = field(default_factory=lambda: "http://127.0.0.1:%s/mcp" % _env("NEXUS_MCP_PORT", "8765"))
    mcp_secret: str = field(default_factory=lambda: _env("NEXUS_MCP_SECRET"))
    # Токен домашних пробников: приложение показывает команду установки на
    # роутер (пробник открывает только /probe/*, не чат и не MCP).
    probe_token: str = field(default_factory=lambda: (_list("NEXUS_PROBE_TOKENS") or [""])[0])
    # Откуда роутер качает установщик и probe.py (репозиторий хаба публичный).
    probe_src: str = field(default_factory=lambda: _env(
        "NEXUS_PROBE_SRC", "https://raw.githubusercontent.com/Rklm-it/nexus-mcp/main").rstrip("/"))

    state_dir: Path = field(
        default_factory=lambda: Path(_env("NEXUS_STATE_DIR", "/var/lib/nexus-mcp")) / "chat")

    # Модель и усилие. Пусто — решает Claude Code (по умолчанию для подписки).
    model: str = field(default_factory=lambda: _env("NEXUS_CHAT_MODEL"))
    effort: str = field(default_factory=lambda: _env("NEXUS_CHAT_EFFORT"))

    # Плановый аудит: «09:00,21:00» по часовому поясу NEXUS_CHAT_TZ. Пусто — выключен.
    audit_at: list[str] = field(default_factory=lambda: _list("NEXUS_CHAT_AUDIT_AT"))
    tz: str = field(default_factory=lambda: _env("NEXUS_CHAT_TZ", "Europe/Moscow"))

    # Сколько ждать кнопки «Разрешить», прежде чем считать действие отклонённым.
    approval_timeout_s: int = field(
        default_factory=lambda: int(_env("NEXUS_CHAT_APPROVAL_MIN", "30")) * 60)
    # Одновременных ответов на весь хаб: подписка одна, лимиты общие.
    max_parallel: int = field(default_factory=lambda: int(_env("NEXUS_CHAT_PARALLEL", "2")))

    @property
    def hub_url(self) -> str:
        """Сам хаб (nexus-mcp) мимо Caddy: его HTTP-ручки /hub/*."""
        return self.mcp_url.rsplit("/mcp", 1)[0]

    @property
    def db_path(self) -> Path:
        return self.state_dir / "chat.db"

    @property
    def work_dir(self) -> Path:
        """Рабочий каталог Claude: по нему Claude Code ищет сессии для resume."""
        return self.state_dir / "work"

    @property
    def logged_in(self) -> bool:
        return bool(_env("CLAUDE_CODE_OAUTH_TOKEN") or _env("ANTHROPIC_API_KEY"))


settings = ChatSettings()
