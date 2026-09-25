"""Список нод: из панели (если она отвечает) плюс поправки из файла.

Панель знает ноды, их статус и heartbeat, но хабу нужно ещё то, чего в ней
нет: SSH-порт и пользователя. Файл `nodes.json` добавляет это и позволяет
описать ноды совсем без панели — на случай, когда хаб с brain'ом не
связан вовсе:

    {
      "defaults": {"ssh_user": "root", "ssh_port": 22},
      "nodes": [
        {"name": "de-1", "ssh_port": 2222},
        {"name": "nl-2", "ip": "203.0.113.7", "note": "нет в панели"}
      ]
    }

Запись с тем же `name`, что в панели, — это поправка; с новым — отдельная нода.
"""

from __future__ import annotations

import json
import logging
from datetime import datetime, timezone
from typing import Any

import httpx

from nexus_mcp import config

logger = logging.getLogger(__name__)

# Столько секунд без heartbeat — нода к панели не приходит. То же число, что
# HEARTBEAT_GRACE_S в brain/app/services/health.py (сторож в тестах).
HEARTBEAT_GRACE_S = 120


class InventoryError(Exception):
    """Ни панель, ни файл не дали списка нод — с причиной."""


def _brain_headers() -> dict:
    return {"X-Admin-Token": config.settings.brain_admin_token}


def _brain_auth() -> tuple[str, str] | None:
    ba = config.settings.brain_basic_auth
    if ba and ":" in ba:
        user, _, pw = ba.partition(":")
        return user, pw
    return None


async def brain_get(path: str, timeout: float = 15.0) -> Any:
    """GET к панели. Ошибка — с кодом и текстом ответа, а не голым «failed»."""
    s = config.settings
    if not s.brain_url or not s.brain_admin_token:
        raise InventoryError("панель не настроена: нет NEXUS_BRAIN_URL / NEXUS_BRAIN_ADMIN_TOKEN")
    async with httpx.AsyncClient(timeout=timeout, auth=_brain_auth()) as c:
        r = await c.get(s.brain_url + path, headers=_brain_headers())
    if r.status_code >= 400:
        raise InventoryError(f"панель ответила {r.status_code} на {path}: {r.text[:200]}")
    return r.json()


async def brain_post(path: str, timeout: float = 60.0) -> Any:
    s = config.settings
    if not s.brain_url or not s.brain_admin_token:
        raise InventoryError("панель не настроена: нет NEXUS_BRAIN_URL / NEXUS_BRAIN_ADMIN_TOKEN")
    async with httpx.AsyncClient(timeout=timeout, auth=_brain_auth()) as c:
        r = await c.post(s.brain_url + path, headers=_brain_headers())
    if r.status_code >= 400:
        raise InventoryError(f"панель ответила {r.status_code} на {path}: {r.text[:200]}")
    return r.json()


def _load_file() -> dict:
    path = config.settings.inventory_file
    if not path.exists():
        return {}
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except (OSError, ValueError) as e:
        raise InventoryError(f"не читается {path}: {e}") from e


def heartbeat_age_s(last: str | None, now: datetime | None = None) -> float | None:
    """Сколько секунд назад нода приходила к панели. None — не приходила ни разу."""
    if not last:
        return None
    try:
        dt = datetime.fromisoformat(last.replace("Z", "+00:00"))
    except ValueError:
        return None
    if dt.tzinfo is None:
        # В БД панели всё наивное UTC (инвариант 19).
        dt = dt.replace(tzinfo=timezone.utc)
    now = now or datetime.now(timezone.utc)
    return round((now - dt).total_seconds(), 1)


def _from_brain(row: dict) -> dict:
    age = heartbeat_age_s(row.get("last_heartbeat_at"))
    return {
        "id": str(row.get("id") or ""),
        "name": row.get("name") or "",
        "ip": row.get("ip_address") or "",
        "api_host": row.get("api_host") or None,
        "api_port": row.get("api_port"),
        "country": row.get("country") or "",
        "active": bool(row.get("is_active", True)),
        "panel_online": bool(row.get("is_online")),
        "last_heartbeat_at": row.get("last_heartbeat_at"),
        "heartbeat_age_s": age,
        "heartbeat_fresh": age is not None and age <= HEARTBEAT_GRACE_S,
        "agent_version": row.get("agent_version"),
        "rf_status": row.get("rf_status"),
        "reputation_status": row.get("reputation_status"),
        "cf_only": bool(row.get("cf_only")),
        "source": "panel",
    }


def merge(brain_rows: list[dict], file_data: dict) -> list[dict]:
    """Панель + файл → единый список. Поправки файла сильнее полей панели
    только там, где панель ничего не знает (ssh_*), и в `ip` — если его явно
    переопределили (нода переехала, а панель ещё нет)."""
    defaults = {"ssh_user": config.settings.ssh_user, "ssh_port": 22}
    defaults.update(file_data.get("defaults") or {})
    nodes: dict[str, dict] = {}
    for row in brain_rows:
        n = _from_brain(row)
        nodes[n["name"]] = n
    for extra in file_data.get("nodes") or []:
        name = extra.get("name")
        if not name:
            continue
        if name in nodes:
            nodes[name].update({k: v for k, v in extra.items() if k != "name"})
        else:
            nodes[name] = {"name": name, "source": "file", "active": True,
                           "panel_online": None, "heartbeat_fresh": None, **extra}
    out = []
    for n in nodes.values():
        for k, v in defaults.items():
            n.setdefault(k, v)
        # SSH идёт на адрес управления, если он есть: это тот, что доступен.
        n.setdefault("ssh_host", n.get("api_host") or n.get("ip"))
        out.append(n)
    out.sort(key=lambda n: n["name"])
    return out


async def load_nodes() -> tuple[list[dict], list[str]]:
    """(ноды, предупреждения). Недоступная панель — предупреждение, не отказ:
    для того хаб и существует, чтобы работать, когда панель слепа."""
    warnings: list[str] = []
    brain_rows: list[dict] = []
    if config.settings.brain_url:
        try:
            brain_rows = await brain_get("/api/v1/servers")
        except (InventoryError, httpx.HTTPError) as e:
            warnings.append(f"список из панели не получен: {e}")
    file_data = _load_file()
    nodes = merge(brain_rows, file_data)
    if not nodes:
        hint = "; ".join(warnings) or "панель не настроена"
        raise InventoryError(
            f"нод нет: {hint}; файл {config.settings.inventory_file} пуст или отсутствует")
    return nodes, warnings


async def find_node(name_or_ip: str) -> dict:
    nodes, _ = await load_nodes()
    key = (name_or_ip or "").strip().lower()
    for n in nodes:
        if key in (n["name"].lower(), str(n.get("ip", "")).lower(), str(n.get("id", "")).lower()):
            return n
    names = ", ".join(n["name"] for n in nodes[:30])
    raise InventoryError(f"нода «{name_or_ip}» не найдена. Есть: {names}")
