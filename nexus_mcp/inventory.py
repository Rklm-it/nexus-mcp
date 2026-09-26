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

from nexus_mcp import config, ssh

logger = logging.getLogger(__name__)

# Столько секунд без heartbeat — нода к панели не приходит. То же число, что
# HEARTBEAT_GRACE_S в brain/app/services/health.py (сторож в тестах).
HEARTBEAT_GRACE_S = 120


class InventoryError(Exception):
    """Ни панель, ни файл не дали списка нод — с причиной."""


# Имя cookie, по которой Caddy панели пропускает мимо basic_auth. То же, что
# в brain/app/core/panel_gate.py и Caddyfile установщиков (сторож в тестах).
GATE_COOKIE = "nexus_gate"


def _brain_headers(panel: dict) -> dict:
    h = {"X-Admin-Token": panel.get("token") or ""}
    if panel.get("gate"):
        h["Cookie"] = f"{GATE_COOKIE}={panel['gate']}"
    return h


def _brain_auth(panel: dict) -> tuple[str, str] | None:
    ba = panel.get("basic_auth") or ""
    if ba and ":" in ba:
        user, _, pw = ba.partition(":")
        return user, pw
    return None


async def _brain(method: str, panel: dict, path: str, timeout: float) -> Any:
    """Запрос к панели. Ошибка — с кодом и текстом ответа, а не голым «failed»."""
    try:
        async with httpx.AsyncClient(timeout=timeout, auth=_brain_auth(panel)) as c:
            r = await c.request(method, panel["url"] + path, headers=_brain_headers(panel))
    except httpx.HTTPError as e:
        raise InventoryError(f"панель {panel['name']} не ответила на {path}: {type(e).__name__}: {e}") from e
    if r.status_code >= 400:
        raise InventoryError(f"панель {panel['name']} ответила {r.status_code} на {path}: {r.text[:200]}")
    return r.json()


async def brain_get(path: str, panel: dict, timeout: float = 15.0) -> Any:
    return await _brain("GET", panel, path, timeout)


async def brain_post(path: str, panel: dict, timeout: float = 60.0) -> Any:
    return await _brain("POST", panel, path, timeout)


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


def merge(by_panel: dict[str, list[dict]], file_data: dict) -> list[dict]:
    """Панели + файл → единый список.

    При одной панели имя ноды — как в панели. При нескольких — `панель/имя`:
    одинаковые имена в разных панелях не должны схлопнуться в одну ноду.
    Поправки файла сильнее полей панели только там, где панель ничего не знает
    (ssh_*), и в `ip` — если его явно переопределили.
    """
    multi = len(by_panel) > 1
    defaults = {"ssh_user": config.settings.ssh_user, "ssh_port": 22}
    defaults.update(file_data.get("defaults") or {})
    nodes: dict[str, dict] = {}
    for pname, rows in by_panel.items():
        for row in rows:
            n = _from_brain(row)
            n["panel"] = pname
            n["short_name"] = n["name"]
            if multi:
                n["name"] = f"{pname}/{n['short_name']}"
            nodes[n["name"]] = n
    for extra in file_data.get("nodes") or []:
        name = extra.get("name")
        if not name:
            continue
        key = f"{extra['panel']}/{name}" if multi and extra.get("panel") else name
        target = nodes.get(key)
        if target is None and multi:
            same = [n for n in nodes.values() if n.get("short_name") == name]
            target = same[0] if len(same) == 1 else None
        fields = {k: v for k, v in extra.items() if k not in ("name", "panel")}
        if target is not None:
            target.update(fields)
        else:
            nodes[key] = {"name": key, "short_name": name, "source": "file", "active": True,
                          "panel": extra.get("panel"), "panel_online": None,
                          "heartbeat_fresh": None, **fields}
    out = []
    for n in nodes.values():
        for k, v in defaults.items():
            n.setdefault(k, v)
        # SSH идёт на адрес управления, если он есть: это тот, что доступен.
        n.setdefault("ssh_host", n.get("api_host") or n.get("ip"))
        out.append(n)
    # ssh_via: имя другой ноды → её адрес (user@host:port). Не имя — оставляем
    # как есть, ssh.parse_via проверит.
    for n in out:
        via = n.get("ssh_via")
        if not via:
            continue
        hop = nodes.get(via) or next((m for m in out if m.get("short_name") == via), None)
        if hop is not None and hop is not n and hop.get("ssh_host"):
            # ssh_host узла бывает «host:port» — иначе вышло бы «host:port:22».
            host, port = ssh.ssh_target(hop)
            n["ssh_via"] = f"{hop.get('ssh_user') or config.settings.ssh_user}@{host}:{port}"
    out.sort(key=lambda n: n["name"])
    return out


async def load_nodes() -> tuple[list[dict], list[str]]:
    """(ноды, предупреждения). Недоступная панель — предупреждение, не отказ:
    для того хаб и существует, чтобы работать, когда панель слепа."""
    import asyncio

    from nexus_mcp import panels

    warnings: list[str] = []
    try:
        plist = panels.all_panels()
    except panels.PanelConfigError as e:
        plist, _ = [], warnings.append(str(e))

    async def one(p: dict):
        try:
            return p["name"], await brain_get("/api/v1/servers", p)
        except InventoryError as e:
            warnings.append(f"список из панели {p['name']} не получен: {e}")
            return p["name"], []

    by_panel = dict(await asyncio.gather(*[one(p) for p in plist]))
    nodes = merge(by_panel, _load_file())
    if not nodes:
        hint = "; ".join(warnings) or "панели не настроены"
        raise InventoryError(
            f"нод нет: {hint}; файл {config.settings.inventory_file} пуст или отсутствует")
    return nodes, warnings


async def find_node(name_or_ip: str) -> dict:
    """Нода по имени (`имя` или `панель/имя`), IP или id. Одинаковое имя в
    двух панелях — отказ со списком, а не первая попавшаяся."""
    nodes, _ = await load_nodes()
    key = (name_or_ip or "").strip().lower()
    exact = [n for n in nodes if key in (n["name"].lower(), str(n.get("ip", "")).lower(),
                                         str(n.get("id", "")).lower())]
    if len(exact) == 1:
        return exact[0]
    short = [n for n in nodes if str(n.get("short_name", "")).lower() == key]
    if len(short) == 1:
        return short[0]
    if len(exact) + len(short) > 1:
        variants = ", ".join(n["name"] for n in (exact or short))
        raise InventoryError(f"«{name_or_ip}» есть в нескольких панелях: {variants} — укажите панель/имя")
    names = ", ".join(n["name"] for n in nodes[:30])
    raise InventoryError(f"нода «{name_or_ip}» не найдена. Есть: {names}")


def node_panel(node: dict) -> dict | None:
    """Панель, к которой относится нода (для ручек панели и адреса heartbeat)."""
    from nexus_mcp import panels

    if not node.get("panel"):
        return None
    try:
        return panels.resolve(node["panel"])
    except panels.PanelConfigError:
        return None
