"""Панели хаба для приложения администратора: список и вход телефона.

Приложение не просит у человека адрес и мастер-токен каждой панели: хаб их
уже знает (`panels.json`). Но токен из хаба на телефон НЕ уходит — хаб сам
регистрирует ключ устройства в панели (`/admin/devices/enroll`) своим
токеном и отдаёт приложению только id устройства. Дальше телефон входит в
панель своим ключом из Keystore, как если бы токен ввели руками.

`gate` отдаётся: это не доступ к панели, а пропуск мимо basic_auth Caddy —
его же панель сама ставит cookie любому зарегистрированному устройству
(`set_session_cookies`). Без него телефон не дойдёт до /api панели
поставщика, у которой /api закрыт паролем.
"""

from __future__ import annotations

import httpx

from nexus_chat.store import StoreError

# Пометка в названии устройства: в «Настройки → Доступ» панели видно, что
# телефон вошёл через хаб, а не мастер-токеном руками.
LABEL_SUFFIX = " · через хаб"
LABEL_MAX = 120  # EnrollIn.label в brain/app/api/v1/admin/devices.py

# Клиент к панели; тесты подменяют его, не трогая httpx целиком.
_client = httpx.AsyncClient


def _panels() -> list[dict]:
    from nexus_mcp import panels

    try:
        return panels.all_panels()
    except panels.PanelConfigError as e:
        raise StoreError(f"список панелей хаба не читается: {e}", 500) from e


def listing() -> list[dict]:
    """Что видит приложение: имя и адрес, без токенов."""
    return [{
        "name": p["name"],
        "url": p["url"],
        # /api за паролем Caddy, а обхода (gate) хаб не знает: телефон до
        # такой панели не дойдёт, даже если хаб его зарегистрирует.
        "password_only": bool(p.get("basic_auth")) and not p.get("gate"),
    } for p in _panels()]


def _label(raw: str) -> str:
    base = (raw or "").strip() or "Nexus Admin"
    return base[:LABEL_MAX - len(LABEL_SUFFIX)] + LABEL_SUFFIX


async def enroll(name: str, public_key: str, label: str, *, timeout: float = 20.0) -> dict:
    from nexus_mcp.inventory import GATE_COOKIE, _brain_auth, _brain_headers

    p = next((x for x in _panels() if x["name"] == name), None)
    if p is None:
        raise StoreError(f"на хабе нет панели «{name}»", 404)
    public_key = (public_key or "").strip()
    if len(public_key) < 32:
        raise StoreError("нужен public_key: публичная половина ключа устройства (SPKI, base64)", 422)
    if not p.get("token"):
        raise StoreError(f"у панели «{name}» на хабе нет токена: nexus-mcp-panels add {name} <url> <токен>", 409)

    url = p["url"] + "/api/v1/admin/devices/enroll"
    try:
        async with _client(timeout=timeout, auth=_brain_auth(p)) as c:
            r = await c.post(url, json={"public_key": public_key, "label": _label(label)},
                             headers=_brain_headers(p))
    except httpx.HTTPError as e:
        raise StoreError(f"панель «{name}» не ответила хабу: {type(e).__name__}: {e}", 502) from e

    if r.status_code >= 400:
        text = r.text[:300]
        if r.status_code == 401 and "basic" in r.headers.get("www-authenticate", "").lower():
            detail = (f"/api панели «{name}» закрыт паролем Caddy: на хабе нужен gate — "
                      f"nexus-mcp-panels add {name} <url> <токен> --gate <VPN_PANEL_GATE_SECRET>")
        elif r.status_code == 403:
            detail = f"панель «{name}» не приняла токен хаба (403): обновите его — nexus-mcp-panels add"
        elif r.status_code == 404:
            detail = f"панель «{name}» слишком старая: нет входа по ключу устройства — обновите панель"
        elif r.status_code == 422:
            detail = f"панель «{name}» не приняла ключ устройства: {text}"
        else:
            detail = f"панель «{name}» ответила {r.status_code}: {text}"
        # 4xx от панели — ответ приложению как есть по смыслу, но код хаба
        # 502: иначе приложение примет 403 за «неверный токен чата».
        raise StoreError(detail, 422 if r.status_code == 422 else 502)

    try:
        device = (r.json() or {}).get("device") or {}
    except ValueError:
        device = {}
    if not device.get("id"):
        raise StoreError(f"панель «{name}» не вернула id устройства: {r.text[:200]}", 502)

    return {
        "ok": True,
        "panel": {"name": p["name"], "url": p["url"]},
        "device": {"id": str(device["id"]), "label": device.get("label", "")},
        "gate": p.get("gate") or r.cookies.get(GATE_COOKIE) or "",
    }
