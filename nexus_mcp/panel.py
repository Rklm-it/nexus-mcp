"""Панель (brain) через её админ-API — глазами администратора.

Хаб ходит в панель с `X-Admin-Token`, как админ-бот и приложение
администратора. Чтение — всё под `/api/v1/admin/*` и соседние админские
ресурсы (серверы, инбаунды, юзеры). Запись — только из короткого списка и
только с `NEXUS_ALLOW_ACTIONS=1` + `confirm=true`.

Секреты из ответов вырезаются ДО того, как попадут в модель: токены нод,
ключи Reality, пароли SS/Hysteria, sub_token юзеров. Диагностике они не
нужны, а однажды попав в переписку, они уже не секрет.
"""

from __future__ import annotations

import json
import re
from typing import Any

import httpx

from nexus_mcp import panels
from nexus_mcp.inventory import _brain_auth, _brain_headers

# Что можно читать. Всё — админские ресурсы панели; публичные ручки
# (подписка, вебхуки платежей, бот) сюда не входят: у них свои секреты в пути.
READ_PREFIXES = (
    "/api/v1/admin/",
    "/api/v1/servers",
    "/api/v1/inbounds",
    "/api/v1/outbounds",
    "/api/v1/users",
    "/api/v1/traffic",
    "/health",
)

# Что можно менять — только то, что лечит или проверяет, и ничего, что
# удаляет данные или трогает деньги. Каждый путь — регулярка на весь путь.
ACTION_PATTERNS = {
    r"/api/v1/admin/nodes/[0-9a-f-]{36}/rf-check": "проверка ноды с check-host (~30 с)",
    r"/api/v1/admin/nodes/[0-9a-f-]{36}/restart/(xray|hysteria-server)": "перезапуск сервиса ноды",
    r"/api/v1/admin/nodes/[0-9a-f-]{36}/update": "обновить агент ноды (через панель)",
    r"/api/v1/admin/nodes/[0-9a-f-]{36}/speedtest": "замер скорости ноды",
    r"/api/v1/admin/monitoring/check": "прогон центра состояния (send=false — без рассылки)",
    r"/api/v1/admin/resync/run": "пересинхронизация юзеров на ноды",
}

MAX_CHARS = 60_000

_SECRET_KEY = re.compile(
    r"(token|secret|password|passwd|private_key|privatekey|api_key|apikey|cookie|"
    r"^pbk$|^psk$|obfs_password|auth_str|seed)",
    re.I,
)
# Эти ключи содержат слово token, но это не секреты, а метаданные.
_NOT_SECRET = {"has_api_token", "token_type", "tokens_used", "token_count"}


class PanelError(Exception):
    pass


def _mask(value: Any) -> Any:
    if isinstance(value, str) and value:
        return value[:4] + "…" if len(value) > 12 else "***"
    if value in (None, "", 0, False):
        return value
    return "***"


def redact(obj: Any) -> Any:
    """Рекурсивно спрятать значения секретных ключей. Первые 4 символа
    оставляем у длинных строк: по ним видно, что поле заполнено и одинаково
    ли оно в двух местах, но восстановить его нельзя."""
    if isinstance(obj, dict):
        out = {}
        for k, v in obj.items():
            if isinstance(k, str) and k not in _NOT_SECRET and _SECRET_KEY.search(k) \
                    and not isinstance(v, (dict, list)):
                out[k] = _mask(v)
            else:
                out[k] = redact(v)
        return out
    if isinstance(obj, list):
        return [redact(x) for x in obj]
    if isinstance(obj, str):
        # Ссылки подписки и vless:// с uuid — прячем токены в пути /sub/<token>.
        return re.sub(r"(/sub/)([A-Za-z0-9_-]{6})[A-Za-z0-9_-]+", r"\1\2…", obj)
    return obj


def _check_path(path: str) -> str:
    p = "/" + (path or "").strip().lstrip("/")
    p = p.split("?", 1)[0]
    if ".." in p or "//" in p or not re.fullmatch(r"[A-Za-z0-9/_.\-]+", p):
        raise PanelError(f"недопустимый путь: {path!r}")
    return p


def check_read_path(path: str) -> str:
    p = _check_path(path)
    if not any(p == pre.rstrip("/") or p.startswith(pre) for pre in READ_PREFIXES):
        raise PanelError(f"чтение {p} не разрешено; можно: {', '.join(READ_PREFIXES)}")
    return p


def check_action_path(path: str) -> str:
    p = _check_path(path)
    for pat in ACTION_PATTERNS:
        if re.fullmatch(pat, p):
            return p
    raise PanelError("действие не из списка разрешённых: "
                     + "; ".join(f"{k} — {v}" for k, v in ACTION_PATTERNS.items()))


def _shrink(data: Any) -> Any:
    """Ответ панели бывает огромным (списки юзеров, логи). Модели нужен
    смысл, а не мегабайт: режем с явной пометкой, сколько отрезано."""
    text = json.dumps(data, ensure_ascii=False, default=str)
    if len(text) <= MAX_CHARS:
        return data
    if isinstance(data, list):
        keep = max(1, int(len(data) * MAX_CHARS / len(text)))
        return {"items": data[:keep], "truncated": f"показано {keep} из {len(data)} — сузьте запрос"}
    if isinstance(data, dict):
        out, used = {}, 0
        for k, v in data.items():
            chunk = len(json.dumps(v, ensure_ascii=False, default=str))
            if used + chunk > MAX_CHARS:
                out[k] = f"…обрезано ({chunk} символов) — запросите отдельно"
            else:
                out[k] = v
                used += chunk
        return out
    return text[:MAX_CHARS] + "…(обрезано)"


HEALTH_LINES = 15
HEALTH_LINE_CHARS = 300


def compact_health(data: Any) -> Any:
    """Ответ /app/health → то, что нужно модели. Мегабайт в нём — хвосты
    логов (`lines`) при проверках: целиком они вытесняли все группы, и модель
    не видела даже, какая проверка красная. У ok/off хвосты убираются, у
    остальных остаются последние HEALTH_LINES строк по HEALTH_LINE_CHARS."""
    if not isinstance(data, dict) or not isinstance(data.get("groups"), list):
        return data
    groups = []
    for g in data["groups"]:
        if not isinstance(g, dict):
            continue
        checks = []
        for c in g.get("checks") or []:
            if not isinstance(c, dict):
                continue
            c = dict(c)
            lines = c.pop("lines", None) or []
            if lines and c.get("status") not in ("ok", "off"):
                c["lines"] = [str(x)[:HEALTH_LINE_CHARS] for x in lines[-HEALTH_LINES:]]
            checks.append(c)
        groups.append({**g, "checks": checks})
    return {**data, "groups": groups}


async def request(method: str, path: str, params: dict | None = None,
                  timeout: float = 30.0, panel_name: str = "", compact=None) -> Any:
    try:
        p = panels.resolve(panel_name)
    except panels.PanelConfigError as e:
        raise PanelError(str(e)) from e
    clean = {k: v for k, v in (params or {}).items() if v is not None and v != ""}
    try:
        async with httpx.AsyncClient(timeout=timeout, auth=_brain_auth(p)) as c:
            r = await c.request(method, p["url"] + path, params=clean, headers=_brain_headers(p))
    except httpx.HTTPError as e:
        raise PanelError(f"панель {p['name']} не ответила на {path}: {type(e).__name__}: {e}") from e
    if r.status_code >= 400:
        detail = r.text[:400]
        hint = ""
        if r.status_code == 401 and "basic" in r.headers.get("www-authenticate", "").lower():
            hint = (" — /api закрыт паролем Caddy: нужен VPN_PANEL_GATE_SECRET из .env панели — "
                    f"nexus-mcp-panels add {p['name']} <url> <токен> --gate <секрет>")
        elif r.status_code == 403:
            hint = " — токен не принят или фича выключена лицензией"
        raise PanelError(f"панель {p['name']} ответила {r.status_code} на {method} {path}: {detail}{hint}")
    try:
        data = r.json()
    except ValueError:
        data = r.text[:MAX_CHARS]
    if compact is not None:
        data = compact(data)
    return _shrink(redact(data))


async def get(path: str, params: dict | None = None, timeout: float = 30.0,
              panel_name: str = "", compact=None) -> Any:
    return await request("GET", check_read_path(path), params, timeout, panel_name, compact)


async def post_action(path: str, params: dict | None = None, timeout: float = 120.0,
                      panel_name: str = "") -> Any:
    return await request("POST", check_action_path(path), params, timeout, panel_name)
