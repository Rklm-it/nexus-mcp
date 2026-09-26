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
import time
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

# Правка конфигурации нод (node_edit): метод + путь целиком. Только ресурсы
# ОДНОЙ ноды — её маршрутизация, relay, инбаунды, настройки. Удаления ноды,
# юзеров, денег здесь нет и быть не должно.
_U = "[0-9a-f-]{36}"
WRITE_PATTERNS = [
    ("PATCH", rf"/api/v1/servers/{_U}"),
    ("POST", rf"/api/v1/servers/{_U}/push-network"),
    ("POST", rf"/api/v1/admin/nodes/{_U}/relay-node"),
    ("POST", rf"/api/v1/servers/{_U}/outbounds"),
    ("DELETE", rf"/api/v1/servers/{_U}/outbounds/{_U}"),
    ("POST", rf"/api/v1/servers/{_U}/inbounds"),
    ("PUT", rf"/api/v1/servers/{_U}/inbounds/order"),
    ("PATCH", rf"/api/v1/servers/{_U}/inbounds/{_U}"),
    ("DELETE", rf"/api/v1/servers/{_U}/inbounds/{_U}"),
    ("POST", rf"/api/v1/servers/{_U}/inbounds/{_U}/push"),
    # Cloudflare-фронт ноды (vgx3d api/v1/admin/cloudflare.py).
    ("POST", rf"/api/v1/admin/cloudflare/servers/{_U}/(enable|verify|disable)"),
]

MAX_CHARS = 60_000

_SECRET_KEY = re.compile(
    r"(token|secret|password|passwd|private_key|privatekey|api_key|apikey|cookie|"
    r"^pbk$|^psk$|obfs_password|auth_str|seed|license_key|session_hash)",
    re.I,
)
# Эти ключи содержат слово token, но это не секреты, а метаданные.
_NOT_SECRET = {"has_api_token", "token_type", "tokens_used", "token_count"}


class PanelError(Exception):
    """status/data — код и разобранный JSON отказа панели, если он был: часть
    ручек отдаёт в отказе не только detail (Cloudflare: шаг и пройденные шаги),
    и это обязано доехать до человека целиком (инвариант 26)."""

    def __init__(self, message: str, status: int | None = None, data: Any = None):
        super().__init__(message)
        self.status = status
        self.data = data


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
        raise PanelError(f"чтение {p} не разрешено; можно: {', '.join(READ_PREFIXES)} "
                         "и любая GET-ручка из каталога панели (panel_endpoints)")
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
                  timeout: float = 30.0, panel_name: str = "", compact=None,
                  body: Any = None, raw: bool = False) -> Any:
    """raw=True — ответ как есть, БЕЗ маскировки: только для кода хаба
    (снимок «как было» для отката правки), в модель такое не отдаётся."""
    try:
        p = panels.resolve(panel_name)
    except panels.PanelConfigError as e:
        raise PanelError(str(e)) from e
    clean = {k: v for k, v in (params or {}).items() if v is not None and v != ""}
    kw = {"json": body} if body is not None else {}
    try:
        async with httpx.AsyncClient(timeout=timeout, auth=_brain_auth(p)) as c:
            r = await c.request(method, p["url"] + path, params=clean, headers=_brain_headers(p), **kw)
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
        try:
            data = r.json()
        except ValueError:
            data = None
        raise PanelError(f"панель {p['name']} ответила {r.status_code} на {method} {path}: {detail}{hint}",
                         r.status_code, data)
    if r.status_code == 204 or not r.content:
        return {} if raw else {"status": r.status_code}
    try:
        data = r.json()
    except ValueError:
        data = r.text[:MAX_CHARS]
    if raw:
        return data
    if compact is not None:
        data = compact(data)
    return _shrink(redact(data))


async def get(path: str, params: dict | None = None, timeout: float = 30.0,
              panel_name: str = "", compact=None) -> Any:
    try:
        p = check_read_path(path)
    except PanelError:
        # Админские ручки вне /api/v1/admin (маршрутизация, лицензии, bypass) —
        # по каталогу самой панели: что она закрыла админ-доступом, то и читаем.
        p = _check_path(path)
        if match_endpoint(await catalog(panel_name), "GET", p) is None:
            raise
    return await request("GET", p, params, timeout, panel_name, compact)


def check_write(method: str, path: str) -> str:
    p = _check_path(path)
    m = method.upper()
    if any(m == wm and re.fullmatch(pat, p) for wm, pat in WRITE_PATTERNS):
        return p
    raise PanelError(f"запись {m} {p} не из списка правок ноды")


async def write(method: str, path: str, body: Any = None, params: dict | None = None,
                timeout: float = 120.0, panel_name: str = "") -> Any:
    """Правка через панель; ответ — сырой (для снимка отката), маскирует вызывающий."""
    return await request(method.upper(), check_write(method, path), params, timeout, panel_name,
                         body=body, raw=True)


async def read_raw(path: str, panel_name: str = "", timeout: float = 30.0,
                   params: dict | None = None) -> Any:
    """Чтение без маскировки — для снимка «как было». В модель не отдавать."""
    return await request("GET", check_read_path(path), params, timeout, panel_name, raw=True)


async def post_action(path: str, params: dict | None = None, timeout: float = 120.0,
                      panel_name: str = "") -> Any:
    return await request("POST", check_action_path(path), params, timeout, panel_name)


# ── Каталог ручек панели и вызов любой из них ──────────────────────────────
# Панель сама отдаёт список всех ручек, закрытых админ-доступом
# (vgx3d brain/app/api/v1/admin/datastore.py, /meta/endpoints). По нему хаб
# знает, что вообще можно вызвать, и не держит второй список (инвариант 25).

CATALOG_PATH = "/api/v1/admin/meta/endpoints"
CATALOG_TTL = 600.0
_catalog_cache: dict[str, tuple[float, list[dict]]] = {}

# Мимо panel_call: вход в панель (ключи устройств, сессии) и ручки, у которых
# свой инструмент с собственными проверками.
CALL_DENY = {
    r"/api/v1/admin/devices(/.*)?": "ключи устройств и вход в панель — только из самой панели",
    r"/api/v1/admin/verify": "проверка входа, не действие",
    r"/api/v1/admin/meta/.*": "каталог — panel_endpoints",
    r"/api/v1/admin/db/query": "запрос к базе — panel_sql",
}

# Чем рискует правка — строка в предпросмотре и на кнопке «Разрешить».
RISK_RULES = [
    (r"bulk|broadcast|update-all|restart-all|resync", "массовое: задевает многих юзеров или все ноды"),
    (r"/system/|self-update|/restart|/brain/", "хост панели: перезапуск или обновление контейнеров"),
    (r"/config|/bots/", "настройки панели или ботов (.env): секреты с пустым значением не меняются"),
    (r"payment|balance|topup|refund|donat|promo|plan|traffic-package|extend", "деньги или сроки подписок"),
    (r"/servers|/inbounds|/outbounds|/nodes|/cloudflare|/cdn", "ноды: может уехать в подписки юзеров"),
    (r"/db/|/redis/", "база или Redis панели"),
]


def _template_re(template: str) -> str:
    out, pos = "", 0
    for m in re.finditer(r"\{([^}/]+)\}", template):
        out += re.escape(template[pos:m.start()])
        out += ".+" if m.group(1).endswith(":path") else "[^/]+"
        pos = m.end()
    return out + re.escape(template[pos:])


def match_endpoint(items: list[dict], method: str, path: str) -> dict | None:
    """Ручка каталога под метод и путь; точный шаблон сильнее параметра
    (/users/bulk — это bulk, а не /users/{user_id})."""
    hits = [e for e in items if e.get("method") == method.upper()
            and re.fullmatch(_template_re(e.get("path", "")), path)]
    hits.sort(key=lambda e: e["path"].count("{"))
    return hits[0] if hits else None


async def catalog(panel_name: str = "", fresh: bool = False) -> list[dict]:
    try:
        key = panels.resolve(panel_name)["name"]
    except panels.PanelConfigError as e:
        raise PanelError(str(e)) from e
    hit = _catalog_cache.get(key)
    if hit and not fresh and hit[0] > time.monotonic():
        return hit[1]
    try:
        data = await request("GET", CATALOG_PATH, None, 30.0, panel_name, raw=True)
    except PanelError as e:
        if e.status == 404:
            raise PanelError(f"панель {key} без каталога ручек ({CATALOG_PATH}): обновите панель — "
                             "до обновления работают только готовые инструменты и panel_get по /api/v1/admin/*",
                             404) from e
        raise
    items = data.get("endpoints") if isinstance(data, dict) else None
    if not isinstance(items, list):
        raise PanelError(f"каталог панели {key} пришёл без endpoints: {str(data)[:200]}")
    _catalog_cache[key] = (time.monotonic() + CATALOG_TTL, items)
    return items


def risk_of(method: str, path: str) -> list[str]:
    out = [why for pat, why in RISK_RULES if re.search(pat, path)]
    if method.upper() == "DELETE":
        out.insert(0, "удаление")
    return out


async def check_call(method: str, path: str, body: Any, panel_name: str = "") -> dict:
    """Ручка для panel_call: есть в каталоге панели, не из запретных, поля тела
    — из её схемы. Возвращает запись каталога."""
    m = method.upper()
    if m not in ("POST", "PUT", "PATCH", "DELETE"):
        raise PanelError("panel_call — для изменений (POST/PUT/PATCH/DELETE); чтение — panel_get")
    p = _check_path(path)
    for pat, why in CALL_DENY.items():
        if re.fullmatch(pat, p):
            raise PanelError(f"{m} {p}: {why}")
    items = await catalog(panel_name)
    entry = match_endpoint(items, m, p)
    if entry is None:
        same = sorted({e["method"] + " " + e["path"] for e in items
                       if re.fullmatch(_template_re(e["path"]), p)})
        hint = f"у этого пути есть: {', '.join(same)}" if same else "поищите panel_endpoints(search=…)"
        raise PanelError(f"{m} {p} нет среди админских ручек панели — {hint}")
    fields = ((entry.get("body") or {}).get("fields") or {})
    if fields and isinstance(body, dict):
        extra = sorted(set(body) - set(fields))
        if extra:
            # Лишнее поле панель молча выбросит — и человек решит, что поменял.
            raise PanelError(f"полей {', '.join(extra)} у {m} {entry['path']} нет; есть: {', '.join(fields)}")
    return entry


async def call(method: str, path: str, body: Any = None, params: dict | None = None,
               timeout: float = 120.0, panel_name: str = "") -> Any:
    """Изменение через панель по каталогу; ответ маскируется."""
    await check_call(method, path, body, panel_name)
    return await request(method.upper(), _check_path(path), params, timeout, panel_name, body=body)


READ_POSTS = ("/api/v1/admin/db/query",)


async def post_read(path: str, body: Any, timeout: float = 60.0, panel_name: str = "") -> Any:
    """POST, который только читает (запрос к базе) — список фиксированный."""
    if path not in READ_POSTS:
        raise PanelError(f"{path} не из читающих POST")
    return await request("POST", path, None, timeout, panel_name, body=body)
