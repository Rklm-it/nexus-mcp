"""Remnawave (и бот-продавец поверх него, 3XUIStore) — связка в хабе.

Зачем. Часть клиентов живёт не на панели Nexus, а на Remnawave с ботом
3XUIStore поверх (pablo: `panelpablo.mooo.com` + бот `auth.pablovpn.com`).
Хаб должен уметь им быстро разворачивать и перенастраивать ноды так же, как
нашим: видеть ноды и клиентов, править конфиг-профили, ставить ноды. Этот
модуль — основа: реестр таких панелей, клиент их API и чтение.

Реестр — `/etc/nexus-mcp/remnawave.json` (0600), отдельно от `panels.json`:
остальные инструменты хаба проходят по тому реестру и ждут API Nexus.

    {"panels": [
      {"name": "pablo", "url": "https://panelpablo.mooo.com", "token": "…",
       "sub_url": "https://auth.pablovpn.com/sub/"}
    ]}

`sub_url` — откуда клиенты берут подписку. У связки с 3XUIStore это SUBPAGE
бота (`<домен бота>/sub/<shortUuid>`), а не ссылка самой Remnawave: все
запросы подписки в Remnawave идут с сервера бота (разведка 04.10.2026).

Управление — командой на хабе, токен в JSON руками не набирать:
    nexus-mcp-remna list
    nexus-mcp-remna add pablo https://panelpablo.mooo.com <API-токен> --sub https://auth.pablovpn.com/sub/
    nexus-mcp-remna remove pablo

Токен Remnawave — полный доступ к панели. Наружу (в ответы модели) он не
уходит, секреты конфигов (privateKey, пароли) — замаскированы.
"""

from __future__ import annotations

import json
import os
import re
import sys
from pathlib import Path
from typing import Any

import httpx

from nexus_mcp import config

# Для тестов: подмена HTTP-транспорта.
_TRANSPORT: httpx.AsyncBaseTransport | None = None

NAME_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_-]{0,31}$")
URL_RE = re.compile(r"^https?://[A-Za-z0-9.\-]+(:\d+)?(/[A-Za-z0-9._~/\-]*)?$")
UUID_RE = re.compile(r"^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$")

# Ключи, значения которых не показываем никогда (конфиги xray, юзеры).
_SECRET_KEY = re.compile(
    r"(privatekey|private_key|password|passwd|secret|token|^auth$|psk|seed|"
    r"vlessuuid|trojanpassword|sspassword)",
    re.I,
)


class RemnaError(Exception):
    def __init__(self, message: str, status: int | None = None):
        super().__init__(message)
        self.status = status


# ── Реестр ─────────────────────────────────────────────────────────────────

def _file() -> Path:
    return config.settings.remna_file


def _read() -> list[dict]:
    path = _file()
    if not path.exists():
        return []
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, ValueError) as e:
        raise RemnaError(f"не читается {path}: {e}") from e
    return [p for p in data.get("panels", []) if p.get("name") and p.get("url")]


def _write(panels: list[dict]) -> None:
    path = _file()
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp = path.with_suffix(".tmp")
    fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(fd, "w", encoding="utf-8") as f:
        json.dump({"panels": panels}, f, ensure_ascii=False, indent=2)
    os.replace(tmp, path)


def all_panels() -> list[dict]:
    return _read()


def resolve(name: str = "") -> dict:
    panels = _read()
    if not panels:
        raise RemnaError("панелей Remnawave на хабе нет: nexus-mcp-remna add <имя> <url> <токен>")
    if not name:
        if len(panels) == 1:
            return panels[0]
        raise RemnaError("панелей Remnawave несколько — укажи panel=: " + ", ".join(p["name"] for p in panels))
    for p in panels:
        if p["name"].lower() == name.lower():
            return p
    raise RemnaError(f"панели Remnawave «{name}» нет. Есть: {', '.join(p['name'] for p in panels)}")


def public_view(p: dict) -> dict:
    return {"name": p["name"], "url": p["url"], "token": bool(p.get("token")),
            "sub_url": p.get("sub_url", "")}


def add(name: str, url: str, token: str, sub_url: str = "") -> dict:
    if not NAME_RE.match(name or ""):
        raise RemnaError("имя: латиница, цифры, - и _, до 32 символов")
    url = (url or "").rstrip("/")
    if not URL_RE.match(url):
        raise RemnaError(f"«{url}» — не адрес панели (https://домен)")
    if not (token or "").strip():
        raise RemnaError("нужен API-токен Remnawave (Настройки → API-токены)")
    if sub_url and not URL_RE.match(sub_url.rstrip("/")):
        raise RemnaError(f"«{sub_url}» — не адрес подписки (https://домен/sub/)")
    panels = [p for p in _read() if p["name"].lower() != name.lower()]
    entry = {"name": name, "url": url, "token": token.strip()}
    if sub_url:
        entry["sub_url"] = sub_url.rstrip("/") + "/"
    panels.append(entry)
    _write(panels)
    return public_view(entry)


def remove(name: str) -> bool:
    panels = _read()
    left = [p for p in panels if p["name"].lower() != name.lower()]
    if len(left) == len(panels):
        return False
    _write(left)
    return True


# ── Клиент API ─────────────────────────────────────────────────────────────

def _headers(p: dict) -> dict:
    return {
        "Authorization": f"Bearer {p['token']}",
        "Accept": "application/json",
        # Remnawave за своим reverse proxy ждёт эти заголовки; при обращении
        # прямо к порту панели без них отвечает 400.
        "X-Forwarded-Proto": "https",
        "X-Forwarded-For": "127.0.0.1",
        "User-Agent": "nexus-hub",
    }


def _fail(r: httpx.Response) -> RemnaError:
    body = (r.text or "")[:300].replace("\n", " ")
    try:
        msg = r.json().get("message") or body
    except ValueError:
        msg = body
    if r.status_code == 401:
        return RemnaError("401: токен Remnawave не принят (отозван, истёк или от другой панели)", 401)
    if r.status_code == 403:
        return RemnaError(f"403: токену не хватает прав на эту ручку ({msg})", 403)
    if r.status_code == 404:
        return RemnaError(f"404: не найдено ({msg})", 404)
    if 300 <= r.status_code < 400:
        return RemnaError(
            f"{r.status_code}: панель шлёт на {r.headers.get('location', '?')} — адрес в реестре "
            "неверный или панель за прокси с входом", r.status_code)
    return RemnaError(f"{r.status_code}: {msg}", r.status_code)


async def request(p: dict, method: str, path: str, *, params: dict | None = None,
                  body: Any = None, timeout: float = 60.0) -> Any:
    kw: dict[str, Any] = {"base_url": p["url"], "headers": _headers(p), "timeout": timeout,
                          "follow_redirects": False}
    if _TRANSPORT is not None:
        kw["transport"] = _TRANSPORT
    async with httpx.AsyncClient(**kw) as c:
        try:
            r = await c.request(method, path, params=params, json=body)
        except httpx.HTTPError as e:
            raise RemnaError(f"панель Remnawave не ответила: {type(e).__name__}: {e}") from e
    if r.status_code not in (200, 201):
        raise _fail(r)
    try:
        data = r.json()
    except ValueError as e:
        raise RemnaError(f"ответ не JSON: {(r.text or '')[:200]}") from e
    return data.get("response", data) if isinstance(data, dict) else data


def _list(resp: Any, key: str = "") -> list:
    """Список из ответа: у одних ручек — массив, у других — {total, <key>: [...]}."""
    if isinstance(resp, list):
        return resp
    if isinstance(resp, dict):
        if key and isinstance(resp.get(key), list):
            return resp[key]
        for v in resp.values():
            if isinstance(v, list):
                return v
    return []


# ── Маскировка ─────────────────────────────────────────────────────────────

def mask(obj: Any) -> Any:
    """Секреты конфигов и юзеров — в «***», клиенты инбаунда — числом."""
    if isinstance(obj, dict):
        out = {}
        for k, v in obj.items():
            if k == "clients" and isinstance(v, list):
                out[k] = f"<{len(v)} клиентов>"
            elif isinstance(k, str) and _SECRET_KEY.search(k) and not isinstance(v, (dict, list)):
                out[k] = "***" if v not in (None, "", 0) else v
            else:
                out[k] = mask(v)
        return out
    if isinstance(obj, list):
        return [mask(x) for x in obj]
    return obj


# ── Чтение ─────────────────────────────────────────────────────────────────

def _gb(value: Any) -> float:
    try:
        return round(int(value) / 1e9, 2)
    except (TypeError, ValueError):
        return 0.0


def node_view(n: dict) -> dict:
    cp = n.get("configProfile") or {}
    inbounds = [i.get("tag") for i in (cp.get("activeInbounds") or []) if isinstance(i, dict)]
    return {
        "name": n.get("name"),
        "uuid": n.get("uuid"),
        "address": n.get("address"),
        "port": n.get("port"),
        "country": n.get("countryCode"),
        "connected": bool(n.get("isConnected")),
        "disabled": bool(n.get("isDisabled")),
        "users_online": n.get("usersOnline"),
        "traffic_used_gb": _gb(n.get("trafficUsedBytes")),
        "traffic_limit_gb": _gb(n.get("trafficLimitBytes")),
        "status_message": n.get("lastStatusMessage") or "",
        "xray_uptime_s": n.get("xrayUptime"),
        "profile_uuid": cp.get("activeConfigProfileUuid"),
        "inbounds": inbounds,
    }


async def nodes(p: dict) -> list[dict]:
    return [node_view(n) for n in _list(await request(p, "GET", "/api/nodes"))]


async def overview(p: dict) -> dict:
    stats = await request(p, "GET", "/api/system/stats")
    ns = await nodes(p)
    meta = {}
    try:
        meta = await request(p, "GET", "/api/system/metadata")
    except RemnaError:
        pass
    users = (stats or {}).get("users") or {}
    online = (stats or {}).get("onlineStats") or {}
    down = [n["name"] for n in ns if not n["connected"] and not n["disabled"]]
    return {
        "panel": p["name"],
        "version": meta.get("version"),
        "users": users.get("statusCounts") or {},
        "users_total": users.get("totalUsers"),
        "online_now": online.get("onlineNow"),
        "online_day": online.get("lastDay"),
        "nodes_total": len(ns),
        "nodes_online": sum(1 for n in ns if n["connected"]),
        "nodes_down": down,
        "sub_url": p.get("sub_url", ""),
    }


def user_view(u: dict, sub_url: str = "") -> dict:
    tr = u.get("userTraffic") or {}
    short = u.get("shortUuid")
    out = {
        "username": u.get("username"),
        "id": u.get("id"),
        "telegram_id": u.get("telegramId"),
        "status": u.get("status"),
        "expire_at": u.get("expireAt"),
        "device_limit": u.get("hwidDeviceLimit"),
        "traffic_used_gb": _gb(tr.get("usedTrafficBytes", u.get("usedTrafficBytes"))),
        "traffic_limit_gb": _gb(u.get("trafficLimitBytes")),
        "online_at": tr.get("onlineAt"),
        "last_node_uuid": tr.get("lastConnectedNodeUuid"),
        "squads": [s.get("name") for s in (u.get("activeInternalSquads") or []) if isinstance(s, dict)],
        "short_uuid": short,
        # Ключ входа не показываем, только совпадает ли он с токеном ссылки:
        # у связки с 3XUIStore они обычно равны.
        "key_equals_link": (u.get("vlessUuid") or "").lower() == (short or "").lower(),
    }
    if sub_url and short:
        out["sub_link"] = sub_url + short
    return out


async def find_user(p: dict, query: str) -> list[dict]:
    """Клиент по Telegram ID, shortUuid / UUID или логину."""
    q = (query or "").strip()
    if not q:
        raise RemnaError("нужен Telegram ID, UUID или логин клиента")
    sub = p.get("sub_url", "")
    if q.isdigit():
        resp = await request(p, "GET", "/api/users", params={
            "start": 0, "size": 20,
            "filters": json.dumps([{"id": "telegramId", "value": q}]),
        })
        rows = _list(resp, "users")
        # Фильтр старых версий бывает «содержит» — оставляем точные совпадения.
        exact = [u for u in rows if str(u.get("telegramId") or "") == q]
        return [user_view(u, sub) for u in (exact or rows)]
    try:
        if UUID_RE.match(q) or re.match(r"^[A-Za-z0-9_-]{8,}$", q):
            u = await request(p, "GET", f"/api/users/by-short-uuid/{q}")
            return [user_view(u, sub)]
    except RemnaError as e:
        if e.status != 404:
            raise
    try:
        u = await request(p, "GET", f"/api/users/by-username/{q}")
        return [user_view(u, sub)]
    except RemnaError as e:
        if e.status == 404:
            return []
        raise


async def user_devices(p: dict, user_id: Any) -> list[dict]:
    try:
        resp = await request(p, "GET", f"/api/hwid/devices/{user_id}")
    except RemnaError as e:
        if e.status == 404:
            return []
        raise
    out = []
    for d in _list(resp, "devices"):
        out.append({k: d.get(k) for k in ("platform", "osVersion", "deviceModel", "userAgent",
                                          "createdAt", "updatedAt")})
    return out


async def find_node(p: dict, name: str) -> dict:
    raw = _list(await request(p, "GET", "/api/nodes"))
    key = (name or "").strip().lower()
    hit = [n for n in raw if (n.get("name") or "").lower() == key
           or (n.get("address") or "").lower() == key or n.get("uuid") == name]
    if not hit:
        hit = [n for n in raw if key and key in (n.get("name") or "").lower()]
    if not hit:
        raise RemnaError(f"ноды «{name}» в Remnawave нет. Есть: "
                         + ", ".join(n.get("name", "?") for n in raw))
    if len(hit) > 1:
        raise RemnaError("под «%s» подходит несколько нод: %s" % (name, ", ".join(n["name"] for n in hit)))
    return hit[0]


def inbound_view(i: dict) -> dict:
    ss = i.get("streamSettings") or {}
    rs = ss.get("realitySettings") or {}
    ts = ss.get("tlsSettings") or {}
    certs = [c.get("certificateFile", "") for c in (ts.get("certificates") or [])]
    domain = ""
    for c in certs:
        m = re.search(r"/live/([^/]+)/", c)
        if m:
            domain = m.group(1)
    v = {
        "tag": i.get("tag"),
        "protocol": i.get("protocol"),
        "port": i.get("port"),
        "network": ss.get("network"),
        "security": ss.get("security"),
    }
    if rs:
        v.update({"reality_sni": rs.get("serverNames"), "reality_dest": rs.get("dest") or rs.get("target"),
                  "short_ids": len(rs.get("shortIds") or []),
                  "min_client_ver": rs.get("minClientVer")})
    if ts:
        v.update({"tls_alpn": ts.get("alpn"), "cert_domain": domain})
    for key in ("wsSettings", "xhttpSettings", "grpcSettings"):
        if ss.get(key):
            v[key] = {k: ss[key].get(k) for k in ("path", "host", "serviceName", "mode") if ss[key].get(k)}
    return v


async def profile(p: dict, node_name: str) -> dict:
    n = await find_node(p, node_name)
    cp_uuid = (n.get("configProfile") or {}).get("activeConfigProfileUuid")
    if not cp_uuid:
        raise RemnaError(f"у ноды «{n.get('name')}» нет конфиг-профиля")
    prof = await request(p, "GET", f"/api/config-profiles/{cp_uuid}")
    cfg = prof.get("config") or {}
    routing = cfg.get("routing") or {}
    return {
        "node": n.get("name"),
        "profile": prof.get("name"),
        "profile_uuid": cp_uuid,
        "inbounds": [inbound_view(i) for i in cfg.get("inbounds") or []],
        "outbounds": [{"tag": o.get("tag"), "protocol": o.get("protocol")} for o in cfg.get("outbounds") or []],
        "routing_rules": mask(routing.get("rules") or []),
        "dns": mask(cfg.get("dns")) if cfg.get("dns") else None,
    }


# ── Команда управления ─────────────────────────────────────────────────────

def main(argv: list[str] | None = None) -> int:
    import argparse

    ap = argparse.ArgumentParser(prog="nexus-mcp-remna", description="Панели Remnawave на хабе")
    sub = ap.add_subparsers(dest="cmd", required=True)
    sub.add_parser("list")
    a = sub.add_parser("add")
    a.add_argument("name")
    a.add_argument("url")
    a.add_argument("token")
    a.add_argument("--sub", default="", help="адрес подписки клиентов (SUBPAGE бота), https://домен/sub/")
    r = sub.add_parser("remove")
    r.add_argument("name")
    args = ap.parse_args(argv)
    try:
        if args.cmd == "list":
            for p in all_panels():
                v = public_view(p)
                print(f"{v['name']:<16} {v['url']}  подписка: {v['sub_url'] or '—'}")
        elif args.cmd == "add":
            v = add(args.name, args.url, args.token, args.sub)
            print(f"добавлена {v['name']} → {v['url']} (хаб подхватит сразу)")
        elif args.cmd == "remove":
            if not remove(args.name):
                print(f"панели «{args.name}» нет", file=sys.stderr)
                return 1
            print(f"удалена {args.name}")
    except RemnaError as e:
        print(f"ошибка: {e}", file=sys.stderr)
        return 2
    return 0


if __name__ == "__main__":
    sys.exit(main())
