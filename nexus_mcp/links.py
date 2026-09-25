"""Ссылки подписки → клиентские xray-конфиги для сквозной проверки.

Конфиг собирается ТЕМ ЖЕ кодом, что отдаёт JSON-подписку клиентам,
`brain/app/services/xray_json.py`. Второй сборщик разошёлся бы с первым
молча (инвариант 25): проверка зеленела бы на конфиге, которого у клиента
нет. Модуль грузится по пути к файлу, а не через `import app...`: пакет
`app` при импорте запечатывает сборку (инвариант 1) и тянет всё brain.
"""

from __future__ import annotations

import base64
import importlib.util
import socket
from functools import lru_cache
from types import ModuleType
from urllib.parse import unquote, urlparse

import httpx

from nexus_mcp import config


class LinksError(Exception):
    pass


@lru_cache(maxsize=1)
def xray_json() -> ModuleType:
    path = config.settings.repo_dir / "brain" / "app" / "services" / "xray_json.py"
    if not path.exists():
        raise LinksError(f"нет {path}: нужен клон vgx3d (NEXUS_REPO_DIR) — его кладёт install.sh")
    spec = importlib.util.spec_from_file_location("nexus_xray_json", path)
    mod = importlib.util.module_from_spec(spec)
    assert spec.loader is not None
    spec.loader.exec_module(mod)
    return mod


def decode_subscription(body: str) -> list[str]:
    """Тело подписки → список URI. Подписка бывает base64 и открытым текстом."""
    text = (body or "").strip()
    if "://" not in text.split("\n", 1)[0]:
        try:
            padded = text + "=" * (-len(text) % 4)
            text = base64.b64decode(padded).decode("utf-8", "replace")
        except (ValueError, UnicodeDecodeError):
            pass
    return [ln.strip() for ln in text.splitlines() if "://" in ln]


async def fetch_links() -> list[str]:
    url = config.settings.test_sub_url
    if not url:
        raise LinksError("нет подписки для проверки: задайте NEXUS_TEST_SUB_URL "
                         "(подписка тестового юзера, привязанного ко всем нодам)")
    # UA обычного клиента: панель отдаёт формат по User-Agent.
    async with httpx.AsyncClient(timeout=20, follow_redirects=True) as c:
        r = await c.get(url, headers={"User-Agent": "v2rayNG/1.9"})
    if r.status_code >= 400:
        raise LinksError(f"подписка ответила {r.status_code}: {r.text[:200]}")
    links = decode_subscription(r.text)
    if not links:
        raise LinksError("в подписке нет ссылок — тестовый юзер не привязан к нодам или истёк")
    return links


def describe(uri: str) -> dict:
    """Короткое описание ссылки для отчёта: протокол, адрес, порт, транспорт."""
    u = urlparse(uri)
    from urllib.parse import parse_qs

    q = parse_qs(u.query)
    return {
        "scheme": u.scheme,
        "host": u.hostname,
        "port": u.port,
        "type": (q.get("type") or [""])[0],
        "security": (q.get("security") or [""])[0],
        "sni": (q.get("sni") or [""])[0],
        "remark": unquote(u.fragment or ""),
    }


def _resolve(host: str) -> set[str]:
    try:
        return {ai[4][0] for ai in socket.getaddrinfo(host, None)}
    except OSError:
        return set()


def links_for_node(links: list[str], node: dict) -> list[str]:
    """Ссылки, ведущие на эту ноду: по IP напрямую или по домену, который в
    него резолвится. Ссылки через CDN сюда не попадут — их адрес это edge
    провайдера, и к самой ноде они отношения не имеют."""
    ip = str(node.get("ip") or "")
    out = []
    for uri in links:
        host = urlparse(uri).hostname or ""
        if not host:
            continue
        if host == ip or ip in _resolve(host):
            out.append(uri)
    return out


def config_for(uri: str) -> dict | None:
    return xray_json().uri_to_config(uri)
