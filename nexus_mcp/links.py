"""Ссылки подписки → клиентские xray-конфиги для сквозной проверки.

Конфиг собирается ТЕМ ЖЕ кодом, что отдаёт JSON-подписку клиентам:
`nexus_mcp/xray_json.py` — побайтовая копия `brain/app/services/xray_json.py`
панели. Второй сборщик разошёлся бы с первым молча (инвариант 25): проверка
зеленела бы на конфиге, которого у клиента нет. Копия, а не клон панели:
репозиторий панели приватный, хабу к нему доступа нет. Совпадение с
оригиналом держит сторож в тестах — правите сборщик в панели, копируйте сюда.
"""

from __future__ import annotations

import base64
import socket
from urllib.parse import unquote, urlparse

import httpx

from nexus_mcp import config, xray_json


class LinksError(Exception):
    pass


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
    return xray_json.uri_to_config(uri)
