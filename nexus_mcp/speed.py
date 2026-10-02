"""Скорость строки подписки с точки обзора — и перебор её параметров.

Зачем: «открывается ли» не отвечает на вопрос «какие параметры CDN нужны».
На Яндекс-CDN интервал постов 1–3 мс открывался везде, а на мобильном
скачивание падало с 70 до 15 Мбит/с и отдача до 0,2 — при том что стенд на
самой ноде (дата-центр) показывал рост. Мерить надо с той же симки.

Вариант — та же ссылка с подменёнными полями `extra` (xhttp): размер поста,
интервал, место данных аплинка, xmux… Хаб собирает из неё клиентский конфиг
(`xray_json`) и шлёт пробнику задание `speed`: поднять xray, померить
задержку, скачивание и отправку через Интернетометр. Варианты идут по
очереди (один xray за раз — телефон и роутер), фоном: прогон — минуты.

Подменяется только клиентская сторона. Размер поста и интервал серверу не
нужны, а вот место данных и метод аплинка сервер обязан понимать: сервер с
`header` не читает тело и cookie, поэтому такой вариант просто не встанет —
это ответ про конфиг ноды, а не про сеть.
"""

from __future__ import annotations

import asyncio
import json
import time
import uuid
from urllib.parse import parse_qsl, quote, urlencode, urlparse, urlunparse

from nexus_mcp import links, sweep
from nexus_mcp.probes import HUB, ProbeError, _ver, registry

MIN_PROBE_VERSION = "1.3.0"
MAX_VARIANTS = 12
# Объём замера по умолчанию: на телефоне это его трафик.
DEFAULT_DL_MB = 10.0
DEFAULT_UL_MB = 4.0
DEFAULT_MAX_TIME = 15.0

# snake_case панели → camelCase ссылки; уже camelCase и неизвестное — как есть.
_CAMEL = {
    "sc_max_each_post_bytes": "scMaxEachPostBytes",
    "sc_min_posts_interval_ms": "scMinPostsIntervalMs",
    "sc_max_buffered_posts": "scMaxBufferedPosts",
    "uplink_http_method": "uplinkHTTPMethod",
    "uplink_data_placement": "uplinkDataPlacement",
    "uplink_chunk_size": "uplinkChunkSize",
    "xpadding_bytes": "xPaddingBytes",
    "xpadding_placement": "xPaddingPlacement",
    "xpadding_method": "xPaddingMethod",
    "max_connections": "maxConnections",
}
# Поля, которые живут в query ссылки, а не в extra.
_QUERY_KEYS = {"mode", "path", "host", "sni", "fp", "alpn"}
_XMUX_KEYS = {"maxConnections", "maxConcurrency", "cMaxReuseTimes", "hMaxRequestTimes",
              "hMaxReusableSecs", "hKeepAlivePeriod"}


class SpeedError(Exception):
    pass


def variant_uri(uri: str, overrides: dict | None) -> str:
    """Ссылка с подменёнными параметрами. xmux сливается, а не заменяется:
    вариант «4 соединения» не должен молча сбросить остальные поля xmux."""
    if not overrides:
        return uri
    u = urlparse(uri)
    q = parse_qsl(u.query, keep_blank_values=True)
    extra_raw = next((v for k, v in q if k == "extra"), "")
    try:
        extra = json.loads(extra_raw) if extra_raw else {}
    except json.JSONDecodeError as e:
        raise SpeedError(f"extra ссылки не разбирается: {e}") from e
    query = {k: v for k, v in q if k != "extra"}
    for key, value in overrides.items():
        k = _CAMEL.get(key, key)
        if k in _QUERY_KEYS:
            query[k] = str(value)
        elif k == "xmux" and isinstance(value, dict):
            extra["xmux"] = {**(extra.get("xmux") or {}), **value}
        elif k in _XMUX_KEYS:
            extra["xmux"] = {**(extra.get("xmux") or {}), k: value}
        else:
            extra[k] = value
    items = list(query.items())
    if extra:
        items.append(("extra", json.dumps(extra, separators=(",", ":"))))
    return urlunparse(u._replace(query=urlencode(items, quote_via=quote, safe="/")))


async def pick_link(panel: str, host: str) -> str:
    """Строка тестовой подписки панели, ведущая на `host` (адрес CDN или ноды)."""
    srcs = sweep.sources(panel)
    for _, url in srcs:
        for uri in await links.fetch_links(url):
            if (urlparse(uri).hostname or "") == host:
                return uri
    raise SpeedError(f"в подписке {panel or 'по умолчанию'} нет строки с адресом {host}: "
                     "передайте ссылку целиком в link")


def check_probe(probe: str) -> None:
    if probe == HUB:
        return
    p = registry.probes.get(probe)
    info = (p.info if p else None) or {}
    if p is None:
        raise SpeedError(f"пробник «{probe}» ни разу не подключался")
    if not info.get("xray"):
        raise SpeedError(f"у пробника «{probe}» нет xray — замер скорости идёт только через xray")
    if _ver(info.get("version")) < _ver(MIN_PROBE_VERSION):
        raise SpeedError(f"пробник «{probe}» версии {info.get('version')}, замер скорости — с "
                         f"{MIN_PROBE_VERSION}. Он обновится сам при следующем подключении, если "
                         "не выключено NEXUS_PROBE_NO_UPDATE")


def _row(name: str, overrides: dict, res: dict) -> dict:
    row = {
        "name": name,
        "overrides": overrides,
        "ok": bool(res.get("ok")),
        "dl_mbit": res.get("dl_mbit", 0.0),
        "ul_mbit": res.get("ul_mbit", 0.0),
        "ping_ms": res.get("ping_ms"),
        "source": res.get("source"),
    }
    for key in ("download", "upload"):
        part = res.get(key) or {}
        if part.get("error") or part.get("status") not in (None, 200, 201, 204):
            row[f"{key}_note"] = {k: part.get(k) for k in ("status", "error", "detail", "bytes", "s") if part.get(k)}
    if not row["ok"]:
        row["error"] = res.get("error")
        row["detail"] = res.get("detail")
        if res.get("xray_log"):
            row["xray_log"] = str(res["xray_log"])[-300:]
    return row


async def run(probe: str, uri: str, variants: dict[str, dict], dl_mb: float, ul_mb: float,
              max_time: float, repeats: int, progress: dict) -> dict:
    plan: list[tuple[str, dict]] = [("as-is", {})]
    plan += [(n, v or {}) for n, v in variants.items() if n != "as-is"]
    plan = [x for x in plan for _ in range(max(1, repeats))]
    progress.update(total=len(plan), done=0)
    rows: list[dict] = []
    job_timeout = 2 * max_time + 45
    for name, overrides in plan:
        progress["current"] = name
        try:
            cfg = links.config_for(variant_uri(uri, overrides))
        except SpeedError as e:
            rows.append({"name": name, "overrides": overrides, "ok": False, "error": "bad_variant", "detail": str(e)})
            progress["done"] += 1
            continue
        if not cfg:
            rows.append({"name": name, "overrides": overrides, "ok": False, "error": "bad_link",
                         "detail": "из ссылки не собрать конфиг xray"})
            progress["done"] += 1
            continue
        try:
            res = await registry.run(probe, "speed", {
                "config": cfg, "dl_bytes": int(dl_mb * 1_000_000), "ul_bytes": int(ul_mb * 1_000_000),
                "max_time": max_time,
            }, timeout=job_timeout)
        except ProbeError as e:
            res = {"ok": False, "error": "probe", "detail": str(e)}
        rows.append(_row(name, overrides, res))
        progress["done"] += 1
    return {"probe": probe, "host": urlparse(uri).hostname, "rows": rows, "summary": summarize(rows)}


def summarize(rows: list[dict]) -> list[dict]:
    """Медиана по варианту: повторы одного варианта сводятся в одну строку."""
    by: dict[str, list[dict]] = {}
    for r in rows:
        by.setdefault(r["name"], []).append(r)

    def med(xs: list[float]) -> float:
        xs = sorted(xs)
        return round(xs[len(xs) // 2], 2) if xs else 0.0

    out = []
    for name, rs in by.items():
        ok = [r for r in rs if r.get("ok")]
        out.append({
            "name": name,
            "runs": len(rs),
            "ok_runs": len(ok),
            "dl_mbit": med([r["dl_mbit"] for r in ok]),
            "ul_mbit": med([r["ul_mbit"] for r in ok]),
            "dl_all": [r.get("dl_mbit") for r in rs],
            "ul_all": [r.get("ul_mbit") for r in rs],
            "overrides": rs[0].get("overrides"),
        })
    return out


class Runs:
    """Один прогон на пробник: два параллельных замера мерили бы друг друга."""

    def __init__(self) -> None:
        self.running: dict[str, dict] = {}
        self.last: dict[str, dict] = {}

    def state(self, probe: str) -> dict:
        cur = self.running.get(probe)
        if cur and not cur["task"].done():
            return {"ok": True, "probe": probe, "running": True, "progress": dict(cur["progress"]),
                    "started": cur["started"]}
        last = self.last.get(probe)
        if last is None:
            return {"ok": True, "probe": probe, "running": False, "last": None}
        return {"ok": True, "probe": probe, "running": False, "last": last}

    def start(self, probe: str, uri: str, variants: dict[str, dict], dl_mb: float = DEFAULT_DL_MB,
              ul_mb: float = DEFAULT_UL_MB, max_time: float = DEFAULT_MAX_TIME, repeats: int = 1) -> dict:
        cur = self.running.get(probe)
        if cur and not cur["task"].done():
            raise SpeedError(f"на пробнике «{probe}» уже идёт замер — дождитесь (speed_state)")
        if len(variants) > MAX_VARIANTS:
            raise SpeedError(f"вариантов {len(variants)}, не больше {MAX_VARIANTS} за прогон")
        check_probe(probe)
        entry = {"id": uuid.uuid4().hex[:10], "started": time.time(), "progress": {"stage": "speed"}}

        async def work():
            try:
                res = await run(probe, uri, variants, dl_mb, ul_mb, max_time, repeats, entry["progress"])
            except Exception as e:  # noqa: BLE001
                res = {"ok": False, "error": type(e).__name__, "detail": str(e)[:300]}
            res["finished_at"] = int(time.time())
            res["took_s"] = round(time.time() - entry["started"], 1)
            self.last[probe] = res
            return res

        entry["task"] = asyncio.create_task(work())
        self.running[probe] = entry
        return self.state(probe)


runs = Runs()
