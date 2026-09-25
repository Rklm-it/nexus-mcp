"""Сколько Claude израсходовал в чате хаба: сегодня, неделя, месяц, всего.

Считается то, что идёт через хаб (чат приложения и аудит по расписанию): после
каждого ответа Claude Code присылает токены по моделям и условную цену в $.
На подписке Pro деньги не списываются — цена показывает масштаб, а реальный
предел — окна лимита подписки (5 часов, неделя). Их Claude Code сообщает
событием, когда состояние меняется; последнее известное хранится в kv.

Разговоры в claude.ai через коннектор хаб не видит — их там и смотреть.

`python -m nexus_chat.usage` — то же строками для меню хаба (nexus-hub).
"""

from __future__ import annotations

import json
import sys
import time
from datetime import datetime, timedelta
from typing import Any
from zoneinfo import ZoneInfo

RATE_KEY = "ratelimit:"
RATE_TITLES = {"five_hour": "5 часов", "seven_day": "неделя", "seven_day_opus": "неделя (Opus)",
               "seven_day_sonnet": "неделя (Sonnet)", "overage": "сверх лимита"}


def _starts(tz: str, now: float) -> dict[str, float]:
    try:
        z = ZoneInfo(tz)
    except Exception:  # noqa: BLE001 — кривая зона не повод падать
        z = ZoneInfo("UTC")
    d = datetime.fromtimestamp(now, z)
    day = d.replace(hour=0, minute=0, second=0, microsecond=0)
    return {"today": day.timestamp(),
            "week": (day - timedelta(days=6)).timestamp(),
            "month": day.replace(day=1).timestamp(),
            "all": 0.0}


def save_rate_limit(store, info: Any) -> None:
    kind = str(getattr(info, "rate_limit_type", None) or "unknown")
    store.kv_set(RATE_KEY + kind, json.dumps({
        "status": getattr(info, "status", None), "utilization": getattr(info, "utilization", None),
        "resets_at": getattr(info, "resets_at", None), "seen": time.time()}))


def rate_limits(store) -> list[dict]:
    out = []
    for kind in list(RATE_TITLES) + ["unknown"]:
        raw = store.kv_get(RATE_KEY + kind)
        if not raw:
            continue
        try:
            v = json.loads(raw)
        except ValueError:
            continue
        # Окно уже сбросилось — старая цифра только путает.
        if v.get("resets_at") and v["resets_at"] < time.time():
            continue
        out.append({"window": kind, "title": RATE_TITLES.get(kind, kind), **v})
    return out


def summary(store, tz: str = "Europe/Moscow", now: float | None = None) -> dict:
    now = now or time.time()
    periods = {k: store.usage_since(ts) for k, ts in _starts(tz, now).items()}
    return {"periods": periods, "limits": rate_limits(store), "tz": tz,
            "note": "только чат и аудит хаба; claude.ai через коннектор сюда не входит"}


def human(n: int | float) -> str:
    n = int(n or 0)
    if n >= 1_000_000:
        return f"{n / 1_000_000:.1f} млн".replace(".0 ", " ")
    if n >= 1_000:
        return f"{n / 1_000:.0f} тыс"
    return str(n)


TITLES = {"today": "Сегодня", "week": "7 дней", "month": "Этот месяц", "all": "Всего"}


def lines(sm: dict) -> list[str]:
    out = []
    for k, title in TITLES.items():
        p = sm["periods"][k]
        out.append(f"{title:<11} {human(p['tokens']):>9} токенов · ответов {p['answers']:<4} "
                   f"· вход {human(p['input'])}, выход {human(p['output'])}, кэш {human(p['cache_read'] + p['cache_write'])}"
                   f" · ≈ ${p['cost_usd']:.2f}")
    month = sm["periods"]["month"]["by_model"]
    if month:
        out.append("По моделям за месяц: " + "; ".join(
            f"{m} {human(v['input'] + v['output'] + v['cache_read'] + v['cache_write'])}"
            for m, v in sorted(month.items(), key=lambda kv: -kv[1]["output"])))
    for lim in sm["limits"]:
        used = f"{round(lim['utilization'] * 100)}%" if lim.get("utilization") is not None else "?"
        when = datetime.fromtimestamp(lim["resets_at"]).strftime("%d.%m %H:%M") if lim.get("resets_at") else ""
        out.append(f"Лимит подписки ({lim['title']}): израсходовано {used}" + (f", сброс {when}" if when else ""))
    if not sm["limits"]:
        out.append("Лимит подписки: Claude ещё не сообщал (сообщает, когда подходит к краю)")
    out.append("$ — условная цена по тарифу API; на подписке Pro деньги не списываются")
    return out


def main(argv: list[str]) -> int:
    from nexus_chat.config import ChatSettings
    from nexus_chat.store import Store

    s = ChatSettings()
    if not s.db_path.exists():
        print("чат ещё не запускался — считать нечего")
        return 0
    sm = summary(Store(s.db_path), s.tz)
    if "--short" in argv:
        per = sm["periods"]
        line = (f"сегодня {human(per['today']['tokens'])} · 7 дней {human(per['week']['tokens'])} · "
                f"месяц {human(per['month']['tokens'])}")
        for lim in sm["limits"]:
            if lim.get("utilization") is not None:
                line += f" · лимит {lim['title']} {round(lim['utilization'] * 100)}%"
        print(line)
        return 0
    if "--json" in argv:
        print(json.dumps(sm, ensure_ascii=False))
    else:
        print("\n".join(lines(sm)))
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
