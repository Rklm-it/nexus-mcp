"""Тестовая подписка панели для проверки из дома — заводит сам хаб.

Прогону подписки (sweep.py) нужна подписка юзера, привязанного ко всем
нодам панели. Раньше её ссылку владелец вписывал руками
(`nexus-mcp-panels sub`) для каждой панели. Теперь хаб заводит в панели
служебного юзера `nexus-probe` сам, через её админ-API:

  POST /api/v1/users {username: nexus-probe}  — без срока и лимита трафика;
      панель сама привязывает нового юзера ко всем активным нодам
      (кроме бесплатной ноды «для истёкших»);
  PATCH /api/v1/admin/users/{id}/comment       — пометка «служебный, не удалять»;
  POST /api/v1/users/{id}/assign-servers       — перед каждым прогоном: досыпать
      ноды, появившиеся после заведения (только добавляет, ничего не снимает).

Ссылка подписки и id юзера остаются в panels.json хаба (0600): в модель и в
приложение токен не отдаётся — в ответах только «есть / нет» и маска.

Заведение юзера — изменение панели, поэтому инструмент без confirm только
показывает план, а с confirm в чате ждёт кнопки «Разрешить» (runner.py).
В приложении кнопка «Завести» сама и есть согласие человека.
"""

from __future__ import annotations

import datetime as _dt

from nexus_mcp import links, panels
from nexus_mcp import panel as panel_api

USERNAME = "nexus-probe"
COMMENT = ("Служебный: подписка для проверки нод из дома (хаб nexus-mcp, пробник на роутере). "
           "Не блокировать и не удалять — удалённого хаб заведёт заново.")


class ProbeSubError(Exception):
    pass


def _mask_url(url: str) -> str:
    return panel_api.redact(url) if url else ""


def _all(panel_name: str) -> list[dict]:
    try:
        return [panels.resolve(panel_name)] if panel_name else panels.all_panels()
    except panels.PanelConfigError as e:
        raise ProbeSubError(str(e)) from e


def listing() -> list[dict]:
    """По каждой панели: есть ли подписка для проверки и откуда она."""
    from nexus_mcp import config

    out = []
    for p in _all(""):
        url = p.get("sub_url") or ""
        source = "auto" if p.get("sub_user_id") else ("manual" if url else "")
        if not url and config.settings.test_sub_url and len(panels.all_panels()) == 1:
            url, source = config.settings.test_sub_url, "env"
        out.append({"panel": p["name"], "has_sub": bool(url), "source": source, "sub": _mask_url(url)})
    return out


async def _find_user(name: str) -> dict | None:
    """Служебный юзер, если он уже есть (завели раньше или вручную)."""
    data = await panel_api.request("GET", "/api/v1/admin/users", {"search": USERNAME, "limit": 20},
                                   panel_name=name, raw=True)
    items = (data or {}).get("items") if isinstance(data, dict) else None
    for u in items or []:
        if u.get("username") == USERNAME:
            return u
    return None


async def _get_user(name: str, user_id: str) -> dict | None:
    try:
        return await panel_api.request("GET", f"/api/v1/users/{user_id}", panel_name=name, raw=True)
    except panel_api.PanelError as e:
        if e.status == 404:
            return None
        raise


def _problems(u: dict) -> list[str]:
    """Почему юзер не годится для проверки — снимать блок сами не будем:
    его мог поставить человек."""
    out = []
    if u.get("is_blocked"):
        out.append("юзер nexus-probe заблокирован в панели")
    if u.get("is_active") is False:
        out.append("юзер nexus-probe выключен в панели")
    exp = u.get("expire_at")
    if exp:
        try:
            when = _dt.datetime.fromisoformat(str(exp).replace("Z", "+00:00")).replace(tzinfo=None)
            if when < _dt.datetime.utcnow():
                out.append(f"у юзера nexus-probe истёк срок ({exp})")
        except ValueError:
            pass
    return out


async def plan(panel_name: str = "") -> dict:
    """Что будет сделано — без изменений в панелях."""
    steps = []
    for p in _all(panel_name):
        name = p["name"]
        try:
            u = None
            if p.get("sub_user_id"):
                u = await _get_user(name, p["sub_user_id"])
            u = u or await _find_user(name)
        except panel_api.PanelError as e:
            steps.append({"panel": name, "action": "error", "detail": str(e)[:300]})
            continue
        if u:
            steps.append({"panel": name, "action": "reuse",
                          "detail": "юзер nexus-probe уже есть — привязать к новым нодам и запомнить подписку",
                          "problems": _problems(u)})
        else:
            steps.append({"panel": name, "action": "create",
                          "detail": "завести юзера nexus-probe: без срока и лимита трафика, на всех активных "
                                    "нодах; служебная пометка в комментарии"})
    return {"ok": True, "confirm_needed": True, "steps": steps,
            "note": "Юзер займёт по одному месту на каждой ноде и виден в списке людей панели. "
                    "Подписка остаётся на хабе и в ответы не попадает."}


async def ensure(panel_name: str) -> dict:
    """Завести (или найти) служебного юзера, привязать ко всем нодам, запомнить
    подписку. По панели — итог или причина отказа; одна панель не мешает другим."""
    results = []
    for p in _all(panel_name):
        results.append(await _ensure_one(p))
    return {"ok": all(r["ok"] for r in results), "panels": results}


async def _ensure_one(p: dict) -> dict:
    name = p["name"]
    created = False
    try:
        u = await _get_user(name, p["sub_user_id"]) if p.get("sub_user_id") else None
        u = u or await _find_user(name)
        if u is None:
            u = await panel_api.request("POST", "/api/v1/users", body={"username": USERNAME},
                                        panel_name=name, raw=True, timeout=60)
            created = True
            try:
                await panel_api.request("PATCH", f"/api/v1/admin/users/{u['id']}/comment",
                                        body={"comment": COMMENT}, panel_name=name, raw=True)
            except panel_api.PanelError:
                pass  # пометка — удобство, не повод отказать
        uid = str(u.get("id") or "")
        token = u.get("sub_token") or ""
        if not token and uid:
            token = ((await _get_user(name, uid)) or {}).get("sub_token") or ""
        if not uid or not token:
            return {"panel": name, "ok": False, "detail": "панель не вернула id или токен подписки юзера"}
        assigned = await refresh_nodes(p, uid)
    except panel_api.PanelError as e:
        return {"panel": name, "ok": False, "detail": str(e)[:300]}

    url = f"{p['url'].rstrip('/')}/api/v1/sub/{token}"
    try:
        panels.set_sub(name, url, user_id=uid)
    except panels.PanelConfigError as e:
        return {"panel": name, "ok": False, "detail": f"подписку не записать на хабе: {e}"}
    out = {"panel": name, "ok": True, "created": created, "user_id": uid, "sub": _mask_url(url),
           "nodes": assigned}
    problems = _problems(u)
    if problems:
        out["ok"] = False
        out["detail"] = "; ".join(problems) + " — включите его в панели, иначе подписка пустая"
    # Сразу проверить, что подписка отдаёт строки: новый юзер уезжает на ноды
    # в фоне (5–15 с), а пустая подписка без объяснения выглядела бы поломкой.
    try:
        out["links"] = len(await links.fetch_links(url))
    except links.LinksError as e:
        out["links"] = 0
        out["links_note"] = (f"{e} — если юзера только что завели, ноды получают его в фоне: "
                             "повторите проверку через минуту")
    return out


async def refresh_nodes(p: dict, user_id: str) -> dict:
    """Досыпать юзеру ноды, появившиеся после заведения (только добавляет)."""
    r = await panel_api.request("POST", f"/api/v1/users/{user_id}/assign-servers",
                                panel_name=p["name"], raw=True, timeout=120)
    return {k: r.get(k) for k in ("assigned", "total", "available")} if isinstance(r, dict) else {}


async def refresh_all(panel_name: str = "") -> list[str]:
    """Перед прогоном: новые ноды — в подписки, заведённые хабом. Отказ —
    заметка в итоге прогона, не повод его не делать."""
    notes = []
    try:
        targets = _all(panel_name)
    except ProbeSubError as e:
        return [str(e)]
    for p in targets:
        if not p.get("sub_user_id"):
            continue
        try:
            r = await refresh_nodes(p, p["sub_user_id"])
            if r.get("assigned"):
                notes.append(f"{p['name']}: тестовому юзеру добавлено нод: {r['assigned']} — на них он "
                             "уезжает в фоне, их строки могут появиться со следующего прогона")
        except panel_api.PanelError as e:
            notes.append(f"{p['name']}: новые ноды к тестовому юзеру не добавлены: {str(e)[:160]}")
    return notes
