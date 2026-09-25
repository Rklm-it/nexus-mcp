"""Данные для меню хаба (bin/nexus-hub): то, что проще взять кодом хаба.

Печатает готовые строки для экрана, секретов не выводит. Любой отказ — одной
строкой с причиной (инвариант 26 vgx3d), код выхода 0: меню не должно
падать из-за того, что панель или bschekbot сейчас не отвечают.
"""

from __future__ import annotations

import asyncio
import sys

from nexus_mcp import bsbord, inventory, panels


def _sim() -> None:
    if not bsbord.enabled():
        print("ключ не задан")
        return
    try:
        a = asyncio.run(bsbord.account())
    except Exception as e:  # noqa: BLE001
        print(f"не отвечает: {str(e)[:120]}")
        return
    print(f"баланс {a['balance_rub']:.2f} ₽ · сегодня {a['spent_today_rub'] or 0:.2f} из {a['daily_cap_rub'] or 0:.0f} ₽")


def _nodes() -> None:
    try:
        nodes, warnings = asyncio.run(inventory.load_nodes())
    except Exception as e:  # noqa: BLE001
        print(f"  ✗ ноды не получены: {str(e)[:200]}")
        return
    for n in nodes:
        hb = n.get("heartbeat_age_s")
        ok = n.get("panel_online") or (hb is not None and hb < 120)
        dot = "\033[32m●\033[0m" if ok else "\033[31m●\033[0m"
        hbs = f"heartbeat {int(hb)} с" if hb is not None else "без heartbeat"
        print(f"  {dot} {n['name']:<26} {str(n.get('ip') or ''):<16} {str(n.get('country') or ''):<3} "
              f"агент {n.get('agent_version') or '?':<9} {hbs}")
    for w in warnings:
        print(f"  ! {w}")


def _edits() -> None:
    """Правки конфигурации нод (node_edit): что, где, откатывается ли."""
    from nexus_mcp import node_edit

    items = node_edit.history(20)
    if not items:
        print("  правок ещё не было")
        return
    for e in items:
        state = ("\033[31m✗\033[0m " + str(e["error"])[:80]) if e["error"] else "\033[32m✓\033[0m"
        tail = " · откачена " + e["rolled_back"] if e["rolled_back"] else (
            " · можно откатить" if e["can_rollback"] else "")
        print(f"  {e['ts']}  {e['edit']}  {e['node']:<22} {e['op']:<15} {state}{tail}")
    print("\n  Откат — попросите Claude в чате: «откати правку <id>»")


def _panel_check(url: str, token: str, gate: str) -> None:
    """Панель отвечает админ-токеном? Перед записью в хаб."""
    import httpx

    headers = {"X-Admin-Token": token}
    cookies = {"nexus_gate": gate} if gate else None
    try:
        r = httpx.get(url.rstrip("/") + "/api/v1/admin/dashboard", headers=headers, cookies=cookies,
                      timeout=20, follow_redirects=False)
    except httpx.HTTPError as e:
        print(f"✗ панель не отвечает: {e}")
        return
    if r.status_code == 200:
        print("✓ панель отвечает, токен принят")
    elif r.status_code in (401, 403):
        why = "basic_auth Caddy — нужен --gate (VPN_PANEL_GATE_SECRET)" if "<" in r.text[:50] \
            else "токен не принят"
        print(f"✗ HTTP {r.status_code}: {why}")
    else:
        print(f"✗ HTTP {r.status_code}: {r.text[:150]}")


def main(argv: list[str]) -> int:
    cmd = argv[0] if argv else ""
    if cmd == "sim":
        _sim()
    elif cmd == "nodes":
        _nodes()
    elif cmd == "edits":
        _edits()
    elif cmd == "panels-count":
        try:
            print(len(panels.all_panels()))
        except Exception:  # noqa: BLE001
            print("?")
    elif cmd == "panel-check" and len(argv) >= 3:
        _panel_check(argv[1], argv[2], argv[3] if len(argv) > 3 else "")
    else:
        print("команды: sim | nodes | edits | panels-count | panel-check <url> <token> [gate]", file=sys.stderr)
        return 2
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
