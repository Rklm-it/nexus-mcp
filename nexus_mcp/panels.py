"""Несколько панелей на одном хабе.

Панели живут в `/etc/nexus-mcp/panels.json` (0600):

    {"panels": [
      {"name": "main", "url": "https://panel.example.ru", "token": "…"},
      {"name": "vip",  "url": "https://panel.example.ru/vip", "token": "…"},
      {"name": "shop2", "url": "https://p2.example.com", "token": "…", "basic_auth": "u:p"}
    ]}

Старая настройка одной панелью (`NEXUS_BRAIN_URL` + `NEXUS_BRAIN_ADMIN_TOKEN`)
работает как раньше: она становится панелью `main`, если в файле такой нет.

Управление — командой на хабе, чтобы токены не набирать в JSON руками:
    nexus-mcp-panels list
    nexus-mcp-panels add shop2 https://p2.example.com <VPN_ADMIN_TOKEN> --gate <VPN_PANEL_GATE_SECRET>
    nexus-mcp-panels remove shop2
"""

from __future__ import annotations

import json
import os
import re
import sys
from pathlib import Path

from nexus_mcp import config

# Заглавные можно (JonyX-VPS): имя уходит в путь реле /relay/<имя>, а путь
# в Caddy сопоставляется без учёта регистра — поэтому имена, различающиеся
# только регистром, запрещены (add/rename это проверяют).
NAME_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_-]{0,31}$")


class PanelConfigError(Exception):
    pass


def _file() -> Path:
    return config.settings.panels_file


def _read_file() -> list[dict]:
    path = _file()
    if not path.exists():
        return []
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, ValueError) as e:
        raise PanelConfigError(f"не читается {path}: {e}") from e
    return [p for p in data.get("panels", []) if p.get("name") and p.get("url")]


def all_panels() -> list[dict]:
    """Все панели: из файла + старая одиночная из окружения (как `main`)."""
    panels = _read_file()
    s = config.settings
    # Панель из установки (окружение) — «main», пока её не переименовали:
    # rename переносит её в файл под новым именем с тем же адресом, и тогда
    # запись из окружения больше не подставляется.
    env_url = (s.brain_url or "").rstrip("/")
    if s.brain_url and s.brain_admin_token and not any(
            p["name"] == "main" or p["url"].rstrip("/") == env_url for p in panels):
        panels.insert(0, {"name": "main", "url": s.brain_url, "token": s.brain_admin_token,
                          "gate": s.brain_gate, "basic_auth": s.brain_basic_auth})
    for p in panels:
        p["url"] = p["url"].rstrip("/")
    return panels


def resolve(name: str = "") -> dict:
    """Панель по имени. Пустое имя — единственная панель; если их несколько,
    это отказ со списком: молча выбрать «первую» значит смотреть не туда."""
    panels = all_panels()
    if not panels:
        raise PanelConfigError("панель не настроена: nexus-mcp-panels add <имя> <url> <токен> "
                               "(или NEXUS_BRAIN_URL / NEXUS_BRAIN_ADMIN_TOKEN)")
    names = [p["name"] for p in panels]
    if not name:
        if len(panels) == 1:
            return panels[0]
        raise PanelConfigError(f"панелей несколько — укажите panel: {', '.join(names)}")
    for p in panels:
        if p["name"] == name:
            return p
    raise PanelConfigError(f"панели «{name}» нет. Есть: {', '.join(names)}")


def public_view(p: dict) -> dict:
    """Для вывода: без токена и пароля."""
    return {"name": p["name"], "url": p["url"], "gate": bool(p.get("gate")),
            "basic_auth": bool(p.get("basic_auth")), "aliases": list(p.get("aliases") or [])}


# ── Команда управления ─────────────────────────────────────────────────────

def _write(panels: list[dict]) -> None:
    path = _file()
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp = path.with_suffix(".tmp")
    fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(fd, "w", encoding="utf-8") as f:
        json.dump({"panels": panels}, f, ensure_ascii=False, indent=2)
    os.replace(tmp, path)


def add(name: str, url: str, token: str, basic_auth: str = "", gate: str = "") -> dict:
    if not NAME_RE.match(name):
        raise PanelConfigError("имя: латиница в нижнем регистре, цифры, - и _, до 32 символов")
    if not re.match(r"^https?://[A-Za-z0-9.\-]+(:\d+)?(/[A-Za-z0-9._~/\-]*)?$", url.rstrip("/")):
        raise PanelConfigError(f"«{url}» — не адрес панели (https://домен[/vip])")
    if not token:
        raise PanelConfigError("нужен токен панели (VPN_ADMIN_TOKEN из её .env)")
    busy = _taken(name, all_panels(), but=name)
    if busy:
        raise PanelConfigError(f"имя «{name}» уже занято: {busy} (регистр букв не различается)")
    panels = [p for p in _read_file() if p["name"] != name]
    entry = {"name": name, "url": url.rstrip("/"), "token": token}
    if gate:
        entry["gate"] = gate
    if basic_auth:
        entry["basic_auth"] = basic_auth
    panels.append(entry)
    _write(panels)
    return public_view(entry)


def _taken(name: str, panels: list[dict], but: str = "") -> str | None:
    for p in panels:
        if p["name"].lower() == name.lower() and p["name"] != but:
            return p["name"]
        if any(a.lower() == name.lower() for a in p.get("aliases", [])) and p["name"] != but:
            return f"{p['name']} (прежнее имя)"
    return None


def rename(old: str, new: str) -> dict:
    """Переименовать панель. Старое имя остаётся псевдонимом реле: ноды,
    которые ходят к панели через /relay/<старое>, не теряют связь."""
    if not NAME_RE.match(new):
        raise PanelConfigError("новое имя: латиница, цифры, - и _, до 32 символов, с буквы или цифры")
    everything = all_panels()
    src = next((p for p in everything if p["name"] == old), None)
    if src is None:
        raise PanelConfigError(f"панели «{old}» нет. Есть: {', '.join(p['name'] for p in everything)}")
    busy = _taken(new, everything, but=old)
    if busy:
        raise PanelConfigError(f"имя «{new}» уже занято: {busy} (регистр букв не различается)")
    file_panels = [p for p in _read_file() if p["name"] != old]
    entry = {k: v for k, v in src.items() if k in ("url", "token", "gate", "basic_auth", "aliases") and v}
    entry["name"] = new
    aliases = [a for a in entry.get("aliases", []) if a.lower() != new.lower()]
    if old.lower() != new.lower() and old not in aliases:
        aliases.append(old)
    entry["aliases"] = aliases
    file_panels.append(entry)
    _write(file_panels)
    return public_view(entry)


def remove(name: str) -> bool:
    panels = _read_file()
    kept = [p for p in panels if p["name"] != name]
    if len(kept) == len(panels):
        return False
    _write(kept)
    return True


def _refresh_relay() -> None:
    """У каждой панели хаба — свой маршрут реле (nexus_mcp.relay)."""
    from nexus_mcp import relay

    print(relay.refresh())


def main(argv: list[str] | None = None) -> int:
    import argparse

    ap = argparse.ArgumentParser(prog="nexus-mcp-panels", description="Панели хаба Nexus MCP")
    sub = ap.add_subparsers(dest="cmd", required=True)
    sub.add_parser("list")
    a = sub.add_parser("add")
    a.add_argument("name")
    a.add_argument("url")
    a.add_argument("token")
    a.add_argument("--gate", default="", help="VPN_PANEL_GATE_SECRET из .env панели (проход мимо basic_auth)")
    a.add_argument("--basic", default="", help="user:pass, если /api панели за basic_auth, а gate не задан")
    r = sub.add_parser("remove")
    r.add_argument("name")
    rn = sub.add_parser("rename", help="переименовать; старое имя остаётся адресом реле")
    rn.add_argument("old")
    rn.add_argument("new")
    args = ap.parse_args(argv)
    try:
        if args.cmd == "list":
            for p in all_panels():
                v = public_view(p)
                how = "gate" if v["gate"] else ("basic_auth" if v["basic_auth"] else "")
                al = f"  прежние имена: {', '.join(v['aliases'])}" if v["aliases"] else ""
                print(f"{v['name']:<16} {v['url']}{f'  ({how})' if how else ''}{al}")
        elif args.cmd == "add":
            v = add(args.name, args.url, args.token, args.basic, args.gate)
            print(f"добавлена {v['name']} → {v['url']} (хаб подхватит сразу)")
            _refresh_relay()
        elif args.cmd == "rename":
            v = rename(args.old, args.new)
            print(f"переименована: {args.old} → {v['name']} (ноды на реле /relay/{args.old} связь не теряют)")
            _refresh_relay()
        elif args.cmd == "remove":
            gone = next((p for p in _read_file() if p["name"] == args.name), None)
            if not remove(args.name):
                print(f"панели «{args.name}» в файле нет", file=sys.stderr)
                return 1
            print(f"удалена {args.name}")
            env_url = (config.settings.brain_url or "").rstrip("/")
            if gone and env_url and gone["url"].rstrip("/") == env_url:
                print("⚠ это панель из установки: без записи в файле она вернётся под именем main — "
                      "чтобы убрать совсем, сотрите NEXUS_BRAIN_URL в /etc/nexus-mcp.env", file=sys.stderr)
            _refresh_relay()
    except PanelConfigError as e:
        print(f"ошибка: {e}", file=sys.stderr)
        return 2
    return 0


if __name__ == "__main__":
    sys.exit(main())
