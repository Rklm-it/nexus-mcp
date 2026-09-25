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
    nexus-mcp-panels add shop2 https://p2.example.com <VPN_ADMIN_TOKEN> [--basic user:pass]
    nexus-mcp-panels remove shop2
"""

from __future__ import annotations

import json
import os
import re
import sys
from pathlib import Path

from nexus_mcp import config

NAME_RE = re.compile(r"^[a-z0-9][a-z0-9_-]{0,31}$")


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
    if s.brain_url and s.brain_admin_token and not any(p["name"] == "main" for p in panels):
        panels.insert(0, {"name": "main", "url": s.brain_url, "token": s.brain_admin_token,
                          "basic_auth": s.brain_basic_auth})
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
    return {"name": p["name"], "url": p["url"], "basic_auth": bool(p.get("basic_auth"))}


# ── Команда управления ─────────────────────────────────────────────────────

def _write(panels: list[dict]) -> None:
    path = _file()
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp = path.with_suffix(".tmp")
    fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(fd, "w", encoding="utf-8") as f:
        json.dump({"panels": panels}, f, ensure_ascii=False, indent=2)
    os.replace(tmp, path)


def add(name: str, url: str, token: str, basic_auth: str = "") -> dict:
    if not NAME_RE.match(name):
        raise PanelConfigError("имя: латиница в нижнем регистре, цифры, - и _, до 32 символов")
    if not re.match(r"^https?://[A-Za-z0-9.\-]+(:\d+)?(/[A-Za-z0-9._~/\-]*)?$", url.rstrip("/")):
        raise PanelConfigError(f"«{url}» — не адрес панели (https://домен[/vip])")
    if not token:
        raise PanelConfigError("нужен токен панели (VPN_ADMIN_TOKEN из её .env)")
    panels = [p for p in _read_file() if p["name"] != name]
    entry = {"name": name, "url": url.rstrip("/"), "token": token}
    if basic_auth:
        entry["basic_auth"] = basic_auth
    panels.append(entry)
    _write(panels)
    return public_view(entry)


def remove(name: str) -> bool:
    panels = _read_file()
    kept = [p for p in panels if p["name"] != name]
    if len(kept) == len(panels):
        return False
    _write(kept)
    return True


def main(argv: list[str] | None = None) -> int:
    import argparse

    ap = argparse.ArgumentParser(prog="nexus-mcp-panels", description="Панели хаба Nexus MCP")
    sub = ap.add_subparsers(dest="cmd", required=True)
    sub.add_parser("list")
    a = sub.add_parser("add")
    a.add_argument("name")
    a.add_argument("url")
    a.add_argument("token")
    a.add_argument("--basic", default="", help="user:pass, если /api панели за basic_auth")
    r = sub.add_parser("remove")
    r.add_argument("name")
    args = ap.parse_args(argv)
    try:
        if args.cmd == "list":
            for p in all_panels():
                v = public_view(p)
                print(f"{v['name']:<16} {v['url']}{'  (basic_auth)' if v['basic_auth'] else ''}")
        elif args.cmd == "add":
            v = add(args.name, args.url, args.token, args.basic)
            print(f"добавлена {v['name']} → {v['url']} (хаб подхватит сразу)")
        elif args.cmd == "remove":
            if not remove(args.name):
                print(f"панели «{args.name}» в файле нет", file=sys.stderr)
                return 1
            print(f"удалена {args.name}")
    except PanelConfigError as e:
        print(f"ошибка: {e}", file=sys.stderr)
        return 2
    return 0


if __name__ == "__main__":
    sys.exit(main())
