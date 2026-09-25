"""Реле нода → хаб → панель для нод, до которых путь к панели режется.

Панель стоит в РФ, ноды за границей, и связка «сеть хостера ноды → IP панели»
режется выборочно: `ger41s2` доходит, `eng41s2` — нет (TLS висит до таймаута),
при этом хаб доходит до обеих сторон. Нода, не достающая до панели, остаётся
красной, не получает новых юзеров и не обновляется (скрипт обновления качается
с панели). Реле — Caddy хаба: `https://<хаб>/relay/<панель>/…` → панель.

Через реле идут ТОЛЬКО пути агента (RELAY_PATHS): heartbeat и обратный канал
(`/api/v1/agent/*`, в т.ч. WebSocket), отчёт о трафике и `/install/*`
(скрипт и тарбол обновления). Всё остальное под `/relay/` падает в общий
обработчик хаба и получает 404. Эти пути у панели и так открыты наружу (их
защищает токен агента), реле не открывает ничего нового — только другую дорогу.

Маршруты собираются из списка панелей хаба в отдельный файл, который Caddyfile
хаба импортирует: `nexus-mcp-panels add/remove` пересобирает его сам.

Безопасность при нескольких панелях на хабе (проверено прогоном на Caddy):
- у каждой панели свой префикс и свой upstream — запрос к /relay/A уходит
  только в панель A; чужого префикса нет — 404 хаба;
- через реле доступны только пути агента, которые у панели и так открыты в
  интернет и защищены токеном агента своей панели; админка — 404;
- обход путей (`..`, %2e, %2f) отбивается: Caddy нормализует путь до проверки,
  маршрут вдобавок запрещает эти последовательности явно;
- секретов панелей (токен, gate, basic_auth) в маршрутах нет, cookie клиента
  срезаются.
"""

from __future__ import annotations

import os
import re
import subprocess
import sys
from pathlib import Path
from urllib.parse import urlparse

from nexus_mcp import config, panels

# /health — публичный у панели; без него разбор ноды на реле видел 404 от
# хаба и писал «нода не достаёт до панели» при живом heartbeat.
RELAY_PATHS = ("/api/v1/agent/*", "/api/v1/traffic/report", "/install/*", "/health")
SNIPPET = Path(os.environ.get("NEXUS_RELAY_CADDY", "/etc/caddy-nexus-mcp/relay.caddy"))
CADDYFILE = Path("/etc/caddy-nexus-mcp/Caddyfile")
_NAME = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_-]{0,31}$")


class RelayError(Exception):
    pass


def hub_url() -> str:
    """Публичный адрес хаба — тот, по которому до него доходят ноды."""
    s = config.settings
    host = (s.public_hosts or [""])[0]
    if not host:
        raise RelayError("у хаба нет публичного адреса (NEXUS_MCP_PUBLIC_HOSTS): реле без Caddy хаба не работает")
    port = os.environ.get("NEXUS_MCP_PUBLIC_PORT", "").strip() or "443"
    return f"https://{host}" + ("" if port == "443" else f":{port}")


def relay_url(panel_name: str) -> str:
    if not _NAME.match(panel_name or ""):
        raise RelayError(f"имя панели «{panel_name}» не годится для реле")
    return f"{hub_url()}/relay/{panel_name}"


def _block(p: dict) -> str:
    u = urlparse(p["url"])
    if u.scheme not in ("http", "https") or not u.hostname:
        raise RelayError(f"панель {p['name']}: адрес {p['url']} не разобрался")
    name = p["name"]
    prefix = f"/relay/{name}"
    upstream = f"{u.scheme}://{u.hostname}" + (f":{u.port}" if u.port else "")
    host = u.hostname + (f":{u.port}" if u.port else "")
    matcher = " ".join(prefix + path for path in RELAY_PATHS)
    lines = [
        f"# панель {name} → {p['url']}",
        f"@relay_{name} {{",
        f"    path {matcher}",
        # Обход путей (`..`, закодированные точка и слэш) Caddy и так
        # нормализует до проверки — это страховка на случай, если перестанет.
        "    not path_regexp (?i)(\\.\\.|%2e|%2f|%5c)",
        "}",
        f"handle @relay_{name} {{",
    ]
    base_path = (u.path or "").rstrip("/")
    if base_path:
        # Панель под путём (VIP-контур: https://домен/vip): префикс реле
        # заменить её путём ОДНОЙ директивой. Пара `uri strip_prefix` +
        # `rewrite` не годится: Caddy выполняет rewrite раньше uri, как их ни
        # пиши, — выходило /vip/relay/vip/… (поймано прогоном на Caddy 2.10).
        lines.append(f"    uri path_regexp ^{re.escape(prefix)} {base_path}")
    else:
        lines.append(f"    uri strip_prefix {prefix}")
    lines += [
        f"    reverse_proxy {upstream} {{",
        f"        header_up Host {host}",
        "        header_up X-Nexus-Relay hub",
        # Cookie ноды панели не нужны, а gate панели реле НЕ добавляет:
        # пути агента у панели и так мимо basic_auth, а секрет в публичном
        # маршруте был бы обходом пароля для всех, кто знает адрес хаба.
        "        header_up -Cookie",
    ]
    lines += [
        "        flush_interval -1",
        "    }",
        "}",
    ]
    return "\n".join(lines)


def caddy_snippet(items: list[dict] | None = None) -> str:
    """Маршруты реле для всех панелей хаба — кусок сайта в Caddyfile."""
    blocks = ["# Сгенерировано nexus_mcp.relay — не править руками: nexus-mcp-panels пересоберёт."]
    for p in items if items is not None else panels.all_panels():
        # Прежние имена (после rename) — те же маршруты: ноды на /relay/<старое>
        # не теряют связь с панелью.
        for name in [p.get("name", "")] + list(p.get("aliases") or []):
            if not _NAME.match(name):
                blocks.append(f"# пропущено имя «{name}»: не годится для пути")
                continue
            blocks.append(_block({**p, "name": name}))
    return "\n\n".join(blocks) + "\n"


def write_snippet(path: Path = SNIPPET) -> bool:
    """Записать маршруты; True — файл изменился и Caddy надо перечитать."""
    text = caddy_snippet()
    if path.exists() and path.read_text(encoding="utf-8") == text:
        return False
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp = path.with_suffix(".tmp")
    fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(fd, "w", encoding="utf-8") as f:
        f.write(text)
    os.replace(tmp, path)
    return True


def reload_caddy() -> str:
    """Перечитать Caddy хаба. Нет Caddy (установка --no-caddy) — не ошибка."""
    if not CADDYFILE.exists():
        return "Caddy хаба не установлен — реле нужно настроить в своём прокси"
    try:
        r = subprocess.run(["caddy", "reload", "--config", str(CADDYFILE), "--adapter", "caddyfile"],
                           capture_output=True, text=True, timeout=30)
    except (OSError, subprocess.TimeoutExpired) as e:
        return f"caddy reload не прошёл: {e}"
    if r.returncode != 0:
        subprocess.run(["systemctl", "restart", "nexus-mcp-caddy"], timeout=60)
        return "caddy reload отказал — Caddy хаба перезапущен"
    return "маршруты реле обновлены"


def refresh() -> str:
    try:
        changed = write_snippet()
    except (RelayError, panels.PanelConfigError, OSError) as e:
        return f"реле не пересобрано: {e}"
    return reload_caddy() if changed else "маршруты реле не изменились"


def main(argv: list[str] | None = None) -> int:
    args = argv if argv is not None else sys.argv[1:]
    if args[:1] == ["caddy"]:
        # Установщик: только записать файл — Caddy он поднимет сам.
        if "--no-reload" in args:
            write_snippet()
            print(f"маршруты реле: {SNIPPET}")
        else:
            print(refresh())
        return 0
    if args[:1] == ["url"] and len(args) == 2:
        print(relay_url(args[1]))
        return 0
    print("использование: python -m nexus_mcp.relay caddy [--no-reload] | url <панель>", file=sys.stderr)
    return 2


if __name__ == "__main__":
    sys.exit(main())
