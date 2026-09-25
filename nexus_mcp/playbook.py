"""Что делать при каждом симптоме: собранное из разборов и чужого опыта.

Источники — наш журнал (docs/journal/) и ролики владельцев VPN-сервисов,
просмотренные 25.09.2026. У каждого приёма есть `evidence`, насколько ему
верить:
  • `ours`      — проверено у нас (журнал);
  • `measured`  — автор показал замер;
  • `repeated`  — независимо говорят двое и больше;
  • `anecdote`  — один случай, «у меня заработало»; пробовать, но не обещать.

Авторы роликов противоречат друг другу (TLS против Reality), потому что у
~7000 операторов связи в РФ разные ТСПУ. Отсюда главное правило: не искать
универсальную настройку, а держать в подписке несколько разных вариантов и
выбирать по сквозной проверке с домашних пробников.
"""

from __future__ import annotations

SOURCES = {
    "journal_monitoring": "docs/journal/MONITORING.md, разбор 22.09.2026 (payload к IP нод режется)",
    "journal_cf": "vgx3d docs/journal/CDN.md, «Cloudflare-фронт ноды одной кнопкой» 23.09.2026",
    "zepvpn": "https://www.youtube.com/watch?v=6RaxU9aXxZk — ZepVPN, 23.09.2026",
    "linkoffreedom_tls": "https://www.youtube.com/watch?v=BkWgtctzIE4 — LinkOfFreedom, 04.06.2026",
    "rfn_tspu": "https://www.youtube.com/watch?v=pPGPuPzCUDQ — RustForNew, 22.08.2026",
    "naive": "https://www.youtube.com/watch?v=vnTgnL1tskw — swrneko, 06.04.2026",
    "vmess_http": "https://www.youtube.com/watch?v=y80eCKUbuP8 — LinkOfFreedom, 23.08.2026",
    "remnawave_docker": "https://www.youtube.com/watch?v=sKVHWAkoYFo — Евгеньевич, 25.01.2026",
    "journal_relay": "vgx3d docs/journal/MONITORING.md, «Реле нода → хаб → панель» 25.09.2026",
    "owner_whitelist": "слово владельца сервиса, 25.09.2026 (vgx3d CLAUDE.md, инвариант 45; "
                       "docs/journal/CDN.md)",
}

# Симптомы, которые приносит человек, а не находка разбора ноды (их кода нет
# в diagnose.py — сторож в тестах это учитывает).
USER_SYMPTOMS = {"docker_pull_hangs", "whitelist_mobile"}

# Симптом (код находки из diagnose.py) → приёмы по порядку: сверху — первое,
# что пробовать.
PLAYBOOK: dict[str, list[dict]] = {
    "payload_filtered": [
        {"do": "Панель → нода → «Включить Cloudflare»: VLESS+WS+TLS через Cloudflare, клиент "
               "идёт на адрес Cloudflare, а не на IP ноды. Проверить строку «· CF» из дома "
               "(node_diagnose с домашними пробниками), потом — флаг «Только через CF».",
         "why": "Сделано в панели ровно под блок IP диапазонами хостера (21.09): IP ноды у клиента "
                "не встречается вовсе, смена IP — «Переприменить», ссылки не меняются.",
         "evidence": "ours", "src": ["journal_cf"],
         "note": "Через Cloudflare едет только WS (Reality/Hysteria2/SS — нет); Cloudflare в РФ "
                 "местами замедляют — решает проверка с домашних пробников; большой трафик — "
                 "риск по ToS. Кнопка идёт через агент: нода, до которой панель не достаёт, "
                 "сначала должна начать приходить к панели сама (heartbeat)."},
        {"do": "Поставить RU-вход перед нодой: клиент → российский VPS → эта нода (у нас это "
               "Outbound с relay_mode xray/iptables, свой порт на каждый выход).",
         "why": "Фильтр висит на пути к IP ноды; с другого IP дорога чистая. Оба автора видели: "
                "напрямую нода «даже не пингуется», через RU-вход — работает.",
         "evidence": "repeated", "src": ["zepvpn", "rfn_tspu"],
         "note": "Как вход советуют Datacheap («прокидывает куда угодно») и Serv.host (шире, но "
                 "блокируют быстрее). Вход тоже могут заблокировать — держать запасной."},
        {"do": "Сменить IP ноды у хостера (обычно дешевле новой VPS).",
         "why": "Блок по IP; новый IP — новая дорога.",
         "evidence": "repeated", "src": ["zepvpn", "rfn_tspu"],
         "note": "Меняет ip_address → разъезжается по подпискам всех юзеров ноды (инвариант 37)."},
        {"do": "Подождать: блокировки иногда снимаются сами.",
         "why": "Бывает; но это не план.", "evidence": "anecdote", "src": ["zepvpn"]},
        {"do": "НЕ перебирать настройки протокола.",
         "why": "Если с чистой сети не проходят TCP/SSH/TLS к IP, «смиритесь и меняйте VPS»: "
                "протокол тут ни при чём.", "evidence": "repeated", "src": ["rfn_tspu", "zepvpn"]},
    ],
    "ip_unreachable": [
        {"do": "Сравнить точки обзора: не открывается у всех (хаб, check-host, домашние) — нода "
               "или хостер (выключена, IP сменился); у одной сети — блок IP у провайдера → как "
               "payload_filtered.", "why": "Разные причины чинятся по-разному.",
         "evidence": "ours", "src": ["journal_monitoring"]},
        {"do": "Панель → нода → «Включить Cloudflare»: VLESS+WS+TLS через Cloudflare, клиент "
               "идёт на адрес Cloudflare, а не на IP ноды. Проверить строку «· CF» из дома "
               "(node_diagnose с домашними пробниками), потом — флаг «Только через CF».",
         "why": "Сделано в панели ровно под блок IP диапазонами хостера (21.09): IP ноды у клиента "
                "не встречается вовсе, смена IP — «Переприменить», ссылки не меняются.",
         "evidence": "ours", "src": ["journal_cf"],
         "note": "Через Cloudflare едет только WS (Reality/Hysteria2/SS — нет); Cloudflare в РФ "
                 "местами замедляют — решает проверка с домашних пробников; большой трафик — "
                 "риск по ToS. Кнопка идёт через агент: нода, до которой панель не достаёт, "
                 "сначала должна начать приходить к панели сама (heartbeat)."},
    ],
    "cf_front_off": [
        {"do": "Панель → нода → «Включить Cloudflare»: VLESS+WS+TLS через Cloudflare, клиент "
               "идёт на адрес Cloudflare, а не на IP ноды. Проверить строку «· CF» из дома "
               "(node_diagnose с домашними пробниками), потом — флаг «Только через CF».",
         "why": "Сделано в панели ровно под блок IP диапазонами хостера (21.09): IP ноды у клиента "
                "не встречается вовсе, смена IP — «Переприменить», ссылки не меняются.",
         "evidence": "ours", "src": ["journal_cf"],
         "note": "Через Cloudflare едет только WS (Reality/Hysteria2/SS — нет); Cloudflare в РФ "
                 "местами замедляют — решает проверка с домашних пробников; большой трафик — "
                 "риск по ToS. Кнопка идёт через агент: нода, до которой панель не достаёт, "
                 "сначала должна начать приходить к панели сама (heartbeat)."},
    ],
    "cf_blocked": [
        {"do": "Для сетей, где режут Cloudflare, держать в подписке другой путь: российский CDN "
               "(Яндекс, Timeweb — CDN-ноды панели) или RU-вход перед нодой.",
         "why": "Фронт прячет IP ноды, но не сам Cloudflare: если провайдер режет Cloudflare, "
                "строка «· CF» у него мертва.", "evidence": "ours", "src": ["journal_cf"],
         "note": "«Только через CF» для такой ноды не включать — клиенты этой сети останутся "
                 "без рабочей строки."},
    ],
    "some_protocols_dead": [
        {"do": "Сменить транспорт: TCP → XHTTP.", "why": "Режут связку протокол+транспорт, а не IP.",
         "evidence": "repeated", "src": ["zepvpn", "rfn_tspu"]},
        {"do": "Сменить uTLS fingerprint: chrome → firefox.", "why": "Режут по отпечатку ClientHello.",
         "evidence": "anecdote", "src": ["zepvpn"]},
        {"do": "Нестандартный порт (автор хвалит VLESS TCP на 12443).",
         "why": "Часть фильтров смотрит только на 443.", "evidence": "anecdote", "src": ["zepvpn"]},
        {"do": "Включить VLESS Encryption (mlkem768x25519) на инбаунде — у нас есть флаг "
               "vless_encryption, по умолчанию выключен.",
         "why": "Замер автора: без неё ~40 Мбит/с и пинг ~40 мс, с ней — упёрся в свой тариф 100 "
                "Мбит/с, пинг 1–10 мс: пропал троттлинг ТСПУ.",
         "evidence": "measured", "src": ["rfn_tspu"]},
        {"do": "Hysteria2 на порту 5443.", "why": "Автор так оживил три сервера и сам не знает почему.",
         "evidence": "anecdote", "src": ["zepvpn"]},
        {"do": "Reality → TLS со своим доменом (Let's Encrypt) и ALPN только http/1.1 (убрать h2).",
         "why": "У автора после этого ожил VLESS на домашнем OpenWrt и мобильном. Менял две вещи "
                "сразу — что помогло, неизвестно; объяснение «HTTP/1.1 не трогают из-за банков» — "
                "догадка. RustForNew видел ОБРАТНОЕ: TLS режется, Reality self-steal живёт.",
         "evidence": "anecdote", "src": ["linkoffreedom_tls", "rfn_tspu"],
         "note": "В ссылке обязательно alpn=http/1.1, иначе клиент падает с «http2: frame too "
                 "large» (docs/journal/CDN.md)."},
        {"do": "Reality self-steal: SNI — свой домен на этой же ноде, target 127.0.0.1:8443.",
         "why": "RustForNew: в их тестах обычный TLS резался, self-steal в тех же условиях работал.",
         "evidence": "anecdote", "src": ["rfn_tspu"]},
        {"do": "Кандидат на исследование: NaiveProxy (Caddy forwardproxy, стек Chromium).",
         "why": "Выглядит как настоящий браузер. xray его не умеет — отдельный сервер и клиенты.",
         "evidence": "anecdote", "src": ["naive"]},
        {"do": "Не брать: VMess + HTTPUpgrade на 80 порту без TLS.",
         "why": "Ставка на «на 80 не смотрят», один случай, трафик без TLS.",
         "evidence": "anecdote", "src": ["vmess_http"]},
    ],
    "all_protocols_dead": [
        {"do": "Сначала убедиться, что IP доступен (reach): если нет — это payload_filtered/"
               "ip_unreachable, а не протоколы.", "why": "«Не работает» ≠ «заблокирован».",
         "evidence": "repeated", "src": ["zepvpn"]},
        {"do": "IP доступен — идти по some_protocols_dead сверху вниз, проверяя каждый шаг "
               "сквозной проверкой с домашних пробников.", "why": "Универсальной настройки нет.",
         "evidence": "repeated", "src": ["rfn_tspu", "zepvpn"]},
    ],
    "old_agent": [
        {"do": "node_action(update_agent): агент с heartbeat и обратным каналом.",
         "why": "Панель на российском IP не дозванивается до нод; зелёной нода становится, только "
                "когда приходит сама.", "evidence": "ours", "src": ["journal_monitoring"]},
    ],
    "no_brain_url": [
        {"do": "node_action(set_brain_url) или update_agent с адресом панели.",
         "why": "Без CELL_BRAIN_URL heartbeat выключен молча.", "evidence": "ours",
         "src": ["journal_monitoring"]},
    ],
    "node_cant_reach_panel": [
        {"do": "node_action(action='use_relay'): агент обновляется через реле хаба и ходит к панели "
               "через него (`https://<хаб>/relay/<панель>`): heartbeat, обратный канал, трафик, "
               "обновления.",
         "why": "Связка «сеть хостера ноды → российский IP панели» режется выборочно (eng41s2 — да, "
                "ger41s2 — нет), а хаб достаёт до обеих сторон. Панель остаётся на месте, клиентам "
                "ничего не меняется.",
         "evidence": "ours", "src": ["journal_relay"]},
        {"do": "Дать ноде другой путь к панели: адрес панели за CDN/Cloudflare или через живую "
               "ноду; управлять через хаб, пока путь не появится.",
         "why": "Если нода не достаёт до панели, ни heartbeat, ни обратный канал не поднимутся.",
         "evidence": "ours", "src": ["journal_monitoring"]},
    ],
    "whitelist_mobile": [
        {"do": "При включённых белых списках (БС) у мобильного оператора — только CDN-ноды "
               "(российский CDN перед нодой: сейчас ru41s2-YA-CDN, ru42s2-tw-cdn). Клиенту на "
               "мобильном с БС — выбирать их в подписке.",
         "why": "БС пропускает только разрешённые адреса; обычная зарубежная нода в них не "
                "входит, а российский CDN — входит. Остальные ноды работают, когда БС не "
                "действуют или клиент на Wi-Fi.",
         "evidence": "ours", "src": ["owner_whitelist"],
         "note": "«Нет пинга на мобильном» при живой ноде (хаб и check-host её видят) — сначала "
                 "спросить, включены ли у оператора белые списки, а не чинить ноду. Проверить "
                 "платно: sim_probe(dpi='on') — только единицы с БС."},
    ],
    "docker_pull_hangs": [
        {"do": "Докер-образ с российского хоста не качается — явный шаг с таймаутом и зеркалом "
               "(наш инвариант 31). У Remnawave то же лечат `docker login`.",
         "why": "Docker Hub с российских хостингов не отказывает, а висит.",
         "evidence": "repeated", "src": ["remnawave_docker"]},
    ],
}

RULES = [
    "Белые списки операторов (на 25.09.2026): при включённом БС работают ТОЛЬКО CDN-ноды (российский CDN перед нодой, сейчас ru41s2-YA-CDN и ru42s2-tw-cdn). Остальные ноды — когда белые списки не действуют или клиент на Wi-Fi.",
    "Для домашних нод правду говорят домашние пробники: дата-центры (хаб, check-host) видят РФ "
    "иначе, чем Ростелеком/Дом.ру.",
    "Не искать универсальную настройку: у операторов разные ТСПУ. Держать в подписке несколько "
    "разных вариантов и выбирать по сквозной проверке.",
    "Сначала доступность IP (TCP → данные → TLS), потом протоколы: если IP резан, протоколом "
    "его не спасти.",
    "Всё, что меняет адрес/порт/транспорт, уезжает в подписки всех юзеров ноды — предлагать, "
    "а применять после согласия.",
]


def lookup(symptom: str = "") -> dict:
    """Приёмы по симптому (или весь справочник, если symptom пуст)."""
    def expand(items: list[dict]) -> list[dict]:
        return [{**it, "src": [SOURCES.get(s, s) for s in it.get("src", [])]} for it in items]

    if symptom:
        items = PLAYBOOK.get(symptom)
        if items is None:
            return {"ok": False, "error": "unknown_symptom",
                    "detail": f"есть: {', '.join(sorted(PLAYBOOK))}", "rules": RULES}
        return {"ok": True, "symptom": symptom, "steps": expand(items), "rules": RULES}
    return {"ok": True, "rules": RULES,
            "playbook": {k: expand(v) for k, v in PLAYBOOK.items()}}
