"""Подписка в формате xray JSON — то, что Happ показывает одним пунктом.

Зачем
─────
Просьба владельца сервиса: «в Happ вместо настроек — JSON». Сейчас подписка
это список URI (`vless://…`), и клиент разбирает каждую ссылку на поля:
адрес, порт, uuid, sni, pbk, sid, path, flow — человек видит на телефоне
настройки по пунктам и может их править (а поправив — сломать). Happ, v2rayN
и Streisand умеют другой формат подписки: массив готовых xray-конфигов
(JSON), где строка — цельный профиль, а не набор редактируемых полей.

Здесь ровно это: тот же список ссылок, который уже собрала подписка,
превращается в массив конфигов. Собираем ИЗ URI, а не из инбаундов, ровно
по одной причине: у ссылок за годы накопились десятки частных случаев (CDN,
xmux, extra, finalmask-маски, encryption), и второй сборщик разошёлся бы с
первым молча — клиент получал бы «почти те же» настройки, которые не
подключаются.

Hysteria2
─────────
Переносится тоже. У xray он живёт не отдельным протоколом, а парой
«протокол + транспорт»: `protocol: hysteria` + `streamSettings.network:
hysteria`, причём пароль читается ИЗ ТРАНСПОРТА
(`hysteriaSettings.auth`), а адрес и порт — из `settings`. Заполнять надо
оба блока: с половиной outbound не работает вовсе.
Salamander-обфускация кладётся так же, как в inbound'ах xray, — в
`finalmask.udp`. Happ отдаёт наш JSON своему xray-ядру как есть, поэтому
формат ровно ядерный, без клиентских вольностей.

Что не переносится
──────────────────
Всё, чего у xray нет в принципе (`s3tunnel://` и прочие наши схемы).
Такие ссылки остаются только в обычной (base64) подписке — молча портить
ими JSON нельзя, поэтому они честно отбрасываются.
"""

from __future__ import annotations

import base64
import json
import logging
from urllib.parse import parse_qs, unquote, urlparse

logger = logging.getLogger(__name__)

# Локальные порты клиента. Значения — те же, что раскладывают v2rayN и Happ
# по умолчанию; клиент их всё равно переопределяет своими настройками.
SOCKS_PORT = 10808
HTTP_PORT = 10809


def _base_inbounds() -> list[dict]:
    return [
        {
            "tag": "socks",
            "port": SOCKS_PORT,
            "listen": "127.0.0.1",
            "protocol": "socks",
            "sniffing": {"enabled": True, "destOverride": ["http", "tls"]},
            "settings": {"auth": "noauth", "udp": True, "allowTransparent": False},
        },
        {
            "tag": "http",
            "port": HTTP_PORT,
            "listen": "127.0.0.1",
            "protocol": "http",
            "sniffing": {"enabled": True, "destOverride": ["http", "tls"]},
            "settings": {"auth": "noauth", "udp": True, "allowTransparent": False},
        },
    ]


def _tail_outbounds() -> list[dict]:
    return [
        {"tag": "direct", "protocol": "freedom", "settings": {}},
        {
            "tag": "block",
            "protocol": "blackhole",
            "settings": {"response": {"type": "http"}},
        },
    ]


def _first(params: dict, key: str, default: str = "") -> str:
    """Значение параметра запроса.

    Раскодировать его отдельно не нужно: `parse_qs` уже снял
    percent-encoding, а второй `unquote` испортил бы путь, в котором `%`
    закодирован намеренно (`/a%2Fb`).
    """
    values = params.get(key)
    if not values:
        return default
    return values[0]


def _stream_settings(params: dict) -> dict:
    """`?type=…&security=…` → `streamSettings` xray-конфига."""
    net = _first(params, "type", "tcp") or "tcp"
    security = _first(params, "security", "none") or "none"
    stream: dict = {"network": net, "security": security}

    sni = _first(params, "sni")
    host = _first(params, "host")
    fp = _first(params, "fp")

    if security == "reality":
        stream["realitySettings"] = {
            "serverName": sni,
            "fingerprint": fp or "chrome",
            "publicKey": _first(params, "pbk"),
            "shortId": _first(params, "sid"),
            "spiderX": _first(params, "spx", "/"),
            "show": False,
        }
    elif security == "tls":
        tls: dict = {
            "serverName": sni or host,
            "fingerprint": fp or "chrome",
            "allowInsecure": _first(params, "allowInsecure") in ("1", "true"),
        }
        alpn = _first(params, "alpn")
        if alpn:
            tls["alpn"] = [a for a in alpn.split(",") if a]
        stream["tlsSettings"] = tls

    path = _first(params, "path", "")

    if net == "ws":
        ws: dict = {"path": path or "/"}
        if host:
            ws["headers"] = {"Host": host}
        stream["wsSettings"] = ws
    elif net == "httpupgrade":
        hu: dict = {"path": path or "/"}
        if host:
            hu["host"] = host
        stream["httpupgradeSettings"] = hu
    elif net == "grpc":
        stream["grpcSettings"] = {
            "serviceName": _first(params, "serviceName", ""),
            "multiMode": _first(params, "mode") == "multi",
        }
    elif net == "xhttp":
        xhttp: dict = {"path": path or "/"}
        if host:
            xhttp["host"] = host
        mode = _first(params, "mode")
        if mode:
            xhttp["mode"] = mode
        # `extra` — это уже готовый JSON (xmux, padding, sc*): кладём как
        # есть. Разбирать его по полям бессмысленно — набор ключей меняется
        # с каждой версией ядра, а ссылка и профиль обязаны совпадать.
        raw_extra = _first(params, "extra")
        if raw_extra:
            try:
                xhttp["extra"] = json.loads(raw_extra)
            except ValueError:
                logger.warning("xray-json: не разобрал extra у ссылки — пропускаю")
        stream["xhttpSettings"] = xhttp
    elif net == "kcp":
        kcp: dict = {
            "header": {"type": _first(params, "headerType", "none") or "none"},
        }
        seed = _first(params, "seed", "")
        if seed:
            kcp["seed"] = seed
        for key in ("mtu", "tti"):
            value = _first(params, key)
            if value.isdigit():
                kcp[key] = int(value)
        stream["kcpSettings"] = kcp

    return stream


def vless_outbound(url) -> dict | None:
    params = parse_qs(url.query)
    uuid = unquote(url.username or "")
    if not uuid or not url.hostname:
        return None

    user: dict = {
        "id": uuid,
        "encryption": _first(params, "encryption", "none") or "none",
    }
    flow = _first(params, "flow")
    if flow:
        user["flow"] = flow

    return {
        "tag": "proxy",
        "protocol": "vless",
        "settings": {
            "vnext": [{
                "address": url.hostname,
                "port": url.port or 443,
                "users": [user],
            }]
        },
        "streamSettings": _stream_settings(params),
    }


def ss_outbound(url) -> dict | None:
    """`ss://<base64(method:password)>@host:port`.

    Наши ss2022-ссылки кладут в userinfo base64 без выравнивания — его и
    разбираем; форма «ss://method:password@host» тоже встречается у чужих
    панелей, поэтому обрабатываем обе.
    """
    if not url.hostname:
        return None
    userinfo = unquote(url.username or "")
    if ":" in userinfo:
        method, _, password = userinfo.partition(":")
    else:
        try:
            pad = "=" * (-len(userinfo) % 4)
            decoded = base64.urlsafe_b64decode(userinfo + pad).decode()
        except Exception:  # noqa: BLE001
            return None
        method, _, password = decoded.partition(":")
    if not method or not password:
        return None

    return {
        "tag": "proxy",
        "protocol": "shadowsocks",
        "settings": {
            "servers": [{
                "address": url.hostname,
                "port": url.port or 443,
                "method": method,
                "password": password,
                "uot": False,
            }]
        },
        "streamSettings": {"network": "tcp"},
    }


def hysteria2_outbound(url) -> dict | None:
    """`hysteria2://<auth>@host:port?sni=…&obfs=…` → outbound xray.

    Форма ядерная, а не «как в клиенте»: Happ передаёт наш JSON своему
    xray как есть. Отсюда два блока — `settings` (адрес, порт, версия) и
    `streamSettings.hysteriaSettings` (пароль): xray читает auth именно из
    транспорта, и с заполненной половиной outbound молча не подключается.

    Пароль — весь userinfo целиком. У нас там либо UUID (ноды с доменом и
    настоящим сертификатом), либо `UUID:UUID` (self-signed, legacy-форма) —
    обе принимает auth-скрипт на ноде, и обе должны доехать без изменений.
    """
    if not url.hostname:
        return None

    auth = unquote(url.username or "")
    if url.password:
        auth = f"{auth}:{unquote(url.password)}"
    if not auth:
        return None

    params = parse_qs(url.query)
    sni = _first(params, "sni") or url.hostname
    # `insecure=1` мы ставим сами нодам с self-signed сертификатом: без
    # него клиент к ним не подключится вовсе.
    insecure = _first(params, "insecure") in ("1", "true")

    stream: dict = {
        "network": "hysteria",
        "security": "tls",
        "tlsSettings": {
            "serverName": sni,
            "alpn": ["h3"],
            "allowInsecure": insecure,
        },
        "hysteriaSettings": {"version": 2, "auth": auth},
    }

    # `mport` (port hopping) в xray-транспорте описания не имеет — в JSON
    # его не кладём. Клиент остаётся на основном порту ссылки: это рабочее
    # подключение, а выдуманное поле ядро отвергло бы вместе с конфигом.
    obfs_password = _first(params, "obfs-password")
    if _first(params, "obfs") == "salamander" and obfs_password:
        stream["finalmask"] = {
            "udp": [{
                "type": "salamander",
                "settings": {"password": obfs_password},
            }],
        }

    return {
        "tag": "proxy",
        "protocol": "hysteria",
        "settings": {
            "version": 2,
            "address": url.hostname,
            "port": url.port or 443,
        },
        "streamSettings": stream,
    }


def uri_to_config(uri: str) -> dict | None:
    """Одна ссылка → один xray-конфиг. None — формат не переносится в JSON."""
    uri = (uri or "").strip()
    if not uri:
        return None
    try:
        url = urlparse(uri)
    except ValueError:
        return None

    if url.scheme == "vless":
        outbound = vless_outbound(url)
    elif url.scheme == "ss":
        outbound = ss_outbound(url)
    elif url.scheme in ("hysteria2", "hy2"):
        outbound = hysteria2_outbound(url)
    else:
        # Наши собственные схемы (s3tunnel:// и подобные): у xray для них
        # outbound'а нет, подсунуть их под чужой протокол нельзя.
        return None

    if not outbound:
        return None

    remark = unquote(url.fragment or "") or url.hostname or "server"
    return {
        "remarks": remark,
        "log": {"loglevel": "warning"},
        "inbounds": _base_inbounds(),
        "outbounds": [outbound, *_tail_outbounds()],
        "routing": {
            "domainStrategy": "IPIfNonMatch",
            "rules": [
                {
                    "type": "field",
                    "outboundTag": "direct",
                    "ip": ["geoip:private"],
                },
            ],
        },
    }


def build_json_subscription(uris: list[str]) -> tuple[list[dict], list[str]]:
    """Список ссылок → (конфиги, ссылки, которые в JSON не переносятся)."""
    configs: list[dict] = []
    skipped: list[str] = []
    for uri in uris:
        cfg = uri_to_config(uri)
        if cfg is None:
            skipped.append(uri)
            continue
        configs.append(cfg)
    return configs, skipped
