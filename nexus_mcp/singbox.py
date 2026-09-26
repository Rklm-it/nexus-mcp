"""xray-конфиг строки подписки → outbound sing-box для сквозной проверки.

Зачем
─────
На роутере с podkop уже стоит sing-box (podkop на нём работает), а xray
туда не влезает: ~30 МБ флеша или 110 МБ ОЗУ на скачивание. sing-box с
флеша даёт сквозную проверку из дома без скачивания.

Почему из xray-конфига, а не из ссылки
──────────────────────────────────────
xray-конфиг собирает `xray_json.py` — копия сборщика панели, тот самый
профиль, что получает клиент. Второй разбор ссылок разошёлся бы с ним
молча (инвариант 25). Здесь только перекладка готовых полей в формат
sing-box. Чего в sing-box нет (xhttp, kcp, VLESS encryption) — None:
такая строка проверяется xray, а не «почти тем же» профилем.
"""

from __future__ import annotations

from urllib.parse import parse_qs, urlencode, urlparse


def _tls(stream: dict) -> dict | None:
    sec = stream.get("security") or "none"
    if sec == "reality":
        rs = stream.get("realitySettings") or {}
        return {
            "enabled": True,
            "server_name": rs.get("serverName") or "",
            # reality в sing-box работает только поверх utls
            "utls": {"enabled": True, "fingerprint": rs.get("fingerprint") or "chrome"},
            "reality": {"enabled": True, "public_key": rs.get("publicKey") or "",
                        "short_id": rs.get("shortId") or ""},
        }
    if sec == "tls":
        ts = stream.get("tlsSettings") or {}
        out: dict = {"enabled": True, "server_name": ts.get("serverName") or ""}
        if ts.get("allowInsecure"):
            out["insecure"] = True
        if ts.get("alpn"):
            out["alpn"] = list(ts["alpn"])
        if ts.get("fingerprint"):
            out["utls"] = {"enabled": True, "fingerprint": ts["fingerprint"]}
        return out
    if sec in ("none", ""):
        return None
    raise ValueError(sec)


def _ws(ws: dict) -> dict:
    """ws; `?ed=2048` в пути — early data xray, у sing-box это поля транспорта."""
    path = ws.get("path") or "/"
    out: dict = {"type": "ws"}
    u = urlparse(path)
    q = parse_qs(u.query)
    ed = (q.pop("ed", None) or [""])[0]
    if ed.isdigit():
        path = u.path + ("?" + urlencode(q, doseq=True) if q else "")
        out["max_early_data"] = int(ed)
        out["early_data_header_name"] = "Sec-WebSocket-Protocol"
    out["path"] = path or "/"
    host = (ws.get("headers") or {}).get("Host")
    if host:
        out["headers"] = {"Host": host}
    return out


def _transport(stream: dict) -> dict | None:
    net = stream.get("network") or "tcp"
    if net in ("tcp", "raw"):
        return None
    if net == "ws":
        return _ws(stream.get("wsSettings") or {})
    if net == "httpupgrade":
        hu = stream.get("httpupgradeSettings") or {}
        out = {"type": "httpupgrade", "path": hu.get("path") or "/"}
        if hu.get("host"):
            out["host"] = hu["host"]
        return out
    if net == "grpc":
        return {"type": "grpc", "service_name": (stream.get("grpcSettings") or {}).get("serviceName") or ""}
    raise ValueError(net)  # xhttp, kcp — у sing-box их нет


def _stream_into(ob: dict, stream: dict) -> None:
    tls = _tls(stream)
    if tls:
        ob["tls"] = tls
    tr = _transport(stream)
    if tr:
        ob["transport"] = tr


def outbound(xray_cfg: dict | None) -> dict | None:
    """Первый outbound xray-конфига → outbound sing-box (tag "proxy"). None —
    в sing-box так не переложить, проверять надо xray."""
    try:
        ob = (xray_cfg or {}).get("outbounds", [])[0]
        proto = ob.get("protocol")
        st = ob.get("settings") or {}
        stream = ob.get("streamSettings") or {}
        if proto == "vless":
            v = st["vnext"][0]
            user = v["users"][0]
            if (user.get("encryption") or "none") != "none":
                return None
            out = {"type": "vless", "tag": "proxy", "server": v["address"], "server_port": int(v["port"]),
                   "uuid": user["id"]}
            if user.get("flow"):
                out["flow"] = user["flow"]
            _stream_into(out, stream)
            return out
        if proto == "shadowsocks":
            s = st["servers"][0]
            if (stream.get("network") or "tcp") not in ("tcp", "raw"):
                return None
            return {"type": "shadowsocks", "tag": "proxy", "server": s["address"], "server_port": int(s["port"]),
                    "method": s["method"], "password": s["password"]}
        if proto == "hysteria":
            ts = stream.get("tlsSettings") or {}
            out = {"type": "hysteria2", "tag": "proxy", "server": st["address"], "server_port": int(st["port"]),
                   "password": (stream.get("hysteriaSettings") or {}).get("auth") or "",
                   "tls": {"enabled": True, "server_name": ts.get("serverName") or "",
                           "alpn": list(ts.get("alpn") or ["h3"])}}
            if ts.get("allowInsecure"):
                out["tls"]["insecure"] = True
            for m in ((stream.get("finalmask") or {}).get("udp") or []):
                if m.get("type") == "salamander":
                    out["obfs"] = {"type": "salamander", "password": (m.get("settings") or {}).get("password", "")}
            return out
    except (KeyError, IndexError, TypeError, ValueError, AttributeError):
        return None
    return None


def config(xray_cfg: dict | None) -> dict | None:
    """Клиентский конфиг sing-box без входа: пробник добавит SOCKS на
    свободном порту, как и xray-конфигу."""
    ob = outbound(xray_cfg)
    if ob is None:
        return None
    return {"log": {"level": "warn"}, "outbounds": [ob]}
