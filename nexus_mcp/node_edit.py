"""Правка конфигурации ноды через её панель: маршрутизация, relay, настройки
ноды, инбаунды — то же, что админ делает на странице сервера.

Порядок всегда один:
1. `plan()` читает текущее состояние, собирает запросы к панели и ОБРАТНЫЕ
   запросы (откат) из сырых, немаскированных данных. Модели отдаётся только
   маскированный предпросмотр и `plan_hash`.
2. Человек соглашается, и тот же вызов повторяется с confirm=true и тем же
   `plan_hash`. План собирается заново: если состояние ноды за это время
   поменялось, хэш не сойдётся и правка не пойдёт — человек соглашался на
   другое.
3. `apply()` пишет запись правки с откатом на диск хаба (0600) ДО первого
   запроса, выполняет шаги по очереди и отмечает, какие прошли. Откат —
   `op="rollback", args={"edit": <id>}`: обратные шаги прошедших, в обратном
   порядке.

Что проверяется до панели (панель сама этого не ловит):
- правило или DNS ссылается на `relay-…`, которого НЕТ среди выходов этой
  ноды. Панель проверяет только, что такая нода существует, и при «применить
  сеть» собирает выход на лету — но relay-юзера на целевой ноде заводит лишь
  relay-node (relay_add). Без него трафик уходит в выход, который целевая
  нода не пускает: у юзеров «нет интернета» при зелёных нодах;
- удаление relay, на который ещё ссылаются правила, — та же поломка;
- маскированное значение («abcd…», «***») из ответа панели в теле записи:
  записали бы маску вместо ключа.
"""

from __future__ import annotations

import copy
import hashlib
import json
import os
import re
import time
import uuid as uuidlib
from typing import Any

from nexus_mcp import config, inventory
from nexus_mcp import panel as panel_api

OPS = {
    "routing": "заменить целиком dns_settings / routing_rules / custom_routes (что передано)",
    "swap_outbound": "выход from → to: в DNS (final_outbound) и во всех правилах маршрутизации",
    "settings": "поля ноды (name, display_name, display_order, note, country, city, is_active, sub_type, "
                "warp_enabled, hysteria_domain, api_host, cf_only, is_free, free_for_all, "
                "router_enabled, router_protocols)",
    "relay_add": "relay через другую ноду: via=<нода>, mode=xray|iptables, listen_port, protocol",
    "relay_remove": "удалить relay: tag=<relay-…>",
    "inbound_update": "inbound=<тег|id>, changes={display_name, is_enabled, is_hidden, display_order, "
                      "listen_port, tag, config{…только меняемые ключи}, force}",
    "inbound_create": "protocol, listen_port, tag, config, display_name, is_enabled",
    "inbound_delete": "inbound=<тег|id>",
    "inbound_push": "inbound=<тег|id> — переприменить на ноду как есть",
    "inbound_order": "inbounds=[теги или id по порядку в подписке]",
    "push_network": "применить DNS/маршрутизацию/relay из панели на ноду",
    "batch": "несколько правок ОДНОЙ ноды одним подтверждением: ops=[{op, args}, …] — "
             "например relay_add → swap_outbound → relay_remove",
    "rollback": "edit=<id правки> — вернуть как было",
}

ROUTING_FIELDS = ("dns_settings", "routing_rules", "custom_routes")
SETTINGS_FIELDS = ("name", "display_name", "display_order", "note", "country", "city", "is_active",
                   "sub_type", "warp_enabled", "hysteria_domain", "api_host", "cf_only", "is_free",
                   "free_for_all", "router_enabled", "router_protocols")
# Что клиент видит в подписке или теряет доступ — предупреждение в плане.
CLIENT_SETTINGS = {"is_active": "нода пропадёт из подписок / вернётся",
                   "sub_type": "меняет, кому нода выдаётся (пересчёт привязок юзеров)",
                   "cf_only": "IP ноды уйдёт из подписки, останется только Cloudflare",
                   "hysteria_domain": "Hysteria2 пересоздаётся с новым сертификатом",
                   "is_free": "общий ключ бесплатного доступа кладётся/снимается",
                   "router_enabled": "меняет конфиг xray ноды"}
INBOUND_FIELDS = ("display_name", "is_enabled", "is_hidden", "display_order", "listen_port", "tag",
                  "config", "force")
INBOUND_CLIENT = {"listen_port": "порт уедет в подписки всех юзеров ноды",
                  "config": "параметры ссылки (SNI/путь/ключи) уедут в подписки всех юзеров",
                  "is_enabled": "ссылка пропадёт из подписок / появится",
                  "tag": "меняет тег на ноде"}
# Выходы, которые есть у xray на любой ноде (как _SYSTEM_OUTBOUND_TAGS панели).
SYSTEM_OUTBOUNDS = {"direct", "proxy", "blocked", "block", "api"}

_MASK = re.compile(r"^(?:\*\*\*|.{1,4}…)$")


class EditError(Exception):
    pass


def _edits_dir():
    d = config.settings.state_dir / "edits"
    d.mkdir(parents=True, exist_ok=True)
    return d


def _step(method: str, path: str, body: Any = None, title: str = "") -> dict:
    return {"method": method, "path": path, "body": body, "title": title}


def _hash(obj: Any) -> str:
    return hashlib.sha256(json.dumps(obj, sort_keys=True, ensure_ascii=False,
                                     default=str).encode()).hexdigest()[:16]


def _masked_values(obj: Any, where: str = "") -> list[str]:
    """Пути до значений, похожих на маску из ответа панели."""
    out = []
    if isinstance(obj, dict):
        for k, v in obj.items():
            out += _masked_values(v, f"{where}.{k}" if where else str(k))
    elif isinstance(obj, list):
        for i, v in enumerate(obj):
            out += _masked_values(v, f"{where}[{i}]")
    elif isinstance(obj, str) and _MASK.match(obj):
        out.append(where or "значение")
    return out


def _rule_tags(rules: Any, dns: Any) -> set[str]:
    tags = set()
    for r in rules or []:
        if isinstance(r, dict):
            t = r.get("outboundTag") or r.get("outbound") or ""
            if t:
                tags.add(t)
    if isinstance(dns, dict) and dns.get("final_outbound"):
        tags.add(dns["final_outbound"])
    return tags


class _Node:
    """Состояние ноды в панели: сервер, выходы, инбаунды — сырые."""

    def __init__(self, n: dict, server: dict, outbounds: list, inbounds: list):
        self.n, self.server, self.outbounds, self.inbounds = n, server, outbounds, inbounds
        self.id = str(server["id"])
        self.panel = n.get("panel") or ""
        self.name = n["name"]

    @property
    def base(self) -> str:
        return f"/api/v1/servers/{self.id}"

    def known_outbounds(self) -> set[str]:
        tags = SYSTEM_OUTBOUNDS | {o["tag"] for o in self.outbounds if o.get("is_enabled", True)}
        if self.server.get("warp_enabled"):
            tags.add("warp-out")
        return tags

    def inbound(self, key: str) -> dict:
        key = str(key or "").strip()
        hits = [i for i in self.inbounds if key in (str(i["id"]), i.get("tag"))]
        if not hits:
            hits = [i for i in self.inbounds if (i.get("display_name") or "").strip() == key]
        if len(hits) != 1:
            have = ", ".join(f"{i.get('tag')} ({i.get('display_name') or '—'})" for i in self.inbounds)
            raise EditError(f"инбаунд «{key}» на {self.name} не найден однозначно. Есть: {have or 'нет'}")
        return hits[0]


async def _load(node: str) -> _Node:
    try:
        n = await inventory.find_node(node)
    except inventory.InventoryError as e:
        raise EditError(str(e)) from e
    if not n.get("id"):
        raise EditError(f"{n['name']} нет в панели — её конфиг правится только через панель")
    pn = n.get("panel") or ""
    try:
        server = await panel_api.read_raw(f"/api/v1/servers/{n['id']}", pn)
        outbounds = await panel_api.read_raw(f"/api/v1/servers/{n['id']}/outbounds", pn)
        inbounds = await panel_api.read_raw(f"/api/v1/servers/{n['id']}/inbounds", pn)
    except panel_api.PanelError as e:
        raise EditError(str(e)) from e
    return _Node(n, server, outbounds or [], inbounds or [])


def _check_routing(nd: _Node, rules: Any, dns: Any, extra_tags: set[str] = frozenset()) -> None:
    missing = _rule_tags(rules, dns) - nd.known_outbounds() - set(extra_tags)
    if missing:
        have = ", ".join(sorted(nd.known_outbounds()))
        raise EditError(
            f"на {nd.name} нет выходов {', '.join(sorted(missing))}: панель собрала бы их на лету, но без "
            f"relay-юзера на целевой ноде — трафик ушёл бы в никуда. Сначала relay_add (можно одним "
            f"batch с этой правкой). Есть: {have}")


# ── Сборка плана по операциям ──────────────────────────────────────────────

def _patch_server(nd: _Node, fields: dict, title: str) -> tuple[list, list]:
    before = {k: copy.deepcopy(nd.server.get(k)) for k in fields}
    return ([_step("PATCH", nd.base, fields, title)],
            [_step("PATCH", nd.base, before, f"вернуть {', '.join(fields)} на {nd.name}")])


async def _plan_routing(nd: _Node, args: dict) -> dict:
    fields = {k: args[k] for k in ROUTING_FIELDS if k in args}
    if not fields:
        raise EditError(f"routing: передайте хотя бы одно из {', '.join(ROUTING_FIELDS)}")
    if "routing_rules" in fields and not isinstance(fields["routing_rules"], list):
        raise EditError("routing_rules — список правил xray")
    if "dns_settings" in fields and not isinstance(fields["dns_settings"], dict):
        raise EditError("dns_settings — объект {servers, final_outbound}")
    _check_routing(nd, fields.get("routing_rules", nd.server.get("routing_rules")),
                   fields.get("dns_settings", nd.server.get("dns_settings")))
    steps, undo = _patch_server(nd, fields, f"маршрутизация {nd.name}: {', '.join(fields)}")
    lines = []
    if "dns_settings" in fields:
        old = (nd.server.get("dns_settings") or {}).get("final_outbound") or "direct"
        new = (fields["dns_settings"] or {}).get("final_outbound") or "direct"
        lines.append(f"весь трафик по умолчанию: {old} → {new}")
    if "routing_rules" in fields:
        lines.append(f"правил: {len(nd.server.get('routing_rules') or [])} → {len(fields['routing_rules'])}")
    return {"steps": steps, "undo": undo, "lines": lines,
            "notes": ["панель сама применит сеть на ноду и перезапустит xray (секунды обрыва у юзеров)"]}


async def _plan_swap(nd: _Node, args: dict) -> dict:
    src, dst = str(args.get("from") or "").strip(), str(args.get("to") or "").strip()
    if not src or not dst or src == dst:
        raise EditError("swap_outbound: нужны from и to, разные")
    rules = copy.deepcopy(nd.server.get("routing_rules") or [])
    dns = copy.deepcopy(nd.server.get("dns_settings") or {})
    hits = 0
    for r in rules:
        for key in ("outboundTag", "outbound"):
            if isinstance(r, dict) and r.get(key) == src:
                r[key] = dst
                hits += 1
    dns_hit = isinstance(dns, dict) and dns.get("final_outbound") == src
    if dns_hit:
        dns["final_outbound"] = dst
    if not hits and not dns_hit:
        raise EditError(f"на {nd.name} выход {src} нигде не используется — менять нечего")
    _check_routing(nd, rules, dns)
    fields = {"routing_rules": rules}
    if dns_hit:
        fields["dns_settings"] = dns
    steps, undo = _patch_server(nd, fields, f"{nd.name}: выход {src} → {dst}")
    lines = [f"правил переключено: {hits}"] + (["весь трафик по умолчанию: {} → {}".format(src, dst)]
                                              if dns_hit else [])
    return {"steps": steps, "undo": undo, "lines": lines,
            "notes": ["панель сама применит сеть на ноду и перезапустит xray (секунды обрыва у юзеров)"]}


async def _plan_settings(nd: _Node, args: dict) -> dict:
    fields = {k: v for k, v in args.items() if k in SETTINGS_FIELDS}
    extra = sorted(set(args) - set(SETTINGS_FIELDS))
    if extra:
        raise EditError(f"settings: поля {', '.join(extra)} так не меняются. Можно: {', '.join(SETTINGS_FIELDS)}")
    if not fields:
        raise EditError("settings: нечего менять")
    steps, undo = _patch_server(nd, fields, f"настройки {nd.name}: {', '.join(fields)}")
    lines = [f"{k}: {json.dumps(nd.server.get(k), ensure_ascii=False)} → {json.dumps(v, ensure_ascii=False)}"
             for k, v in fields.items()]
    warn = [f"{k} — {CLIENT_SETTINGS[k]}" for k in fields if k in CLIENT_SETTINGS]
    return {"steps": steps, "undo": undo, "lines": lines, "clients": warn}


async def _plan_relay_add(nd: _Node, args: dict) -> dict:
    via = str(args.get("via") or "").strip()
    if not via:
        raise EditError("relay_add: via=<нода, через которую пускать трафик>")
    try:
        target = await inventory.find_node(via)
    except inventory.InventoryError as e:
        raise EditError(str(e)) from e
    if (target.get("panel") or "") != nd.panel or not target.get("id"):
        raise EditError(f"{target['name']} не из той же панели, что {nd.name}")
    if str(target["id"]) == nd.id:
        raise EditError("relay на саму себя не бывает")
    tag = f"relay-{str(target['id'])[:8]}"
    if any(o["tag"] == tag for o in nd.outbounds):
        raise EditError(f"на {nd.name} relay {tag} ({target['name']}) уже есть")
    mode = str(args.get("mode") or "xray")
    if mode not in ("xray", "iptables"):
        raise EditError("mode: xray | iptables")
    body = {"relay_server_id": str(target["id"]), "relay_mode": mode,
            "listen_port": args.get("listen_port"), "protocol": args.get("protocol")}
    notes = []
    if not target.get("panel_online"):
        notes.append(f"ВНИМАНИЕ: {target['name']} в панели красная — relay через неё может не везти трафик")
    return {"steps": [_step("POST", f"/api/v1/admin/nodes/{nd.id}/relay-node", body,
                            f"{nd.name}: relay через {target['name']} ({tag}, {mode})")],
            "undo": [{"resolve": "outbound", "server_id": nd.id, "tag": tag, "method": "DELETE",
                      "title": f"убрать relay {tag} с {nd.name}"}],
            "lines": [f"новый выход {tag} → {target['name']} ({target.get('ip')})",
                      "маршрутизацию это не меняет: дальше swap_outbound или routing"],
            "notes": notes, "new_tags": {tag}}


async def _plan_relay_remove(nd: _Node, args: dict) -> dict:
    tag = str(args.get("tag") or "").strip()
    ob = next((o for o in nd.outbounds if o["tag"] == tag), None)
    if not ob:
        raise EditError(f"на {nd.name} нет relay «{tag}». Есть: "
                        + (", ".join(o["tag"] for o in nd.outbounds) or "нет"))
    used = tag in _rule_tags(nd.server.get("routing_rules"), nd.server.get("dns_settings"))
    if used:
        raise EditError(f"на {tag} ещё ссылаются правила или DNS {nd.name} — трафик по ним пропадёт. "
                        f"Сначала swap_outbound from={tag} to=<другой выход>")
    body = {k: ob.get(k) for k in ("tag", "protocol", "target_address", "target_port", "config",
                                   "is_enabled", "relay_mode", "listen_port")}
    return {"steps": [_step("DELETE", f"{nd.base}/outbounds/{ob['id']}", None, f"{nd.name}: удалить {tag}")],
            "undo": [_step("POST", f"{nd.base}/outbounds", body, f"вернуть relay {tag} на {nd.name}")],
            "lines": [f"удалить выход {tag} → {ob.get('target_address')}:{ob.get('target_port')}"]}


def _inbound_warns(changes: dict) -> list[str]:
    return [f"{k} — {INBOUND_CLIENT[k]}" for k in changes if k in INBOUND_CLIENT]


async def _plan_inbound_update(nd: _Node, args: dict) -> dict:
    ib = nd.inbound(args.get("inbound"))
    changes = dict(args.get("changes") or {})
    extra = sorted(set(changes) - set(INBOUND_FIELDS))
    if extra:
        raise EditError(f"inbound_update: поля {', '.join(extra)} так не меняются. Можно: {', '.join(INBOUND_FIELDS)}")
    if not changes:
        raise EditError("inbound_update: changes пуст")
    if "config" in changes and not isinstance(changes["config"], dict):
        raise EditError("config — объект только с меняемыми ключами (панель сливает его с текущим)")
    before = {k: copy.deepcopy(ib.get(k)) for k in changes if k not in ("config", "force")}
    if "config" in changes:
        old_cfg = ib.get("config") or {}
        before["config"] = {k: copy.deepcopy(old_cfg.get(k)) for k in changes["config"]}
    path = f"{nd.base}/inbounds/{ib['id']}"
    lines = []
    for k, v in changes.items():
        if k == "config":
            for ck, cv in v.items():
                lines.append(f"config.{ck}: {json.dumps((ib.get('config') or {}).get(ck), ensure_ascii=False)}"
                             f" → {json.dumps(cv, ensure_ascii=False)}")
        elif k != "force":
            lines.append(f"{k}: {json.dumps(ib.get(k), ensure_ascii=False)} → {json.dumps(v, ensure_ascii=False)}")
    label = f"{ib.get('tag')} ({ib.get('display_name') or ib.get('protocol')})"
    return {"steps": [_step("PATCH", path, changes, f"{nd.name}: инбаунд {label}")],
            "undo": [_step("PATCH", path, before, f"вернуть инбаунд {label} на {nd.name}")],
            "lines": lines, "clients": _inbound_warns(changes)}


async def _plan_inbound_create(nd: _Node, args: dict) -> dict:
    body = {k: args[k] for k in ("protocol", "tag", "listen_port", "config", "is_enabled",
                                 "display_name", "force") if k in args}
    if not body.get("protocol"):
        raise EditError("inbound_create: нужен protocol")
    tag = body.get("tag") or ""
    undo = ([{"resolve": "inbound", "server_id": nd.id, "tag": tag, "method": "DELETE",
              "title": f"удалить созданный инбаунд {tag} с {nd.name}"}] if tag else
            [{"resolve": "inbound_new", "server_id": nd.id,
              "known": [str(i["id"]) for i in nd.inbounds], "method": "DELETE",
              "title": f"удалить созданный инбаунд с {nd.name}"}])
    return {"steps": [_step("POST", f"{nd.base}/inbounds", body, f"{nd.name}: новый инбаунд {body['protocol']}")],
            "undo": undo, "lines": [f"протокол {body['protocol']}, порт {body.get('listen_port') or 'по умолчанию'}"],
            "clients": ["новая ссылка появится в подписках всех юзеров ноды"]}


async def _plan_inbound_delete(nd: _Node, args: dict) -> dict:
    ib = nd.inbound(args.get("inbound"))
    body = {"protocol": ib["protocol"], "tag": ib["tag"], "listen_port": ib["listen_port"],
            "config": ib.get("config") or {}, "is_enabled": ib.get("is_enabled", True),
            "display_name": ib.get("display_name"), "force": True}
    return {"steps": [_step("DELETE", f"{nd.base}/inbounds/{ib['id']}", None,
                            f"{nd.name}: удалить инбаунд {ib['tag']}")],
            "undo": [_step("POST", f"{nd.base}/inbounds", body, f"вернуть инбаунд {ib['tag']} на {nd.name}")],
            "lines": [f"удалить {ib['tag']} ({ib.get('display_name') or ib['protocol']}, порт {ib['listen_port']})"],
            "clients": ["ссылка пропадёт из подписок всех юзеров ноды; откат вернёт её с прежними ключами"]}


async def _plan_inbound_push(nd: _Node, args: dict) -> dict:
    ib = nd.inbound(args.get("inbound"))
    return {"steps": [_step("POST", f"{nd.base}/inbounds/{ib['id']}/push", None,
                            f"{nd.name}: переприменить {ib['tag']}")],
            "undo": [], "lines": [f"переприменить {ib['tag']} на ноде как есть"]}


async def _plan_inbound_order(nd: _Node, args: dict) -> dict:
    keys = args.get("inbounds") or []
    if not isinstance(keys, list) or not keys:
        raise EditError("inbound_order: inbounds=[теги по порядку]")
    ids = [str(nd.inbound(k)["id"]) for k in keys]
    old = [str(i["id"]) for i in sorted(nd.inbounds, key=lambda i: (i.get("display_order") or 0))]
    return {"steps": [_step("PUT", f"{nd.base}/inbounds/order", {"inbound_ids": ids},
                            f"{nd.name}: порядок инбаундов")],
            "undo": [_step("PUT", f"{nd.base}/inbounds/order", {"inbound_ids": old},
                           f"вернуть порядок инбаундов {nd.name}")],
            "lines": ["порядок в подписке: " + " → ".join(str(k) for k in keys)],
            "clients": ["новый порядок ссылок клиенты увидят при обновлении подписки"]}


async def _plan_push_network(nd: _Node, args: dict) -> dict:
    _check_routing(nd, nd.server.get("routing_rules"), nd.server.get("dns_settings"))
    return {"steps": [_step("POST", f"{nd.base}/push-network", None, f"{nd.name}: применить сеть")],
            "undo": [], "lines": ["применить DNS/маршрутизацию/relay из панели на ноду"],
            "notes": ["xray ноды перезапустится (секунды обрыва у юзеров)"]}


def _simulate(nd: _Node, op: str, p: dict) -> None:
    """Следующая операция пакета видит ноду такой, какой её оставит эта."""
    for st in p["steps"]:
        if st["method"] == "PATCH" and st["path"] == nd.base:
            nd.server.update(copy.deepcopy(st["body"]))
    if op == "relay_add":
        for tag in p.get("new_tags") or ():
            nd.outbounds.append({"tag": tag, "is_enabled": True, "id": "(будет создан)"})
    if op == "relay_remove":
        gone = {st["path"].rsplit("/", 1)[-1] for st in p["steps"]}
        nd.outbounds = [o for o in nd.outbounds if str(o.get("id")) not in gone]


BATCH_OPS = ("routing", "swap_outbound", "settings", "relay_add", "relay_remove", "push_network",
             "inbound_update", "inbound_push", "inbound_order")
MAX_BATCH = 8


async def _plan_batch(nd: _Node, args: dict) -> dict:
    ops = args.get("ops") or []
    if not isinstance(ops, list) or not ops:
        raise EditError("batch: ops=[{op, args}, …]")
    if len(ops) > MAX_BATCH:
        raise EditError(f"batch: не больше {MAX_BATCH} операций за раз")
    out = {"steps": [], "undo": [], "lines": [], "clients": [], "notes": []}
    for i, item in enumerate(ops, 1):
        op = (item or {}).get("op")
        if op not in BATCH_OPS:
            raise EditError(f"batch #{i}: «{op}» в пакете нельзя. Можно: {', '.join(BATCH_OPS)}")
        try:
            sub = await _PLANNERS[op](nd, dict(item.get("args") or {}))
        except EditError as e:
            raise EditError(f"batch #{i} ({op}): {e}") from e
        sub["undo"] = (sub.get("undo") or []) + [None] * (len(sub["steps"]) - len(sub.get("undo") or []))
        _simulate(nd, op, sub)
        out["steps"] += sub["steps"]
        out["undo"] += sub["undo"]
        out["lines"] += [f"{i}. {op}: {ln}" for ln in sub.get("lines") or []] or [f"{i}. {op}"]
        out["clients"] += sub.get("clients") or []
        out["notes"] += [n for n in sub.get("notes") or [] if n not in out["notes"]]
    return out


_PLANNERS = {
    "routing": _plan_routing, "swap_outbound": _plan_swap, "settings": _plan_settings,
    "relay_add": _plan_relay_add, "relay_remove": _plan_relay_remove,
    "inbound_update": _plan_inbound_update, "inbound_create": _plan_inbound_create,
    "inbound_delete": _plan_inbound_delete, "inbound_push": _plan_inbound_push,
    "inbound_order": _plan_inbound_order, "push_network": _plan_push_network,
    "batch": _plan_batch,
}


# ── План, применение, откат ────────────────────────────────────────────────

def _load_edit(edit_id: str) -> dict:
    if not re.fullmatch(r"[0-9a-f]{12}", edit_id or ""):
        raise EditError("edit — id правки из ответа node_edit (12 символов)")
    path = _edits_dir() / f"{edit_id}.json"
    if not path.exists():
        raise EditError(f"правки {edit_id} на хабе нет — список: node_edits")
    return json.loads(path.read_text(encoding="utf-8"))


def _save_edit(rec: dict) -> None:
    path = _edits_dir() / f"{rec['id']}.json"
    tmp = path.with_suffix(".tmp")
    fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(fd, "w", encoding="utf-8") as f:
        json.dump(rec, f, ensure_ascii=False, default=str)
    os.replace(tmp, path)


async def _plan_rollback(args: dict) -> tuple[dict, dict]:
    rec = _load_edit(str(args.get("edit") or ""))
    if rec.get("op") == "rollback":
        raise EditError("откат отката не делается — сделайте правку заново")
    if rec.get("rolled_back"):
        raise EditError(f"правка {rec['id']} уже откачена ({rec['rolled_back']})")
    done = rec.get("done", 0)
    if not done:
        raise EditError(f"у правки {rec['id']} не прошёл ни один шаг — откатывать нечего")
    undo = [u for i, u in enumerate(rec["undo"]) if i < done and u]
    if not undo:
        raise EditError(f"у {rec['op']} нет отката (действие без изменения настроек)")
    return rec, {"steps": list(reversed(undo)), "undo": [],
                 "lines": [f"откатить правку {rec['id']} ({rec['op']} на {rec['node']}, {rec['ts']})"]
                 + [f"— {s.get('title')}" for s in rec.get("titles", [])]}


async def plan(node: str, op: str, args: dict | None = None) -> dict:
    """Собрать план. Возвращает внутренний план (с сырыми телами) — наружу
    только preview()."""
    args = dict(args or {})
    if op not in OPS:
        raise EditError(f"операции «{op}» нет. Есть: " + "; ".join(f"{k} — {v}" for k, v in OPS.items()))
    if op == "rollback":
        rec, p = await _plan_rollback(args)
        p.update(node=rec["node"], node_id=rec["node_id"], panel=rec["panel"], op=op, args=args)
    else:
        nd = await _load(node)
        p = await _PLANNERS[op](nd, args)
        p.update(node=nd.name, node_id=nd.id, panel=nd.panel, op=op, args=args)
        # Одна операция = одна нода: чужие id в путях — отказ, а не «правка соседа».
        for s in p["steps"]:
            if nd.id not in s["path"]:
                raise EditError(f"шаг {s['method']} {s['path']} не про ноду {nd.name}")
    # Откат по шагам: undo[i] — обратный шаг для steps[i] (None — нечего).
    p["undo"] = list(p.get("undo") or []) + [None] * (len(p["steps"]) - len(p.get("undo") or []))
    for s in p["steps"]:
        if not s.get("resolve"):
            panel_api.check_write(s["method"], s["path"])
        masked = _masked_values(s.get("body"))
        if masked:
            raise EditError("в теле правки маскированные значения (" + ", ".join(masked[:5]) +
                            ") — это маска из ответа панели, а не настоящий ключ. Передавайте только "
                            "меняемые поля, секреты хаб подставит сам")
    p["plan_hash"] = _hash({"node_id": p["node_id"], "op": op, "steps": p["steps"]})
    return p


def preview(p: dict) -> dict:
    """Что показать модели и человеку: маскированно, без сырых ключей."""
    return {
        "node": p["node"], "panel": p["panel"] or None, "op": p["op"],
        "changes": p.get("lines", []),
        "steps": [f"{s['method']} {s.get('path') or s.get('tag') or 'созданный инбаунд'} — {s.get('title', '')}"
                  for s in p["steps"]],
        "bodies": [panel_api.redact(s.get("body")) for s in p["steps"] if s.get("body") is not None],
        "affects_clients": p.get("clients") or [],
        "notes": p.get("notes") or [],
        "rollback": "есть" if any(p.get("undo") or []) else "нет (действие не меняет настроек)",
        "plan_hash": p["plan_hash"],
    }


async def _resolve(u: dict, panel_name: str) -> dict:
    """Шаг отката, id которого стал известен только после правки."""
    sid = u["server_id"]
    if u["resolve"] == "outbound":
        items = await panel_api.read_raw(f"/api/v1/servers/{sid}/outbounds", panel_name)
        hit = next((o for o in items or [] if o["tag"] == u["tag"]), None)
        if not hit:
            raise EditError(f"relay {u['tag']} уже нет — откатывать нечего")
        return _step("DELETE", f"/api/v1/servers/{sid}/outbounds/{hit['id']}", None, u.get("title", ""))
    items = await panel_api.read_raw(f"/api/v1/servers/{sid}/inbounds", panel_name)
    if u["resolve"] == "inbound":
        hit = next((i for i in items or [] if i["tag"] == u["tag"]), None)
    else:
        new = [i for i in items or [] if str(i["id"]) not in set(u.get("known") or [])]
        hit = new[0] if len(new) == 1 else None
    if not hit:
        raise EditError("созданный инбаунд не найден однозначно — удалите его через inbound_delete")
    return _step("DELETE", f"/api/v1/servers/{sid}/inbounds/{hit['id']}", None, u.get("title", ""))


async def apply(p: dict) -> dict:
    """Выполнить план. Запись с откатом — на диск ДО первого запроса."""
    rec = {"id": uuidlib.uuid4().hex[:12], "ts": time.strftime("%Y-%m-%d %H:%M:%S"),
           "node": p["node"], "node_id": p["node_id"], "panel": p["panel"], "op": p["op"],
           "args": panel_api.redact(p.get("args")), "undo": p.get("undo") or [], "done": 0,
           "titles": [{"title": s.get("title")} for s in p["steps"]], "plan_hash": p["plan_hash"]}
    rollback_of = p["args"].get("edit") if p["op"] == "rollback" else None
    _save_edit(rec)
    results, error = [], ""
    for s in p["steps"]:
        try:
            step = await _resolve(s, p["panel"]) if s.get("resolve") else s
            res = await panel_api.write(step["method"], step["path"], step.get("body"), panel_name=p["panel"])
        except (panel_api.PanelError, EditError) as e:
            error = str(e)
            break
        rec["done"] += 1
        _save_edit(rec)
        results.append(_short_result(res))
    rec["error"] = error
    _save_edit(rec)
    if rollback_of and not error:
        orig = _load_edit(rollback_of)
        orig["rolled_back"] = rec["ts"]
        _save_edit(orig)
    total = len(p["steps"])
    out = {"ok": not error, "edit": rec["id"], "node": p["node"], "op": p["op"],
           "done_steps": f"{rec['done']} из {total}", "results": results}
    if error:
        out["detail"] = f"шаг {rec['done'] + 1} из {total} не прошёл: {error}"
        if rec["done"] and any(rec["undo"][:rec["done"]]):
            out["rollback"] = f"node_edit(op='rollback', args={{'edit': '{rec['id']}'}}) вернёт прошедшие шаги"
    elif any(rec["undo"]):
        out["rollback"] = f"node_edit(op='rollback', args={{'edit': '{rec['id']}'}})"
    return out


def _short_result(res: Any) -> Any:
    """Ответ панели коротко и маскированно: ошибки ноды и предупреждения — видно."""
    res = panel_api.redact(res)
    if isinstance(res, dict):
        keep = {k: res[k] for k in ("status", "tag", "name", "relay_server", "warning", "push_error",
                                    "display_name", "listen_port", "is_enabled", "dns_settings")
                if k in res and res[k] not in (None, "")}
        return keep or {"ok": True}
    if isinstance(res, list):
        return {"items": len(res)}
    return res


def history(limit: int = 20) -> list[dict]:
    items = []
    for f in sorted(_edits_dir().glob("*.json"), key=lambda x: x.stat().st_mtime, reverse=True)[:limit]:
        try:
            r = json.loads(f.read_text(encoding="utf-8"))
        except ValueError:
            continue
        items.append({"edit": r["id"], "ts": r["ts"], "node": r["node"], "op": r["op"],
                      "args": r.get("args"), "done": r.get("done"), "error": r.get("error") or None,
                      "rolled_back": r.get("rolled_back"), "can_rollback": any(r.get("undo") or []) and
                      r.get("op") != "rollback" and not r.get("rolled_back") and r.get("done", 0) > 0})
    return items
