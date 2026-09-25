"""Точки обзора: сам хаб и домашние пробники.

Пробник сам приходит к хабу (`POST /probe/poll`, держим до 25 с), забирает
задания и возвращает результаты (`POST /probe/result`). Хаб ждёт результат
на future. Всё в памяти процесса: пробники переподключаются сами, а
незавершённые задания после рестарта хаба никому не нужны.

Имя `hub` зарезервировано: это проверки с самого хаба, тем же кодом
`probe/probe.py`, что работает дома.
"""

from __future__ import annotations

import asyncio
import importlib.util
import itertools
import time
from dataclasses import dataclass, field
from functools import lru_cache
from pathlib import Path
from types import ModuleType

HUB = "hub"
POLL_HOLD_S = 25.0
# Пробник, не приходивший дольше этого, считаем отключённым.
PROBE_STALE_S = 90.0


@lru_cache(maxsize=1)
def probe_lib() -> ModuleType:
    """probe.py — единственный источник проб: и дома, и на хабе."""
    path = Path(__file__).resolve().parents[1] / "probe" / "probe.py"
    spec = importlib.util.spec_from_file_location("nexus_probe", path)
    mod = importlib.util.module_from_spec(spec)
    assert spec.loader is not None
    spec.loader.exec_module(mod)
    return mod


@dataclass
class Probe:
    name: str
    last_seen: float = 0.0
    info: dict = field(default_factory=dict)
    remote_addr: str = ""
    queue: asyncio.Queue = field(default_factory=asyncio.Queue)


class ProbeError(Exception):
    pass


class Registry:
    def __init__(self) -> None:
        self.probes: dict[str, Probe] = {}
        self.pending: dict[str, asyncio.Future] = {}
        self._ids = itertools.count(1)

    def _get(self, name: str) -> Probe:
        p = self.probes.get(name)
        if p is None:
            p = self.probes[name] = Probe(name=name)
        return p

    # ── Сторона пробника ──

    async def poll(self, name: str, info: dict | None, remote_addr: str,
                   hold: float = POLL_HOLD_S) -> list[dict]:
        if name == HUB:
            raise ProbeError("имя «hub» зарезервировано за самим хабом")
        p = self._get(name)
        p.last_seen = time.time()
        p.remote_addr = remote_addr
        if info:
            p.info = info
        jobs: list[dict] = []
        try:
            jobs.append(await asyncio.wait_for(p.queue.get(), timeout=hold))
        except asyncio.TimeoutError:
            return []
        while not p.queue.empty() and len(jobs) < 10:
            jobs.append(p.queue.get_nowait())
        p.last_seen = time.time()
        return jobs

    def result(self, name: str, job_id: str, result: dict) -> bool:
        p = self.probes.get(name)
        if p:
            p.last_seen = time.time()
        fut = self.pending.pop(str(job_id), None)
        if fut is None or fut.done():
            return False
        fut.set_result(result)
        return True

    # ── Сторона хаба ──

    def list(self) -> list[dict]:
        now = time.time()
        out = [{"name": HUB, "online": True, "where": "сам хаб"}]
        for p in sorted(self.probes.values(), key=lambda x: x.name):
            age = round(now - p.last_seen, 1) if p.last_seen else None
            out.append({
                "name": p.name,
                "online": age is not None and age <= PROBE_STALE_S,
                "last_seen_s": age,
                "remote_addr": p.remote_addr,
                "xray": bool((p.info or {}).get("xray")),
                "platform": (p.info or {}).get("platform"),
                "queued": p.queue.qsize(),
            })
        return out

    async def run(self, probe: str, kind: str, args: dict, timeout: float = 40.0) -> dict:
        """Выполнить задание на пробнике и дождаться результата."""
        if probe == HUB:
            lib = probe_lib()
            from nexus_mcp import config

            return await asyncio.to_thread(lib.run_job, kind, args, config.settings.xray_bin or None)
        p = self.probes.get(probe)
        if p is None:
            known = ", ".join([HUB, *self.probes]) or HUB
            raise ProbeError(f"пробник «{probe}» ни разу не подключался. Есть: {known}")
        if not p.last_seen or time.time() - p.last_seen > PROBE_STALE_S:
            raise ProbeError(f"пробник «{probe}» не на связи {round(time.time() - p.last_seen)} с "
                             "— проверьте, запущен ли probe.py дома")
        job_id = str(next(self._ids))
        fut: asyncio.Future = asyncio.get_running_loop().create_future()
        self.pending[job_id] = fut
        await p.queue.put({"id": job_id, "kind": kind, "args": args})
        try:
            return await asyncio.wait_for(fut, timeout=timeout)
        except asyncio.TimeoutError:
            self.pending.pop(job_id, None)
            return {"ok": False, "error": "probe_timeout",
                    "detail": f"пробник «{probe}» не вернул результат за {timeout:.0f} с"}


registry = Registry()
