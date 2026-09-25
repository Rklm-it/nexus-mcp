"""SSH к нодам — только готовыми рецептами, без произвольного шелла.

На хабе лежит ключ ко всем нодам парка, это самая ценная машина. Поэтому
MCP не даёт выполнить «любую команду»: только скрипты из `recipes.py`,
параметры которых проверены (сервис из списка, число строк в пределах,
IP — настоящий IP). Скрипт уходит в `bash -s` через stdin, поэтому
кавычки в нём не ломаются и в командную строку ssh ничего не подставляется.
"""

from __future__ import annotations

import asyncio
import re
import shlex
import time
from dataclasses import dataclass

from nexus_mcp import config

# Потолок вывода, который отдаём модели: логи бывают огромными.
MAX_OUTPUT = 60_000


@dataclass
class SshResult:
    ok: bool
    rc: int | None
    stdout: str
    stderr: str
    ms: float
    # Почему не вышло — короткое имя, по нему выбирается совет.
    failure: str | None = None

    def as_dict(self) -> dict:
        d = {"ok": self.ok, "rc": self.rc, "ms": self.ms, "stdout": self.stdout}
        if self.stderr:
            d["stderr"] = self.stderr
        if self.failure:
            d["failure"] = self.failure
            d["hint"] = FAILURE_HINTS.get(self.failure, "")
        return d


FAILURE_HINTS = {
    "timeout": "SSH не ответил вовремя: пакеты к ноде с хаба не доходят (фильтр по дороге) "
               "или нода выключена. Сверить с пробами TCP/баннер и с check-host. Нода жива, "
               "а дорога режется — заходить через живую ноду: \"ssh_via\" в nodes.json.",
    "refused": "Порт SSH закрыт: sshd не запущен или слушает другой порт (поправка ssh_port в nodes.json).",
    "unreachable": "Маршрута до ноды нет: IP сменился или машина удалена у хостера.",
    "auth": "Нода не принимает ключ хаба: публичный ключ не добавлен в authorized_keys ноды.",
    "hostkey": "Ключ хоста изменился: ноду переустановили, либо подмена. Проверить и удалить "
               "старую запись из known_hosts хаба.",
    "no_key": "На хабе нет SSH-ключа (NEXUS_SSH_KEY).",
    "remote_error": "Команда на ноде завершилась с ошибкой — см. stdout/stderr.",
    "ssh_error": "ssh завершился с ошибкой, которую хаб не распознал — причина в stderr.",
    "kill_timeout": "Команда на ноде не уложилась в отведённое время и была прервана.",
    "bad_via": "ssh_via в nodes.json не распознан: имя ноды из списка или user@host[:port].",
}

# Промежуточный узел (ssh_via) уходит в ProxyCommand, то есть в шелл: только
# user@host[:port] без лишних символов. Имя ноды inventory.merge уже заменил
# на её адрес.
_VIA_RE = re.compile(r"^(?:([a-z_][a-z0-9_-]{0,31})@)?([A-Za-z0-9.-]{1,253})(?::(\d{1,5}))?$")


def parse_via(via: str) -> tuple[str, str, int] | None:
    m = _VIA_RE.match((via or "").strip())
    if not m:
        return None
    return m.group(1) or config.settings.ssh_user, m.group(2), int(m.group(3) or 22)


def classify(stderr: str, rc: int | None) -> str | None:
    """Текст ошибки ssh → причина. rc=255 — это ошибка самого ssh, остальное —
    код команды на ноде."""
    s = (stderr or "").lower()
    if rc == 0:
        return None
    if rc == 255 or rc is None:
        if "timed out" in s or "timeout" in s:
            return "timeout"
        if "connection refused" in s:
            return "refused"
        if "no route to host" in s or "network is unreachable" in s:
            return "unreachable"
        if "permission denied" in s:
            return "auth"
        if "host key verification failed" in s or "remote host identification has changed" in s:
            return "hostkey"
        if "connection reset" in s or "connection closed" in s or "kex_exchange" in s:
            # Соединение открылось и умерло на обмене ключами — тот же почерк
            # фильтра, что «TCP есть, данных нет».
            return "timeout"
        return "ssh_error"
    return "remote_error"


def _trim(text: str) -> str:
    if len(text) <= MAX_OUTPUT:
        return text
    return "…(начало обрезано)…\n" + text[-MAX_OUTPUT:]


def _common_opts() -> list[str]:
    s = config.settings
    return [
        "-o", "BatchMode=yes",
        "-o", "ConnectTimeout=10",
        "-o", "ServerAliveInterval=5",
        "-o", "ServerAliveCountMax=3",
        "-o", "StrictHostKeyChecking=accept-new",
        "-o", f"UserKnownHostsFile={s.known_hosts}",
        "-o", "LogLevel=ERROR",
    ]


def ssh_argv(node: dict) -> list[str]:
    """argv ssh к ноде. С ssh_via — через промежуточный узел (ProxyCommand
    с тем же ключом): дорога «зарубежная нода → зарубежная нода» не режется
    там, где режется «хаб → нода»."""
    s = config.settings
    s.state_dir.mkdir(parents=True, exist_ok=True)
    argv = ["ssh", "-i", s.ssh_key, "-p", str(int(node.get("ssh_port") or 22)), *_common_opts()]
    if node.get("ssh_via"):
        via = parse_via(str(node["ssh_via"]))
        if via is None:
            raise ValueError(node["ssh_via"])
        user, host, port = via
        proxy = ["ssh", "-i", s.ssh_key, "-p", str(port), *_common_opts(), "-W", "%h:%p", f"{user}@{host}"]
        argv += ["-o", "ProxyCommand=" + " ".join(shlex.quote(x) for x in proxy)]
    return argv + [f"{node.get('ssh_user') or s.ssh_user}@{node['ssh_host']}", "bash", "-s"]


async def run_script(node: dict, script: str, timeout: float = 45.0) -> SshResult:
    """Выполнить скрипт на ноде. Никогда не бросает: отказ — это результат."""
    import os

    if not os.path.exists(config.settings.ssh_key):
        return SshResult(False, None, "", f"нет файла ключа {config.settings.ssh_key}", 0.0, "no_key")
    if not node.get("ssh_host"):
        return SshResult(False, None, "", "у ноды нет адреса", 0.0, "unreachable")
    try:
        argv = ssh_argv(node)
    except ValueError:
        return SshResult(False, None, "", f"ssh_via «{node.get('ssh_via')}» не распознан", 0.0, "bad_via")
    t0 = time.monotonic()
    proc = await asyncio.create_subprocess_exec(
        *argv,
        stdin=asyncio.subprocess.PIPE,
        stdout=asyncio.subprocess.PIPE,
        stderr=asyncio.subprocess.PIPE,
    )
    try:
        out, err = await asyncio.wait_for(proc.communicate(script.encode()), timeout=timeout)
    except asyncio.TimeoutError:
        proc.kill()
        out, err = await proc.communicate()
        ms = round((time.monotonic() - t0) * 1000, 1)
        # Разделяем «не соединились» и «соединились, но долго»: по stderr
        # ssh не видно разницы, а по выводу видно — пришёл ли хоть байт.
        failure = "kill_timeout" if out else "timeout"
        return SshResult(False, None, _trim(out.decode("utf-8", "replace")),
                         err.decode("utf-8", "replace")[-2000:], ms, failure)
    ms = round((time.monotonic() - t0) * 1000, 1)
    rc = proc.returncode
    stderr = err.decode("utf-8", "replace")[-4000:]
    failure = classify(stderr, rc)
    return SshResult(rc == 0, rc, _trim(out.decode("utf-8", "replace")), stderr, ms, failure)
