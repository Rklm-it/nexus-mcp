# Развёртывание хаба на VPS — по шагам

Итог: Claude подключается к хабу как коннектор и через него сам проверяет
**панель** (здоровье, центр состояния, юзеры, платежи, логи) и **ноды** (SSH,
доступность IP, протоколы).

**Что нужно:**
- VPS на Ubuntu 22+ или Debian 11+ с root;
- домен или поддомен, у которого A-запись указывает на IP этой VPS;
- свободный **80 порт** (Let's Encrypt).

---

## Шаг 0. Подходит ли эта VPS

Хаб должен доставать до нод **данными**, а не только по TCP. На кандидате
выполните проверку к одной-двум красным нодам:

```bash
IP=<IP красной ноды>
timeout 10 bash -c "exec 3<>/dev/tcp/$IP/22; head -c 40 <&3"; echo
timeout 10 openssl s_client -connect $IP:443 </dev/null 2>&1 | grep -E "Protocol|Cipher|errno" | head -3
```

| Результат | Значит |
|---|---|
| `SSH-2.0-OpenSSH…` и строка `Protocol : TLSv1.3` | подходит, идём дальше |
| висит 10 секунд, пусто | путь режется, как у brain: берите VPS другого хостера (зарубежную или ту, где проходит) |

Проверяйте на одной и той же ноде: быстро открывается одна, а режется другая.

## Шаг 1. Домен

У DNS-провайдера добавьте A-запись, например `mcp.вашдомен.ru` → IP VPS.
Проверка: `dig +short mcp.вашдомен.ru` возвращает IP VPS.

Если на VPS уже стоит нода Nexus, 443 порт занят xray. Тогда в шаге 3
добавьте `--port 9443`. Если занят и 80 (nginx на CDN-ноде), хаб лучше ставить
на отдельную VPS.

## Шаг 2. Токен GitHub (репо приватный)

GitHub → Settings → Developer settings → Personal access tokens →
**Fine-grained tokens** → Generate new token:
- Repository access: **Only select repositories** → `nexus-mcp`
- Permissions → Repository permissions → **Contents: Read-only**

Скопируйте токен (`github_pat_…`).

## Шаг 3. Установка

```bash
apt-get update && apt-get install -y git
git clone https://<ТОКЕН>@github.com/Rklm-it/nexus-mcp.git /root/nexus-mcp
cd /root/nexus-mcp && git remote set-url origin https://github.com/Rklm-it/nexus-mcp.git

bash install.sh \
  --domain mcp.вашдомен.ru \
  --brain-url https://ваша-панель.ru \
  --brain-token <VPN_ADMIN_TOKEN из /opt/vgx3d/.env панели>
# если 443 занят: добавьте --port 9443
```

Токен панели: на сервере панели `grep ^VPN_ADMIN_TOKEN /opt/vgx3d/.env`.

Установщик сам ставит зависимости, xray для проверок, Caddy с сертификатом и
systemd-сервисы `nexus-mcp` и `nexus-mcp-caddy`. В конце он печатает три
вещи, **сохраните их**:
1. адрес коннектора `https://mcp.вашдомен.ru/mcp/<секрет>`;
2. публичный ключ хаба `ssh-ed25519 AAAA… nexus-mcp@…`;
3. команду для домашнего пробника.

Проверка:
```bash
systemctl status nexus-mcp nexus-mcp-caddy --no-pager | grep Active
curl -s https://mcp.вашдомен.ru/healthz        # {"ok":true,"service":"nexus-mcp"}
```

## Шаг 4. Ключ хаба на ноды

Хаб заходит на ноды по SSH своим ключом. Добавьте ключ на каждую ноду.

**Если с хаба ноды пускают по паролю:**
```bash
ssh-copy-id -i /etc/nexus-mcp/id_ed25519.pub root@<IP ноды>
```

**Если на ноду у вас уже есть доступ откуда-то** (свой компьютер, живая нода):
```bash
echo '<публичный ключ хаба>' | ssh root@<IP ноды> 'mkdir -p ~/.ssh && cat >> ~/.ssh/authorized_keys'
# через живую ноду как прыжок:
echo '<ключ>' | ssh -J root@<живая нода> root@<красная> 'mkdir -p ~/.ssh && cat >> ~/.ssh/authorized_keys'
```

**Если никак** — веб-консоль (VNC) в панели хостера, вставить ключ в
`/root/.ssh/authorized_keys`.

Проверка с хаба:
```bash
ssh -i /etc/nexus-mcp/id_ed25519 -o BatchMode=yes root@<IP ноды> 'cat /opt/vpn-cell/agent/VERSION'
```

SSH на нестандартном порту или не под root — впишите это в
`/etc/nexus-mcp/nodes.json`:
```json
{"defaults": {"ssh_user": "root", "ssh_port": 22},
 "nodes": [{"name": "имя-как-в-панели", "ssh_port": 2222}]}
```

## Шаг 5. Тестовый юзер для сквозной проверки

В панели заведите юзера, например `mcp-test`: без лимитов, привязанного **ко всем
нодам**. Скопируйте его ссылку подписки и впишите в `/etc/nexus-mcp.env`:
```
NEXUS_TEST_SUB_URL=https://ваша-панель.ru/sub/<токен>
```
Без этого хаб проверяет всё, кроме «работает ли протокол на самом деле».

## Шаг 6. Действия (по желанию)

Чтобы хаб мог обновлять агент, прописывать адрес панели и перезапускать
сервисы на нодах, добавьте в `/etc/nexus-mcp.env`:
```
NEXUS_ALLOW_ACTIONS=1
```
Каждое действие Claude всё равно делает только после вашего «да» (`confirm=true`),
и всё пишется в `/var/lib/nexus-mcp/audit.jsonl`.

После правок `.env`:
```bash
systemctl restart nexus-mcp
```

## Шаг 7. Коннектор в claude.ai

claude.ai → **Settings → Connectors → Add custom connector**:
- Name: `Nexus nodes`
- URL: `https://mcp.вашдомен.ru/mcp/<секрет>` (из шага 3)

Новый коннектор появляется в **новых** сессиях. Для проверки скажите
Claude: «проверь панель и красные ноды через nexus». Он вызовет `panel_health`,
`panel_findings`, `nodes_list` и `fleet_check`.

Секрет лежит в `/etc/nexus-mcp.env`, строка `NEXUS_MCP_SECRET`. Сменить его: впишите
новый (40+ символов), выполните `systemctl restart nexus-mcp` и поменяйте URL коннектора.

## Шаг 8. Домашний пробник

Для домашних нод это главное: проверка из **домашнего** интернета, где сидят
клиенты. Нужен компьютер или роутер, который включён постоянно.

**Linux / роутер с python3:**
```bash
mkdir -p ~/nexus-probe && cd ~/nexus-probe
scp root@<хаб>:/opt/nexus-mcp/app/probe/probe.py .
# xray для сквозной проверки (необязательно, но желательно):
curl -fsSLO https://github.com/XTLS/Xray-core/releases/latest/download/Xray-linux-64.zip && unzip -o Xray-linux-64.zip xray
python3 probe.py --hub https://mcp.вашдомен.ru --token <PROBE_TOKEN> --name ростелеком-дом --xray ./xray
```

Автозапуск (systemd):
```bash
cat > /etc/systemd/system/nexus-probe.service <<'EOF'
[Unit]
Description=Nexus probe
After=network-online.target
[Service]
WorkingDirectory=/root/nexus-probe
ExecStart=/usr/bin/python3 /root/nexus-probe/probe.py --hub https://mcp.вашдомен.ru --token <PROBE_TOKEN> --name ростелеком-дом --xray /root/nexus-probe/xray
Restart=always
RestartSec=10
[Install]
WantedBy=multi-user.target
EOF
systemctl daemon-reload && systemctl enable --now nexus-probe
```

**Windows:**
1. Поставить Python с python.org, отметив «Add to PATH».
2. Скачать `probe.py` и `Xray-windows-64.zip` (распаковать `xray.exe` рядом).
3. Запуск:
   `python probe.py --hub https://mcp.вашдомен.ru --token <PROBE_TOKEN> --name дом-мтс --xray xray.exe`
4. Автозапуск: Планировщик заданий → создать задачу → триггер «При входе в систему».

В `--name` пишите провайдера: в отчёте будет видно, у кого что режут.
`PROBE_TOKEN` лежит в `/etc/nexus-mcp.env`, строка `NEXUS_PROBE_TOKENS`.
Пробник у знакомых — дайте им отдельный токен: впишите его через запятую
в `NEXUS_PROBE_TOKENS`.

Проверка без хаба: `python3 probe.py --once <IP ноды>`.

## Обновление хаба

```bash
cd /root/nexus-mcp
git pull https://<ТОКЕН>@github.com/Rklm-it/nexus-mcp.git main   # токен в .git/config не хранится
bash install.sh --domain mcp.вашдомен.ru      # добавьте --port 9443, если ставили с ним
```
Секреты, ключ и настройки сохраняются: установщик читает их из `/etc/nexus-mcp.env`.

## Если что-то не так

| Симптом | Где смотреть |
|---|---|
| установщик остановился | последняя строка `[x] …` называет шаг и причину |
| `healthz` не отвечает по https | `journalctl -u nexus-mcp-caddy -n 50`: сертификат (A-запись, 80 порт) |
| хаб не стартует | `journalctl -u nexus-mcp -n 50`: чаще всего короткий `NEXUS_MCP_SECRET` |
| коннектор «не может подключиться» | URL целиком, с `/mcp/<секрет>`; `curl https://…/healthz` снаружи |
| `ssh_auth` в отчёте | ключ хаба не добавлен на ноду (шаг 4) |
| `ssh_timeout` на всех нодах | с этой VPS путь до нод режется: шаг 0 не пройден |
| «список из панели не получен» | `--brain-url` / `--brain-token`; если `/api` панели за паролем — `NEXUS_BRAIN_BASIC_AUTH=user:pass` |
| пробник «не на связи» | запущен ли `probe.py` дома, верный ли `--token` (при неверном печатает `хаб ответил 401`) |
