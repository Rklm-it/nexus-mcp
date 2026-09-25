# Развёртывание хаба на VPS — по шагам

Итог: Claude подключается к хабу как коннектор и через него сам проверяет
**панель** (здоровье, центр состояния, юзеры, платежи, логи) и **ноды** (SSH,
доступность IP, протоколы).

**Что нужно:** VPS на Ubuntu 22+ или Debian 11+ с root, свободный **80 порт**
(для сертификата). Домен не обязателен.

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

## Шаг 1. Два токена

- **GitHub** (репо приватный): GitHub → Settings → Developer settings →
  Personal access tokens → **Fine-grained tokens** → Generate new token →
  Repository access: **Only select repositories** → `nexus-mcp` →
  Permissions → **Contents: Read-only**. Скопируйте `github_pat_…`.
- **Панели**: на сервере панели `grep ^VPN_ADMIN_TOKEN /opt/vgx3d/.env`.

## Шаг 2. Установка — одна команда

На VPS под root:

```bash
T=<github_pat_…>
curl -fsSL -H "Authorization: Bearer $T" -H "Accept: application/vnd.github.raw" \
  https://api.github.com/repos/Rklm-it/nexus-mcp/contents/install.sh \
  | bash -s -- --token "$T" \
      --brain-url https://<адрес вашей панели> \
      --brain-token <VPN_ADMIN_TOKEN>
```

Сам установщик:
- **адрес хаба** — `<IP>.sslip.io`, домен и DNS не нужны. Свой поддомен:
  `--domain mcp.вашдомен.ru` (A-запись на IP VPS);
- **порт** — 443, а если его занял xray (на VPS стоит нода), 9443;
- **ставит** зависимости, xray для проверок, Caddy с сертификатом Let's Encrypt
  (порт **80** должен быть свободен), сервисы `nexus-mcp` и `nexus-mcp-caddy`.

В конце он печатает три вещи, **сохраните их**:
1. адрес коннектора `https://…/mcp/<секрет>`;
2. публичный ключ хаба `ssh-ed25519 AAAA… nexus-mcp@…`;
3. команду для домашнего пробника.

Проверка:
```bash
systemctl status nexus-mcp nexus-mcp-caddy --no-pager | grep Active
curl -s https://<адрес хаба>/healthz        # {"ok":true,"service":"nexus-mcp"}
```

## Шаг 3. Ключ хаба на ноды

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

## Шаг 4. Тестовый юзер для сквозной проверки

В панели заведите юзера, например `mcp-test`: без лимитов, привязанного **ко всем
нодам**. Скопируйте его ссылку подписки и впишите в `/etc/nexus-mcp.env`:
```
NEXUS_TEST_SUB_URL=https://ваша-панель.ru/sub/<токен>
```
Без этого хаб проверяет всё, кроме «работает ли протокол на самом деле».

## Шаг 5. Действия (по желанию)

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

## Шаг 6. Коннектор в claude.ai

claude.ai → **Settings → Connectors → Add custom connector**:
- Name: `Nexus nodes`
- URL: адрес коннектора из шага 2

Новый коннектор появляется в **новых** сессиях. Для проверки скажите
Claude: «проверь панель и красные ноды через nexus». Он вызовет `panel_health`,
`panel_findings`, `nodes_list` и `fleet_check`.

Секрет лежит в `/etc/nexus-mcp.env`, строка `NEXUS_MCP_SECRET`. Сменить его: впишите
новый (40+ символов), выполните `systemctl restart nexus-mcp` и поменяйте URL коннектора.

## Шаг 7. Домашний пробник

Для домашних нод это главное: проверка из **домашнего** интернета, где сидят
клиенты. Нужен компьютер или роутер, который включён постоянно.

**Linux / роутер с python3:**
```bash
mkdir -p ~/nexus-probe && cd ~/nexus-probe
scp root@<хаб>:/opt/nexus-mcp/app/probe/probe.py .
# xray для сквозной проверки (необязательно, но желательно):
curl -fsSLO https://github.com/XTLS/Xray-core/releases/latest/download/Xray-linux-64.zip && unzip -o Xray-linux-64.zip xray
python3 probe.py --hub <адрес хаба> --token <PROBE_TOKEN> --name ростелеком-дом --xray ./xray
```

Автозапуск (systemd):
```bash
cat > /etc/systemd/system/nexus-probe.service <<'EOF'
[Unit]
Description=Nexus probe
After=network-online.target
[Service]
WorkingDirectory=/root/nexus-probe
ExecStart=/usr/bin/python3 /root/nexus-probe/probe.py --hub <адрес хаба> --token <PROBE_TOKEN> --name ростелеком-дом --xray /root/nexus-probe/xray
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
   `python probe.py --hub <адрес хаба> --token <PROBE_TOKEN> --name дом-мтс --xray xray.exe`
4. Автозапуск: Планировщик заданий → создать задачу → триггер «При входе в систему».

В `--name` пишите провайдера: в отчёте будет видно, у кого что режут.
`PROBE_TOKEN` лежит в `/etc/nexus-mcp.env`, строка `NEXUS_PROBE_TOKENS`.
Пробник у знакомых — дайте им отдельный токен: впишите его через запятую
в `NEXUS_PROBE_TOKENS`.

Проверка без хаба: `python3 probe.py --once <IP ноды>`.

## Обновление хаба

Та же команда из шага 2, можно без `--brain-*`. Адрес, порт, секреты, ключ и
настройки установщик берёт из `/etc/nexus-mcp.env`, поэтому URL коннектора
не меняется.

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
