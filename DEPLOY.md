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

## Шаг 1. Два значения из панели

На сервере панели:
```bash
grep -E '^(VPN_ADMIN_TOKEN|VPN_PANEL_GATE_SECRET)=' /opt/nexus/.env
```
Каталог панели: `/opt/nexus` у клиентской установки (лицензия), `/opt/vgx3d` у
мастера — дальше везде подставляйте свой.
`VPN_ADMIN_TOKEN` — токен админ-API. `VPN_PANEL_GATE_SECRET` пропускает хаб мимо
пароля Caddy (Basic Auth), которым закрыт `/api` панели. Пароль Basic Auth
вспоминать не нужно.

## Шаг 2. Установка — одна команда

На VPS под root:

```bash
bash <(curl -fsSL --connect-timeout 15 https://raw.githubusercontent.com/Rklm-it/nexus-mcp/main/install.sh) \
  --brain-url https://<адрес вашей панели> \
  --brain-token <VPN_ADMIN_TOKEN> --brain-gate <VPN_PANEL_GATE_SECRET>
```

Сам установщик:
- **адрес хаба** — `<IP>.sslip.io`, домен и DNS не нужны. Свой поддомен:
  `--domain mcp.вашдомен.ru` (A-запись на IP VPS);
- **порт** — 443, а если его занял xray (на VPS стоит нода), 9443;
- **ставит** зависимости, xray для проверок, Caddy с сертификатом Let's Encrypt
  (порт **80** должен быть свободен), сервисы `nexus-mcp` и `nexus-mcp-caddy`.
- **идёт в фоне** (юнит `nexus-mcp-install`), на экране — её лог. Оборвалось
  SSH или нажали Ctrl+C — установка продолжается: переподключитесь и запустите
  ту же команду (покажет лог идущей) или `tail -f /var/log/nexus-mcp-install.log`.
  Без фона — `--foreground`.

В конце он печатает всё нужное дальше. **Потеряли — не страшно**, в любой
момент на хабе:

```bash
nexus-mcp-info          # ссылка коннектора, ключ хаба, команда пробника, панели
nexus-mcp-info --url    # только ссылка коннектора
```

Что там:
1. адрес коннектора `https://…/mcp/<секрет>`;
2. публичный ключ хаба `ssh-ed25519 AAAA… nexus-mcp@…`;
3. команду для домашнего пробника.

Проверка:
```bash
systemctl status nexus-mcp nexus-mcp-caddy --no-pager | grep Active
curl -s https://<адрес хаба>/healthz        # {"ok":true,"service":"nexus-mcp"}
```

## Несколько панелей

Один хаб и один коннектор на все панели. Первая добавляется установкой
(`--brain-url`, это панель `main`), остальные — командой на хабе:

```bash
nexus-mcp-panels add vip   https://panel.example.ru/vip <VPN_ADMIN_TOKEN VIP-контура> --gate <VPN_PANEL_GATE_SECRET>
nexus-mcp-panels add shop2 https://p2.example.com <её VPN_ADMIN_TOKEN> --gate <её VPN_PANEL_GATE_SECRET>
nexus-mcp-panels list
nexus-mcp-panels remove shop2
```

Хаб подхватывает изменения сразу, перезапуск не нужен. Ноды всех панелей
видны вместе, а при нескольких панелях называются `панель/имя` (`shop2/de-1`).
Инструментам панели Claude передаёт `panel=<имя>`.

⚠️ Хаб хранит токены всех панелей и SSH-ключ ко всем их нодам. Свои панели
держите на одном хабе. Панели **чужих клиентов** — на отдельных хабах с
отдельными коннекторами: взлом одного хаба не должен открывать всех.

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

**Хаб до ноды не достаёт** (SSH с хаба висит или рвётся, а нода жива) —
заходить через живую ноду: из-за границы дорога до ноды обычно чистая.
`ssh_via` — имя другой ноды или `user@host:port`; ключ хаба нужен на обеих:
```json
{"defaults": {"ssh_user": "root", "ssh_port": 22},
 "nodes": [{"name": "eng41s2", "ssh_via": "ger41s2"}]}
```
Проверки доступности IP (TCP, данные, TLS) при этом идут напрямую — они и
меряют прямую дорогу. Файл читается на каждом запросе, перезапуск не нужен.

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
- URL: адрес коннектора — `nexus-mcp-info --url` на хабе

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

## Шаг 8. Чат с Claude в приложении Nexus Admin

Установщик ставит рядом с хабом сервис `nexus-chat`: в нём Claude работает на
**вашей подписке** (Pro/Max) и пользуется всеми инструментами этого хаба, то
есть видит все его панели и ноды. В приложении это полноценный чат: ответ
печатается по мере написания, видно, какие проверки Claude запускает. Действия
(перезапуск, обновление агента, действия в панели) ждут вашей кнопки
«Разрешить». Встроенных инструментов Claude Code (шелл, файлы) в чате нет:
на хабе лежит ключ ко всем нодам.

⚠ **Сервер должен стоять в стране, где Claude доступен.** Anthropic не
обслуживает часть стран, в т.ч. РФ: с такого IP и вход, и ответы получают
`403 forbidden` («Request not allowed»). Проверка:
`curl -s -X POST https://api.anthropic.com/v1/messages -d '{}'` — `forbidden`
значит «не отсюда», `authentication_error` — сеть в порядке.
`nexus-chat-login` проверяет это сам.

**1. Войти в подписку** — один раз, на хабе:
```bash
nexus-chat-login
```
Команда покажет ссылку: откройте её в браузере (можно на телефоне), войдите в
claude.ai, подтвердите и вставьте код обратно. Claude Code напечатает токен
`sk-ant-oat01-…`, его нужно вставить ещё раз. Команда проверит его живым
запросом и перезапустит чат. Если токен уже получен на ПК (`claude setup-token`),
передайте его аргументом: `nexus-chat-login <токен>`. Проверить вход:
`nexus-chat-login --status`.

**2. Подключить приложение.** `nexus-mcp-info` в пункте 5 печатает строку
`https://<хаб>/chat#<токен>`. В приложении: вкладка «Ещё» → «Claude» →
«Подключить хаб», вставить строку.

**Настройки** в `/etc/nexus-mcp.env`, после правки `systemctl restart nexus-chat`:

| Переменная | Что |
|---|---|
| `NEXUS_CHAT_AUDIT_AT` | плановый аудит, например `09:00,21:00`: Claude сам проходит все панели и присылает сводку уведомлением |
| `NEXUS_CHAT_TZ` | часовой пояс для аудита, по умолчанию `Europe/Moscow` |
| `NEXUS_CHAT_MODEL` | модель; пусто — по умолчанию Claude Code для вашей подписки |
| `NEXUS_CHAT_EFFORT` | `low` … `max`; пусто — по умолчанию |
| `NEXUS_CHAT_APPROVAL_MIN` | сколько минут ждать кнопки «Разрешить» (по умолчанию 30) |

Лимиты у чата и у Claude Code на ПК общие: это одна подписка. Когда лимит
близко, чат пишет об этом в ленте.

Сами действия выполняются только при `NEXUS_ALLOW_ACTIONS=1` (шаг 5). Без него
кнопка «Разрешить» пропустит вызов, но хаб ответит «действия выключены».

## Шаг 9. SIM-проверки операторов (bschekbot, по желанию)

Хаб и домашние пробники стоят на проводном интернете и не видят, что делает
с трафиком мобильный оператор, тем более с **включёнными белыми списками**.
У bschekbot (bsbord.com) стоят SIM-карты каждого оператора в каждом
федеральном округе, с белым списком и без. Через хаб Claude может:

- `sim_probe` — проверить IP, домен, порт и TLS-SNI ноды глазами МТС, Билайна,
  Мегафона, Т2, Yota… в нужных округах (`node=` сам берёт порты, CF-фронт и SNI);
- `sim_vless` — проверить, поднимается ли туннель (VLESS/Reality, Hysteria2 и
  др.) с этих SIM;
- `sim_geo` — узнать, из каких городов РФ открывается цель (домашние и
  мобильные провайдеры);
- `sim_units`, `sim_account`, `sim_result`, `sim_cancel` — единицы, баланс,
  результат долгой проверки и её отмена (бесплатно).

**Ключ:** кабинет bsbord.com → API (тариф Bronze и выше), ключ `bsk_live_…`
показывается один раз. В `/etc/nexus-mcp.env`:
```
NEXUS_BSBORD_KEY=bsk_live_…
NEXUS_BSBORD_DAILY_RUB=300
```
затем `systemctl restart nexus-mcp nexus-chat`. Можно сразу при установке:
`--bsbord-key bsk_live_…`.

**Деньги.** Проверки платные. Каждая идёт в два шага:
1. бесплатный preview: цена и какие единицы поедут;
2. запуск с `confirm=true` и потолком `max_credits`, не ниже цены из preview.

В чате приложения запуск ждёт кнопки «Разрешить» с ценой в заголовке. Сверху
действует дневной потолок хаба `NEXUS_BSBORD_DAILY_RUB`: сверх него хаб
откажет сам. Расходы пишутся в `/var/lib/nexus-mcp/bsbord_spend.jsonl`.

⚠ `sim_vless` и `sim_geo` с `node=` отправляют сервису ссылки ноды из
**тестовой** подписки (`NEXUS_TEST_SUB_URL`). Ссылки клиентов туда не уходят.

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
| «список из панели не получен» / 401 | `--brain-url` / `--brain-token` / `--brain-gate` (значения из `.env` панели, шаг 1) |
| пробник «не на связи» | запущен ли `probe.py` дома, верный ли `--token` (при неверном печатает `хаб ответил 401`) |
| приложение: «Claude на хабе не вошёл в подписку» | `nexus-chat-login` на хабе |
| приложение: «неверный токен чата» | строку подключения заново из `nexus-mcp-info` (пункт 5) |
| в чате «HTTP 401» / «invalid token» | токен подписки отозван или истёк: `nexus-chat-login` |
| `sim_*`: `tier_too_low` / `api_not_available` | тариф bschekbot ниже Bronze или у ключа нет доступа к API |
| `sim_*`: `daily_cap` | исчерпан дневной потолок хаба: `NEXUS_BSBORD_DAILY_RUB` |
| `sim_*`: `insufficient_credits` | пополнить баланс в кабинете bsbord.com |
| чат не отвечает | `journalctl -u nexus-chat -n 50`; `curl -s 127.0.0.1:8766/chat/healthz` |
