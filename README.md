> **Версия 2.1.0: кабинет проекта и несколько почтовых ящиков Beget.**
> Инструкция установки и использования: [BEGET_UPDATE.md](BEGET_UPDATE.md).
> Для проекта с подключёнными ящиками следуйте DNS-инструкции Beget; рекомендации самостоятельного MX ниже относятся только к прежнему режиму.

> **Обновлённая версия:** сначала прочитайте [UPGRADE.md](UPGRADE.md). Безопасные defaults и поведение SMTP изменены: relay-only, STARTTLS AUTH, явные SMTP-домены аккаунта, optional inbound, encrypted secrets, новая очередь. Ниже сохранена историческая справка; при расхождении приоритет у UPGRADE.md и .env.example. Desktop/mobile QA выполнена на изолированной тестовой БД; результаты — reports/VISUAL_QA.md.

# SMTP Service

SMTP-сервис с веб-панелью администратора для управления отправкой email.

## Возможности

- **SMTP-сервер** — приём входящих писем с аутентификацией
- **REST API** — отправка писем через HTTP (`POST /api/send`)
- **Админ-панель** — управление сайтами, шаблонами и просмотр логов
- **Шаблоны** — HTML-шаблоны с переменными (`{{code}}`, `{{name}}` и т.д.)
- **Внешние провайдеры** — Postmark, SendGrid, Mailgun, SES, Yandex: пресеты, проверка коннекта и failover через REST API
- **Webhooks** — подписанные события о письмах в ваши системы
- **Docker** — готов к деплою на VPS

## Быстрый старт (одна команда)

```bash
git clone https://github.com/acoulbot/smtp.git && cd smtp && bash setup.sh
```

По умолчанию запускается на порту **3005**. Для другого порта:

```bash
bash setup.sh --port 8080
```

С настройкой relay (для отправки писем):

```bash
bash setup.sh --relay-host smtp.yandex.ru --relay-user email@yandex.ru --relay-pass app-password
```

Все опции: `bash setup.sh --help`

### Ручная установка (без скрипта)

```bash
git clone https://github.com/acoulbot/smtp.git
cd smtp
cp .env.example .env
nano .env
docker compose up -d
```

### Без Docker

```bash
# Python 3.11+
pip install .

# Запустить
python -m app  # WEB_PORT=3005 по умолчанию; WEB_HOST=127.0.0.1
```

## Конфигурация (.env)

| Переменная | Описание | По умолчанию |
|---|---|---|
| `SMTP_DOMAIN` | Домен SMTP-сервера | `localhost` |
| `SMTP_PORT` | Порт SMTP (внутри контейнера) | `2525` |
| `WEB_PORT` | Порт веб-панели | `3005` |
| `ADMIN_USERNAME` | Логин админки | `admin` |
| `ADMIN_PASSWORD` | Пароль админки | задаётся при установке |
| `SECRET_KEY` | Ключ для сессий | `change-me...` |
| `RELAY_HOST` | SMTP-хост для отправки | — |
| `RELAY_PORT` | Порт relay | `587` |
| `RELAY_USERNAME` | Логин relay | — |
| `RELAY_PASSWORD` | Пароль relay | — |

## API

### Проверка статуса

```bash
curl http://localhost:3005/api/health
```

### Проверка ключа (`GET /api/me`)

Точка входа для интеграции: сторонний проект просит пользователя вставить ключ и
проверяет его здесь. `401` — ключ неверный, `200` — вот что он даёт.

```bash
curl https://smtp.example.com/api/me -H "Authorization: Bearer sm_ваш_ключ_сайта"
```

```json
{
  "type": "site",
  "site": { "domain": "alpha.ru", "name": "Проект A",
            "sender_email": "noreply@alpha.ru", "is_active": true,
            "has_relay": true, "dkim_configured": true },
  "scopes": ["emails:send", "domains:read", "webhooks:manage", "providers:manage"],
  "service": { "version": "2.0.0", "smtp_domain": "mail.alpha.ru" }
}
```

Глобальный `API_KEY` отвечает `{"type": "global", "site": null, "scopes": ["*"],
"sites_count": 2, ...}`.

Ответ намеренно не содержит секретов — ни самого ключа, ни пароля relay, ни
приватного ключа DKIM — поэтому его безопасно логировать на стороне клиента.
Типовой сценарий «подключить сервис»:

```js
const r = await fetch(`${SMTP_URL}/api/me`, {
  headers: { Authorization: `Bearer ${key}` },
});
if (r.status === 401) return { error: "Неверный ключ" };
const me = await r.json();
// сохранить key зашифрованным на СЕРВЕРЕ и показать «Подключено к me.site.domain»
```

Ключ должен жить только на бэкенде: попав в браузер, он позволит любому
посетителю отправлять письма от вашего домена.

### Отправка письма

Аутентификация обязательна для всех эндпоинтов кроме `/api/health`,
`/api/webhooks/events` и `/api/providers/presets`. Ключ каждого сайта смотрите в
админке (**Сайты → API ключ**).

Ключ сайта видит только свой сайт: `GET /api/domains` вернёт один домен, а
`GET /api/domains/{другой-домен}/dns` ответит `404`. Полный список домейнов
доступен только глобальному `API_KEY`.

```bash
curl -X POST http://localhost:3005/api/emails \
  -H "Content-Type: application/json" \
  -H "Authorization: Bearer sm_ваш_ключ_сайта" \
  -d '{
    "from_email": "noreply@example.com",
    "to": "user@mail.com",
    "subject": "Код подтверждения",
    "html": "<p>Ваш код: <b>123456</b></p>"
  }'
```

Через заранее настроенный шаблон:

```bash
curl -X POST http://localhost:3005/api/send \
  -H "Content-Type: application/json" \
  -H "Authorization: Bearer sm_ваш_ключ_сайта" \
  -d '{
    "site_domain": "example.com",
    "template_slug": "verification-code",
    "to_email": "user@mail.com",
    "variables": {"code": "123456"}
  }'
```

## Внешние SMTP-провайдеры

Отправку можно вести через внешнего провайдера (это лучший вариант для
доставляемости) и управлять этим через API, а не только руками в админке.

### Пресеты

`GET /api/providers/presets` отдаёт готовые настройки: Postmark, SendGrid,
Mailgun, Amazon SES, Yandex 360, Gmail и `custom`. Пресет заполняет host, порт и
TLS и подсказывает, что провайдер ждёт в качестве логина — например, у SendGrid
это буквально слово `apikey`, а у Postmark один и тот же токен идёт и логином, и
паролем. Любое поле можно переопределить.

### Подключение

```bash
# сначала проверить креды, ничего не сохраняя
curl -X POST http://localhost:3005/api/providers/test \
  -H "Content-Type: application/json" \
  -H "Authorization: Bearer sm_ваш_ключ_сайта" \
  -d '{"host": "smtp.postmarkapp.com", "port": 587, "username": "ТОКЕН", "password": "ТОКЕН"}'

# затем сохранить
curl -X POST http://localhost:3005/api/providers \
  -H "Content-Type: application/json" \
  -H "Authorization: Bearer sm_ваш_ключ_сайта" \
  -d '{"name": "Postmark", "preset": "postmark", "username": "ТОКЕН", "password": "ТОКЕН", "priority": 10}'
```

| Метод и путь | Назначение |
|---|---|
| `GET /api/providers/presets` | известные провайдеры и их настройки по умолчанию |
| `GET /api/providers` | провайдеры сайта, по возрастанию `priority` |
| `POST /api/providers` | добавить провайдера |
| `GET /api/providers/{id}` | один провайдер |
| `PATCH /api/providers/{id}` | изменить; пропущенные поля не трогаются |
| `DELETE /api/providers/{id}` | удалить |
| `POST /api/providers/test` | проверить произвольные host/port/креды **без сохранения** |
| `POST /api/providers/{id}/test` | проверить сохранённого провайдера, результат пишется в `last_test_ok` |
| `GET /api/providers/{id}/resolved-order` | какой relay реально будет использован и в каком порядке |

Проверка коннекта не просто говорит «не работает» — она возвращает список
пройденных шагов, поэтому видно, где именно сломалось: недоступен хост, не вышло
со STARTTLS или отвергнуты креды.

```json
{"ok": true, "error": "", "steps": [
  "connected to smtp.postmarkapp.com:587", "EHLO accepted (250)",
  "STARTTLS negotiated", "authenticated as ТОКЕН"]}
```

Пароли **write-only**: в ответах их нет, вместо этого приходит
`has_password: true`. `PATCH` без поля `password` сохраняет текущий пароль, а с
ним — сбрасывает результат прошлой проверки, потому что он больше ничего не
доказывает.

### Какой relay победит

Порядок жёсткий и обратно совместимый:

1. активные провайдеры сайта — по `priority`, затем по id;
2. поля `relay_*` самого сайта (те, что в форме админки);
3. глобальные `RELAY_*` из `.env`;
4. если ничего не настроено — прямая доставка по MX получателя.

Отправка идёт по этому списку сверху вниз: если провайдер не отвечает,
берётся следующий, и письмо не теряется. В логе и в вебхуке видно, через кого
оно в итоге ушло (поле `relay`). Проверить порядок для конкретного сайта —
`GET /api/providers/{id}/resolved-order`.

> Порт **465** — это implicit TLS (SMTPS), а не STARTTLS. Раньше любой relay шёл
> через `SMTP` + `starttls()`, из-за чего 465 не работал вовсе — а Yandex
> документирует именно его. Теперь порт 465 определяется автоматически.

## Webhooks

Сервис умеет сам сообщать вашим системам о судьбе писем — чтобы подключить CRM,
Slack или собственный бэкенд, не опрашивая логи.

### События

| Событие | Когда |
|---|---|
| `email.sent` | письмо принято следующим узлом (relay или MX получателя) |
| `email.failed` | доставить не удалось, попытки исчерпаны |
| `email.received` | на один из ваших доменов пришло входящее письмо |

### Подписка

```bash
curl -X POST http://localhost:3005/api/webhooks \
  -H "Content-Type: application/json" \
  -H "Authorization: Bearer sm_ваш_ключ_сайта" \
  -d '{
    "url": "https://example.com/hooks/smtp",
    "events": ["email.sent", "email.failed"],
    "description": "продакшн-бэкенд"
  }'
```

В ответе придёт `secret` — сохраните его, им проверяется подпись. Полный набор:

| Метод и путь | Назначение |
|---|---|
| `GET /api/webhooks/events` | список доступных событий |
| `GET /api/webhooks` | список подписок сайта |
| `POST /api/webhooks` | создать подписку |
| `GET /api/webhooks/{id}` | одна подписка |
| `PATCH /api/webhooks/{id}` | изменить URL, события, активность |
| `DELETE /api/webhooks/{id}` | удалить подписку и историю доставок |
| `POST /api/webhooks/{id}/test` | отправить тестовое событие **сразу** и вернуть ответ вашего сервера |
| `POST /api/webhooks/{id}/rotate-secret` | сменить секрет подписи |
| `GET /api/webhooks/{id}/deliveries` | журнал доставок |
| `GET /api/webhooks/{id}/stats` | счётчики по статусам |

Ключ сайта работает только со своим сайтом. Глобальный `API_KEY` может управлять
любым, но обязан указать цель: `?site_domain=example.com`.

### Проверка подписи

Каждый запрос приходит с заголовком `X-Smtp-Signature: t=<unix>,v1=<hmac>`.
Подпись — HMAC-SHA256 от строки `"{t}.{сырое тело}"` с ключом-секретом. Время
входит в подпись, поэтому перехваченный запрос нельзя переиграть позже.

```python
import hmac, hashlib, time

def verify(secret: str, raw_body: bytes, header: str, tolerance: int = 300) -> bool:
    parts = dict(p.split("=", 1) for p in header.split(","))
    ts, given = int(parts["t"]), parts["v1"]
    if abs(time.time() - ts) > tolerance:
        return False
    expected = hmac.new(secret.encode(), f"{ts}.".encode() + raw_body, hashlib.sha256).hexdigest()
    return hmac.compare_digest(expected, given)
```

Сопутствующие заголовки: `X-Smtp-Event`, `X-Smtp-Delivery-Id`, `X-Smtp-Attempt`.

### Доставка и повторы

Событие сохраняется в БД в той же транзакции, что и лог письма, а отправляет его
фоновый воркер — поэтому медленный подписчик никогда не задерживает ответ API и
доставка переживает рестарт. Ответ `2xx` считается успехом; всё остальное
повторяется с задержкой 10 с → 1 мин → 5 мин → 30 мин, до `WEBHOOK_MAX_ATTEMPTS`
попыток. История видна в админке и через `/deliveries`.

> Диспетчер работает внутри процесса и рассчитан на один экземпляр — как и
> остальной сервис (SQLite, один контейнер). При запуске двух реплик события
> уйдут дважды: для этого нужна общая очередь или блокировка строк.

Настройки: `WEBHOOK_TIMEOUT_SECONDS`, `WEBHOOK_MAX_ATTEMPTS`,
`WEBHOOK_POLL_INTERVAL_SECONDS`, `WEBHOOK_CONCURRENCY`,
`WEBHOOK_ALLOW_PRIVATE_TARGETS`, `WEBHOOK_REQUIRE_HTTPS`.

По умолчанию URL в приватных, loopback- и link-local-сетях отклоняются: ключ от
API иначе позволял бы направить сервер на внутренние адреса вроде
`169.254.169.254` (SSRF). Для локальной разработки включите
`WEBHOOK_ALLOW_PRIVATE_TARGETS=true`.

## Админ-панель

Локально доступна по адресу `http://127.0.0.1:3005/admin`; внешний доступ — через HTTPS reverse proxy (см. UPGRADE.md).

- **Дашборд** — статистика и последние события
- **Сайты** — добавление сайтов с настройками SMTP relay, API-ключ, DNS-записи
- **Шаблоны** — HTML-шаблоны с переменными для каждого сайта
- **Webhooks** — подписки на события, тестовая отправка, журнал доставок
- **Логи** — история всех отправленных и полученных писем
- **Гайд** — пошаговая настройка домена и доставляемости
- **Пользователи** — управление доступом (только для роли `admin`)

## Тесты

```bash
pip install -e '.[dev]'
pytest
ruff check app tests
```

## Структура проекта

```
├── app/
│   ├── main.py                    # FastAPI + lifespan (SMTP, воркер webhooks)
│   ├── config.py                  # Настройки из .env
│   ├── database.py                # SQLAlchemy async engine, миграции, сид админа
│   ├── models.py                  # Site, EmailTemplate, EmailLog, User, Webhook, EmailProvider…
│   ├── auth.py                    # Сессии админки
│   ├── api_auth.py                # Bearer-аутентификация REST API, scopes, /api/me
│   ├── ratelimit.py               # Лимиты по IP
│   ├── smtp_server.py             # SMTP-сервер (aiosmtpd)
│   ├── smtp_client.py             # Отправка через smtplib / MX
│   ├── dkim_util.py               # Генерация ключей и подпись DKIM
│   ├── net_util.py                # DNS-хелперы
│   ├── providers.py               # Пресеты, проверка коннекта, выбор relay
│   ├── webhook_service.py         # Подпись, SSRF-guard, диспетчер доставок
│   ├── routes_api.py              # REST: отправка, домены
│   ├── routes_providers.py        # REST: внешние SMTP-провайдеры
│   ├── routes_webhooks.py         # REST: управление webhooks
│   ├── routes_admin.py            # Админка: сайты, шаблоны, DNS, логи, юзеры
│   ├── routes_admin_webhooks.py   # Админка: webhooks
│   └── templates/                 # Jinja2 HTML-шаблоны
├── tests/
├── Dockerfile
├── docker-compose.yml
├── pyproject.toml
└── .env.example
```
