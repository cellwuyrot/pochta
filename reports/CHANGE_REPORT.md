# Отчёт о доработке — порт 3005

## Чек-лист и результаты

- Изучен исходный код, настройки, модели, шаблоны и тесты; исходный набор: **162 passed** (`baseline.txt`).
- Добавлены regression-тесты P0/P1 **до** исправления: **9 failed** (`security-before.txt`) — AUTH без TLS, группы админки с ролью user, пароль в HTML, ложный 250 при отказе БД.
- После этапа 1: **9 passed** (`security-after.txt`), затем интеграция остальных изменений.
- Итоговый набор: **203 passed, 1 warning**, 17.00 сек (`all-tests.txt`). Warning — уведомление Starlette о будущем переходе testclient с httpx на httpx2; это не ошибка теста.
- `ruff check app tests tools`: успешно (`lint.txt`). `compileall` и `bash -n setup.sh`: успешно. Финальный wheel собран, наличие CSS/JS/шаблонов и launcher проверено.
- Настоящие loopback SMTP/TLS соединения: AUTH только после STARTTLS, правильный/неправильный пароль, MIME с вложением через выбранный relay. TLS verification не отключалась: доверие тестовому cert задано через CA file.
- Дополнительные проверки: роли на всех admin router endpoints (guard проверяет минимум 40 запросов, не пустую выборку), queue persistence/recovery/retries/idempotency/site isolation, CSRF и Origin, сохранение/удаление secret, encrypted-at-rest и повторная миграция, backup/restore SQLite, XFF trust, webhook IP pinning/rebinding и SMTP private targets.
- Старые тесты не удалены. Три проверки cleartext relay AUTH изменены на ожидаемый запрет; успешная авторизация по настоящему TLS покрыта дополнительно. Login-тесты получают настоящий CSRF token с формы. Старые локальные fixture явно включают HTTP/private targets/direct MX для совместимости; production defaults защищены.

## Исправления

1. AUTH всегда требует STARTTLS. Ошибочные/отсутствующие cert/key не включают cleartext AUTH.
2. Единый admin guard проверяет роль из БД. Подписанное значение role в cookie не повышает права.
3. Relay/provider secret write-only в формах и REST. Пустое поле сохраняет, отдельное действие удаляет; REST empty password явно очищает. Fernet-шифрование секретов, миграция plaintext и процедура ротации ключа.
4. Приём входящих по умолчанию выключен; при opt-in полный MIME сохраняется до 250, storage failure даёт 451.
5. SMTP/REST используют одну политику providers → site relay → global relay; direct MX — только явный opt-in. MIME/вложения SMTP не теряются. Credentials не наследуются от другого relay.
6. SMTP аккаунты ограничены явно разрешёнными активными доменами; ограничены число получателей, MIME size и account/min. Нормализация domain (lowercase/IDNA/точка), API input limits и HTML escaping variables.
7. Новый encrypted durable outbox с idempotency, 202/status API, backoff, attempt logs, unknown вместо небезопасного автоповтора. Legacy sync endpoints сохранены.
8. Статусы и метрики отличают SMTP acceptance от mailbox delivery. История маршрутов/ошибок связана correlation ID.
9. CSRF для изменяющих форм, Origin checks, POST logout, strict external-script/style CSP, security headers; XFF только от доверенного socket peer.
10. HTTPS webhooks по умолчанию, повторная validation и IP pinning, no redirects/proxy bypass. SMTP также pinning, public addresses/ограниченные ports.
11. Compose panel bind localhost, submission 587, read-only TLS mount, secure cookies по умолчанию; local HTTP требует явный флаг. Backup tool и Caddy example.
12. White/black flat CSS/Jinja, внешние стили и JS, sidebar/mobile toggle, таблицы/списки/нейтральные статусы. CRUD, ordering, testing SMTP providers; queue/history/diagnostics pages. Desktop/mobile просмотр выполнен после согласия пользователя: 24 страницы + ошибка входа, пустая очередь и раскрытое мобильное меню. Исправлены контраст, отступы, кнопки и переносы; автоматизированные DOM-проверки без ошибок.

13. Порт 3005 — default в Settings, canonical launcher `python -m app`, Docker/Compose, setup.sh и примерах. Реальный запуск проверен: health/login/CSS/JS отвечают на 127.0.0.1:3005. WEB_PORT сохраняет возможность переопределения.

## Оставшиеся ограничения

Локальные проверки пройдены; это не подтверждение production-ready для конкретного сервера. Остаются single-instance SQLite, без PostgreSQL/Alembic, дневных/распределённых квот, bounce/DSN, полного mailbox/attachments UI и части расширенных CRM-функций. Для старых sync endpoints нет durable/idempotent admission. Health не заменяет мониторинг доставляемости. Подробности, изменения контрактов и upgrade/backup/rotation — `UPGRADE.md`.

Production deployment, real external deliveries, production DNS/TLS/firewall/HTTPS proxy не проверялись и не изменялись.

## Изменённые файлы

- Изменён: `.dockerignore`
- Изменён: `.env.example`
- Изменён: `Dockerfile`
- Изменён: `README.md`
- Добавлен: `UPGRADE.md`
- Добавлен: `app/__main__.py`
- Изменён: `app/api_auth.py`
- Изменён: `app/auth.py`
- Изменён: `app/config.py`
- Изменён: `app/database.py`
- Добавлен: `app/domain_util.py`
- Изменён: `app/main.py`
- Изменён: `app/models.py`
- Добавлен: `app/outbox.py`
- Изменён: `app/providers.py`
- Изменён: `app/ratelimit.py`
- Изменён: `app/routes_admin.py`
- Добавлен: `app/routes_admin_providers.py`
- Изменён: `app/routes_api.py`
- Добавлен: `app/routes_outbox.py`
- Изменён: `app/routes_providers.py`
- Добавлен: `app/secret_store.py`
- Добавлен: `app/security.py`
- Изменён: `app/smtp_client.py`
- Изменён: `app/smtp_server.py`
- Добавлен: `app/smtp_transport.py`
- Добавлен: `app/static/css/app.css`
- Добавлен: `app/static/js/app.js`
- Изменён: `app/templates/base.html`
- Изменён: `app/templates/dashboard.html`
- Изменён: `app/templates/dns.html`
- Изменён: `app/templates/guide.html`
- Изменён: `app/templates/login.html`
- Изменён: `app/templates/logs.html`
- Добавлен: `app/templates/message.html`
- Изменён: `app/templates/nav.html`
- Добавлен: `app/templates/provider_form.html`
- Добавлен: `app/templates/providers.html`
- Добавлен: `app/templates/queue.html`
- Добавлен: `app/templates/settings.html`
- Изменён: `app/templates/site_form.html`
- Изменён: `app/templates/sites.html`
- Изменён: `app/templates/template_form.html`
- Изменён: `app/templates/templates_list.html`
- Изменён: `app/templates/user_form.html`
- Изменён: `app/templates/users.html`
- Изменён: `app/templates/webhook_deliveries.html`
- Изменён: `app/templates/webhook_form.html`
- Изменён: `app/templates/webhooks.html`
- Изменён: `app/webhook_service.py`
- Добавлен: `app/webhook_transport.py`
- Добавлен: `deploy/Caddyfile.example`
- Изменён: `docker-compose.yml`
- Изменён: `pyproject.toml`
- Изменён: `setup.sh`
- Изменён: `tests/conftest.py`
- Добавлен: `tests/test_hardening_and_outbox.py`
- Изменён: `tests/test_provider_resolution.py`
- Добавлен: `tests/test_security_regressions.py`
- Изменён: `tests/test_session_cookie_over_http.py`
- Добавлен: `tests/test_web_port.py`
- Добавлен: `tools/backup.py`

## Проверка поставляемого архива

ZIP проверен на целостность и отсутствие runtime-БД, .env и ключей. После распаковки в отдельную папку: **203 passed, 1 warning** (reports/archive-tests.txt). В архив не включены промежуточные неуспешные прогоны; security-before.txt сохранён как доказательство исходных регрессий.
