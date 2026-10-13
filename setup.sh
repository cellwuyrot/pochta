#!/bin/bash
set -e
umask 077

# ============================================
#  SMTP Service — автоустановка и запуск
# ============================================
#
#  Использование:
#    bash setup.sh
#    bash setup.sh --port 3005
#    bash setup.sh --port 3005 --domain mail.example.com
#
# ============================================

PORT="${PORT:-3005}"
SMTP_PORT="${SMTP_PORT:-587}"
DOMAIN="${DOMAIN:-$(hostname -f 2>/dev/null || hostname)}"
ADMIN_USER=""
ADMIN_PASS=""
LOCAL_HTTP=false

# --- Парсинг аргументов ---
while [[ $# -gt 0 ]]; do
    case $1 in
        --local-http) LOCAL_HTTP=true; shift ;;
        --port) PORT="$2"; shift 2 ;;
        --smtp-port) SMTP_PORT="$2"; shift 2 ;;
        --domain) DOMAIN="$2"; shift 2 ;;
        --admin-user) ADMIN_USER="$2"; shift 2 ;;
        --admin-pass) ADMIN_PASS="$2"; shift 2 ;;
        --relay-host) RELAY_HOST="$2"; shift 2 ;;
        --relay-port) RELAY_PORT="$2"; shift 2 ;;
        --relay-user) RELAY_USER="$2"; shift 2 ;;
        --relay-pass) RELAY_PASS="$2"; shift 2 ;;
        -h|--help)
            echo "Использование: bash setup.sh [опции]"
            echo ""
            echo "Опции:"
            echo "  --local-http        Локальная разработка без HTTPS (bind всё равно localhost)"
            echo "  --port PORT         Порт веб-панели (по умолчанию: 3005)"
            echo "  --smtp-port PORT    Порт SMTP (по умолчанию: 587)"
            echo "  --domain DOMAIN     Домен сервера"
            echo "  --admin-user USER   Логин админки"
            echo "  --admin-pass PASS   Пароль админки"
            echo "  --relay-host HOST   SMTP relay хост (например smtp.yandex.ru)"
            echo "  --relay-port PORT   SMTP relay порт (по умолчанию: 587)"
            echo "  --relay-user USER   SMTP relay логин"
            echo "  --relay-pass PASS   SMTP relay пароль"
            echo ""
            echo "Примеры:"
            echo "  bash setup.sh"
            echo "  bash setup.sh --port 8080"
            echo "  bash setup.sh --port 3005 --relay-host smtp.yandex.ru --relay-user me@yandex.ru --relay-pass app-password"
            exit 0
            ;;
        *) echo "Неизвестная опция: $1"; exit 1 ;;
    esac
done

# --- Запрос логина/пароля если не указаны ---
if [ -z "$ADMIN_USER" ]; then
    read -p "Введите логин для админки: " ADMIN_USER
    if [ -z "$ADMIN_USER" ]; then
        ADMIN_USER="admin"
        echo "  Используется логин по умолчанию: admin"
    fi
fi

if [ -z "$ADMIN_PASS" ]; then
    while true; do
        read -s -p "Введите пароль для админки: " ADMIN_PASS
        echo
        if [ -z "$ADMIN_PASS" ]; then
            echo "  Пароль не может быть пустым!"
            continue
        fi
        read -s -p "Повторите пароль: " ADMIN_PASS2
        echo
        if [ "$ADMIN_PASS" != "$ADMIN_PASS2" ]; then
            echo "  Пароли не совпадают, попробуйте снова."
            continue
        fi
        break
    done
fi

SECRET_KEY=$(openssl rand -hex 32 2>/dev/null || python3 -c "import secrets; print(secrets.token_hex(32))" 2>/dev/null || head -c 64 /dev/urandom | xxd -p | tr -d '\n')
API_KEY="sm_$(openssl rand -hex 24 2>/dev/null || python3 -c "import secrets; print(secrets.token_hex(24))" 2>/dev/null)"

SERVER_IP=$(hostname -I 2>/dev/null | awk '{print $1}' || echo 'your-server')

echo ""
echo "========================================="
echo "  SMTP Service — установка"
echo "========================================="
echo "  Веб-панель:  порт $PORT"
echo "  SMTP:        порт $SMTP_PORT"
echo "  Домен:       $DOMAIN"
echo "  Админка:     http://127.0.0.1:$PORT/admin"
echo "  Логин:       $ADMIN_USER"
echo "  API ключ сохранён только в .env"
echo "========================================="
echo ""

# --- Проверка Docker ---
if ! command -v docker &>/dev/null; then
    echo "[*] Docker не найден. Устанавливаю..."
    curl -fsSL https://get.docker.com | sh
    sudo systemctl enable docker
    sudo systemctl start docker
    echo "[+] Docker установлен"
fi

if ! docker compose version &>/dev/null && ! docker-compose --version &>/dev/null; then
    echo "[*] Docker Compose не найден. Устанавливаю..."
    sudo apt-get update -qq && sudo apt-get install -y -qq docker-compose-plugin 2>/dev/null || \
    sudo pip3 install docker-compose 2>/dev/null || true
fi

# --- Создание .env ---
echo "[*] Генерирую .env..."
cat > .env << EOF
# === SMTP Service Configuration ===

SMTP_DOMAIN=$DOMAIN
SMTP_PORT=2525
WEB_PORT=$PORT
SMTP_HOST_PORT=$SMTP_PORT

ADMIN_USERNAME=$ADMIN_USER
ADMIN_PASSWORD=$ADMIN_PASS

SECRET_KEY=$SECRET_KEY
ALLOW_DIRECT_MX=false
INBOUND_ENABLED=false
WEBHOOK_REQUIRE_HTTPS=true
API_KEY=$API_KEY

DATABASE_URL=sqlite+aiosqlite:///./data/smtp.db

# Production panel: localhost + HTTPS reverse proxy. --local-http is explicit dev-only.
COOKIE_SECURE=$([ "$LOCAL_HTTP" = true ] && echo false || echo true)

# Swagger UI at /api/docs. Off by default: it enumerates the whole API surface
# to anonymous visitors.
API_DOCS_ENABLED=false

TLS_CERT_PATH=/app/tls/cert.pem
TLS_KEY_PATH=/app/tls/key.pem

RELAY_HOST=${RELAY_HOST:-}
RELAY_PORT=${RELAY_PORT:-587}
RELAY_USERNAME=${RELAY_USER:-}
RELAY_PASSWORD=${RELAY_PASS:-}
RELAY_USE_TLS=true
EOF
echo "[+] .env создан"

# Compose reads WEB_PORT and SMTP_HOST_PORT from .env; do not rewrite YAML with sed.
echo "[+] Порты: веб=127.0.0.1:$PORT, smtp=$SMTP_PORT"

# --- Создание папки данных ---
mkdir -p data tls

# --- Запуск ---
echo "[*] Собираю и запускаю контейнер..."
if docker compose version &>/dev/null; then
    docker compose up -d --build
else
    docker-compose up -d --build
fi

echo ""
echo "========================================="
echo "  SMTP Service запущен!"
echo "========================================="
echo ""
echo "  Админка:  http://127.0.0.1:$PORT/admin"
echo "  Логин:    $ADMIN_USER"
echo "  API:      http://127.0.0.1:$PORT/api/health"
echo "  API ключ сохранён только в .env"
echo ""
echo "  Панель доступна только на localhost. Для production настройте HTTPS reverse proxy."
echo "  Пример: deploy/Caddyfile.example. Secure cookie включён, кроме --local-http."
echo "  SMTP AUTH недоступен без TLS_CERT_PATH/TLS_KEY_PATH и сертификата."
echo ""
echo "  Отправка письма:"
echo "  curl -X POST http://127.0.0.1:$PORT/api/emails \\"
echo "    -H 'Content-Type: application/json' \\"
echo "    -H 'Authorization: Bearer $API_KEY' \\"
echo "    -d '{\"from_email\":\"noreply@$DOMAIN\",\"to\":\"test@test.com\",\"subject\":\"Test\",\"html\":\"<p>Hello</p>\"}'"
echo ""
if [ -z "$RELAY_HOST" ]; then
    echo "  [!] Relay не настроен — добавьте SMTP relay в админке (Сайты → DNS)."
    echo "      Или в .env: RELAY_HOST, RELAY_USERNAME, RELAY_PASSWORD"
fi
echo ""
