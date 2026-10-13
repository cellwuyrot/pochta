#!/bin/sh
# Run BEFORE overlaying the update. Never publish this backup (it contains secrets).
set -eu
PROJECT_DIR=${1:-/root/pochta}
cd "$PROJECT_DIR"
PROJECT_DIR=$(pwd -P)
BACKUP_ROOT=$(dirname "$PROJECT_DIR")/pochta-backups
mkdir -p "$BACKUP_ROOT"
chmod 700 "$BACKUP_ROOT"
BACKUP_DIR=$(mktemp -d "$BACKUP_ROOT/beget-$(date +%Y%m%d-%H%M%S)-XXXXXX")
chmod 700 "$BACKUP_DIR"

# Snapshot source/config outside the project, without runtime caches or Git history.
tar --exclude='./.git' --exclude='./data' --exclude='./.venv*' \
    --exclude='./__pycache__' --exclude='./.pytest_cache' --exclude='./.ruff_cache' \
    -czf "$BACKUP_DIR/project-before.tar.gz" .
chmod 600 "$BACKUP_DIR/project-before.tar.gz"

# Stop the worker for a consistent volume snapshot. Failure leaves it stopped;
# no new code is applied by this script.
docker compose stop smtp-service
# This service already mounts smtp-data:/app/data. One-off run has no public ports.
docker compose run --rm --no-deps --user 0 \
    -v "$BACKUP_DIR:/backup" smtp-service sh -c \
    'mkdir -p /backup/data && cp -a /app/data/. /backup/data/'
chmod -R go-rwx "$BACKUP_DIR"
printf '\nBackup ready: %s\nService is stopped. Apply update, then rebuild.\n' "$BACKUP_DIR"
