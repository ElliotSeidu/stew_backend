#!/usr/bin/env bash
set -euo pipefail

BACKUP_DIR="/var/backups/stew"
RETENTION_DAYS=14
STAMP="$(date -u +%Y-%m-%d_%H%M%S)"
OUT_FILE="${BACKUP_DIR}/stew_${STAMP}.dump"

mkdir -p "${BACKUP_DIR}"
pg_dump -U stew_user -h 127.0.0.1 -d stew_prod -Fc -f "${OUT_FILE}"
chmod 600 "${OUT_FILE}"

# Prune old local backups
find "${BACKUP_DIR}" -type f -name "stew_*.dump" -mtime "+${RETENTION_DAYS}" -delete

# Example off-server encrypted sync (uncomment and configure):
# rclone copy "${OUT_FILE}" remote-bucket:stew-db-backups/
