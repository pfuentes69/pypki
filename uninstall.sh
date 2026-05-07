#!/usr/bin/env bash
# uninstall.sh — Stop and remove the Docker Compose stack created by setup.sh
# Usage: bash uninstall.sh
set -euo pipefail

APP_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$APP_DIR"

if ! command -v docker >/dev/null 2>&1; then
    echo "Docker is not installed or not in PATH." >&2
    exit 1
fi

if ! docker compose version >/dev/null 2>&1; then
    echo "Docker Compose plugin is not available." >&2
    exit 1
fi

echo "Stopping and removing the pyPKI containers..."
docker compose down --remove-orphans

echo
echo "pyPKI containers removed."
echo "Persistent data was preserved in:"
echo "  - config/"
echo "  - out/"
echo "  - data/mariadb/"
echo
echo "To permanently delete the MariaDB data, remove data/mariadb manually."
