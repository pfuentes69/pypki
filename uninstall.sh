#!/usr/bin/env bash
# uninstall.sh — Remove the pyPKI systemd service installed by setup.sh
# Usage: sudo bash uninstall.sh
set -euo pipefail

SERVICE="pypki"
SERVICE_FILE="/etc/systemd/system/${SERVICE}.service"

if [[ $EUID -ne 0 ]]; then
    echo "Run with sudo: sudo bash uninstall.sh" >&2
    exit 1
fi

if [[ ! -f "$SERVICE_FILE" ]]; then
    echo "Service file $SERVICE_FILE not found — nothing to remove."
    exit 0
fi

systemctl stop    "$SERVICE" 2>/dev/null && echo "Stopped $SERVICE"    || true
systemctl disable "$SERVICE" 2>/dev/null && echo "Disabled $SERVICE"   || true
rm -f "$SERVICE_FILE"
systemctl daemon-reload
echo "Removed $SERVICE_FILE"
echo "Done. App files and database are untouched."
