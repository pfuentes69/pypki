#!/usr/bin/env bash
# =============================================================================
#  pypki – server setup script
#  Usage:  sudo bash setup.sh
#
#  Supports: Ubuntu 22.04/24.04, Debian 11/12, Rocky/AlmaLinux/RHEL 9
# =============================================================================
set -euo pipefail

# ── Colours ───────────────────────────────────────────────────────────────────
RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'
BLUE='\033[0;34m'; BOLD='\033[1m'; NC='\033[0m'
step()  { echo -e "\n${BLUE}${BOLD}==> $*${NC}"; }
ok()    { echo -e "  ${GREEN}[OK]${NC}  $*"; }
warn()  { echo -e "  ${YELLOW}[WARN]${NC} $*"; }
die()   { echo -e "  ${RED}[ERR]${NC}  $*" >&2; exit 1; }

# ── Must run as root ──────────────────────────────────────────────────────────
[[ "$EUID" -eq 0 ]] || die "Run with sudo:  sudo bash setup.sh"

# ── Project root = directory containing this script ──────────────────────────
APP_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$APP_DIR"

# ── Determine the OS user that will own/run the app ──────────────────────────
#    If called via sudo, use the real user; otherwise fall back to 'pypki'
if [[ -n "${SUDO_USER:-}" && "$SUDO_USER" != "root" ]]; then
    APP_USER="$SUDO_USER"
else
    APP_USER="pypki"
fi

# ── Detect Linux distribution ─────────────────────────────────────────────────
# shellcheck source=/dev/null
source /etc/os-release
DISTRO_ID="${ID:-unknown}"
DISTRO_LIKE="${ID_LIKE:-}"

is_debian_family() {
    [[ "$DISTRO_ID" == ubuntu || "$DISTRO_ID" == debian || "$DISTRO_ID" == linuxmint ]] ||
    echo "$DISTRO_LIKE" | grep -qw "debian"
}
is_rhel_family() {
    [[ "$DISTRO_ID" =~ ^(rhel|centos|rocky|almalinux|fedora)$ ]] ||
    echo "$DISTRO_LIKE" | grep -qw "rhel\|fedora"
}

# =============================================================================
#  1. INSTALL SYSTEM PACKAGES
# =============================================================================
step "Installing system packages"

if is_debian_family; then
    export DEBIAN_FRONTEND=noninteractive
    apt-get update -qq

    # Determine the best available Python 3.x (>=3.11)
    for PY_PKG in python3.12 python3.11; do
        if apt-cache show "$PY_PKG" &>/dev/null 2>&1; then
            PREFERRED_PY="$PY_PKG"; break
        fi
    done
    PREFERRED_PY="${PREFERRED_PY:-python3}"

    apt-get install -y \
        "$PREFERRED_PY" "${PREFERRED_PY}-venv" "${PREFERRED_PY}-dev" \
        python3-pip \
        mariadb-server \
        libmariadb-dev pkg-config \
        openssl curl git
    ok "Debian/Ubuntu packages installed"

elif is_rhel_family; then
    # Enable EPEL for Rocky/Alma if not already present
    if ! rpm -q epel-release &>/dev/null; then
        dnf install -y epel-release || true
    fi
    dnf install -y \
        python3 python3-pip python3-devel \
        mariadb-server mariadb-devel \
        openssl curl git gcc
    ok "RHEL-family packages installed"

else
    warn "Unrecognised distro '$DISTRO_ID'. Skipping package installation."
    warn "Ensure python3.11+, mariadb-server, and pip are installed manually."
fi

# =============================================================================
#  2. FIND A USABLE PYTHON (>=3.11)
# =============================================================================
step "Locating Python 3.11+"

PY_CMD=""
for cmd in python3.12 python3.11 python3.10 python3; do
    if command -v "$cmd" &>/dev/null; then
        PY_MAJOR=$("$cmd" -c "import sys; print(sys.version_info.major)")
        PY_MINOR=$("$cmd" -c "import sys; print(sys.version_info.minor)")
        if [[ "$PY_MAJOR" -ge 3 && "$PY_MINOR" -ge 11 ]]; then
            PY_CMD="$cmd"; break
        fi
    fi
done

[[ -n "$PY_CMD" ]] || die "Python 3.11+ not found. Install it and re-run."
PY_VERSION=$("$PY_CMD" --version)
ok "Using $PY_CMD ($PY_VERSION)"

# =============================================================================
#  3. CREATE APP USER (if not using the sudo caller's account)
# =============================================================================
if [[ "$APP_USER" == "pypki" ]]; then
    if ! id "$APP_USER" &>/dev/null; then
        step "Creating system user '$APP_USER'"
        useradd --system --no-create-home --shell /usr/sbin/nologin "$APP_USER"
        ok "User '$APP_USER' created"
    else
        ok "User '$APP_USER' already exists"
    fi
fi

# =============================================================================
#  4. MARIADB – start service and create DB + user
# =============================================================================
step "Configuring MariaDB"

systemctl enable --now mariadb
ok "MariaDB service running"

DB_NAME="pypki_db"
DB_USER="pypki_user"

# Generate a random DB password unless the caller supplied one
if [[ -z "${PYPKI_DB_PASS:-}" ]]; then
    DB_PASS="$(openssl rand -base64 21 | tr -dc 'A-Za-z0-9' | head -c 24)"
else
    DB_PASS="$PYPKI_DB_PASS"
fi

# Run the SQL as root (works with both socket-auth and password-auth)
mariadb --batch -u root <<SQL
CREATE DATABASE IF NOT EXISTS \`${DB_NAME}\`
    CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci;
CREATE USER IF NOT EXISTS '${DB_USER}'@'localhost' IDENTIFIED BY '${DB_PASS}';
GRANT ALL PRIVILEGES ON \`${DB_NAME}\`.* TO '${DB_USER}'@'localhost';
FLUSH PRIVILEGES;
SQL
ok "Database '$DB_NAME' and user '$DB_USER' ready"

# =============================================================================
#  5. WRITE config/config.json
#     Always generate a fresh file so the DB credentials are guaranteed to match
#     the user/password we just created.  Any pre-existing file is backed up.
# =============================================================================
step "Writing configuration"

mkdir -p config/cert_templates config/ca_store config/ocsp_responders

# Preserve a custom secret_key if one is already set so JWT sessions survive re-runs.
EXISTING_SECRET=""
if [[ -f config/config.json ]]; then
    EXISTING_SECRET=$(python3 -c "
import json, sys
try:
    d = json.load(open('config/config.json'))
    sk = d.get('secret_key','')
    if sk and sk != 'replace-with-64-random-chars' and len(sk) > 8:
        print(sk)
except Exception:
    pass
" 2>/dev/null || true)
    cp config/config.json "config/config.json.bak.$(date +%Y%m%d%H%M%S)"
    warn "Existing config/config.json backed up (config/config.json.bak.*)"
fi

if [[ -n "$EXISTING_SECRET" ]]; then
    SECRET_KEY="$EXISTING_SECRET"
    ok "Reusing existing secret_key"
else
    SECRET_KEY="$(openssl rand -base64 48 | tr -dc 'A-Za-z0-9_-' | head -c 64)"
fi

cat > config/config.json <<JSON
{
    "db_config": {
        "host": "localhost",
        "port": 3306,
        "user": "${DB_USER}",
        "password": "${DB_PASS}",
        "database": "${DB_NAME}"
    },
    "template_folder":       "config/cert_templates",
    "ca_store_folder":       "config/ca_store",
    "ocsp_responder_folder": "config/ocsp_responders",
    "default_ca_id":         1,
    "default_template":      7,
    "secret_key":            "${SECRET_KEY}"
}
JSON
ok "config/config.json written"

# Save credentials to a protected file so the admin can note them
CREDS_FILE="$APP_DIR/.setup_credentials"
cat > "$CREDS_FILE" <<CREDS
# pypki setup – generated credentials
# NOTE: Delete this file after you have noted the values.
DB_NAME=${DB_NAME}
DB_USER=${DB_USER}
DB_PASS=${DB_PASS}
SECRET_KEY=${SECRET_KEY}
CREDS
chmod 600 "$CREDS_FILE"
ok "Credentials saved to .setup_credentials  ← delete this file after noting them"

# =============================================================================
#  6. OUTPUT DIRECTORIES
# =============================================================================
mkdir -p out/crl out/backup
ok "Output directories ready"

# =============================================================================
#  7. PYTHON VIRTUAL ENVIRONMENT + DEPENDENCIES
# =============================================================================
step "Setting up Python virtual environment"

if [[ ! -d venv ]]; then
    "$PY_CMD" -m venv venv
    ok "Virtual environment created"
else
    warn "venv already exists — reusing it"
fi

venv/bin/pip install --upgrade pip --quiet
venv/bin/pip install -r requirements.txt --quiet
ok "Python dependencies installed"

# =============================================================================
#  8. INITIALISE DATABASE SCHEMA + SEED DATA
# =============================================================================
step "Initialising database"

venv/bin/python utils/reset_pki.py
ok "Database schema and seed data created"

# =============================================================================
#  9. FILE OWNERSHIP
# =============================================================================
step "Setting file ownership"

chown -R "$APP_USER":"$APP_USER" "$APP_DIR"
ok "Ownership set to $APP_USER"

# =============================================================================
#  10. SYSTEMD SERVICE
# =============================================================================
step "Installing systemd service"

SERVICE=/etc/systemd/system/pypki.service

cat > "$SERVICE" <<UNIT
[Unit]
Description=pyPKI – Web-based PKI Management
Documentation=https://github.com/your-org/pypki
After=network.target mariadb.service
Requires=mariadb.service

[Service]
Type=simple
User=${APP_USER}
Group=${APP_USER}
WorkingDirectory=${APP_DIR}
ExecStart=${APP_DIR}/venv/bin/python web/app.py
Restart=on-failure
RestartSec=5s

# Log to journald
StandardOutput=journal
StandardError=journal
SyslogIdentifier=pypki

# Basic hardening
PrivateTmp=true
NoNewPrivileges=true
ProtectSystem=strict
ProtectHome=true
ReadWritePaths=${APP_DIR}/out ${APP_DIR}/config

[Install]
WantedBy=multi-user.target
UNIT

systemctl daemon-reload
systemctl enable pypki
systemctl restart pypki
ok "Service installed and started"

# Give the process a moment to bind before we check
sleep 2
if systemctl is-active --quiet pypki; then
    ok "Service is running  (journalctl -u pypki -f to tail logs)"
else
    warn "Service did not start cleanly. Check:  journalctl -u pypki -n 50"
fi

# =============================================================================
#  DONE
# =============================================================================
echo ""
echo -e "${GREEN}${BOLD}════════════════════════════════════════════════════${NC}"
echo -e "${GREEN}${BOLD}  pypki setup complete!${NC}"
echo -e "${GREEN}${BOLD}════════════════════════════════════════════════════${NC}"
echo ""
echo -e "  Application URL : ${BOLD}http://$(hostname -I | awk '{print $1}'):8080${NC}"
echo ""
echo -e "  Default login   : ${BOLD}admin${NC} / ${BOLD}admin${NC}"
echo -e "  ${RED}${BOLD}→ Change the admin password immediately after first login.${NC}"
echo ""
echo -e "  Useful commands:"
echo -e "    sudo systemctl status pypki"
echo -e "    sudo journalctl -u pypki -f"
echo ""
if [[ -f "$APP_DIR/.setup_credentials" ]]; then
    echo -e "  ${YELLOW}Remember to delete .setup_credentials once you have noted the DB password.${NC}"
    echo ""
fi
