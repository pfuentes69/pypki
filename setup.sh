#!/usr/bin/env bash
# =============================================================================
#  pypki – server setup script (Docker Compose edition)
#  Usage:  sudo bash setup.sh
#
#  Installs Docker + Docker Compose (if needed), generates credentials,
#  writes config/config.json, and brings up the application stack.
#
#  Supports: Ubuntu 22.04/24.04, Debian 11/12, Rocky/AlmaLinux/RHEL 9
#  Safe to re-run — skips steps that are already done.
# =============================================================================
set -euo pipefail

# ── Colours ───────────────────────────────────────────────────────────────────
RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'
BLUE='\033[0;34m'; BOLD='\033[1m'; NC='\033[0m'
step() { echo -e "\n${BLUE}${BOLD}==> $*${NC}"; }
ok()   { echo -e "  ${GREEN}[OK]${NC}  $*"; }
warn() { echo -e "  ${YELLOW}[WARN]${NC} $*"; }
die()  { echo -e "  ${RED}[ERR]${NC}  $*" >&2; exit 1; }

[[ "$EUID" -eq 0 ]] || die "Run with sudo:  sudo bash setup.sh"

APP_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$APP_DIR"

# Who should own the files (caller via sudo, or root)
REAL_USER="${SUDO_USER:-root}"

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
#  1. INSTALL DOCKER
# =============================================================================
step "Checking Docker"

if command -v docker &>/dev/null; then
    ok "Docker already installed ($(docker --version))"
else
    step "Installing Docker"
    if is_debian_family; then
        apt-get update -qq
        apt-get install -y ca-certificates curl gnupg
        install -m 0755 -d /etc/apt/keyrings
        curl -fsSL https://download.docker.com/linux/${DISTRO_ID}/gpg \
            | gpg --dearmor -o /etc/apt/keyrings/docker.gpg
        chmod a+r /etc/apt/keyrings/docker.gpg
        echo "deb [arch=$(dpkg --print-architecture) signed-by=/etc/apt/keyrings/docker.gpg] \
https://download.docker.com/linux/${DISTRO_ID} $(. /etc/os-release && echo "$VERSION_CODENAME") stable" \
            > /etc/apt/sources.list.d/docker.list
        apt-get update -qq
        apt-get install -y docker-ce docker-ce-cli containerd.io docker-compose-plugin
    elif is_rhel_family; then
        dnf install -y dnf-plugins-core
        dnf config-manager --add-repo https://download.docker.com/linux/rhel/docker-ce.repo
        dnf install -y docker-ce docker-ce-cli containerd.io docker-compose-plugin
    else
        die "Unsupported distro '$DISTRO_ID'. Install Docker manually: https://docs.docker.com/engine/install/"
    fi
    systemctl enable --now docker
    ok "Docker installed and started"
fi

# Ensure Docker Compose plugin is available
if ! docker compose version &>/dev/null; then
    die "Docker Compose plugin not found. Re-run after installing: apt-get install docker-compose-plugin"
fi
ok "Docker Compose available ($(docker compose version --short))"

# Add the real user to the docker group so they can run docker without sudo
if [[ "$REAL_USER" != "root" ]] && ! groups "$REAL_USER" | grep -qw docker; then
    usermod -aG docker "$REAL_USER"
    warn "Added $REAL_USER to the 'docker' group — log out and back in for it to take effect"
fi

# =============================================================================
#  2. GENERATE CREDENTIALS
# =============================================================================
step "Configuring credentials"

DB_NAME="pypki_db"
DB_USER="pypki_user"

# If .env already exists, read existing passwords so we don't rotate them.
# HSM_PIN_KEK is also reused — rotating it would invalidate every encrypted
# software key in the database.
HSM_PIN_KEK=""
if [[ -f "$APP_DIR/.env" ]]; then
    DB_ROOT_PASSWORD=$(grep ^DB_ROOT_PASSWORD "$APP_DIR/.env" | cut -d= -f2-)
    DB_PASSWORD=$(grep ^DB_PASSWORD     "$APP_DIR/.env" | cut -d= -f2-)
    HSM_PIN_KEK=$(grep ^HSM_PIN_KEK     "$APP_DIR/.env" | cut -d= -f2- || true)
    ok ".env already exists — reusing existing DB passwords and HSM_PIN_KEK"
else
    DB_ROOT_PASSWORD="$(openssl rand -base64 21 | tr -dc 'A-Za-z0-9' | head -c 24)"
    DB_PASSWORD="$(openssl rand -base64 21 | tr -dc 'A-Za-z0-9' | head -c 24)"
fi

# Generate HSM_PIN_KEK if missing. This is the deployment-wide KEK that
# encrypts software keys at rest under per-provider keys derived via HKDF.
# Once set, do NOT rotate without re-encrypting every KeyStorage row.
if [[ -z "$HSM_PIN_KEK" ]]; then
    HSM_PIN_KEK="$(openssl rand -base64 48 | tr -dc 'A-Za-z0-9_-' | head -c 64)"
fi

cat > "$APP_DIR/.env" <<ENV
DB_ROOT_PASSWORD=${DB_ROOT_PASSWORD}
DB_NAME=${DB_NAME}
DB_USER=${DB_USER}
DB_PASSWORD=${DB_PASSWORD}
HSM_PIN_KEK=${HSM_PIN_KEK}
ENV
chmod 600 "$APP_DIR/.env"
ok ".env written"

# =============================================================================
#  3. WRITE config/config.json
# =============================================================================
step "Writing config/config.json"

mkdir -p config/cert_templates config/ca_store config/ocsp_responders

# Preserve an existing custom secret_key across re-runs
SECRET_KEY=""
if [[ -f config/config.json ]]; then
    SECRET_KEY=$(python3 -c "
import json, sys
try:
    d = json.load(open('config/config.json'))
    sk = d.get('secret_key','')
    if sk and 'change-me' not in sk and len(sk) > 16:
        print(sk)
except Exception:
    pass
" 2>/dev/null || true)
fi

if [[ -z "$SECRET_KEY" ]]; then
    SECRET_KEY="$(openssl rand -base64 48 | tr -dc 'A-Za-z0-9_-' | head -c 64)"
fi

cat > config/config.json <<JSON
{
    "db_config": {
        "host": "db",
        "port": 3306,
        "user": "${DB_USER}",
        "password": "${DB_PASSWORD}",
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
ok "config/config.json written  (DB host = 'db', user = ${DB_USER})"

# Save a human-readable credentials summary
CREDS_FILE="$APP_DIR/.setup_credentials"
cat > "$CREDS_FILE" <<CREDS
# pyPKI setup credentials — generated $(date)
# Delete this file once you have noted the values.
DB_NAME=${DB_NAME}
DB_USER=${DB_USER}
DB_PASSWORD=${DB_PASSWORD}
DB_ROOT_PASSWORD=${DB_ROOT_PASSWORD}
SECRET_KEY=${SECRET_KEY}
HSM_PIN_KEK=${HSM_PIN_KEK}
CREDS
chmod 600 "$CREDS_FILE"
ok "Credentials saved to .setup_credentials  ← delete after noting them"

# =============================================================================
#  4. ENSURE OUTPUT + DATA DIRECTORIES EXIST
# =============================================================================
step "Creating data directories"

mkdir -p out/crl out/backup data/mariadb data/softhsm/tokens
[[ "$REAL_USER" != "root" ]] && chown -R "$REAL_USER":"$REAL_USER" out data || true
ok "out/, data/mariadb/, and data/softhsm/tokens/ ready"

# =============================================================================
#  5. BUILD IMAGE AND START STACK
# =============================================================================
step "Building and starting containers"

docker compose pull db   --quiet 2>/dev/null || true
docker compose build app --quiet
docker compose up -d
ok "Stack started"

# Wait briefly and check both containers are up
sleep 5
if docker compose ps --format json | python3 -c "
import sys, json
data = sys.stdin.read().strip()
# docker compose ps --format json outputs one JSON object per line
lines = [l for l in data.splitlines() if l.strip()]
services = [json.loads(l) for l in lines]
bad = [s['Service'] for s in services if s.get('State','') != 'running']
if bad:
    print('Not running: ' + ', '.join(bad))
    sys.exit(1)
" 2>/dev/null; then
    ok "All containers running"
else
    warn "One or more containers may not be running yet."
    warn "Check with:  docker compose ps"
    warn "Logs:        docker compose logs -f"
fi

# =============================================================================
#  DONE
# =============================================================================
echo ""
echo -e "${GREEN}${BOLD}════════════════════════════════════════════════════${NC}"
echo -e "${GREEN}${BOLD}  pyPKI setup complete!${NC}"
echo -e "${GREEN}${BOLD}════════════════════════════════════════════════════${NC}"
echo ""
echo -e "  Application URL : ${BOLD}http://$(hostname -I | awk '{print $1}'):8080${NC}"
echo ""
echo -e "  Default login   : ${BOLD}superadmin${NC} / ${BOLD}password${NC}"
echo -e "  ${RED}${BOLD}→ Change the superadmin password immediately after first login.${NC}"
echo ""
echo -e "  Useful commands:"
echo -e "    docker compose ps"
echo -e "    docker compose logs -f app"
echo -e "    docker compose logs -f db"
echo -e "    docker compose restart app"
echo -e "    docker compose down"
echo ""
if [[ -f "$APP_DIR/.setup_credentials" ]]; then
    echo -e "  ${YELLOW}Remember to delete .setup_credentials once you have noted the DB password.${NC}"
    echo ""
fi
