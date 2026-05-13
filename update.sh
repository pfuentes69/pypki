#!/usr/bin/env bash
# =============================================================================
#  pypki – update script (Docker Compose edition)
#  Usage:  sudo bash update.sh
#
#  Pulls the latest code, rebuilds the app image, and restarts the stack.
#  Schema migrations run automatically at app startup (migrate_schema is
#  idempotent — safe to re-run; see doc/ca-management-specs.md §4.3).
#
#  Does NOT touch .env, config/config.json, or the database volume.
#  Safe to re-run.
# =============================================================================
set -euo pipefail

RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'
BLUE='\033[0;34m'; BOLD='\033[1m'; NC='\033[0m'
step() { echo -e "\n${BLUE}${BOLD}==> $*${NC}"; }
ok()   { echo -e "  ${GREEN}[OK]${NC}  $*"; }
warn() { echo -e "  ${YELLOW}[WARN]${NC} $*"; }
die()  { echo -e "  ${RED}[ERR]${NC}  $*" >&2; exit 1; }

[[ "$EUID" -eq 0 ]] || die "Run with sudo:  sudo bash update.sh"

APP_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$APP_DIR"

[[ -d .git ]]              || die "Not a git repository — clone the repo first, or use setup.sh for a fresh install."
[[ -f docker-compose.yml ]] || die "docker-compose.yml not found in $APP_DIR"
[[ -f .env ]]              || die ".env not found — run setup.sh first."

# =============================================================================
#  1. STOP THE STACK
# =============================================================================
step "Stopping stack"
docker compose down
ok "Stack stopped"

# =============================================================================
#  2. PULL LATEST CODE
# =============================================================================
step "Pulling latest code from origin"

CURRENT=$(git rev-parse --short HEAD)
if git pull --ff-only 2>&1 | tee /tmp/pypki-pull.log; then
    NEW=$(git rev-parse --short HEAD)
    if [[ "$CURRENT" == "$NEW" ]]; then
        ok "Already at latest commit ($NEW) — rebuilding anyway in case the image is stale"
    else
        ok "Updated $CURRENT → $NEW"
    fi
else
    # Common failure: data/ was tracked in pre-273d740 commits and a host user
    # can't stat the container-owned files. Recovery is documented in the
    # release notes for commits fbd8b62 / 273d740.
    if grep -q "cannot stat 'data/" /tmp/pypki-pull.log 2>/dev/null; then
        die "git pull tripped over the legacy 'data/' tracking. \
This is a one-time upgrade hiccup — see the recovery steps in the README for the data/ + .env untrack commits (fbd8b62, 273d740), then re-run update.sh."
    fi
    die "git pull failed — see output above. Stack remains stopped."
fi
rm -f /tmp/pypki-pull.log

# =============================================================================
#  3. REBUILD AND START
# =============================================================================
step "Rebuilding app image"
docker compose build app --quiet
ok "Image rebuilt"

step "Starting stack"
docker compose up -d
ok "Stack started"

# =============================================================================
#  4. WAIT FOR HEALTH AND SHOW MIGRATION OUTPUT
# =============================================================================
step "Waiting for containers to become healthy"
for i in {1..30}; do
    if docker compose ps --format json 2>/dev/null \
        | python3 -c "
import sys, json
lines = [l for l in sys.stdin.read().splitlines() if l.strip()]
svcs  = [json.loads(l) for l in lines]
bad   = [s['Service'] for s in svcs if s.get('State','') != 'running']
sys.exit(1 if bad else 0)
" 2>/dev/null; then
        ok "All containers running"
        break
    fi
    sleep 2
    [[ $i -eq 30 ]] && warn "Containers still settling — check 'docker compose ps' manually"
done

step "Recent migrate_schema output"
# 200 lines is enough to capture every "adding ..." line and the
# signing_algorithm backfill confirmations even on an active install.
docker compose logs --tail 200 app 2>&1 | grep -E "migrate_schema|signing_algorithm|ERROR|CRITICAL" \
    || warn "No migrate_schema lines in recent logs — that usually means the schema was already current."

echo ""
echo -e "${GREEN}${BOLD}════════════════════════════════════════════════════${NC}"
echo -e "${GREEN}${BOLD}  Update complete${NC}"
echo -e "${GREEN}${BOLD}════════════════════════════════════════════════════${NC}"
echo ""
echo -e "  URL          : ${BOLD}http://$(hostname -I | awk '{print $1}'):8080${NC}"
echo -e "  Tail logs    : docker compose logs -f app"
echo -e "  Container ps : docker compose ps"
echo ""
echo -e "  ${YELLOW}Tip:${NC} hard-refresh the browser (Cmd/Ctrl+Shift+R) to bust cached templates."
echo ""
