#!/bin/bash
set -e

CONFIG_PATH="${PYPKI_CONFIG:-config/config.json}"
export PYPKI_CONFIG_PATH="$CONFIG_PATH"

# Ensure output directories exist (bind mount may be empty on first run)
mkdir -p /app/out/crl /app/out/backup

# ── SoftHSM2 dev-token auto-init ───────────────────────────────────────────────
# Initialise a development token on first boot if SOFTHSM2_AUTO_INIT is enabled
# and no token with the requested label exists yet. The token persists across
# container restarts via the bind mount on /var/lib/softhsm/tokens.
# Override SOFTHSM2_PIN / SOFTHSM2_SO_PIN for non-dev deployments, or set
# SOFTHSM2_AUTO_INIT=false to skip entirely.
if [[ "${SOFTHSM2_AUTO_INIT:-true}" == "true" ]] && command -v softhsm2-util >/dev/null 2>&1; then
    SOFTHSM_LABEL="${SOFTHSM2_TOKEN_LABEL:-pypki-dev}"
    SOFTHSM_PIN_VAL="${SOFTHSM2_PIN:-1234}"
    SOFTHSM_SO_PIN_VAL="${SOFTHSM2_SO_PIN:-5678}"

    if softhsm2-util --show-slots 2>/dev/null | grep -q "Label:[[:space:]]*${SOFTHSM_LABEL}"; then
        echo "SoftHSM2 token '${SOFTHSM_LABEL}' already initialised."
    else
        echo "Initialising SoftHSM2 token '${SOFTHSM_LABEL}'..."
        softhsm2-util --init-token --free \
            --label "${SOFTHSM_LABEL}" \
            --pin "${SOFTHSM_PIN_VAL}" \
            --so-pin "${SOFTHSM_SO_PIN_VAL}"
        echo "SoftHSM2 token initialised."
    fi
fi

# Wait for MariaDB to be ready (it takes a few seconds to initialise)
echo "Waiting for database..."
until python3 - <<'EOF'
import json, os, sys, mysql.connector
cfg = json.load(open(os.environ["PYPKI_CONFIG_PATH"]))["db_config"]
try:
    c = mysql.connector.connect(
        host=cfg["host"], port=cfg.get("port", 3306),
        user=cfg["user"], password=cfg["password"]
    )
    c.close()
except Exception as e:
    sys.exit(1)
EOF
do
    sleep 2
done
echo "Database is ready."

# Initialise the schema on first run (table count == 0 means empty DB)
TABLE_COUNT=$(python3 - <<'EOF'
import json, os, mysql.connector
cfg = json.load(open(os.environ["PYPKI_CONFIG_PATH"]))["db_config"]
c = mysql.connector.connect(
    host=cfg["host"], port=cfg.get("port", 3306),
    user=cfg["user"], password=cfg["password"],
    database=cfg["database"]
)
cur = c.cursor()
cur.execute("SELECT COUNT(*) FROM information_schema.tables WHERE table_schema = DATABASE()")
print(cur.fetchone()[0])
c.close()
EOF
)

if [[ "$TABLE_COUNT" -eq 0 ]]; then
    echo "Empty database detected — initialising schema..."
    python3 utils/reset_pki.py "$CONFIG_PATH"
    echo "Schema initialised."
else
    echo "Database already initialised (${TABLE_COUNT} tables found)."
fi

echo "Starting gunicorn..."
exec gunicorn \
    --bind 0.0.0.0:8080 \
    --workers 2 \
    --timeout 120 \
    --access-logfile - \
    --error-logfile - \
    "web.app:app"
