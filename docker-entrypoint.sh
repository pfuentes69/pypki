#!/bin/bash
set -e

# Ensure output directories exist (bind mount may be empty on first run)
mkdir -p /app/out/crl /app/out/backup

# Wait for MariaDB to be ready (it takes a few seconds to initialise)
echo "Waiting for database..."
until python3 - <<'EOF'
import sys, mysql.connector, json
cfg = json.load(open("config/config.json"))["db_config"]
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
import mysql.connector, json
cfg = json.load(open("config/config.json"))["db_config"]
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
    python3 utils/reset_pki.py
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
