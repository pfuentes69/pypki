"""
DB Migration: Add UNIQUE constraint on (ca_id, serial_number) to Certificates.

This migration enforces serial-number uniqueness at the database level, replacing
the previous in-memory set approach that was not thread-safe and required loading
all serial numbers on every certificate request.

Changes applied (idempotently):
  Certificates
    + UNIQUE KEY uq_ca_serial (ca_id, serial_number)

The migration checks whether the key already exists before attempting to add it.

Usage:
    python utils/migrate_serial_uniqueness.py [config_file]

    config_file defaults to config/config.json
"""

import sys
import os

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

import json
import mysql.connector

DEFAULT_CONFIG = os.path.join(os.path.dirname(__file__), '..', 'config', 'config.json')
config_path = sys.argv[1] if len(sys.argv) > 1 else DEFAULT_CONFIG

with open(config_path) as f:
    config = json.load(f)

db_cfg = config['db_config']
DB_NAME = db_cfg['database']

print(f"Connecting to {db_cfg['host']}:{db_cfg.get('port', 3306)} / {DB_NAME} …")

conn = mysql.connector.connect(
    host=db_cfg['host'],
    port=db_cfg.get('port', 3306),
    user=db_cfg['user'],
    password=db_cfg['password'],
    database=DB_NAME,
)
cursor = conn.cursor(dictionary=True)


def index_exists(table: str, index_name: str) -> bool:
    cursor.execute(
        "SELECT COUNT(*) AS cnt FROM information_schema.STATISTICS "
        "WHERE TABLE_SCHEMA = %s AND TABLE_NAME = %s AND INDEX_NAME = %s",
        (DB_NAME, table, index_name)
    )
    return cursor.fetchone()["cnt"] > 0


print("Step 1 – Certificates: add UNIQUE KEY uq_ca_serial (ca_id, serial_number) …")
if index_exists("Certificates", "uq_ca_serial"):
    print("  [skip]  index already exists")
else:
    cursor.execute(
        "ALTER TABLE Certificates ADD UNIQUE KEY uq_ca_serial (ca_id, serial_number)"
    )
    print("  [done]  uq_ca_serial added")

conn.commit()
cursor.close()
conn.close()

print()
print("Migration complete.")
