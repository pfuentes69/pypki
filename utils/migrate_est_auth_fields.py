"""
DB Migration: Add authentication fields to ESTAliases

Applies the following changes to an existing database, idempotently:

  1. Add column  username VARCHAR(255)
     (skipped if the column already exists)

  2. Add column  password_hash VARCHAR(255)
     (skipped if the column already exists)

  3. Add column  cert_fingerprint VARCHAR(255)
     (skipped if the column already exists)

These columns support Basic Authentication (username / password_hash) and
a future mTLS flow (cert_fingerprint) on EST enrollment endpoints.

The password_hash column is intended to store a Werkzeug PBKDF2-SHA256 hash
produced by werkzeug.security.generate_password_hash().

Usage:
    python utils/migrate_est_auth_fields.py [config_file]

    config_file defaults to config/config.json
"""

import sys
import os

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

import json
import mysql.connector

# ── Config ────────────────────────────────────────────────────────────────────

DEFAULT_CONFIG = os.path.join(os.path.dirname(__file__), '..', 'config', 'config.json')

config_path = sys.argv[1] if len(sys.argv) > 1 else DEFAULT_CONFIG

with open(config_path) as f:
    config = json.load(f)

db_cfg = config['db_config']
DB_NAME = db_cfg['database']

# ── Helpers ───────────────────────────────────────────────────────────────────

def column_exists(cursor, table, column):
    cursor.execute(
        """SELECT COUNT(*) FROM information_schema.COLUMNS
           WHERE TABLE_SCHEMA = %s AND TABLE_NAME = %s AND COLUMN_NAME = %s""",
        (DB_NAME, table, column)
    )
    return cursor.fetchone()[0] > 0


def add_column_if_missing(cursor, table, column, definition, after=None):
    if column_exists(cursor, table, column):
        print(f"  [skip]  {table}.{column} already exists")
        return
    after_clause = f" AFTER `{after}`" if after else ""
    cursor.execute(f"ALTER TABLE `{table}` ADD COLUMN `{column}` {definition}{after_clause}")
    print(f"  [done]  Added {table}.{column}")


# ── Main ──────────────────────────────────────────────────────────────────────

print(f"Connecting to {db_cfg['host']}:{db_cfg['port']} / {DB_NAME} …")

conn = mysql.connector.connect(
    host=db_cfg['host'],
    port=db_cfg.get('port', 3306),
    user=db_cfg['user'],
    password=db_cfg['password'],
    database=DB_NAME,
)
cursor = conn.cursor()

print("Migrating ESTAliases table …")

add_column_if_missing(cursor, 'ESTAliases', 'username',         'VARCHAR(255)',  after='is_default')
add_column_if_missing(cursor, 'ESTAliases', 'password_hash',    'VARCHAR(255)',  after='username')
add_column_if_missing(cursor, 'ESTAliases', 'cert_fingerprint', 'VARCHAR(255)',  after='password_hash')

conn.commit()
cursor.close()
conn.close()

print("Migration complete.")
