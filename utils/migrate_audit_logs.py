"""
DB Migration: Replace CertificateLogs and old AuditLogs with the new AuditLogs table.

Changes applied (idempotently):

  1. Drop the CertificateLogs table (and its FK constraint) if it exists.
  2. Drop the old AuditLogs table if it exists (had action_type / action_details columns).
  3. Create the new AuditLogs table:

       id            INT            PK AUTO_INCREMENT
       resource_type VARCHAR(64)    NOT NULL  — 'certificates', 'cas', 'templates', etc.
       resource_id   INT            NULL      — id of the affected row in the DB
       action        VARCHAR(64)    NOT NULL  — e.g. 'CREATE', 'UPDATE', 'DELETE', 'REVOKE'
       user_id       INT            NOT NULL DEFAULT 0  — 0 = automated/system
       created_at    TIMESTAMP      DEFAULT CURRENT_TIMESTAMP

Usage:
    python utils/migrate_audit_logs.py [config_file]

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

# ── Connect ───────────────────────────────────────────────────────────────────

print(f"Connecting to {db_cfg['host']}:{db_cfg.get('port', 3306)} / {DB_NAME} …")

conn = mysql.connector.connect(
    host=db_cfg['host'],
    port=db_cfg.get('port', 3306),
    user=db_cfg['user'],
    password=db_cfg['password'],
    database=DB_NAME,
)
cursor = conn.cursor()

# Temporarily disable FK checks so we can drop tables with constraints
cursor.execute("SET FOREIGN_KEY_CHECKS = 0")

# ── Step 1: Drop CertificateLogs ──────────────────────────────────────────────

print("Dropping CertificateLogs table (if it exists) …")
cursor.execute("DROP TABLE IF EXISTS CertificateLogs")
print("  [done]")

# ── Step 2: Drop old AuditLogs ────────────────────────────────────────────────

print("Dropping old AuditLogs table (if it exists) …")
cursor.execute("DROP TABLE IF EXISTS AuditLogs")
print("  [done]")

# ── Step 3: Re-enable FK checks ───────────────────────────────────────────────

cursor.execute("SET FOREIGN_KEY_CHECKS = 1")

# ── Step 4: Create new AuditLogs ──────────────────────────────────────────────

print("Creating new AuditLogs table …")
cursor.execute("""
    CREATE TABLE AuditLogs (
        id            INT          PRIMARY KEY AUTO_INCREMENT,
        resource_type VARCHAR(64)  NOT NULL,
        resource_id   INT          NULL,
        action        VARCHAR(64)  NOT NULL,
        user_id       INT          NOT NULL DEFAULT 0,
        created_at    TIMESTAMP    DEFAULT CURRENT_TIMESTAMP
    )
""")
print("  [done]  AuditLogs table created")

# ── Commit ────────────────────────────────────────────────────────────────────

conn.commit()
cursor.close()
conn.close()

print()
print("Migration complete.")
