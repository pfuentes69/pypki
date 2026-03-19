"""
DB Migration: Add OCSP responder configuration columns to OCSPResponders table.

Adds five new columns if they don't already exist:
  - response_validity_hours INT DEFAULT 24  (derived from existing response_validity * 24)
  - nonce_policy             ENUM('optional','required','disabled') DEFAULT 'optional'
  - include_cert_in_response BOOLEAN DEFAULT TRUE
  - responder_id_encoding    ENUM('hash','name') DEFAULT 'hash'
  - hash_algorithm           ENUM('sha1','sha256') DEFAULT 'sha1'

Safe to run multiple times (idempotent: skips columns that already exist).

Usage:
    python utils/migrate_ocsp_settings.py [config_file]

    config_file defaults to config/config.json
"""

import sys
import os
import json

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

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

# Fetch existing columns
cursor.execute("""
    SELECT COLUMN_NAME
    FROM INFORMATION_SCHEMA.COLUMNS
    WHERE TABLE_SCHEMA = %s AND TABLE_NAME = 'OCSPResponders'
""", (DB_NAME,))
existing_columns = {row['COLUMN_NAME'] for row in cursor.fetchall()}

new_columns = [
    ("response_validity_hours", "INT DEFAULT 24"),
    ("nonce_policy",            "ENUM('optional','required','disabled') DEFAULT 'optional'"),
    ("include_cert_in_response","BOOLEAN DEFAULT TRUE"),
    ("responder_id_encoding",   "ENUM('hash','name') DEFAULT 'hash'"),
    ("hash_algorithm",          "ENUM('sha1','sha256') DEFAULT 'sha1'"),
]

for col_name, col_def in new_columns:
    if col_name in existing_columns:
        print(f"  [skip]  column '{col_name}' already exists")
    else:
        cursor.execute(f"ALTER TABLE OCSPResponders ADD COLUMN {col_name} {col_def}")
        print(f"  [done]  added column '{col_name}'")

# Populate response_validity_hours from existing response_validity where null/zero
cursor.execute("""
    UPDATE OCSPResponders
    SET response_validity_hours = response_validity * 24
    WHERE response_validity_hours IS NULL OR response_validity_hours = 0
""")
if cursor.rowcount:
    print(f"  [done]  populated response_validity_hours for {cursor.rowcount} row(s)")

conn.commit()
cursor.close()
conn.close()

print()
print("Migration complete.")
