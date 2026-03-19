"""
DB Migration: Consolidate HSM fields into KeyStorage.

IMPORTANT — run order
---------------------
This migration must be run AFTER migrate_keys_to_kms.py.
That earlier script moves private keys from CertificationAuthorities /
OCSPResponders into KeyStorage and sets private_key_reference.  This
script then copies token_password to the corresponding KeyStorage rows and
drops the now-redundant token_slot / token_key_id / token_password columns
from both CA and OCSP tables.

Changes applied (idempotently):

  KeyStorage
    + token_password  VARCHAR(255)  NULL

  CertificationAuthorities
    - token_slot      INT
    - token_key_id    VARCHAR(64)
    - token_password  VARCHAR(64)

  OCSPResponders
    - token_slot      INT
    - token_key_id    VARCHAR(64)
    - token_password  VARCHAR(64)

The token_password for HSM CAs / OCSP responders is copied to the
matching KeyStorage row before the columns are dropped so no data is lost.

Usage:
    python utils/migrate_hsm_fields.py [config_file]

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

print(f"Connecting to {db_cfg['host']}:{db_cfg.get('port', 3306)} / {DB_NAME} …")

conn = mysql.connector.connect(
    host=db_cfg['host'],
    port=db_cfg.get('port', 3306),
    user=db_cfg['user'],
    password=db_cfg['password'],
    database=DB_NAME,
)
cursor = conn.cursor(dictionary=True)


def column_exists(table: str, column: str) -> bool:
    cursor.execute(
        "SELECT COUNT(*) AS cnt FROM information_schema.COLUMNS "
        "WHERE TABLE_SCHEMA = %s AND TABLE_NAME = %s AND COLUMN_NAME = %s",
        (DB_NAME, table, column)
    )
    return cursor.fetchone()["cnt"] > 0


# ── Step 1: Add token_password to KeyStorage ──────────────────────────────────

print("Step 1 – KeyStorage: add token_password column …")
if column_exists("KeyStorage", "token_password"):
    print("  [skip]  column already exists")
else:
    cursor.execute(
        "ALTER TABLE KeyStorage ADD COLUMN token_password VARCHAR(255) NULL"
    )
    print("  [done]  token_password added to KeyStorage")

# ── Step 2: Copy token_password for HSM CAs ───────────────────────────────────

print("Step 2 – Copy token_password from CertificationAuthorities to KeyStorage …")
if column_exists("CertificationAuthorities", "token_password"):
    cursor.execute("""
        UPDATE KeyStorage ks
        JOIN CertificationAuthorities ca ON ca.private_key_reference = ks.id
        SET ks.token_password = ca.token_password
        WHERE ca.token_password IS NOT NULL
          AND ca.token_password != ''
          AND ks.storage_type = 'HSM'
    """)
    print(f"  [done]  {cursor.rowcount} KeyStorage row(s) updated")
else:
    print("  [skip]  token_password column already removed from CertificationAuthorities")

# ── Step 3: Copy token_password for HSM OCSP responders ──────────────────────

print("Step 3 – Copy token_password from OCSPResponders to KeyStorage …")
if column_exists("OCSPResponders", "token_password"):
    cursor.execute("""
        UPDATE KeyStorage ks
        JOIN OCSPResponders ocsp ON ocsp.private_key_reference = ks.id
        SET ks.token_password = ocsp.token_password
        WHERE ocsp.token_password IS NOT NULL
          AND ocsp.token_password != ''
          AND ks.storage_type = 'HSM'
    """)
    print(f"  [done]  {cursor.rowcount} KeyStorage row(s) updated")
else:
    print("  [skip]  token_password column already removed from OCSPResponders")

# ── Step 4: Drop token_* columns from CertificationAuthorities ───────────────

print("Step 4 – CertificationAuthorities: drop token_slot, token_key_id, token_password …")
for col in ("token_slot", "token_key_id", "token_password"):
    if column_exists("CertificationAuthorities", col):
        cursor.execute(f"ALTER TABLE CertificationAuthorities DROP COLUMN {col}")
        print(f"  [done]  dropped {col}")
    else:
        print(f"  [skip]  {col} already absent")

# ── Step 5: Drop token_* columns from OCSPResponders ────────────────────────

print("Step 5 – OCSPResponders: drop token_slot, token_key_id, token_password …")
for col in ("token_slot", "token_key_id", "token_password"):
    if column_exists("OCSPResponders", col):
        cursor.execute(f"ALTER TABLE OCSPResponders DROP COLUMN {col}")
        print(f"  [done]  dropped {col}")
    else:
        print(f"  [skip]  {col} already absent")

# ── Commit ────────────────────────────────────────────────────────────────────

conn.commit()
cursor.close()
conn.close()

print()
print("Migration complete.")
