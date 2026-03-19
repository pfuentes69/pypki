"""
DB Migration: Backfill ca_id on OCSPResponders.

For each row in OCSPResponders where ca_id is NULL, this script looks up the
matching CA in CertificationAuthorities by ski = issuer_ski and sets ca_id.

Changes applied (idempotently — only rows with ca_id IS NULL are updated):
  OCSPResponders
    ca_id  INT  (populated from CertificationAuthorities.id WHERE ski = issuer_ski)

Usage:
    python utils/migrate_ocsp_ca_id.py [config_file]

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

print("Backfilling OCSPResponders.ca_id …")

cursor.execute("SELECT id, name, issuer_ski FROM OCSPResponders WHERE ca_id IS NULL")
rows = cursor.fetchall()

if not rows:
    print("  [skip]  no rows with ca_id IS NULL")
else:
    updated = 0
    for row in rows:
        cursor.execute(
            "SELECT id FROM CertificationAuthorities WHERE ski = %s",
            (row['issuer_ski'],)
        )
        ca = cursor.fetchone()
        if ca:
            cursor.execute(
                "UPDATE OCSPResponders SET ca_id = %s WHERE id = %s",
                (ca['id'], row['id'])
            )
            print(f"  [done]  OCSP '{row['name']}' (id={row['id']}) → ca_id={ca['id']}")
            updated += 1
        else:
            print(f"  [warn]  OCSP '{row['name']}' (id={row['id']}): "
                  f"no CA found with ski='{row['issuer_ski']}' — ca_id left NULL")

    print(f"  {updated} of {len(rows)} row(s) updated")

conn.commit()
cursor.close()
conn.close()

print()
print("Migration complete.")
