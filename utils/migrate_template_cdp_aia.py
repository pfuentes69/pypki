"""
DB Migration: Update CertificateTemplates CDP and AIA extension schema.

Old CDP format:
  "cdp": { "url": "...", "critical": false }

New CDP format:
  "cdp": { "include": true, "useCADefault": false, "url": "...", "critical": false }

Old AIA format:
  "aia": { "authorityInfoAccess": { "OCSP": { "url": "..." }, "caIssuers": { "url": "..." } }, "critical": false }

New AIA format:
  "aia": {
    "critical": false,
    "ocsp":      { "include": true, "useCADefault": false, "url": "..." },
    "caIssuers": { "include": true, "useCADefault": false, "url": "..." }
  }

Templates that already use the new format (detected by the presence of "include" key in cdp
or sub-objects in aia) are skipped.

Usage:
    python utils/migrate_template_cdp_aia.py [config_file]

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


def migrate_cdp(cdp: dict) -> dict:
    """Convert old CDP format to new format."""
    if "include" in cdp:
        return None  # already new format
    return {
        "include":      True,
        "useCADefault": False,
        "url":          cdp.get("url", ""),
        "critical":     cdp.get("critical", False),
    }


def migrate_aia(aia: dict) -> dict:
    """Convert old AIA format to new format."""
    if "ocsp" in aia or "caIssuers" in aia:
        return None  # already new format
    access = aia.get("authorityInfoAccess", {})
    new_aia = {"critical": aia.get("critical", False)}

    ocsp_data = access.get("OCSP")
    new_aia["ocsp"] = (
        {"include": True, "useCADefault": False, "url": ocsp_data["url"]}
        if ocsp_data else {"include": False}
    )

    issuers_data = access.get("caIssuers")
    new_aia["caIssuers"] = (
        {"include": True, "useCADefault": False, "url": issuers_data["url"]}
        if issuers_data else {"include": False}
    )

    return new_aia


cursor.execute("SELECT id, name, definition FROM CertificateTemplates")
rows = cursor.fetchall()

updated = skipped = 0

for row in rows:
    definition = row['definition']
    if isinstance(definition, str):
        definition = json.loads(definition)

    ext = definition.get("extensions", {})
    changed = False

    if "cdp" in ext:
        new_cdp = migrate_cdp(ext["cdp"])
        if new_cdp is not None:
            ext["cdp"] = new_cdp
            changed = True

    if "aia" in ext:
        new_aia = migrate_aia(ext["aia"])
        if new_aia is not None:
            ext["aia"] = new_aia
            changed = True

    if not changed:
        print(f"  [skip]  id={row['id']} '{row['name']}' — already up to date")
        skipped += 1
        continue

    cursor.execute(
        "UPDATE CertificateTemplates SET definition = %s WHERE id = %s",
        (json.dumps(definition), row['id'])
    )
    print(f"  [done]  id={row['id']} '{row['name']}' — migrated")
    updated += 1

conn.commit()
cursor.close()
conn.close()

print()
print(f"Updated: {updated}  |  Skipped: {skipped}")
print("Migration complete.")
