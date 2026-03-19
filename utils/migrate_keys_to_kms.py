"""
Phase 1 – KMS Migration: move CA and OCSP responder private keys into KeyStorage.

For every row in CertificationAuthorities and OCSPResponders where private_key_reference
is NULL, this script:
  1. Reads the existing private_key / HSM fields from the source table.
  2. Inserts a new row into KeyStorage.
  3. Sets private_key_reference to the new ID.

The script is idempotent: rows that already have private_key_reference set are skipped.

Usage:
    python utils/migrate_keys_to_kms.py [config_file]

    config_file defaults to config/config.json
"""

import sys
import os

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

import time
import json
import mysql.connector
from pypki.db import PKIDataBase


# ── Helpers ──────────────────────────────────────────────────────────────────

def determine_storage_type(row: dict) -> str:
    """Return 'HSM' if the row uses an HSM key, otherwise 'Plain'."""
    token_key_id = row.get("token_key_id") or ""
    return "HSM" if token_key_id.strip() else "Plain"


def migrate_table(cursor, db_name: str, source_table: str, stats: dict) -> None:
    """
    Migrate keys from source_table (CertificationAuthorities or OCSPResponders)
    into KeyStorage and back-fill private_key_reference.
    """
    cursor.execute(f"USE {db_name}")

    cursor.execute(f"""
        SELECT id, name, private_key, private_key_reference,
               token_slot, token_key_id, token_password
        FROM {source_table}
    """)
    rows = cursor.fetchall()

    for row in rows:
        row_id   = row["id"]
        row_name = row["name"]

        if row["private_key_reference"] is not None:
            print(f"  [{source_table}] id={row_id} '{row_name}' — already migrated, skipping")
            stats["skipped"] += 1
            continue

        storage_type = determine_storage_type(row)

        # Insert into KeyStorage (include token_password for HSM keys)
        cursor.execute(f"USE {db_name}")
        cursor.execute("""
            INSERT INTO KeyStorage (private_key, storage_type, hsm_slot, hsm_token_id, token_password)
            VALUES (%s, %s, %s, %s, %s)
        """, (
            row["private_key"],
            storage_type,
            row["token_slot"],
            row["token_key_id"] or None,
            row["token_password"] or None,
        ))
        new_key_id = cursor.lastrowid

        # Back-fill private_key_reference
        cursor.execute(f"""
            UPDATE {source_table}
            SET private_key_reference = %s
            WHERE id = %s
        """, (new_key_id, row_id))

        print(f"  [{source_table}] id={row_id} '{row_name}' — migrated → KeyStorage id={new_key_id} ({storage_type})")
        stats["migrated"] += 1


# ── Main ─────────────────────────────────────────────────────────────────────

def main():
    config_file = sys.argv[1] if len(sys.argv) > 1 else "config/config.json"

    print(f"KMS Phase 1 Migration")
    print(f"Config: {config_file}")
    print()

    with open(config_file, "r") as f:
        config = json.load(f)

    db_config = config["db_config"]
    db_name   = db_config["database"]

    connection = mysql.connector.connect(
        host=db_config["host"],
        port=db_config["port"],
        user=db_config["user"],
        password=db_config["password"],
        database=db_name,
    )
    cursor = connection.cursor(dictionary=True, buffered=True)

    stats = {"migrated": 0, "skipped": 0}

    try:
        print("── CertificationAuthorities ─────────────────────────────────")
        migrate_table(cursor, db_name, "CertificationAuthorities", stats)
        print()

        print("── OCSPResponders ───────────────────────────────────────────")
        migrate_table(cursor, db_name, "OCSPResponders", stats)
        print()

        connection.commit()
        print("── Result ───────────────────────────────────────────────────")
        print(f"  Migrated : {stats['migrated']}")
        print(f"  Skipped  : {stats['skipped']}")
        print()
        print("Migration committed successfully.")

    except Exception as e:
        connection.rollback()
        print(f"\nERROR: {e}")
        print("Transaction rolled back. No changes were made.")
        sys.exit(1)

    finally:
        cursor.close()
        connection.close()


if __name__ == "__main__":
    start = time.time()
    main()
    print(f"\nCompleted in {time.time() - start:.3f}s")
