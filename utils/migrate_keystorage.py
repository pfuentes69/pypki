"""
DB Migration: PrivateKeyStorage → KeyStorage

Applies the following changes to an existing database, idempotently:

  1. Rename table  PrivateKeyStorage  →  KeyStorage
     (skipped if KeyStorage already exists)

  2. Add column    key_type VARCHAR(64)
     (skipped if the column already exists)

  3. Add column    public_key TEXT
     (skipped if the column already exists)

  4. Backfill key_type (and public_key) for existing rows where key_type IS NULL.
     Each row's private_key material is parsed with the cryptography library:
       - PEM private key  → RSA-<size>, ECDSA-<curve>, or Ed25519
       - base64 raw bytes → AES-<bits>  (128 / 192 / 256 / 512)
       - HSM row (no PEM) → skipped with a warning

Usage:
    python utils/migrate_keystorage.py [config_file]

    config_file defaults to config/config.json
"""

import sys
import os

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

import base64
import time
import json
import mysql.connector

from cryptography.hazmat.primitives.serialization import (
    load_pem_private_key, Encoding, PublicFormat
)
from cryptography.hazmat.primitives.asymmetric import rsa, ec, ed25519


# ── EC curve name mapping ──────────────────────────────────────────────────────

_CURVE_MAP = {
    "secp256r1": "P-256",
    "secp384r1": "P-384",
    "secp521r1": "P-521",
}


# ── Key introspection ─────────────────────────────────────────────────────────

def detect_key(private_key_str: str) -> tuple:
    """
    Parse private_key_str and return (key_type, public_key_pem).
    Returns (None, None) if the material cannot be identified.
    """
    if not private_key_str or not private_key_str.strip():
        return None, None

    # ── Try asymmetric PEM ───────────────────────────────────────────────────
    if "-----" in private_key_str:
        try:
            key = load_pem_private_key(private_key_str.encode("utf-8"), password=None)
            pub = key.public_key()
            pub_pem = pub.public_bytes(Encoding.PEM, PublicFormat.SubjectPublicKeyInfo).decode()

            if isinstance(key, rsa.RSAPrivateKey):
                return f"RSA-{key.key_size}", pub_pem
            elif isinstance(key, ec.EllipticCurvePrivateKey):
                curve = _CURVE_MAP.get(key.curve.name, key.curve.name)
                return f"ECDSA-{curve}", pub_pem
            elif isinstance(key, ed25519.Ed25519PrivateKey):
                return "Ed25519", pub_pem
            else:
                return None, None
        except Exception:
            return None, None

    # ── Try symmetric base64 (AES) ───────────────────────────────────────────
    try:
        raw = base64.b64decode(private_key_str.strip())
        size_bits = len(raw) * 8
        if size_bits in {128, 192, 256, 512}:
            return f"AES-{size_bits}", None
    except Exception:
        pass

    return None, None


# ── Helpers ───────────────────────────────────────────────────────────────────

def table_exists(cursor, db_name: str, table_name: str) -> bool:
    cursor.execute("""
        SELECT COUNT(*) AS cnt
        FROM information_schema.TABLES
        WHERE TABLE_SCHEMA = %s AND TABLE_NAME = %s
    """, (db_name, table_name))
    return cursor.fetchone()["cnt"] > 0


def column_exists(cursor, db_name: str, table_name: str, column_name: str) -> bool:
    cursor.execute("""
        SELECT COUNT(*) AS cnt
        FROM information_schema.COLUMNS
        WHERE TABLE_SCHEMA = %s AND TABLE_NAME = %s AND COLUMN_NAME = %s
    """, (db_name, table_name, column_name))
    return cursor.fetchone()["cnt"] > 0


# ── Migration steps ───────────────────────────────────────────────────────────

def step_rename_table(cursor, db_name: str) -> None:
    """Rename PrivateKeyStorage to KeyStorage if needed."""
    if not table_exists(cursor, db_name, "PrivateKeyStorage"):
        if table_exists(cursor, db_name, "KeyStorage"):
            print("  [SKIP] KeyStorage already exists — rename not needed")
        else:
            print("  [WARN] Neither PrivateKeyStorage nor KeyStorage found — nothing to rename")
        return

    if table_exists(cursor, db_name, "KeyStorage"):
        print("  [SKIP] Both tables exist — skipping rename (manual check may be needed)")
        return

    cursor.execute(f"USE {db_name}")
    cursor.execute("RENAME TABLE PrivateKeyStorage TO KeyStorage")
    print("  [OK]   Renamed PrivateKeyStorage → KeyStorage")


def step_add_column(cursor, db_name: str, column_name: str, column_def: str) -> None:
    """Add a column to KeyStorage if it doesn't already exist."""
    if column_exists(cursor, db_name, "KeyStorage", column_name):
        print(f"  [SKIP] Column KeyStorage.{column_name} already exists")
        return

    cursor.execute(f"USE {db_name}")
    cursor.execute(f"ALTER TABLE KeyStorage ADD COLUMN {column_name} {column_def}")
    print(f"  [OK]   Added column KeyStorage.{column_name}")


def step_backfill_key_type(cursor, db_name: str) -> None:
    """Populate key_type (and public_key) for rows where key_type is NULL."""
    cursor.execute(f"USE {db_name}")
    cursor.execute("""
        SELECT id, storage_type, private_key
        FROM KeyStorage
        WHERE key_type IS NULL
    """)
    rows = cursor.fetchall()

    if not rows:
        print("  [SKIP] No rows with NULL key_type — nothing to backfill")
        return

    updated = skipped = unknown = 0

    for row in rows:
        row_id       = row["id"]
        storage_type = row["storage_type"]
        private_key  = row["private_key"]

        if storage_type == "HSM":
            print(f"  [SKIP] id={row_id} storage_type=HSM — cannot derive key_type from HSM reference")
            skipped += 1
            continue

        key_type, pub_pem = detect_key(private_key)

        if key_type is None:
            print(f"  [WARN] id={row_id} — could not identify key material, skipping")
            unknown += 1
            continue

        cursor.execute("""
            UPDATE KeyStorage
            SET key_type = %s, public_key = %s
            WHERE id = %s
        """, (key_type, pub_pem, row_id))

        pub_note = " + public_key" if pub_pem else ""
        print(f"  [OK]   id={row_id} → key_type={key_type}{pub_note}")
        updated += 1

    print()
    print(f"  Updated: {updated}  |  Skipped (HSM): {skipped}  |  Unrecognised: {unknown}")


# ── Main ──────────────────────────────────────────────────────────────────────

def main():
    config_file = sys.argv[1] if len(sys.argv) > 1 else "config/config.json"

    print("DB Migration: PrivateKeyStorage → KeyStorage")
    print(f"Config: {config_file}")
    print()

    with open(config_file, "r") as f:
        config = json.load(f)

    db_config = config["db_config"]
    db_name = db_config["database"]

    connection = mysql.connector.connect(
        host=db_config["host"],
        port=db_config["port"],
        user=db_config["user"],
        password=db_config["password"],
        database=db_name,
    )
    cursor = connection.cursor(dictionary=True, buffered=True)

    try:
        print("── Step 1: Rename table ─────────────────────────────────────")
        step_rename_table(cursor, db_name)
        print()

        print("── Step 2: Add key_type column ──────────────────────────────")
        step_add_column(cursor, db_name, "key_type", "VARCHAR(64) NULL AFTER certificate_id")
        print()

        print("── Step 3: Add public_key column ────────────────────────────")
        step_add_column(cursor, db_name, "public_key", "TEXT NULL AFTER private_key")
        print()

        print("── Step 4: Backfill key_type ────────────────────────────────")
        step_backfill_key_type(cursor, db_name)
        print()

        connection.commit()
        print("── Migration committed successfully. ────────────────────────")

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
