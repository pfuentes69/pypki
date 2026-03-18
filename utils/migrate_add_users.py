"""
DB Migration: Create Users table and seed the first superadmin account.

Applies the following changes to an existing database, idempotently:

  1. Create the Users table (skipped if it already exists):

       id            INT            PK AUTO_INCREMENT
       username      VARCHAR(255)   NOT NULL UNIQUE
       password_hash VARCHAR(255)   NOT NULL  — Werkzeug PBKDF2-SHA256
       role          ENUM           'superadmin' | 'admin' | 'user' | 'auditor'
       is_active     BOOLEAN        DEFAULT TRUE
       last_login    TIMESTAMP      NULL
       created_at    TIMESTAMP      DEFAULT NOW
       updated_at    TIMESTAMP      ON UPDATE NOW

  2. Insert a 'superadmin' account with password 'password'
     (skipped if a user named 'superadmin' already exists).

Usage:
    python utils/migrate_add_users.py [config_file]

    config_file defaults to config/config.json

After running, log in and immediately change the password.
"""

import sys
import os

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

import json
import mysql.connector
from werkzeug.security import generate_password_hash

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

# ── Step 1: Create Users table ────────────────────────────────────────────────

print("Creating Users table …")

cursor.execute("""
    CREATE TABLE IF NOT EXISTS Users (
        id            INT          PRIMARY KEY AUTO_INCREMENT,
        username      VARCHAR(255) NOT NULL UNIQUE,
        password_hash VARCHAR(255) NOT NULL,
        role          ENUM('superadmin', 'admin', 'user', 'auditor') NOT NULL DEFAULT 'user',
        is_active     BOOLEAN      NOT NULL DEFAULT TRUE,
        last_login    TIMESTAMP    NULL,
        created_at    TIMESTAMP    DEFAULT CURRENT_TIMESTAMP,
        updated_at    TIMESTAMP    DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP
    )
""")

print("  [done]  Users table is present")

# ── Step 2: Seed superadmin account ──────────────────────────────────────────

print("Seeding superadmin account …")

hashed = generate_password_hash('password')

cursor.execute("SELECT COUNT(*) FROM Users WHERE username = 'superadmin'")
(count,) = cursor.fetchone()

if count > 0:
    cursor.execute(
        "UPDATE Users SET password_hash = %s WHERE username = 'superadmin'",
        (hashed,)
    )
    print("  [done]  Reset password for existing 'superadmin' user")
else:
    cursor.execute(
        "INSERT INTO Users (username, password_hash, role) VALUES (%s, %s, 'superadmin')",
        ('superadmin', hashed)
    )
    print("  [done]  Created user 'superadmin' with role 'superadmin'")

print()
print("  *** IMPORTANT: log in and change this password immediately ***")

# ── Commit ────────────────────────────────────────────────────────────────────

conn.commit()
cursor.close()
conn.close()

print()
print("Migration complete.")
