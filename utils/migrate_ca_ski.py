"""
DB Migration: Recompute CertificationAuthorities.ski using the correct method.

The previous implementation hashed the full SubjectPublicKeyInfo DER for RSA
keys, which does not match what OCSP clients compute as issuer_key_hash
(SHA-1 of the BIT STRING value, i.e. the PKCS#1 / RSAPublicKey DER).

This migration recomputes the ski for every CA row:
  1. Try to read it from the certificate's SubjectKeyIdentifier extension
     (most accurate — this is exactly what OCSP clients use).
  2. Fall back to computing SHA-1 of the BIT STRING value:
       EC  → SHA-1 of the uncompressed point (was already correct)
       RSA → SHA-1 of the PKCS#1 DER (was incorrectly hashing the full SPKI)

The OCSPResponders.issuer_ski column is read from config files and is not
touched by this migration (it already contains the correct value).

Usage:
    python utils/migrate_ca_ski.py [config_file]

    config_file defaults to config/config.json
"""

import sys
import os

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

import json
import mysql.connector
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat
from cryptography.hazmat.primitives.asymmetric import ec

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


def compute_ski(cert_pem: str) -> str:
    """Return the correct SKI hex string for a PEM certificate."""
    cert = x509.load_pem_x509_certificate(cert_pem.encode("utf-8"))
    try:
        ext = cert.extensions.get_extension_for_class(x509.SubjectKeyIdentifier)
        return ext.value.digest.hex()
    except x509.ExtensionNotFound:
        pub = cert.public_key()
        if isinstance(pub, ec.EllipticCurvePublicKey):
            key_bytes = pub.public_bytes(Encoding.X962, PublicFormat.UncompressedPoint)
        else:
            key_bytes = pub.public_bytes(Encoding.DER, PublicFormat.PKCS1)
        digest = hashes.Hash(hashes.SHA1())
        digest.update(key_bytes)
        return digest.finalize().hex()


print("Recomputing ski for all CertificationAuthorities rows …")
cursor.execute("SELECT id, name, ski, certificate FROM CertificationAuthorities")
rows = cursor.fetchall()

updated = 0
for row in rows:
    if not row['certificate']:
        print(f"  [skip]  CA id={row['id']} '{row['name']}': no certificate stored")
        continue

    correct_ski = compute_ski(row['certificate'])
    if correct_ski == row['ski']:
        print(f"  [ok]    CA id={row['id']} '{row['name']}': ski already correct ({correct_ski})")
    else:
        cursor.execute(
            "UPDATE CertificationAuthorities SET ski = %s WHERE id = %s",
            (correct_ski, row['id'])
        )
        print(f"  [fixed] CA id={row['id']} '{row['name']}': {row['ski']} → {correct_ski}")
        updated += 1

print(f"\n{updated} of {len(rows)} row(s) updated.")

conn.commit()
cursor.close()
conn.close()

print()
print("Migration complete.")
