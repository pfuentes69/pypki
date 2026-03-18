# PyPKI

A Python PKI (Public Key Infrastructure) library and service stack. PyPKI provides certificate issuance, revocation, OCSP responses, CRL generation, and key management behind a REST API, with a browser-based management interface and a set of offline test scripts.

---

## Features

- Issue X.509 certificates from a CSR or a JSON request (software keys or PKCS#11 HSM)
- Certificate templates — policy documents that enforce key usage, EKU, SANs, validity, and more
- CA hierarchy support — root and intermediate CAs, certificate chains
- CRL generation
- OCSP responder (RFC 6960)
- EST server (RFC 7030, `/.well-known/est/`)
- Key Management Service (KMS) — centralised key storage and signing; supports software keys and PKCS#11 HSM tokens
- PKCS#12 export
- MySQL backend
- Flask REST API
- Bootstrap 5 web management interface

---

## Requirements

- Python 3.12+
- MySQL 8.0+ (or compatible MariaDB)
- A PKCS#11 library only if using HSM keys (e.g. SoftHSM, SafeNet)

Python dependencies are in `requirements.txt`. Key packages:

| Package | Purpose |
|---|---|
| `cryptography` | Core X.509 / key operations |
| `asn1crypto` | Low-level DER patching (signature replacement) |
| `Flask` | REST API and web interface |
| `mysql-connector-python` | Database access |
| `pykcs11` | PKCS#11 / HSM support |
| `APScheduler` | Background task scheduling |

---

## Project Structure

```
pypki/                          # Python library (importable as `pypki`)
│   ├── ca.py                   # CertificationAuthority — config loading, signing
│   ├── certificate_tools.py    # Certificate / CSR / PKCS#12 generation
│   ├── core.py                 # PyPKI facade — high-level orchestration
│   ├── db.py                   # PKIDataBase — all MySQL operations
│   ├── key_tools.py            # KeyTools — key generation and signing (software + HSM)
│   ├── kms.py                  # KeyManagementService — key generation and KMS signing
│   ├── ocsp_responder.py       # OCSPResponder — OCSP response generation
│   ├── pkcs11_helper.py        # PKCS11Helper — PKCS#11 session wrapper
│   └── pki_tools.py            # PKITools — shared constants and helpers

api/                            # Flask REST API
│   ├── app.py                  # Application factory (create_app)
│   ├── routes/                 # Blueprint route handlers
│   └── services/               # Business logic and adapters

web/                            # Web interfaces
│   ├── app.py                  # Lightweight EST test client (port 5000)
│   ├── html/                   # Static management UI (Bootstrap 5, talks to the API)
│   └── templates/              # Jinja2 templates for the EST client

config/                         # Runtime configuration
│   ├── config.json             # Active config (DB connection, folder paths)
│   ├── ca_store/               # CA config JSON files (one per CA)
│   ├── cert_templates/         # Certificate template JSON files
│   └── ocsp_responders/        # OCSP responder config JSON files

utils/                          # Command-line utilities
│   ├── reset_pki.py            # Drop and recreate the database, reload all config
│   ├── migrate_keys_to_kms.py  # Phase 1 KMS migration — move keys into KeyStorage
│   ├── migrate_keystorage.py   # Schema upgrade — rename table, add columns, backfill
│   ├── generate_crls.py        # Generate and publish CRLs for all CAs
│   └── generate_sample_certs.py

tests/                          # Offline test scripts
│   ├── __main__.py             # Interactive test menu (python -m tests)
│   ├── generate_self_signed_cert.py
│   ├── generate_ca_signed_cert.py
│   ├── generate_ca_signed_cert_from_csr.py
│   ├── generate_ca_signed_p12.py
│   ├── generate_self_signed_p12.py
│   ├── generate_ocsp_cert.py
│   ├── parse_csr_to_json.py
│   └── pkcs11_test.py

doc/                            # Documentation
│   ├── database.md             # Full database schema reference
│   ├── certificate_templates.md # Certificate template JSON format
│   ├── kms_strategy.md         # KMS integration strategy and phases
│   ├── project_notes.md        # Development notes
│   ├── structure.md            # Detailed project structure
│   └── request_examples/       # Sample request JSONs, CSR, and key files

out/                            # Generated output (certificates, keys, CRLs, logs)
```

---

## Setup

### 1. Create a virtual environment

```bash
git clone <repo-url>
cd pypki
bash setup_env.sh
source venv/bin/activate
```

Or manually:

```bash
python3 -m venv venv
source venv/bin/activate
pip install -r requirements.txt
```

### 2. Configure the database connection

Copy the template and edit as needed:

```bash
cp config/config.json config/config.local.json
```

```json
{
    "db_config": {
        "host": "localhost",
        "port": 3306,
        "user": "root",
        "password": "your_password",
        "database": "pypki_db"
    },
    "template_folder": "config/cert_templates",
    "ca_store_folder": "config/ca_store",
    "ocsp_responder_folder": "config/ocsp_responders",
    "default_ca_id": 1,
    "default_template": 7
}
```

The database user needs `CREATE`, `DROP`, `ALTER`, and full DML privileges on the target database.

### 3. Initialise the database

Creates all tables and loads the CAs, certificate templates, and OCSP responders from `config/`:

```bash
python utils/reset_pki.py config/config.local.json
```

> **Warning:** `reset_pki.py` drops the existing database before recreating it. All data is lost.

The schema includes: `KeyStorage`, `CertificationAuthorities`, `CertificateTemplates`, `Certificates`, `OCSPResponders`, `ESTAliases`, `CertificateLogs`, `CertificateRevocationLists`, `AuditLogs`. See `doc/database.md` for the full schema.

---

## Running the API

```bash
python api/app.py
```

The REST API starts on `http://0.0.0.0:8080`. Log output is written to `out/app.log` and stdout.

Key endpoints:

| Method | Path | Description |
|---|---|---|
| GET | `/api/status` | Health check |
| GET | `/api/ca` | List CAs |
| GET | `/api/ca/<id>` | CA details and certificate |
| GET | `/api/template` | List certificate templates |
| GET | `/api/template/<id>` | Template details |
| GET | `/api/template/<id>/export` | Download template as JSON |
| PUT | `/api/template/<id>` | Update a template |
| POST | `/api/template` | Create a template |
| POST | `/api/certificate/issue` | Issue a certificate from a CSR |
| GET | `/api/certificate/<id>` | Certificate details |
| GET | `/api/certificate/pem/<id>` | Download certificate PEM |
| POST | `/api/certificate/revoke/<id>` | Revoke a certificate |
| GET | `/api/est` | List EST aliases |
| POST | `/api/est` | Create EST alias |
| GET | `/api/est/<id>` | Get EST alias |
| PUT | `/api/est/<id>` | Update EST alias |
| DELETE | `/api/est/<id>` | Delete EST alias |
| POST | `/api/est/<id>/set-default` | Set default EST alias |
| POST | `/api/kms/generate-key` | Generate a key via the KMS |
| GET | `/.well-known/est[/<label>]/cacerts` | CA certificate (public, no auth) |
| POST | `/.well-known/est[/<label>]/simpleenroll` | Enroll via CSR → PKCS#7 (Basic Auth if configured) |
| POST | `/.well-known/est[/<label>]/simpleenrollpem` | Enroll via CSR → PEM, non-standard (Basic Auth if configured) |

---

## Management interface

Open `web/html/index.html` in a browser while the API server is running. The interface is organised into four sidebar sections:

**Certificates**
- **Dashboard** — system overview (metrics, CA summary, recent activity)
- **Certificates** — list, inspect, and revoke issued certificates
- **Request** — issue a certificate from a JSON payload
- **CSR Tool** — browser-based key and CSR generator (ECC P-256 or RSA 2048, no server round-trip)

**Certification Authorities**
- **CAs & CRL** — CA list, certificate chain and CRL download
- **Templates** — list, edit, create, and export certificate templates

**EST Service**
- **EST Config** — manage EST enrollment aliases (CA + template binding, Basic Auth credentials)
- **EST Test** — interactively test `cacerts` and `simpleenroll` endpoints against a selected alias

**KMS**
- **Key Generation** — generate RSA, ECDSA, Ed25519, or AES keys

The static pages talk directly to the API at `http://127.0.0.1:8080/api`.

---

## Tests

Interactive menu listing all available tests:

```bash
python -m tests
```

Run a single test directly:

```bash
python tests/generate_self_signed_cert.py
python tests/generate_ca_signed_cert.py
python tests/parse_csr_to_json.py
```

Tests that use a CA load its configuration directly from `config/ca_store/` and sign offline — no running API or database is required. Generated output is written to `out/`.

---

## Utilities

| Script | Description |
|---|---|
| `utils/reset_pki.py` | Recreate the database from scratch and reload all config |
| `utils/migrate_keystorage.py` | Schema upgrade: rename `PrivateKeyStorage` → `KeyStorage`, add `key_type` / `public_key` columns, backfill `key_type` from existing key material |
| `utils/migrate_keys_to_kms.py` | Move CA and OCSP private keys into `KeyStorage`, populate `private_key_reference` |
| `utils/migrate_est_auth_fields.py` | Idempotent schema upgrade: add `username`, `password_hash`, `cert_fingerprint` columns to `ESTAliases` (for existing databases — not needed on fresh installs) |
| `utils/generate_crls.py` | Generate and export CRLs for all active CAs |
| `utils/generate_sample_certs.py` | Issue a batch of sample certificates |

All scripts accept an optional config file path as the first argument (default: `config/config.json`):

```bash
python utils/reset_pki.py config/config.local.json
python utils/migrate_keystorage.py config/config.local.json
```

---

## Documentation

| File | Contents |
|---|---|
| `doc/database.md` | Full schema — all tables, columns, and foreign keys |
| `doc/certificate_templates.md` | Template JSON format and all supported fields |
| `doc/kms_strategy.md` | KMS integration design and migration phases |
| `doc/request_examples/` | Sample request JSON files and example CSR (see `README.md` inside) |
| `doc/structure.md` | Detailed project structure |
