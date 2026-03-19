# pyPKI

A Python PKI (Public Key Infrastructure) management service. pyPKI provides certificate issuance, revocation, OCSP responses, CRL generation, and key management behind a REST API, with a browser-based management interface.

---

## Features

- Issue X.509 certificates from a CSR or a JSON request (software keys or PKCS#11 HSM)
- Certificate templates — policy documents that enforce key usage, EKU, SANs, validity, AIA, and CDP
- CA hierarchy support — root and intermediate CAs, certificate chains
- CRL generation and publishing
- OCSP responder (RFC 6960) — configurable nonce policy, hash algorithm, and responder ID encoding
- EST server (RFC 7030, `/.well-known/est/`)
- Key Management Service (KMS) — centralised key storage; supports software keys and PKCS#11 HSM tokens
- PKCS#12 export
- MariaDB / MySQL backend
- Flask REST API
- Bootstrap 5 browser management interface
- Audit log, application log, and database backup/restore tools

---

## Requirements

- Python 3.11+
- MariaDB 10.6+ or MySQL 8.0+
- A PKCS#11 library only if using HSM keys (e.g. SoftHSM, SafeNet)

Python dependencies are in `requirements.txt`. Key packages:

| Package | Purpose |
|---|---|
| `cryptography` | Core X.509 / key operations |
| `asn1crypto` | Low-level DER patching |
| `Flask` | REST API and web interface |
| `mysql-connector-python` | Database access |
| `pykcs11` | PKCS#11 / HSM support |
| `APScheduler` | Background task scheduling |
| `PyJWT` | Authentication tokens |

---

## Quick Start (Linux server)

The included `setup.sh` installs all dependencies, configures MariaDB, creates the database, and sets up a systemd service in one step.

```bash
git clone <repo-url>
cd pypki
sudo bash setup.sh
```

The script will:

1. Install system packages (Python, MariaDB, dev headers) via `apt` or `dnf`
2. Create a `pypki_user` database user with a randomly generated password
3. Generate `config/config.json` with the DB credentials and a random JWT secret key
4. Create a Python virtual environment and install `requirements.txt`
5. Initialise the database schema and seed data (`utils/reset_pki.py`)
6. Install and start a `pypki` systemd service

After setup the interface is available at `http://<server-ip>:8080`.

**Default credentials: `admin` / `admin` — change immediately after first login.**

Credentials generated during setup are saved to `.setup_credentials` (chmod 600). Delete that file once you have noted the database password.

> Supported distros: Ubuntu 22.04/24.04, Debian 11/12, Rocky/Alma/RHEL 9.
> Run `sudo bash setup.sh` again at any time — it is safe to re-run (skips already-done steps).

---

## Manual Setup

### 1. Install system dependencies

Debian/Ubuntu:
```bash
sudo apt-get install python3.12 python3.12-venv python3.12-dev \
    mariadb-server libmariadb-dev pkg-config openssl
```

RHEL/Rocky/Alma:
```bash
sudo dnf install python3 python3-devel mariadb-server mariadb-devel openssl
```

### 2. Create the virtual environment

```bash
python3 -m venv venv
source venv/bin/activate
pip install -r requirements.txt
```

### 3. Create a MariaDB database and user

```sql
CREATE DATABASE pypki_db CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci;
CREATE USER 'pypki_user'@'localhost' IDENTIFIED BY 'your_strong_password';
GRANT ALL PRIVILEGES ON pypki_db.* TO 'pypki_user'@'localhost';
FLUSH PRIVILEGES;
```

### 4. Create `config/config.json`

```json
{
    "db_config": {
        "host": "localhost",
        "port": 3306,
        "user": "pypki_user",
        "password": "your_strong_password",
        "database": "pypki_db"
    },
    "template_folder":       "config/cert_templates",
    "ca_store_folder":       "config/ca_store",
    "ocsp_responder_folder": "config/ocsp_responders",
    "default_ca_id":         1,
    "default_template":      7,
    "secret_key":            "replace-with-64-random-chars"
}
```

Generate a secret key with:
```bash
openssl rand -base64 48 | tr -dc 'A-Za-z0-9_-' | head -c 64
```

### 5. Initialise the database

> **Warning:** this drops and recreates the entire database. All existing data is lost.

```bash
venv/bin/python utils/reset_pki.py
```

### 6. Start the server

```bash
source venv/bin/activate
python web/app.py
```

The server starts on `http://0.0.0.0:8080`. Logs are written to `out/app.log` and stdout.

---

## Project Structure

```
pypki/                          # Core Python library
│   ├── ca.py                   # CertificationAuthority — config loading, signing
│   ├── certificate_tools.py    # Certificate / CSR / PKCS#12 generation
│   ├── core.py                 # PyPKI facade — high-level orchestration
│   ├── db.py                   # PKIDataBase — all database operations
│   ├── key_tools.py            # Key generation and signing (software + HSM)
│   ├── kms.py                  # KeyManagementService
│   ├── ocsp_responder.py       # OCSP response generation
│   ├── pkcs11_helper.py        # PKCS#11 session wrapper
│   └── pki_tools.py            # Shared constants and helpers

web/                            # Flask application
│   ├── app.py                  # Entry point
│   ├── routes/                 # Blueprint route handlers
│   │   ├── main_routes.py      # Main REST API
│   │   ├── auth_routes.py      # Login / JWT
│   │   ├── est_routes.py       # EST (RFC 7030)
│   │   └── ocsp_routes.py      # OCSP (RFC 6960)
│   ├── services/               # Business logic adapters
│   ├── static/                 # Client-side JS (auth.js, pypki_ui.js)
│   └── templates/              # Jinja2/Bootstrap 5 pages

config/                         # Runtime configuration (not committed to git)
│   ├── config.json             # DB connection, folder paths, secret key
│   ├── ca_store/               # CA config JSON files
│   ├── cert_templates/         # Certificate template JSON files
│   └── ocsp_responders/        # OCSP responder config JSON files

utils/                          # Command-line utilities
│   ├── reset_pki.py            # Drop and recreate database, reload all config
│   ├── restore_backup.py       # Restore database from a SQL backup file
│   ├── generate_crls.py        # Generate and publish CRLs for all active CAs
│   ├── generate_sample_certs.py
│   ├── migrate_ocsp_settings.py    # Add OCSP settings columns to existing DB
│   └── migrate_template_cdp_aia.py # Migrate CDP/AIA template schema

tests/                          # Offline test scripts (no running server needed)
│   ├── __main__.py             # Interactive test menu: python -m tests
│   └── …

doc/                            # Documentation
out/                            # Generated output (certs, CRLs, logs, backups)
```

---

## Management Interface

Open `http://localhost:8080` in a browser. The interface is organised into sidebar sections:

**Certificates**
- **Dashboard** — system overview, CA summary, recent audit activity
- **Certificates** — list, inspect, and revoke issued certificates
- **Request** — issue a certificate from a JSON payload
- **CSR Tool** — browser-based key and CSR generator (ECC P-256 or RSA 2048)

**Certification Authorities**
- **CAs & CRL** — CA list, add CA, certificate chain and CRL downloads
- **Templates** — list, edit, create, and export certificate templates
- **OCSP Responders** — add, view, edit, and delete OCSP responders

**EST Service**
- **EST Config** — manage enrollment aliases (CA + template binding, optional Basic Auth)
- **EST Test** — test `cacerts` and `simpleenroll` against a selected alias

**KMS**
- **Key Generation** — generate RSA, ECDSA, Ed25519, or AES keys

**Administration**
- **Users** — manage local user accounts and roles (`superadmin`, `admin`, `user`, `auditor`)
- **Audit Log** — view and export the activity audit trail
- **Tools** — database backup/restore, reset PKI, application log viewer

---

## REST API

All authenticated endpoints require `Authorization: Bearer <token>` obtained from `POST /api/auth/login`.

### Authentication

| Method | Path | Description |
|---|---|---|
| POST | `/api/auth/login` | Log in, returns JWT |
| POST | `/api/auth/logout` | Invalidate token |
| GET | `/api/auth/me` | Current user info |

### Certification Authorities

| Method | Path | Description |
|---|---|---|
| GET | `/api/ca` | List all CAs |
| POST | `/api/ca` | Add a CA (PEM or PKCS#12) |
| GET | `/api/ca/<id>` | CA summary |
| PUT | `/api/ca/<id>` | Update CA settings |
| DELETE | `/api/ca/<id>` | Delete a CA |
| GET | `/api/ca/<id>/full` | CA details with parsed certificate fields |
| GET | `/api/ca/<id>/cert` | CA certificate PEM — public, no auth |
| GET | `/api/ca/<id>/cert/der` | CA certificate DER — public, no auth |
| GET | `/api/ca/<id>/crl` | Current CRL PEM — public, no auth |
| GET | `/api/ca/<id>/crl/der` | Current CRL DER — public, no auth |
| POST | `/api/ca/<id>/crl` | Issue a new CRL |

### Certificates

| Method | Path | Description |
|---|---|---|
| GET | `/api/certificate` | List certificates (paginated, filterable) |
| GET | `/api/certificate/<id>` | Certificate details |
| GET | `/api/certificate/pem/<id>` | Download certificate PEM — public, no auth |
| GET | `/api/certificate/status/<id>` | Revocation status |
| POST | `/api/certificate/issue` | Issue certificate from JSON request |
| POST | `/api/certificate/issue-pkcs12` | Issue certificate + key as PKCS#12 |
| POST | `/api/certificate/revoke/<id>` | Revoke a certificate |
| POST | `/api/certificate/pkcs12/<id>` | Download existing certificate + key as PKCS#12 |
| GET | `/api/certificate/private-key/<id>` | Get private key PEM (admin only) |
| POST | `/api/certificate/parse-csr` | Parse a CSR and return JSON fields |

### Certificate Templates

| Method | Path | Description |
|---|---|---|
| GET | `/api/template` | List templates |
| POST | `/api/template` | Create a template |
| GET | `/api/template/<id>` | Template details |
| PUT | `/api/template/<id>` | Update a template |
| GET | `/api/template/<id>/export` | Export template as JSON |

### OCSP Responders

| Method | Path | Description |
|---|---|---|
| GET | `/api/ocsp` | List OCSP responders |
| POST | `/api/ocsp` | Add a responder (PEM or PKCS#12) |
| GET | `/api/ocsp/<id>` | Responder details |
| PUT | `/api/ocsp/<id>` | Update responder settings |
| DELETE | `/api/ocsp/<id>` | Delete a responder |

OCSP protocol requests are handled at `/ocsp/<issuer-ski>` (POST for RFC 6960, GET with base64-encoded request appended to path).

### EST Service

| Method | Path | Description |
|---|---|---|
| GET | `/api/est` | List EST aliases |
| POST | `/api/est` | Create an alias |
| GET | `/api/est/<id>` | Alias details |
| PUT | `/api/est/<id>` | Update an alias |
| DELETE | `/api/est/<id>` | Delete an alias |
| POST | `/api/est/<id>/set-default` | Set as default alias |
| GET | `/.well-known/est[/<label>]/cacerts` | CA certificate (public) |
| POST | `/.well-known/est[/<label>]/simpleenroll` | Enroll via CSR → PKCS#7 |
| POST | `/.well-known/est[/<label>]/simpleenrollpem` | Enroll via CSR → PEM |

### Users

| Method | Path | Description |
|---|---|---|
| GET | `/api/users` | List users |
| POST | `/api/users` | Create user |
| GET | `/api/users/<id>` | User details |
| PUT | `/api/users/<id>` | Update user |
| DELETE | `/api/users/<id>` | Delete user |

### KMS and Tools

| Method | Path | Description |
|---|---|---|
| POST | `/api/kms/generate-key` | Generate a key |
| GET | `/api/audit-logs` | Query audit log (paginated) |
| POST | `/api/audit-logs/clear` | Clear audit log |
| GET | `/api/tools/app-log` | Application log tail |
| POST | `/api/tools/clear-app-log` | Clear application log |
| POST | `/api/tools/backup-db` | Create a database backup |
| GET | `/api/tools/backups` | List available backups |
| POST | `/api/tools/restore-db` | Restore from a backup |
| POST | `/api/tools/reset-pki` | Full database reset (destructive) |

---

## Utilities

| Script | Description |
|---|---|
| `utils/reset_pki.py` | Drop and recreate the database; reload all config from `config/` |
| `utils/restore_backup.py` | Restore the database from a SQL backup file |
| `utils/generate_crls.py` | Generate and export CRLs for all active CAs |
| `utils/generate_sample_certs.py` | Issue a batch of sample certificates |
| `utils/migrate_ocsp_settings.py` | Add OCSP settings columns to an existing database |
| `utils/migrate_template_cdp_aia.py` | Migrate CDP/AIA template schema to the explicit format |

All scripts accept an optional config file path as the first argument (default: `config/config.json`):

```bash
python utils/reset_pki.py config/config.local.json
```

> Migration scripts are only needed when upgrading an existing installation. Fresh installs created by `setup.sh` or `reset_pki.py` include all current schema changes.

---

## Tests

Interactive test menu (operates directly on the library — no running server required):

```bash
source venv/bin/activate
python -m tests
```

Or run a single test:

```bash
python tests/generate_self_signed_cert.py
python tests/generate_ca_signed_cert.py
```

Generated output is written to `out/`.

---

## Documentation

| File | Contents |
|---|---|
| `doc/database.md` | Full schema — all tables, columns, and foreign keys |
| `doc/certificate_templates.md` | Template JSON format and all supported fields |
| `doc/kms_strategy.md` | KMS integration design and migration phases |
| `doc/structure.md` | Detailed project structure |
| `doc/request_examples/` | Sample request JSON files and example CSR |
