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
- MariaDB backend
- Flask + Gunicorn REST API
- Bootstrap 5 browser management interface
- Audit log, application log, and database backup/restore tools

---

## Requirements

**For Docker deployment on Linux (servers):**
- Docker Engine 24+
- Docker Compose plugin

**For Docker deployment on macOS / Windows:**
- Docker Desktop (includes Compose)

**For local/development setup (without Docker):**
- Python 3.11+
- MariaDB 10.6+

---

## Quick Start — Docker On Linux (recommended for servers)

The included `setup.sh` installs Docker (if needed), generates credentials, and starts the full stack in one command.

```bash
git clone <repo-url>
cd pypki
sudo bash setup.sh
```

The script will:

1. Install Docker and the Compose plugin via the official Docker repository
2. Generate random passwords and write them to `.env` and `config/config.json`
3. Create `out/` and `data/mariadb/` directories for persistent data
4. Build the application image and start the `app` + `db` containers

After setup the interface is available at `http://<server-ip>:8080`.

**Default credentials: `superadmin` / `password` — change immediately after first login.**

Generated passwords are saved to `.setup_credentials` (chmod 600). Delete that file once you have noted the values.

> Supported distros: Ubuntu 22.04/24.04, Debian 11/12, Rocky/Alma/RHEL 9.
> Safe to re-run — existing `.env` passwords and `secret_key` are preserved across re-runs.

`setup.sh` is Linux-only. On macOS with Docker Desktop, use the Docker Desktop flow below instead of `setup.sh`.

### Common commands

```bash
docker compose ps               # status of all containers
docker compose logs -f app      # tail application logs
docker compose logs -f db       # tail database logs
docker compose restart app      # restart the app (e.g. after editing config)
docker compose down             # stop the stack (data is preserved)
docker compose down -v          # stop containers and Compose-managed volumes; data/mariadb is preserved
```

To fully remove the database contents from a Docker deployment, stop the stack and delete `data/mariadb/` manually.

### Where data lives

All persistent data is stored on the host as plain directories — easy to back up, inspect, and migrate:

| Host path | Contents |
|---|---|
| `config/` | Configuration — edit on the host, `docker compose restart app` to apply |
| `out/` | Generated output: certificates, CRLs, logs, backups |
| `data/mariadb/` | Raw MariaDB data files — for routine backups prefer the built-in backup/restore tools; copy this directory only with MariaDB stopped |
| `data/softhsm/tokens/` | SoftHSM2 PKCS#11 token files — the dev-token created on first boot, plus any keys generated against it |

### SoftHSM2 development token

A SoftHSM2 software token (`pypki-dev`, user PIN `1234`, SO PIN `5678`) is initialised inside the container on first boot for HSM development and testing. The token state lives in `data/softhsm/tokens/` so it survives container restarts.

> The default PIN is intentionally weak — change `SOFTHSM2_PIN`, `SOFTHSM2_SO_PIN`, and `SOFTHSM2_TOKEN_LABEL` in `docker-compose.yml` for any non-dev deployment, or set `SOFTHSM2_AUTO_INIT=false` to skip the auto-init entirely.

Verify the token is present from the host:

```bash
docker compose exec app pkcs11-tool --module "$PKCS11_MODULE" --list-slots
```

End-to-end app integration with the HSM path is in progress — see [doc/hsm-gap-analysis.md](doc/hsm-gap-analysis.md).

---

## Quick Start — macOS With Docker Desktop

Use this path when developing on a Mac. It does not use `setup.sh`.

For this Docker Desktop workflow, you do **not** need to create a local Python virtual environment just to run the application. Python dependencies are installed inside the Docker image during `docker compose build` from `requirements.txt`.

If you also want to run project scripts or tests directly on your Mac outside Docker, create a local `.venv` separately with:

```bash
bash setup_venv.sh
```

### 1. Install and start Docker Desktop

Install Docker Desktop for Mac and make sure it is running before you start the stack.

### 2. Create `.env`

```bash
cp .env.example .env
```

Edit `.env` and set strong values for:

- `DB_ROOT_PASSWORD`
- `DB_PASSWORD`
- `HSM_PIN_KEK` — the deployment-wide KEK used to encrypt software keys at rest under per-provider keys. Generate with `openssl rand -base64 48 | tr -dc 'A-Za-z0-9_-' | head -c 64`. **Do not rotate after first run — every encrypted `KeyStorage` row would become unreadable.**

`DB_NAME` and `DB_USER` can usually stay at their defaults.

### 3. Update `config/config.json`

Open `config/config.json` and confirm:
- `db_config.host` is `"db"` (the Compose service name — already the shipped default)
- `db_config.password` matches the `DB_PASSWORD` you set in `.env`
- `secret_key` is replaced with a real random value and not left as the shipped placeholder

The shipped `config/config.json` uses `"change_me_app"` as the password. If you changed `DB_PASSWORD` in `.env`, set `db_config.password` to the same value here.

Generate a `secret_key` with:

```bash
openssl rand -base64 48 | tr -dc 'A-Za-z0-9_-' | head -c 64
```

### 4. Start the stack

```bash
docker compose build
docker compose up -d
```

On first boot, the container entrypoint initialises an empty database automatically. Watch progress with:

```bash
docker compose logs -f app
```

### 5. Open the application

Open `http://localhost:8080`.

Default credentials on a fresh database are `superadmin` / `password`.

Useful commands:

```bash
docker compose ps
docker compose logs -f app
docker compose logs -f db
docker compose restart app
docker compose down
```

Persistent data is stored in `config/`, `out/`, and `data/mariadb/` on the host.

---

## Manual / Development Setup

### 1. Install system dependencies

macOS:
```bash
brew install python@3.13 mariadb pkg-config openssl libmariadb softhsm opensc
brew services start mariadb
```

Debian/Ubuntu:
```bash
sudo apt-get install python3.13 python3.13-venv python3.13-dev \
    mariadb-server libmariadb-dev pkg-config openssl \
    softhsm2 opensc
sudo systemctl enable --now mariadb
```

RHEL/Rocky/Alma:
```bash
sudo dnf install python3 python3-devel mariadb-server mariadb-devel openssl \
    softhsm opensc
sudo systemctl enable --now mariadb
```

`softhsm2` and `opensc` are needed for HSM development against the SoftHSM2 software token. They are optional for software-only signing but pyPKI's HSM gap-closure work assumes they are installed (see [doc/hsm-gap-analysis.md](doc/hsm-gap-analysis.md)).

### 2. Create the virtual environment

Convenience script:

```bash
bash setup_venv.sh
```

Manual equivalent:

```bash
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
```

### 3. Create the MariaDB user

`utils/reset_pki.py` (Step 5) creates the database itself — only the user and grant are needed here:

```sql
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

> **Note:** in Docker, `host` must be `db` (the Compose service name). For a local setup use `localhost`.

Generate a `secret_key` with:
```bash
openssl rand -base64 48 | tr -dc 'A-Za-z0-9_-' | head -c 64
```

The secret key is used to sign JWT authentication tokens. Keep it stable across restarts to avoid invalidating active sessions.

Also export `HSM_PIN_KEK` in the environment before running scripts or the server. This is the deployment-wide KEK used by the KMS to encrypt software private keys at rest under per-provider keys (see [doc/kms-strategy.md §6-7](doc/kms-strategy.md)). Generate a separate strong random value:

```bash
export HSM_PIN_KEK="$(openssl rand -base64 48 | tr -dc 'A-Za-z0-9_-' | head -c 64)"
```

Persist it in your shell rc, `.envrc`, or systemd `EnvironmentFile`. **Do not rotate after first key has been generated — every encrypted `KeyStorage` row would become unreadable.**

### 5. Initialise the database

> **Note:** Creates the database schema and seeds initial data. Safe on a fresh installation; on an existing installation all data is lost.

```bash
PYTHONPATH=. .venv/bin/python utils/reset_pki.py
```

### 6. (Optional) Initialise a SoftHSM2 development token

Skip this step if you are not working on the HSM integration.

Initialise a software PKCS#11 token once — it persists in `~/.config/softhsm2/tokens/` (macOS, default user-mode config) or `/var/lib/softhsm/tokens/` (Linux, default system-wide config) across reboots:

```bash
softhsm2-util --init-token --free \
    --label pypki-dev --pin 1234 --so-pin 5678
```

Verify with `pkcs11-tool` — the module path differs by platform:

```bash
# macOS (Homebrew)
pkcs11-tool --module "$(brew --prefix)/lib/softhsm/libsofthsm2.so" --list-slots

# Debian/Ubuntu
pkcs11-tool --module /usr/lib/softhsm/libsofthsm2.so --list-slots

# RHEL/Rocky/Alma
pkcs11-tool --module /usr/lib64/pkcs11/libsofthsm2.so --list-slots
```

End-to-end app integration with the HSM path is in progress — see [doc/hsm-gap-analysis.md](doc/hsm-gap-analysis.md). The token can be exercised today with `pkcs11-tool` for environment validation.

### 7. Start the server

```bash
source .venv/bin/activate
PYTHONPATH=. python web/app.py
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
│   ├── app.py                  # Entry point (also gunicorn target: web.app:app)
│   ├── routes/                 # Blueprint route handlers
│   │   ├── main_routes.py      # Main REST API
│   │   ├── auth_routes.py      # Login / JWT
│   │   ├── est_routes.py       # EST (RFC 7030)
│   │   └── ocsp_routes.py      # OCSP (RFC 6960)
│   ├── services/               # Business logic adapters
│   ├── static/                 # Client-side JS (auth.js, pypki_ui.js)
│   └── templates/              # Jinja2/Bootstrap 5 pages

config/                         # Shipped defaults plus runtime configuration
│   ├── config.json             # Active config written/used at runtime
│   ├── ca_store/               # CA config JSON files
│   ├── cert_templates/         # Certificate template JSON files
│   └── ocsp_responders/        # OCSP responder config JSON files

utils/                          # Command-line utilities
│   ├── reset_pki.py            # Drop and recreate database, reload all config
│   ├── restore_backup.py       # Restore database from a SQL backup file
│   ├── generate_crls.py        # Generate and export CRLs for all active CAs
│   ├── generate_sample_certs.py
│   ├── migrate_ocsp_settings.py    # Add OCSP settings columns to existing DB
│   └── migrate_template_cdp_aia.py # Migrate CDP/AIA template schema

tests/                          # Offline test scripts (no running server needed)
│   ├── __main__.py             # Interactive test menu: python -m tests
│   └── …

Dockerfile                      # Application container image
docker-compose.yml              # Stack definition (app + db)
docker-entrypoint.sh            # Container startup: waits for DB, initialises schema, starts gunicorn
.env.example                    # Docker Compose env template — copy to .env before running
setup.sh                        # Linux server bootstrap: installs Docker, writes credentials, starts stack
setup_venv.sh                   # Local Python virtualenv bootstrap (.venv)

doc/                            # Documentation
out/                            # Generated output (certs, CRLs, logs, backups)
data/                           # Persistent container data (created automatically on first run)
│   └── mariadb/                # MariaDB data files
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

The full REST API reference lives in [doc/rest-api.md](/Users/pedro/Development/Python/pypki/doc/rest-api.md).

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

Most operational scripts accept an optional config file path as the first argument (default: `config/config.json`). `generate_sample_certs.py` is intentionally environment-specific sample data tooling.

> Migration scripts are only needed when upgrading an existing installation. Fresh installs via `setup.sh` include all current schema changes.

**Running utilities against a Docker deployment:**
```bash
docker compose exec app python utils/reset_pki.py
docker compose exec app python utils/generate_crls.py
```

---

## Tests

Interactive test menu (operates directly on the library — no running server required):

```bash
source .venv/bin/activate
PYTHONPATH=. python -m tests
```

---

## Documentation

| File | Contents |
|---|---|
| `doc/database.md` | Full schema — all tables, columns, and foreign keys |
| `doc/certificate-templates.md` | Template JSON format and all supported fields |
| `doc/kms-strategy.md` | KMS integration design and migration phases |
| `doc/softhsm2-manual.md` | SoftHSM2 operator manual — install, init, key ops, backup/restore |
| `doc/rest-api.md` | REST API reference |
| `doc/roadmap.md` | Proposed future evolutions and improvement areas |
| `doc/PROGRESS.md` | Operational status board — every roadmap item broken down with done / partial / pending / deferred markers |
| `doc/hsm-gap-analysis.md` | Closed-bug catalogue for the HSM / PKCS#11 work (Phases 0–6) |
| `doc/structure.md` | Detailed project structure |
| `doc/request_examples/` | Sample request JSON files and example CSR |
