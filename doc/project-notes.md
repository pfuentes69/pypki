# Project Notes

Operator-facing notes on how the project is laid out, how it boots, and which
subsystems are mature versus still in-flight. Companion documents:
[structure.md](structure.md) for the file tree, [database.md](database.md) for
the schema, [rest-api.md](rest-api.md) for the HTTP surface, and
[roadmap.md](roadmap.md) for planned work.

## Overview

PyPKI is a Flask-based PKI management service. It bundles:

- a core library in `pypki/` for CA, certificate, CRL, OCSP, KMS, and DB operations
- a web/API layer in `web/` that serves both REST endpoints and the management UI
- JWT-based authentication for the management API and UI
- a background scheduler that periodically regenerates CRLs to `out/crl/`
- an EST server (RFC 7030) and an OCSP responder (RFC 6960)
- a Key Management Service abstraction with software keys and PKCS#11/HSM keys
- a MariaDB backend accessed through `mysql-connector-python` with a connection pool
- Docker-first deployment via `docker-compose.yml`, plus a documented local/dev path

## Current Architecture

```
web/            -> Flask app factory, REST routes, templates, static assets
pypki/          -> Core PKI logic, crypto helpers, DB layer, OCSP / KMS / PKCS#11
config/         -> Runtime config, CA definitions, cert templates, OCSP responder configs
utils/          -> Administrative scripts and schema migrations
MariaDB         -> Persistent storage
out/            -> Generated artefacts: certificates, CRLs, app log, backups
```

The application listens on port `8080` in both local and Docker runs.

## Startup Model

### Docker (Linux server)

`setup.sh` is the supported Linux server bootstrap path. It:

1. installs Docker Engine and the Compose plugin when needed
2. generates random DB credentials and a `secret_key`, writes them to `.env`,
   `config/config.json`, and a chmod-600 `.setup_credentials` summary file
3. creates `out/crl/`, `out/backup/`, and `data/mariadb/`
4. builds and starts the `app` and `db` containers via `docker compose`

`docker-entrypoint.sh` then runs inside the `app` container:

1. waits for MariaDB to accept connections
2. counts tables in the configured database
3. runs `utils/reset_pki.py` if the database is empty (first boot)
4. starts Gunicorn with `web.app:app` on port 8080

### Docker (macOS / Windows with Docker Desktop)

`setup.sh` is Linux-only. On macOS / Windows the documented flow is to copy
`.env.example` to `.env`, set strong passwords plus a real `secret_key` in
`config/config.json`, then `docker compose build && docker compose up -d`. The
same `docker-entrypoint.sh` initialises the schema on first boot.

### Local / Development

The local path uses:

- Python 3.11+ (enforced by `setup_venv.sh`)
- a locally running MariaDB server
- `bash setup_venv.sh` (or an equivalent manual `.venv` setup)
- `PYTHONPATH=. python web/app.py` for an in-process Flask run; same
  `web.app:app` target works under Gunicorn

## Database Notes

- The schema is defined in `pypki/db.py` inside `PKIDataBase.create_database()`.
- Connections go through `mysql.connector.pooling.MySQLConnectionPool`, created
  lazily on first use.
- Fresh installs seed a built-in `superadmin` user with password `password`.
- `utils/reset_pki.py` is the authoritative way to recreate the schema from
  current code.
- Currently shipped upgrade scripts: `utils/migrate_ocsp_settings.py` and
  `utils/migrate_template_cdp_aia.py`. Fresh installs do not need them.

## API and UI Notes

- Auth endpoints live under `/api/auth` (JWT issued by `auth_routes.py`).
- Main management endpoints live under `/api` (`main_routes.py`).
- OCSP protocol traffic is served at `POST /ocsp` and
  `GET /ocsp/<base64-request>` (`ocsp_routes.py`).
- EST is served under `/.well-known/est/` (`est_routes.py`).
- The browser UI is server-rendered from `web/templates/` and uses
  `web/static/` JavaScript helpers.
- The shared `PyPKI` instance and the CRL publication scheduler are bootstrapped
  in `web/services/__init__.py`. The scheduler regenerates CRLs every
  `CRL_PUBLICATION_FREQ` seconds (default 10 minutes) and writes DER + PEM
  copies under `out/crl/`.

## KMS and HSM Notes

- All certificate and OCSP signing routes through `KeyManagementService.sign_digest()`;
  CAs and OCSP responders no longer hold key material directly. See
  [kms-specs.md](kms-specs.md) for the design and the migration phases.
- The KMS UI (`kms_keygen.html`) and `/kms/generate-key` endpoint can generate
  RSA, ECDSA, Ed25519, and AES keys — but only as software keys persisted with
  `storage_type='Plain'`.
- The PKCS#11 / HSM path is wired end-to-end at the architecture level but has
  several correctness, portability, and operator-experience gaps that block
  production use. They are tracked in detail in
  [hsm-support-specs.md](hsm-support-specs.md), with the corresponding work items
  reflected in [roadmap.md](roadmap.md).

## Operational Notes

- The active config path defaults to `config/config.json`. The container honours
  `PYPKI_CONFIG` to override that location.
- Persistent Docker data lives in `config/`, `out/`, and `data/mariadb/`.
- `uninstall.sh` stops and removes the Docker Compose stack but preserves those
  data directories. Removing `data/mariadb/` is left to the operator.
- The application log is written to `out/app.log` and to stdout.

## Areas Worth Improving

The detailed list lives in [roadmap.md](roadmap.md). The headline themes:

- HSM / PKCS#11 support has correctness blockers (RSA mechanism, missing ECDSA
  branch) and portability gaps (hard-coded macOS module path, ignored slot
  number). See [hsm-support-specs.md](hsm-support-specs.md).
- Test coverage is still mostly script-based rather than automated; CI for
  linting and a disposable-MariaDB integration run is open.
- Security hardening: encryption-at-rest for software keys in `KeyStorage`,
  PIN handling for HSM keys, and either implementing or removing the
  `storage_type='Encrypted'` path.
- Deployment / operations: production deployment guide (TLS termination,
  reverse proxies, backups, restore drills), explicit health endpoints, and
  safer uninstall semantics.
- Documentation: keep operator docs aligned with the Docker-first path and
  separate historical design notes from current operator documentation more
  clearly.
