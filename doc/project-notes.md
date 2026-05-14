# Project Notes

Operator-facing notes on how the project is laid out, how it boots,
and which subsystems are mature versus still in-flight. Companion
documents: [structure.md](structure.md) for the file tree,
[database-specs.md](database-specs.md) for the schema,
[rest-api.md](rest-api.md) for the HTTP surface,
[roadmap.md](roadmap.md) for planned work, and
[PROGRESS.md](PROGRESS.md) for the line-by-line status.

## Overview

pyPKI is a Flask-based PKI management service. It bundles:

- a core library in `pypki/` for CA, certificate, CRL, OCSP, KMS, and DB
  operations
- a KMS layer with sibling `software` and `pkcs11` backends, encrypted-at-rest
  software keys, and per-provider activation secrets
- a web/API layer in `web/` that serves both REST endpoints and the
  management UI
- JWT-based authentication for the management API and UI
- a background scheduler that periodically regenerates CRLs to `out/crl/`
- an EST server (RFC 7030 subset — `cacerts` + `simpleenroll`) and an
  OCSP responder (RFC 6960)
- a MariaDB backend accessed through `mysql-connector-python` with a
  connection pool
- Docker-first deployment via `docker-compose.yml`, plus a documented
  local/dev path

## Current Architecture

```
web/            -> Flask app factory, REST routes, templates, static assets
pypki/          -> Core PKI logic, KMS, backends, DB layer, OCSP, PKCS#11 helpers
config/         -> Runtime config, certificate templates, OCSP responder configs
utils/          -> Administrative scripts and schema migrations
MariaDB         -> Persistent storage
out/            -> Generated artefacts: certificates, CRLs, app log, backups
```

The application listens on port `8080` in both local and Docker runs.

The authoritative per-area specs live in `doc/`:

| Surface | Spec |
|---|---|
| CA management | [ca-management-specs.md](ca-management-specs.md) |
| End-entity certificates | [certificate-management-specs.md](certificate-management-specs.md) |
| Certificate templates | [certificate-template-specs.md](certificate-template-specs.md) |
| EST service | [est-specs.md](est-specs.md) |
| KMS | [kms-specs.md](kms-specs.md) |
| HSM contracts | [hsm-support-specs.md](hsm-support-specs.md) |
| Database schema | [database-specs.md](database-specs.md) |

## Startup Model

### Docker (Linux server)

`setup.sh` is the supported Linux server bootstrap path. It:

1. installs Docker Engine and the Compose plugin when needed
2. generates random DB credentials, a JWT `secret_key`, and a master
   `HSM_PIN_KEK`; writes them to `.env`, `config/config.json`, and a
   chmod-600 `.setup_credentials` summary file
3. creates `out/crl/`, `out/backup/`, and `data/mariadb/`
4. builds and starts the `app` and `db` containers via `docker compose`

`docker-entrypoint.sh` then runs inside the `app` container:

1. waits for MariaDB to accept connections
2. counts tables in the configured database
3. runs `utils/reset_pki.py` if the database is empty (first boot)
4. otherwise runs `PKIDataBase.migrate_schema()` idempotently
5. starts Gunicorn with `web.app:app` on port 8080

`update.sh` is the upgrade path: pull the latest code, rebuild the image,
restart the stack. Idempotent `migrate_schema()` lands any new columns
at boot; `.env`, `config/config.json`, and the DB volume are untouched.

### Docker (macOS / Windows with Docker Desktop)

`setup.sh` is Linux-only. On macOS / Windows the documented flow is to
copy `.env.example` to `.env`, set strong passwords plus a real
`secret_key` and `HSM_PIN_KEK` in `.env`, then
`docker compose build && docker compose up -d`. The same
`docker-entrypoint.sh` initialises the schema on first boot.

### Local / Development

The local path uses:

- Python 3.11+ (enforced by `setup_venv.sh`)
- a locally running MariaDB server
- `bash setup_venv.sh` (or an equivalent manual `.venv` setup)
- `bash launch.sh` (activates `.venv`, runs `PYTHONPATH=. python web/app.py`);
  same `web.app:app` target works under Gunicorn

The local-dev path reads `HSM_PIN_KEK` from `.env` automatically via
`web/services/__init__.py` so software-key encryption-at-rest works the
same way as in Docker.

## Database Notes

- The schema is defined in `pypki/db.py` inside
  `PKIDataBase.create_database()`; the full table-by-table reference is
  in [database-specs.md](database-specs.md).
- Connections go through `mysql.connector.pooling.MySQLConnectionPool`,
  created lazily on first use.
- Fresh installs seed a built-in `superadmin` user with password
  `password` (rotate on first login).
- `utils/reset_pki.py` is the authoritative way to recreate the schema
  from current code (destructive — drops the database first).
- `PKIDataBase.migrate_schema()` runs at every boot and applies
  idempotent in-place migrations (column adds). Currently shipped
  one-shot scripts for installs that pre-date in-process migration:
  `utils/migrate_ocsp_settings.py`, `utils/migrate_template_cdp_aia.py`.
  Fresh installs do not need them.

## API and UI Notes

- Auth endpoints live under `/api/auth` (JWT issued by `auth_routes.py`).
- Main management endpoints live under `/api` (`main_routes.py`).
- OCSP protocol traffic is served at `POST /ocsp` and
  `GET /ocsp/<base64-request>` (`ocsp_routes.py`).
- EST is served under `/.well-known/est/` (`est_routes.py`). The current
  build implements `cacerts`, `simpleenroll`, and the non-standard
  `simpleenrollpem`; `simplereenroll` / `csrattrs` / `serverkeygen` are
  not yet implemented. See [est-specs.md](est-specs.md).
- The browser UI is server-rendered from `web/templates/` and uses
  `web/static/` JavaScript helpers.
- The shared `PyPKI` instance and the CRL publication scheduler are
  bootstrapped in `web/services/__init__.py`. The scheduler regenerates
  CRLs every `CRL_PUBLICATION_FREQ` seconds (default 10 minutes) and
  writes DER + PEM copies under `out/crl/`.

## KMS and HSM Notes

- All certificate / CRL / OCSP signing routes through
  `KeyManagementService.sign_digest()`. CAs and OCSP responders hold no
  key material — they reference a `KeyStorage` row owned by a provider.
- The KMS layer has two backends in
  [pypki/backends/](../pypki/backends/): `software.py` (KEK-wrapped
  software keys) and `pkcs11.py` (HSM tokens). Both implement the same
  contract; routes are backend-agnostic.
- Software keys are AES-256-GCM-encrypted at rest under a per-provider
  KEK derived from the master `HSM_PIN_KEK` via HKDF-SHA256.
- HSM PINs can be stored encrypted in the DB (`auth_secret_ref =
  db:encrypted`), resolved from an env var (`env:`), or prompted
  interactively (`operator:prompt`). `vault:` is reserved.
- The KMS management UI lives at `/crypto_providers.html` and
  `/kms_keys.html`; the per-key view is `/key_details.html`. The legacy
  `kms_keygen.html` page is kept for the standalone keygen tool.
- HSM regression target is SoftHSM2; vendor-fidelity passes against
  YubiHSM 2, Thales DPoD, and AWS CloudHSM are deferred to
  hardware / SDK availability. See
  [kms-specs.md §13 Phase 7](kms-specs.md).

## Operational Notes

- The active config path defaults to `config/config.json`. The
  container honours `PYPKI_CONFIG` to override that location.
- Persistent Docker data lives in `config/`, `out/`, and
  `data/mariadb/`.
- `uninstall.sh` stops and removes the Docker Compose stack but
  preserves those data directories. Removing `data/mariadb/` is left
  to the operator.
- The application log is written to `out/app.log` and to stdout.
- DB backups (created via `POST /api/tools/backup-db`) land in
  `out/backup/`.

## Areas Worth Improving

The detailed list lives in [roadmap.md](roadmap.md); per-task status
lives in [PROGRESS.md](PROGRESS.md). The headline themes today:

- **Testing.** KMS / software-key regimes have pytest coverage; the
  app-level surfaces (certificate issuance, revocation, CRL, OCSP,
  EST, user management) are still on script-based smoke tests. CI
  (lint, syntax check, pytest, disposable-MariaDB integration) is
  not yet wired.
- **Deployment / operations.** No production deployment guide for
  TLS termination / reverse proxies / backup-restore drills; the
  `/api/status` endpoint is a stub liveness probe rather than a real
  readiness check.
- **UX polish.** Destructive-action confirmations on CA / OCSP /
  template / user deletes are still the simpler shape (KMS deletes
  got rich confirmations in Phase 5b). Inline form validation
  unchecked on CA / template / OCSP / EST forms. Audit-log
  search / filter / retention is pending.
- **EST authentication.** Basic Auth only today; mTLS client-cert auth
  is specified as CR-0001 in
  [est-specs.md §14.1](est-specs.md) and pending implementation.
- **Documentation lifecycle.** No CHANGELOG.md; no per-release schema
  migration upgrade notes.
- **HSM vendor fidelity.** SoftHSM2 is the regression target; YubiHSM
  2 / Thales DPoD / AWS CloudHSM Luna passes are deferred to
  hardware / SDK availability.
