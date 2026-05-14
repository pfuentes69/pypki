# Project Structure

```
pypki/
│
├── pypki/                          # Core PKI library
│   ├── __init__.py
│   ├── core.py                     # PyPKI main class (orchestrator)
│   ├── ca.py                       # CertificationAuthority class
│   ├── db.py                       # PKIDataBase class (MariaDB backend via mysql-connector)
│   ├── certificate_tools.py        # Certificate generation logic
│   ├── key_tools.py                # Key generation and management
│   ├── key_encryption.py           # AES-256-GCM KEK wrapping helpers
│   ├── kms.py                      # KeyManagementService (KMS signing)
│   ├── signing_algorithm.py        # CR-0003 signing-algorithm tokens
│   ├── ocsp_responder.py           # OCSPResponder class
│   ├── pkcs11_helper.py            # PKCS#11 / HSM low-level helpers
│   ├── pki_tools.py                # PKI utility constants and helpers
│   ├── log.py                      # Logger setup
│   └── backends/                   # KMS backend implementations
│       ├── base.py                 # Backend protocol + typed errors (BackendError, …)
│       ├── software.py             # Software-key backend (KEK-wrapped at rest)
│       └── pkcs11.py               # PKCS#11 backend (HSM tokens)
│
├── web/                            # Flask web service — API + management UI
│   ├── __init__.py                 # App factory (create_app)
│   ├── app.py                      # Entry point — starts the server on port 8080
│   ├── routes/
│   │   ├── main_routes.py          # /api/* endpoints (CAs, certs, CRLs, OCSP, templates, users, tools)
│   │   ├── auth_routes.py          # /api/auth/* endpoints (login, logout)
│   │   ├── est_routes.py           # /.well-known/est/* endpoints (RFC 7030)
│   │   └── ocsp_routes.py          # POST /ocsp and GET /ocsp/<base64> (RFC 6960 OCSP responder)
│   ├── services/
│   │   ├── __init__.py             # Shared PyPKI instance + background scheduler
│   │   └── api_adapters.py         # Adapter layer between routes and core library
│   ├── static/                     # Client-side JavaScript
│   │   ├── auth.js                 # JWT auth helper — token storage, fetch monkey-patch, logout
│   │   └── pypki_ui.js             # Shared UI utilities — toast notifications, confirm modal
│   └── templates/                  # Jinja2 / Bootstrap 5 templates
│       ├── base.html               # Base layout — sidebar, common head, JS constants
│       ├── login.html              # Sign-in page (standalone, no base)
│       ├── index.html              # Dashboard (metrics, CA summary, recent activity)
│       ├── certificate_list.html   # Certificate inventory
│       ├── certificate_request.html # Issue certificate from JSON
│       ├── certificate_details.html # Certificate details and revocation
│       ├── csr_tool.html           # Browser-based CSR generator (no server round-trip)
│       ├── cas_and_crls.html       # CA list and CRL download
│       ├── ca_add.html             # Add CA (PEM / PKCS#12 / KMS key bind / in-app keygen)
│       ├── ca_details.html         # CA details, CRL management
│       ├── ca_editor.html          # Edit CA settings
│       ├── ca_install_cert.html    # Install signed cert into a pending-issuance CA (CR-0001)
│       ├── template_list.html      # Certificate templates
│       ├── template_editor.html    # Create / edit template
│       ├── ocsp_list.html          # OCSP responder list
│       ├── ocsp_add.html           # Add OCSP responder (PEM or PKCS#12)
│       ├── ocsp_details.html       # OCSP responder details
│       ├── ocsp_editor.html        # Edit OCSP responder settings
│       ├── est_list.html           # EST alias management
│       ├── est_editor.html         # Create / edit EST alias
│       ├── est_test.html           # EST endpoint tester
│       ├── crypto_providers.html   # Crypto provider CRUD (software / pkcs11)
│       ├── crypto_provider_details.html # Provider details + activation status
│       ├── kms_keys.html           # KMS key inventory (generate / import / delete)
│       ├── key_details.html        # Key details — usage, public key, delete
│       ├── kms_keygen.html         # Standalone KMS key generator
│       ├── users_list.html         # User management
│       ├── user_editor.html        # Create / edit user
│       ├── audit_logs.html         # Audit log viewer
│       ├── app_logs.html           # Application log viewer
│       └── tools.html              # DB backup / restore / reset
│
├── config/                         # Shipped defaults plus runtime configuration
│   ├── config.json                 # Active config (DB connection, folder paths, secret key)
│   ├── ca_store/                   # CA configuration files (one JSON per CA)
│   ├── cert_templates/             # Certificate template definitions (JSON)
│   └── ocsp_responders/            # OCSP responder configuration files
│
├── utils/                          # Administrative scripts
│   ├── reset_pki.py                # Drop and recreate the database, reload all config
│   ├── restore_backup.py           # Restore database from a SQL backup file
│   ├── generate_sample_certs.py    # Issue a batch of sample certificates
│   ├── generate_crls.py            # Generate and export CRLs for all active CAs
│   ├── migrate_ocsp_settings.py    # Add OCSP settings columns to an existing database
│   └── migrate_template_cdp_aia.py # Migrate CDP/AIA template schema to explicit format
│
├── tests/                          # Pytest suites + interactive smoke scripts
│   ├── conftest.py                 # Pytest fixtures (FakeDB, kms, softhsm_*, …)
│   ├── test_kms_software_backend.py
│   ├── test_kms_pkcs11_backend.py
│   ├── test_kms_phase4_secrets.py
│   ├── test_kms_phase5_keymgmt.py
│   ├── test_kms_phase6_hardening.py
│   ├── test_pkcs12_storage_regime.py
│   ├── __main__.py                 # Interactive smoke-script menu (python -m tests)
│   ├── generate_self_signed_cert.py
│   ├── generate_ca_signed_cert.py
│   ├── generate_ca_signed_cert_from_csr.py
│   ├── generate_ca_signed_p12.py
│   ├── generate_self_signed_p12.py
│   ├── generate_ocsp_cert.py
│   └── parse_csr_to_json.py
│
├── doc/                            # Documentation
│   ├── database-specs.md           # Database specification — schema and lifecycle
│   ├── ca-management-specs.md      # CA management specification
│   ├── certificate-management-specs.md # End-entity certificate management specification
│   ├── certificate-template-specs.md # Certificate template management specification
│   ├── est-specs.md                # EST service specification
│   ├── kms-specs.md                # KMS specification
│   ├── hsm-support-specs.md        # HSM-specific contracts
│   ├── softhsm2-manual.md          # SoftHSM2 operator manual
│   ├── PROGRESS.md                 # Operational status board
│   ├── project-notes.md            # Operator-facing notes (overview, startup, ops)
│   ├── rest-api.md                 # REST API reference
│   ├── roadmap.md                  # Strategic intent across all areas
│   ├── structure.md                # This file
│   ├── request_examples/           # Sample request JSONs, CSR, and key files
│   └── learning/                   # Reference notes (architecture, patterns)
│
├── out/                            # Generated output (gitignored)
│   ├── app.log
│   ├── *.pem / *.p12 / *.der
│   ├── crl/
│   └── backup/
│
├── setup.sh                        # Docker-based setup: writes config, builds image, starts Compose stack
├── setup_venv.sh                   # Creates the local .venv and installs Python dependencies
├── update.sh                       # Pull latest code, rebuild image, restart stack (no data touch)
├── launch.sh                       # Activate .venv and run web/app.py (local-dev shortcut)
├── uninstall.sh                    # Stops and removes the Docker Compose stack (preserves data)
├── docker-entrypoint.sh            # Container entrypoint — waits for DB, seeds on empty, starts Gunicorn
├── docker-compose.yml
├── Dockerfile
├── requirements.txt
└── README.md
```

## Layer summary

| Layer | Package | Responsibility |
|---|---|---|
| Core library | `pypki/` | CA operations, certificate generation, key management, database access, OCSP, KMS |
| Web service | `web/` | Flask app factory, REST API blueprints, Jinja2 UI, static assets |
| Configuration | `config/` | DB connection, CA definitions, certificate templates, OCSP responder config |
| Utilities | `utils/` | Database initialisation, schema migrations, batch operations |
| Tests | `tests/` | Offline scripts that exercise the library directly (no server required) |
