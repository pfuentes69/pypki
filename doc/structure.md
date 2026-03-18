# Project Structure

```
pypki/
│
├── pypki/                          # Core PKI library
│   ├── __init__.py
│   ├── core.py                     # PyPKI main class (orchestrator)
│   ├── ca.py                       # CertificationAuthority class
│   ├── db.py                       # PKIDataBase class (MySQL backend)
│   ├── certificate_tools.py        # Certificate generation logic
│   ├── key_tools.py                # Key generation and management
│   ├── kms.py                      # KeyManagementService (KMS signing)
│   ├── ocsp_responder.py           # OCSPResponder class
│   ├── pkcs11_helper.py            # PKCS#11 / HSM support
│   ├── pki_tools.py                # PKI utility constants and helpers
│   └── log.py                      # Logger setup
│
├── web/                            # Flask web service — API + management UI
│   ├── __init__.py                 # App factory (create_app)
│   ├── app.py                      # Entry point — starts the server on port 8080
│   ├── routes/
│   │   ├── main_routes.py          # /api/* endpoints (CAs, certificates, CRLs, templates, users)
│   │   ├── auth_routes.py          # /api/auth/* endpoints (login, logout)
│   │   ├── est_routes.py           # /.well-known/est/* endpoints (RFC 7030)
│   │   └── ocsp_routes.py          # /ocsp endpoint (OCSP responder)
│   ├── services/
│   │   ├── __init__.py             # Shared PyPKI instance + background scheduler
│   │   └── api_adapters.py         # Adapter layer between routes and core library
│   ├── static/                     # Client-side JavaScript
│   │   ├── auth.js                 # JWT auth helper — token storage, fetch monkey-patch, logout
│   │   └── pypki_ui.js             # Shared UI utilities — toast notifications, confirm modal
│   └── templates/                  # Jinja2 templates
│       ├── base.html               # Base layout — sidebar, common head, JS constants
│       ├── login.html              # Sign-in page (standalone, no base)
│       ├── index.html              # Dashboard
│       ├── certificate_list.html   # Certificate inventory
│       ├── certificate_request.html # Issue certificate
│       ├── certificate_details.html # Certificate details and revocation
│       ├── csr_tool.html           # Browser-based CSR generator (no server round-trip)
│       ├── cas_and_crls.html       # CA list and CRL download
│       ├── ca_details.html         # CA details, CRL management
│       ├── template_list.html      # Certificate templates
│       ├── template_editor.html    # Create / edit template
│       ├── est_list.html           # EST alias management
│       ├── est_editor.html         # Create / edit EST alias
│       ├── est_test.html           # EST endpoint tester
│       ├── kms_keygen.html         # KMS key generation
│       ├── users_list.html         # User management
│       └── user_editor.html        # Create / edit user
│
├── config/                         # Runtime configuration
│   ├── config.py                   # Config loader
│   ├── config.json                 # Default config (DB connection, folder paths, secret key)
│   ├── config.local.json           # Local environment overrides (gitignored)
│   ├── config.aws.json             # AWS environment config
│   ├── config.phobos.json          # Phobos environment config
│   ├── ca_store/                   # CA configuration files (one JSON per CA)
│   ├── cert_templates/             # Certificate template definitions (JSON)
│   └── ocsp_responders/            # OCSP responder configuration files
│
├── utils/                          # Administrative scripts
│   ├── reset_pki.py                # Drop and recreate the database, reload all config
│   ├── migrate_keystorage.py       # Schema upgrade: PrivateKeyStorage → KeyStorage
│   ├── migrate_keys_to_kms.py      # Move CA/OCSP keys into KeyStorage
│   ├── migrate_est_auth_fields.py  # Add auth columns to ESTAliases
│   ├── migrate_add_users.py        # Add Users table (for existing databases)
│   ├── generate_sample_certs.py    # Issue a batch of sample certificates
│   └── generate_crls.py            # Generate and export CRLs for all active CAs
│
├── tests/                          # Offline test scripts (no running server needed)
│   ├── __main__.py                 # Interactive test menu (python -m tests)
│   ├── generate_self_signed_cert.py
│   ├── generate_ca_signed_cert.py
│   ├── generate_ca_signed_cert_from_csr.py
│   ├── generate_ca_signed_p12.py
│   ├── generate_self_signed_p12.py
│   ├── generate_ocsp_cert.py
│   ├── parse_csr_to_json.py
│   └── pkcs11_test.py
│
├── doc/                            # Documentation
│   ├── database.md                 # Full database schema reference
│   ├── certificate_templates.md    # Certificate template JSON format
│   ├── kms_strategy.md             # KMS integration strategy and phases
│   ├── project_notes.md            # Development notes
│   ├── structure.md                # This file
│   ├── request_examples/           # Sample request JSONs, CSR, and key files
│   └── learning/                   # Reference notes (architecture, patterns)
│
├── out/                            # Generated output (gitignored)
│   ├── app.log
│   ├── *.pem / *.p12 / *.der
│   └── crl/
│
├── venv/                           # Python virtual environment (gitignored)
├── setup_env.sh                    # Creates venv and installs requirements
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
