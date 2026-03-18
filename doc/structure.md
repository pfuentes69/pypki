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
│   ├── ocsp_responder.py           # OCSPResponder class
│   ├── pkcs11_helper.py            # PKCS#11 / HSM support
│   ├── pki_tools.py                # PKI utility constants and helpers
│   └── log.py                      # Logger setup
│
├── api/                            # Flask REST API
│   ├── __init__.py                 # App factory (create_app)
│   ├── app.py                      # API entry point
│   ├── routes/
│   │   ├── main_routes.py          # /api/* endpoints (CAs, certificates, CRLs, templates)
│   │   ├── est_routes.py           # /.well-known/est/* endpoints (RFC 7030)
│   │   └── ocsp_routes.py          # /ocsp endpoint (OCSP responder)
│   └── services/
│       ├── __init__.py             # Shared PyPKI instance
│       └── api_adapters.py         # Adapter layer between routes and core library
│
├── web/                            # Web frontend
│   ├── app.py                      # Legacy Flask UI entry point (port 5000)
│   ├── templates/                  # Jinja2 templates for legacy Flask UI
│   │   ├── base.html
│   │   ├── index.html
│   │   ├── get_ca_cert.html
│   │   ├── request_cert_csr.html
│   │   ├── request_cert_form.html
│   │   └── select_value.html
│   └── html/                       # Static management UI (Bootstrap 5, primary interface)
│       ├── index.html              # Dashboard
│       ├── certificate_list.html   # Certificate inventory
│       ├── certificate_request.html # Issue certificate
│       ├── certificate_details.html # Certificate details
│       ├── csr_tool.html           # Browser-based CSR generator
│       ├── cas_and_crls.html       # CA list and CRL download
│       ├── ca_details.html         # CA details
│       ├── template_list.html      # Certificate templates
│       ├── template_editor.html    # Create / edit template
│       ├── est_list.html           # EST alias management
│       ├── est_editor.html         # Create / edit EST alias
│       ├── est_test.html           # EST endpoint tester
│       └── kms_keygen.html         # KMS key generation
│
├── config/                         # Configuration files
│   ├── config.py                   # Config loader
│   ├── config.json                 # Default config
│   ├── config.local.json           # Local environment config
│   ├── config.aws.json             # AWS environment config
│   ├── config.phobos.json          # Phobos environment config
│   ├── ca_store/                   # CA configuration files
│   │   ├── ca1_config.json
│   │   ├── ca2_config.json
│   │   └── iot_rootca_config.json
│   ├── cert_templates/             # Certificate template definitions (JSON)
│   │   ├── template_base.json
│   │   ├── ca_cert_template.json
│   │   ├── client_cert_template.json
│   │   ├── client_cert_template_v2.json
│   │   ├── server_cert_template.json
│   │   ├── smime_cert_template.json
│   │   ├── ocsp_responder_cert_template.json
│   │   ├── iot_device_cert_template.json
│   │   └── iot_rootca_cert_template.json
│   └── ocsp_responders/            # OCSP responder configuration files
│       └── iot_rootca_ocsp.json
│
├── utils/                          # Administrative scripts
│   ├── reset_pki.py                # Drop and recreate the PKI database
│   ├── migrate_keystorage.py       # Schema upgrade: PrivateKeyStorage → KeyStorage
│   ├── migrate_keys_to_kms.py      # Move CA/OCSP keys into KeyStorage
│   ├── migrate_est_auth_fields.py  # Add username/password_hash/cert_fingerprint to ESTAliases
│   ├── generate_sample_certs.py    # Generate sample certificates
│   └── generate_crls.py            # Generate and export CRLs
│
├── examples/                       # Usage examples
│   ├── generate_self_signed_cert.py
│   ├── generate_self_signed_p12.py
│   ├── generate_ca_signed_cert.py
│   ├── generate_ca_signed_cert_from_csr.py
│   ├── generate_ca_signed_p12.py
│   ├── generate_ocsp_cert.py
│   ├── parse_csr_to_json.py
│   └── pkcs11_test.py
│
├── doc/
│   ├── request_examples/           # Sample certificate request files
│   │   ├── ca_cert_request.json
│   │   ├── client_cert_request.json
│   │   ├── server_cert_request.json
│   │   ├── iot_device_cert_request.json
│   │   ├── iot_rootca_cert_request.json
│   │   ├── csr.conf
│   │   ├── example.csr
│   │   ├── example.key
│   │   └── README.md
│
├── tests/                          # Test suite
│   └── __main__.py
│
├── doc/                            # Documentation
│   ├── api_structure.md
│   ├── api_samples.md
│   ├── aia.md
│   ├── crl.md
│   ├── ocsp.md
│   ├── config_management.md
│   ├── db_utils.md
│   ├── logs.md
│   ├── scheduler.md
│   └── project_notes.md
│
├── out/                            # Generated output (gitignored)
│   ├── app.log
│   ├── *.pem / *.p12 / *.der       # Generated certificates and keys
│   └── crl/                        # Generated CRL files
│       └── *.crl
│
├── venv/                           # Python virtual environment (gitignored)
├── setup_env.sh                    # Environment setup script
├── requirements.txt
├── .env                            # Environment variables (gitignored)
├── .gitignore
├── structure.txt
└── README.md
```
