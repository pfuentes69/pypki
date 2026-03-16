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
├── web/                            # Flask web frontend (UI)
│   ├── app.py                      # Web app entry point
│   ├── templates/
│   │   ├── base.html
│   │   ├── index.html
│   │   ├── get_ca_cert.html
│   │   ├── request_cert_csr.html
│   │   ├── request_cert_form.html
│   │   └── select_value.html
│   └── tests/                      # Static HTML prototypes
│       ├── certificate_list.html
│       ├── certificate_details.html
│       └── certificate_request.html
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
├── request_examples/               # Sample certificate request files
│   ├── ca_cert_request.json
│   ├── client_cert_request.json
│   ├── server_cert_request.json
│   ├── iot_device_cert_request.json
│   ├── iot_rootca_cert_request.json
│   ├── csr.conf
│   ├── example.csr
│   └── example.key
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
