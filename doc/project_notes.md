# Project Notes

## Overview

PyPKI is a Python-based Public Key Infrastructure system providing certificate lifecycle management, revocation, and OCSP responder capabilities. It is structured as a core library, a REST API layer, and an optional web frontend, backed by a MySQL database.

---

## Certificate Generation Flow

1. **Key generation:**
   - By the client (CSR submitted directly)
   - By the platform (key pair generated server-side as part of the request)

2. **Request construction:**
   - A certificate template is selected — this mandates all extensions, key constraints, and validity; only the subject name and SAN come from the request.
   - A CA is selected (or the certificate is self-signed).
   - The request is submitted as a CSR. Two paths:
     - CSR provided by the client
     - CSR generated internally from a JSON payload containing subject name and SAN fields

3. **Certificate signing:**
   - A TBS (To-Be-Signed) Certificate is assembled from the template + request.
   - For software keys: signed directly with the CA private key.
   - For HSM keys: TBS hash is sent to HSM, signature is patched back into the certificate (`patch_certificate_signature()`).

---

## Architecture

### Layered design

```
web/           →  Optional Flask UI (port 5000)
api/routes/    →  Flask HTTP endpoints (port 8080)
api/services/  →  Business logic adapters
pypki/         →  Core PKI library (crypto, DB, templates)
config/        →  JSON configuration (CA store, templates, OCSP)
MySQL          →  Persistent storage
```

### Key design patterns

- **Template-driven issuance:** Certificate policy (extensions, key constraints, validity, subject fields) is fully defined in JSON templates. Routes only pass through subject name and SAN.
- **Adapter layer:** `api/services/api_adapters.py` decouples Flask routes from the core library. Serialization (bytes → JSON-safe types) is handled here.
- **Singleton PKI instance:** A single `PyPKI` object is initialized at startup in `api/services/__init__.py` and reused across all requests.
- **Context-managed DB connections:** `PKIDataBase` uses a context manager (`with db.connection()`) for connection lifecycle management.

---

## Core Library (`pypki/`)

### `core.py` — `PyPKI`
Main orchestrator. Manages CAs, templates, OCSP responders, and database operations.

Key methods:
- `load_config_json()` — loads config from JSON
- `reset_pki()` — initializes DB and loads all resources
- `select_ca_by_id()` / `select_ca_by_name()` — sets the active CA
- `select_cert_template_by_id()` / `select_cert_template_by_name()` — sets the active template
- `generate_certificate_and_key()` — issues a certificate with a new key pair
- `generate_certificate_from_csr()` — issues a certificate from a submitted CSR
- `revoke_certificate()` — marks a certificate as revoked
- `generate_crl()` — generates a CRL for the active CA
- `load_ca_collection()` / `load_template_collection()` / `load_ocsp_responders()` — caches resources in memory on startup

### `certificate_tools.py` — `CertificateTools`
Certificate and CSR construction with template enforcement.

Key methods:
- `load_certificate_template()` — parses the JSON template
- `load_certificate_request()` — parses the subject/SAN request payload
- `build_subject()` — constructs the X.509 subject name, enforcing required/optional fields from template
- `build_san()` — constructs SubjectAlternativeName (DNS, IP, email)
- `build_template_extensions()` — adds all configured extensions: KeyUsage, EKU, BasicConstraints, SKI, AKI, AIA, CDP, OCSP-NoCheck
- `generate_csr()` — creates a CSR
- `generate_certificate_from_csr()` — signs a CSR with the CA key
- `patch_csr()` — modifies a CSR while preserving the original public key (used in EST flows)
- `patch_certificate_signature()` — replaces signature bytes (used in HSM deferred-signing flows)
- `generate_pkcs12()` — packages certificate + key as PKCS#12

### `ca.py` — `CertificationAuthority`
Represents a CA with its certificate, private key, and chain. Supports both software keys (PEM) and HSM-based keys (PKCS#11). Generates collision-free serial numbers.

### `db.py` — `PKIDataBase`
All database operations against MySQL.

Tables:
| Table | Purpose |
|---|---|
| `CertificationAuthorities` | CA records with cert, chain, HSM config |
| `Certificates` | Issued certificates with status (Active / Revoked / Expired) |
| `CertificateTemplates` | JSON-encoded certificate templates |
| `OCSPResponders` | OCSP responder configs |
| `KeyStorage` | Asymmetric and symmetric keys (plain/encrypted/HSM) |
| `ESTAliases` | EST protocol alias → CA + template mapping |
| `CertificateLogs` | Certificate lifecycle audit log |
| `CertificateRevocationLists` | Stored CRL records |
| `AuditLogs` | Security audit trail |

### `ocsp_responder.py` — `OCSPResponder`
Generates signed OCSP responses. Matches requests by issuer SKI. Supports Good, Revoked, and Unknown statuses. Includes nonce handling for replay protection.

### `key_tools.py` — `KeyTools`
Key generation and management. Supports RSA (2048/3072/4096) and ECDSA (P-256/P-384/P-521). Can delegate key operations to HSM via PKCS#11.

### `pki_tools.py` — `PKITools`
OID mappings, revocation reason codes, and utility helpers for certificate parsing and format conversion.

---

## API Layer (`api/`)

### App factory (`api/__init__.py`)
Creates the Flask app with CORS enabled and registers three blueprints:
- `/api` → main certificate and CA operations
- `/ocsp` → OCSP responder
- `/.well-known` → EST enrollment

### Main routes (`api/routes/main_routes.py`)

| Method | Path | Description |
|---|---|---|
| GET | `/api/ca` | List CAs (id, name) |
| GET | `/api/ca/<id>` | CA details |
| GET | `/api/ca/crl/<ca_id>` | Download CRL (DER) |
| GET | `/api/certificate` | List certificates (paginated, filterable by ca_id / template_id) |
| GET | `/api/certificate/<id>` | Certificate details |
| GET | `/api/certificate/pem/<id>` | Download certificate as PEM |
| GET | `/api/certificate/status/<id>` | Revocation status |
| POST | `/api/certificate/issue` | Issue certificate from CSR |
| POST | `/api/certificate/revoke/<id>` | Revoke certificate |
| GET | `/api/template` | List templates |
| GET | `/api/template/<id>` | Template details |
| POST | `/api/template` | Create template |
| PUT | `/api/template/<id>` | Update template |
| GET | `/api/getestaliases` | List EST aliases |

### OCSP routes (`api/routes/ocsp_routes.py`)

| Method | Path | Description |
|---|---|---|
| POST/GET | `/ocsp` | OCSP responder (DER POST body or base64-encoded URL path) |

Parses serial number and issuer SKI from the request, queries certificate status in DB, returns a signed OCSP response.

### EST routes (`api/routes/est_routes.py`)
Implements RFC 7030 EST (Enrollment over Secure Transport):

| Method | Path | Description |
|---|---|---|
| GET | `/.well-known/est[/<label>]/cacerts` | CA certificate chain (PEM) |
| POST | `/.well-known/est[/<label>]/simpleenroll` | Enroll via CSR → PKCS#7 response |
| POST | `/.well-known/est[/<label>]/simpleenrollpem` | Enroll via CSR → PEM response (non-standard) |

Supports labeled enrollment via `<label>` mapped to EST aliases.

### Service init (`api/services/__init__.py`)
Initializes the global `pki` instance and starts a background CRL generation task (APScheduler, every 10 minutes). CRLs are written to `out/crl/` in both DER and PEM formats.

---

## Configuration System (`config/`)

### Main config (`config.json`)
```json
{
  "db_config": { "host", "port", "user", "password", "database" },
  "template_folder": "config/cert_templates",
  "ca_store_folder": "config/ca_store",
  "ocsp_responder_folder": "config/ocsp_responders",
  "default_ca_id": 1,
  "default_template": 7
}
```

Environment-specific overrides: `config.local.json`, `config.aws.json`, `config.phobos.json`.

### Certificate templates (`config/cert_templates/*.json`)
Define certificate policy:
- `template_name`, `max_validity` (days)
- `subject_name` — required/optional fields (CN, O, C, OU, …)
- `extensions` — KeyUsage, EKU, BasicConstraints, SAN, SKI, AKI, AIA, CDP, OCSP-NoCheck
- `allowed_cryptography` — permitted algorithms and key sizes

Available templates: base, CA, client, client v2, server, S/MIME, OCSP responder, IoT device, IoT root CA.

### CA store (`config/ca_store/*.json`)
Per-CA configuration:
- CA name, max validity, serial number length, CRL validity
- `crypto`: PEM certificate + private key (or HSM token slot / key ID / password)
- Extension config (AIA, CDP URLs)

### OCSP responder config (`config/ocsp_responders/*.json`)
- Issuer SKI for routing requests to the correct responder
- Responder certificate and signing key (software or HSM)
- Response validity period

---

## Web Frontend (`web/`)

Simple Flask UI (port 5000) for manual certificate operations:
- Request certificate via form or CSR upload
- Download CA certificate
- Communicates with the EST server at `http://127.0.0.1:8080/.well-known/est`

Static HTML prototypes in `web/tests/`: certificate list, certificate details, certificate request.

---

## Dependencies

| Package | Purpose |
|---|---|
| `cryptography==44.0.2` | Cryptographic operations |
| `asn1crypto==1.5.1` | ASN.1 parsing/encoding |
| `Flask==3.1.0` | Web framework |
| `mysql-connector-python==9.3.0` | MySQL driver |
| `pykcs11==1.5.17` | PKCS#11 HSM interface |
| `APScheduler==3.11.0` | Background scheduling |
| `Requests==2.32.3` | HTTP client (web frontend → EST) |
| `flask_cors` | CORS support |

---

## HSM Integration

- PKCS#11 support via `pykcs11`
- Configured per CA and OCSP responder via `token_slot`, `token_key_id`, `token_password`
- Deferred signing flow: TBS Certificate is constructed, hash is sent to HSM, returned signature is patched into the certificate via `patch_certificate_signature()`

---

## Current Status

Recent commits reflect active development:
- `d0c46bf` — Resources (CAs, templates, OCSP responders) now loaded into memory on startup for performance
- `43684ba` — OCSP responder fully functional
- `ac8437b` — EST alias support, logging improvements
- `f05ae28` — API integrated with PyPKI core and MySQL database
