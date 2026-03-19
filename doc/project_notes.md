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
Represents a CA with its certificate and chain. Signing is delegated to the injected `KeyManagementService` via a `kms_key_id`. Generates random serial numbers; uniqueness is enforced by the `uq_ca_serial` DB constraint with automatic retry on collision.

### `db.py` — `PKIDataBase`
All database operations against MySQL. Uses a `MySQLConnectionPool` (configurable pool size via `"pool_size"` in `db_config`, default 5) with `threading.local()` for per-thread connection checkout, making it safe for multi-threaded Flask deployments.

Tables:
| Table | Purpose |
|---|---|
| `CertificationAuthorities` | CA records with cert, chain, and reference to key in KeyStorage |
| `Certificates` | Issued certificates with status (Active / Revoked / Expired); unique per CA by serial |
| `CertificateTemplates` | JSON-encoded certificate templates |
| `OCSPResponders` | OCSP responder configs |
| `KeyStorage` | Asymmetric and symmetric keys (plain/encrypted/HSM); HSM entries include `token_password` |
| `ESTAliases` | EST alias → CA + template mapping, with optional Basic Auth credentials |
| `CertificateRevocationLists` | Stored CRL records |
| `AuditLogs` | System-wide audit trail (resource_type, resource_id, action, user_id) |
| `Users` | Authenticated users with role-based access control |

### `ocsp_responder.py` — `OCSPResponder`
Generates signed OCSP responses. Matches requests by issuer SKI. Supports Good, Revoked, and Unknown statuses. Includes nonce handling for replay protection.

### `key_tools.py` — `KeyTools`
Key generation and management. Supports RSA (2048/3072/4096) and ECDSA (P-256/P-384/P-521). Can delegate key operations to HSM via PKCS#11.

### `pki_tools.py` — `PKITools`
Shared constants: `OID_MAPPING` (OID → human-readable name dict) and `REVOCATION_REASONS` (RFC 5280 reason code → description dict). No methods — callers access the dicts directly.

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
| GET | `/api/est` | List EST aliases |
| POST | `/api/est` | Create EST alias |
| GET | `/api/est/<id>` | Get EST alias |
| PUT | `/api/est/<id>` | Update EST alias (password only re-hashed when provided) |
| DELETE | `/api/est/<id>` | Delete EST alias |
| POST | `/api/est/<id>/set-default` | Set default EST alias (clears previous default) |

### OCSP routes (`api/routes/ocsp_routes.py`)

| Method | Path | Description |
|---|---|---|
| POST/GET | `/ocsp` | OCSP responder (DER POST body or base64-encoded URL path) |

Parses serial number and issuer SKI from the request, queries certificate status in DB, returns a signed OCSP response.

### EST routes (`api/routes/est_routes.py`)
Implements RFC 7030 EST (Enrollment over Secure Transport):

| Method | Path | Auth | Description |
|---|---|---|---|
| GET | `/.well-known/est[/<label>]/cacerts` | None (public) | CA certificate chain (PEM) |
| POST | `/.well-known/est[/<label>]/simpleenroll` | Basic Auth (if configured) | Enroll via CSR → PKCS#7 response |
| POST | `/.well-known/est[/<label>]/simpleenrollpem` | Basic Auth (if configured) | Enroll via CSR → PEM response (non-standard) |

`<label>` maps to an `ESTAliases` record; omitting it uses the default alias. When the alias has a `username` set, `simpleenroll` and `simpleenrollpem` require HTTP Basic Auth with matching credentials verified against the stored PBKDF2-SHA256 hash. Returns `401 Unauthorized` with `WWW-Authenticate: Basic realm="EST"` on failure. `cacerts` is always public per RFC 7030.

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

Static HTML management UI in `web/html/` (Bootstrap 5 + Bootstrap Icons). Pages communicate directly with the API at `http://127.0.0.1:8080/api` via `fetch`. No server-side rendering — open directly in a browser.

| Page | Description |
|---|---|
| `index.html` | Dashboard — metrics, CA overview, health check |
| `certificate_list.html` | Certificate inventory with status filtering |
| `certificate_request.html` | Issue a certificate from a JSON payload |
| `csr_tool.html` | Browser-based CSR generator (ECC P-256 / RSA 2048, key never leaves browser) |
| `cas_and_crls.html` | CA list, chain download, CRL download |
| `ca_details.html` | Single CA details |
| `template_list.html` | Certificate template inventory |
| `template_editor.html` | Create / edit certificate templates |
| `est_list.html` | EST alias management (EST Config) |
| `est_editor.html` | Create / edit EST alias |
| `est_test.html` | Interactive EST endpoint tester (cacerts and simpleenroll) |
| `kms_keygen.html` | KMS key generation |

A legacy Flask app (`web/app.py`) provides a minimal Jinja2 UI on port 5000 for manual EST operations; the static `web/html/` pages are the primary interface.

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
- HSM keys are stored in `KeyStorage` with `storage_type = 'HSM'`; the slot, token ID, and PIN (`token_password`) are columns on that row
- All signing goes through `KeyManagementService`; HSM and software keys are transparent to callers
- Deferred signing flow: TBS Certificate is constructed, hash is sent to HSM, returned signature is patched into the certificate via `patch_certificate_signature()`

---

## Current Status

Recent work:
- **EST Basic Auth** — `ESTAliases` stores `username` + PBKDF2-SHA256 `password_hash`; `simpleenroll`/`simpleenrollpem` enforce auth when configured; `cacerts` is public per RFC 7030
- **EST management UI** — full CRUD web pages (`est_list.html`, `est_editor.html`) and interactive tester (`est_test.html`)
- **CSR Tool** — browser-side key and CSR generation (`csr_tool.html`), no server round-trip; supports ECC P-256 and RSA 2048 with SAN
- **DB connection pool** — `PKIDataBase` replaced single shared connection with `MySQLConnectionPool` + `threading.local()` for thread-safe multi-request handling
- **EST admin API** — full CRUD REST endpoints at `/api/est` for alias management
- **KMS integration** — all private keys centralised in `KeyStorage`; signing routed through `KeyManagementService`; HSM token PIN stored in `KeyStorage.token_password`; `token_slot/token_key_id/token_password` removed from CA and OCSP tables
- **Audit log** — new `AuditLogs` table replaces `CertificateLogs`; every CRUD operation writes an entry; admin Audit Logs page with pagination, CSV export, and clear function
- **CA editor** — web UI for editing CA name, validity, serial length, CRL validity, and default extensions (AIA/CDP)
- **App logs page** — admin page showing last 100 lines of `out/app.log` with archive-and-clear function
- **Serial uniqueness** — DB-level `UNIQUE KEY uq_ca_serial (ca_id, serial_number)` on `Certificates`; in-memory serial set and full-table `fetch_used_serials()` removed; issuance methods retry on the (essentially impossible) collision
