# Database Structure

PyPKI uses MySQL as its backend. The schema is created by `PKIDataBase.create_database()` in `pypki/db.py`. All tables are created in a single named database defined in the configuration file.

---

## Entity Relationship Overview

```
KeyStorage ◄─── CertificationAuthorities
                               │
                    ┌──────────┤
                    │          │
               ESTAliases  OCSPResponders
                    │
             CertificateTemplates
                    │
               Certificates ──► CertificateLogs
                    │
      CertificateRevocationLists (via CertificationAuthorities)
```

---

## Tables

### KeyStorage

Stores cryptographic keys, either in plain text, encrypted, or as a reference to an HSM slot. Both asymmetric key pairs and symmetric keys are stored here.

| Column | Type | Constraints | Description |
|---|---|---|---|
| `id` | INT | PK, AUTO_INCREMENT | |
| `certificate_id` | INT | | Reference to the associated certificate (informational) |
| `key_type` | VARCHAR(64) | | Algorithm and parameter string, e.g. `RSA-3072`, `ECDSA-P-256`, `Ed25519`, `AES-256` |
| `private_key` | TEXT | | PEM-encoded private key (asymmetric) or base64-encoded raw bytes (symmetric) |
| `public_key` | TEXT | | PEM-encoded SubjectPublicKeyInfo (asymmetric keys only; NULL for symmetric) |
| `storage_type` | ENUM | NOT NULL | `Encrypted`, `Plain`, or `HSM` |
| `hsm_slot` | INT | | PKCS#11 slot number (HSM only) |
| `hsm_token_id` | VARCHAR(255) | | HSM token identifier (HSM only) |
| `created_at` | TIMESTAMP | DEFAULT NOW | |

---

### CertificationAuthorities

One row per Certification Authority loaded into the system.

| Column | Type | Constraints | Description |
|---|---|---|---|
| `id` | INT | PK, AUTO_INCREMENT | |
| `name` | VARCHAR(255) | NOT NULL | Display name of the CA |
| `description` | TEXT | | Optional description |
| `contact_email` | VARCHAR(255) | | Contact e-mail |
| `certificate` | TEXT | | PEM-encoded CA certificate |
| `public_key` | TEXT | | PEM-encoded CA public key |
| `ski` | VARCHAR(64) | | Subject Key Identifier (hex SHA-1 of public key) |
| `private_key` | TEXT | | PEM-encoded private key (null when using HSM) |
| `private_key_reference` | INT | FK → KeyStorage | Used when the key is stored in KeyStorage |
| `certificate_chain` | TEXT | | PEM bundle of the full chain up to the root |
| `token_slot` | INT | | PKCS#11 slot number |
| `token_key_id` | VARCHAR(64) | | PKCS#11 key ID |
| `token_password` | VARCHAR(64) | | PKCS#11 token PIN |
| `max_validity` | INT | | Maximum certificate validity in days this CA may issue |
| `serial_number_length` | INT | | Byte length used when generating random serial numbers |
| `crl_validity` | INT | DEFAULT 365 | How many days a generated CRL remains valid |
| `extensions` | JSON | NOT NULL | CA-level X.509 extension configuration |
| `is_default` | BOOLEAN | DEFAULT FALSE | Whether this is the default CA |
| `created_at` | TIMESTAMP | DEFAULT NOW | |
| `updated_at` | TIMESTAMP | ON UPDATE NOW | |

**Foreign keys**
- `private_key_reference` → `KeyStorage(id)`

---

### CertificateTemplates

Policy documents that control certificate issuance. The full template definition is stored as a JSON document.

| Column | Type | Constraints | Description |
|---|---|---|---|
| `id` | INT | PK, AUTO_INCREMENT | |
| `name` | VARCHAR(255) | NOT NULL | Template display name (mirrors `template_name` inside `definition`) |
| `definition` | JSON | NOT NULL | Complete template JSON (see `doc/certificate_templates.md`) |
| `is_default` | BOOLEAN | DEFAULT FALSE | Whether this is the default template |
| `created_at` | TIMESTAMP | DEFAULT NOW | |
| `updated_at` | TIMESTAMP | ON UPDATE NOW | |

---

### Certificates

Every certificate issued by the system, regardless of CA or template.

| Column | Type | Constraints | Description |
|---|---|---|---|
| `id` | INT | PK, AUTO_INCREMENT | |
| `ca_id` | INT | FK → CertificationAuthorities | The CA that signed this certificate |
| `template_id` | INT | FK → CertificateTemplates | The template used at issuance |
| `serial_number` | VARCHAR(255) | NOT NULL | Hex-encoded serial number |
| `subject_name` | VARCHAR(255) | | RFC 4514 string of the subject DN |
| `issuer_name` | VARCHAR(255) | | RFC 4514 string of the issuer DN |
| `not_before` | DATETIME | | Certificate validity start |
| `not_after` | DATETIME | | Certificate validity end |
| `public_key` | TEXT | | PEM-encoded public key |
| `private_key_reference` | INT | FK → KeyStorage | Set when the system generated the key pair |
| `status` | ENUM | NOT NULL, DEFAULT `Active` | `Active`, `Revoked`, or `Expired` |
| `revoked_at` | TIMESTAMP | | Timestamp of revocation (null if not revoked) |
| `revocation_reason` | INT | | RFC 5280 reason code (null if not revoked) |
| `certificate_data` | TEXT | | PEM-encoded certificate |
| `fingerprint` | VARCHAR(128) | NOT NULL, UNIQUE | SHA-256 fingerprint (hex) |
| `created_at` | TIMESTAMP | DEFAULT NOW | |
| `updated_at` | TIMESTAMP | ON UPDATE NOW | |

**Foreign keys**
- `ca_id` → `CertificationAuthorities(id)`
- `template_id` → `CertificateTemplates(id)`
- `private_key_reference` → `KeyStorage(id)`

**Revocation reason codes** (RFC 5280)

| Code | Meaning |
|---|---|
| 0 | unspecified |
| 1 | keyCompromise |
| 2 | cACompromise |
| 3 | affiliationChanged |
| 4 | superseded |
| 5 | cessationOfOperation |
| 6 | certificateHold |
| 9 | privilegeWithdrawn |

---

### ESTAliases

Named aliases for the EST (Enrollment over Secure Transport, RFC 7030) service. Each alias binds a CA and a certificate template, allowing different enrollment profiles to be exposed under different URL paths.

| Column | Type | Constraints | Description |
|---|---|---|---|
| `id` | INT | PK, AUTO_INCREMENT | |
| `name` | VARCHAR(255) | NOT NULL | Alias name used in the EST URL path (`/.well-known/est/<name>/`) |
| `ca_id` | INT | FK → CertificationAuthorities | CA used to sign certificates for this alias |
| `template_id` | INT | FK → CertificateTemplates | Template applied for this alias |
| `is_default` | BOOLEAN | DEFAULT FALSE | Whether this is the default alias (used when no name is specified) |
| `created_at` | TIMESTAMP | DEFAULT NOW | |
| `updated_at` | TIMESTAMP | ON UPDATE NOW | |

**Foreign keys**
- `ca_id` → `CertificationAuthorities(id)`
- `template_id` → `CertificateTemplates(id)`

---

### OCSPResponders

Configuration for OCSP responder instances. Each responder is tied to a specific issuing CA via the CA's Subject Key Identifier.

| Column | Type | Constraints | Description |
|---|---|---|---|
| `id` | INT | PK, AUTO_INCREMENT | |
| `name` | VARCHAR(255) | NOT NULL | Display name |
| `ca_id` | INT | FK → CertificationAuthorities | The CA whose certificates this responder services |
| `issuer_ski` | VARCHAR(128) | NOT NULL, UNIQUE | Subject Key Identifier of the issuing CA (used to route OCSP requests) |
| `issuer_certificate` | TEXT | | PEM-encoded issuer certificate |
| `not_after` | DATETIME | | Expiry of the OCSP responder certificate |
| `response_validity` | INT | DEFAULT 1 | How many days an OCSP response remains valid |
| `private_key` | TEXT | | PEM-encoded OCSP responder private key |
| `private_key_reference` | INT | | Reference to KeyStorage (when applicable) |
| `certificate` | TEXT | | PEM-encoded OCSP responder certificate |
| `token_slot` | INT | | PKCS#11 slot number |
| `token_key_id` | VARCHAR(64) | | PKCS#11 key ID |
| `token_password` | VARCHAR(64) | | PKCS#11 token PIN |
| `created_at` | TIMESTAMP | DEFAULT NOW | |
| `updated_at` | TIMESTAMP | ON UPDATE NOW | |

**Foreign keys**
- `ca_id` → `CertificationAuthorities(id)`

---

### CertificateLogs

Audit trail for lifecycle events on individual certificates.

| Column | Type | Constraints | Description |
|---|---|---|---|
| `id` | INT | PK, AUTO_INCREMENT | |
| `certificate_id` | INT | FK → Certificates | The affected certificate |
| `action` | ENUM | NOT NULL | `Issued`, `Revoked`, `Renewed`, `Updated`, or `Expired` |
| `reason` | TEXT | | Free-text description of the action |
| `created_at` | TIMESTAMP | DEFAULT NOW | |

**Foreign keys**
- `certificate_id` → `Certificates(id)`

---

### CertificateRevocationLists

Stores generated CRL data alongside validity metadata.

| Column | Type | Constraints | Description |
|---|---|---|---|
| `id` | INT | PK, AUTO_INCREMENT | |
| `ca_id` | INT | FK → CertificationAuthorities | The CA that issued this CRL |
| `crl_data` | TEXT | | DER or PEM-encoded CRL |
| `issue_date` | TIMESTAMP | | When the CRL was generated |
| `next_update` | TIMESTAMP | | When the next CRL must be published |
| `created_at` | TIMESTAMP | DEFAULT NOW | |
| `updated_at` | TIMESTAMP | ON UPDATE NOW | |

**Foreign keys**
- `ca_id` → `CertificationAuthorities(id)`

---

### AuditLogs

General-purpose audit log for system-level actions (not tied to a specific certificate).

| Column | Type | Constraints | Description |
|---|---|---|---|
| `id` | INT | PK, AUTO_INCREMENT | |
| `action_type` | VARCHAR(255) | | Category or type of the action |
| `action_details` | JSON | | Arbitrary JSON payload describing the action |
| `user_id` | INT | | Identifier of the user who triggered the action |
| `created_at` | TIMESTAMP | DEFAULT NOW | |

---

## Foreign Key Summary

| Table | Column | References |
|---|---|---|
| CertificationAuthorities | private_key_reference | KeyStorage(id) |
| Certificates | ca_id | CertificationAuthorities(id) |
| Certificates | template_id | CertificateTemplates(id) |
| Certificates | private_key_reference | KeyStorage(id) |
| ESTAliases | ca_id | CertificationAuthorities(id) |
| ESTAliases | template_id | CertificateTemplates(id) |
| OCSPResponders | ca_id | CertificationAuthorities(id) |
| CertificateLogs | certificate_id | Certificates(id) |
| CertificateRevocationLists | ca_id | CertificationAuthorities(id) |

---

## Database Management

The schema is created (or recreated from scratch) by running:

```python
from pypki import PKIDataBase

db = PKIDataBase(config)
with db.connection():
    db.create_database()
```

The utility script `utils/reset_pki.py` wraps this call and is used to drop and reinitialise the entire database during development or deployment.

> **Warning:** `create_database()` drops the existing database before recreating it. All data is lost.
