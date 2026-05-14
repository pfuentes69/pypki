# Database Specification

This is the consolidated specification for the persistence layer in
pyPKI. It is the single source of truth for the database design: the
schema as it currently is, the entity relationships that bind the
tables, the schema lifecycle (initial creation, idempotent in-process
migrations, optional one-shot scripts), operational concerns
(backup / restore, reset), and the known weaknesses + security risks
the operator should be aware of.

Status of each schema-touching work item lives in
[PROGRESS.md §7](PROGRESS.md); the strategic intent and cross-area
framing live in [roadmap.md](roadmap.md). The functional surfaces that
read and write these tables are specified in
[ca-management-specs.md](ca-management-specs.md),
[certificate-management-specs.md](certificate-management-specs.md),
[certificate-template-specs.md](certificate-template-specs.md), and
[kms-specs.md](kms-specs.md). This document covers the *data layer*
only — column shapes, foreign keys, constraints, and how the schema
evolves.

A developer reading only this document should have enough to
understand the on-disk shape, identify the operator-visible gaps, and
plan the remaining work.

---

## 1. Goals

1. **Single backend.** pyPKI targets MariaDB (MySQL-compatible),
   accessed through the `mysql-connector-python` driver. One named
   schema holds every table; there is no sharding, no replicas at the
   application layer, and no per-tenant separation.
2. **Schema is code.** The authoritative schema lives in
   `PKIDataBase.create_database()` ([db.py:3271](../pypki/db.py#L3271))
   and `PKIDataBase.migrate_schema()` ([db.py:2639](../pypki/db.py#L2639)).
   Fresh installs and dev resets call `create_database()` (drops and
   recreates); upgrades to running installs are picked up by
   `migrate_schema()` at boot, which is idempotent and additive.
3. **Foreign keys enforce referential integrity.** Cross-table
   references (CA → keys, certs → CA + template + key, EST alias → CA
   + template, OCSP responder → CA, CRL → CA, KMS key → provider) are
   FK-constrained. Cascade rules are application-mediated where the
   business logic is non-trivial (CA delete unlinks issued certs
   rather than deleting them).
4. **Encrypted at rest at the column level.** Private-key material in
   `KeyStorage` is KEK-wrapped before insert; the master KEK is held
   only in process memory. The database itself is plaintext from the
   filesystem's perspective; operators are expected to combine column
   encryption with disk-level encryption.
5. **Audit trail in-database.** Every create / update / delete /
   revoke action that the management surface initiates writes a row
   to `AuditLogs`. The schema is the place audit history lives — there
   is no external SIEM dependency in the default deployment.
6. **No silent destruction.** Schema migrations only add — they never
   drop columns or alter types in place. Destructive operations live
   behind explicit utility scripts (`reset_pki.py`).

---

## 2. Status

### 2.1 What is in place

**Schema creation**
- `create_database()` drops the configured schema, recreates it, and
  builds the 10 tables in two phases: tables first, then foreign-key
  constraints (so create order does not depend on FK target existence).
- `reset_pki.py` is the public entry point: it calls
  `create_database()` and seeds the built-in `superadmin` account with
  the default password `password`.

**Idempotent migrations**
- `migrate_schema()` runs at every boot. Each migration step checks
  `INFORMATION_SCHEMA` for the missing column / table / index and
  applies the change only when needed. Bailouts:
  - the configured database does not exist yet → log + return.
  - the database exists but is empty → log + return (a subsequent
    `create_database()` will build the modern schema directly).
- Currently-shipped in-process migrations:
  - `CertificationAuthorities.key_owned`
    ([db.py:2682–2696](../pypki/db.py#L2682-L2696)).
  - `CertificationAuthorities.state` and `pending_csr` for CR-0001
    ([db.py:2698–2745](../pypki/db.py#L2698-L2745)).
  - `AuditLogs.metadata` JSON ([db.py:2747–2761](../pypki/db.py#L2747-L2761)).
  - `KeyStorage.provider_id`, `KeyStorage.label`, `KeyStorage.key_owned`
    ([db.py:2851–2934](../pypki/db.py#L2851-L2934)).
  - `CertificationAuthorities.signing_algorithm`
    ([db.py:3099–3135](../pypki/db.py#L3099-L3135)).
  - `Certificates.is_self_signed`
    ([db.py:3200–3215](../pypki/db.py#L3200-L3215)).

**One-shot migration scripts (for installs that pre-date in-process
migration)**
- [utils/migrate_ocsp_settings.py](../utils/migrate_ocsp_settings.py)
  — adds the modern OCSP responder columns
  (`response_validity_hours`, `nonce_policy`,
  `include_cert_in_response`, `responder_id_encoding`,
  `hash_algorithm`).
- [utils/migrate_template_cdp_aia.py](../utils/migrate_template_cdp_aia.py)
  — rewrites legacy CDP/AIA template JSON to the explicit
  `include`/`useCADefault` shape.

**Tables**
- 10 tables, listed under §4. Names use PascalCase plural for entity
  tables (`Certificates`, `Users`, `KeyStorage` is the exception —
  singular by long-standing convention).
- All entity tables carry `id INT PK AUTO_INCREMENT`; lifecycle tables
  carry `created_at` + `updated_at` timestamps.

### 2.2 What is pending

- **Schema-migration release notes.** No CHANGELOG-style document
  states which migrations apply per release; operators inferring
  upgrade safety must read the `migrate_schema()` body. Captured in
  [PROGRESS.md §7](PROGRESS.md).
- **Per-release "what changed" notes.** No CHANGELOG.md exists.
- **`metadata` JSON on audit rows is partially wired.** Column exists
  on `AuditLogs`; only some write paths populate it. Most certificate
  / CA / template events still record bare metadata-less rows. See
  [certificate-management-specs.md §13.7](certificate-management-specs.md)
  and [ca-management-specs.md §12](ca-management-specs.md).
- **Unique constraints under-applied.** `CertificationAuthorities.name`,
  `CertificateTemplates.name`, and per-table `is_default` flags are
  not enforced unique at the schema level despite being functionally
  unique. See §8.1.
- **Legacy column carry-over.** `CertificationAuthorities.private_key`,
  `OCSPResponders.private_key`, and `KeyStorage.token_password` are
  legacy / unused on modern rows but still part of the schema.
- **Hierarchy modelling.** `CertificationAuthorities.parent_ca_id` and
  `is_self_signed` for CAs are not yet in the schema — captured in
  [ca-management-specs.md §2.2](ca-management-specs.md).

---

## 3. Architecture

### 3.1 Layered model

```
  application code (core.py, web/services, web/routes, pypki/*)
                  │
                  ▼
          PKIDataBase (pypki/db.py)        ← single class wrapping
                  │                          connect / cursor / commit
                  ▼
       mysql-connector-python                ← driver
                  │
                  ▼
                MariaDB                      ← target DBMS
```

- All SQL goes through methods on `PKIDataBase`. Routes and the facade
  never construct cursors directly — they call `pki.get_db()` and
  invoke a method that returns rows / counts.
- `PKIDataBase` is per-process; cursors are per-call. Connection
  pooling is handled by the driver. The `with db.connection():` context
  manager guarantees commit-or-rollback on the request boundary.
- The schema is defined exactly once, in
  `create_database()`. Every other code path that touches structure
  (the migration steps in `migrate_schema()`, the one-shot scripts in
  `utils/`) is an addition that converges existing databases onto the
  shape `create_database()` would have produced from scratch.

### 3.2 Two design decisions, recorded

**Decision A — Application-mediated cascade.** Foreign-key
constraints enforce *referential* integrity (you cannot insert a row
that points nowhere) but not *deletion semantics* (what happens to
referencing rows when the target is deleted). The CA delete path, for
example, runs a fixed cascade order in a single transaction
([db.py:932–1000](../pypki/db.py#L932-L1000)):

1. Delete dependent `OCSPResponders` rows.
2. Delete dependent `ESTAliases` rows.
3. Delete dependent `CertificateRevocationLists` rows.
4. Set `Certificates.ca_id` to NULL on every issued cert (preserves
   the cert row + audit trail).
5. Delete the `CertificationAuthorities` row itself.
6. Delete the bound `KeyStorage` row only when `key_owned = TRUE`.

Doing this in SQL via `ON DELETE CASCADE` / `ON DELETE SET NULL` would
either lose the audit trail (cascade certificates) or silently break
the `key_owned` invariant. Keeping the cascade in Python lets each
case carry its own justification and produces a structured response
that names the affected counts.

**Decision B — KEK-wrapped column encryption, not full-database
encryption.** Private keys (`KeyStorage.private_key`,
`OCSPResponders.private_key`) are AES-256-GCM-encrypted under a
per-provider KEK before insert; the KEK is derived from a master
secret held only in process memory. The database file itself is
plaintext from MariaDB's perspective. This is intentional:

- It survives DB backup / replication / restore without leaking the
  KEK alongside the ciphertext.
- It lets the master secret stay outside the database boundary
  (env var / file / HSM-resolved).
- It does not protect against an attacker with both file access *and*
  process-memory access; that is explicitly out of scope. See
  [kms-specs.md §6–7](kms-specs.md).

---

## 4. Data model

The schema contains 10 tables. The relationship overview:

```
CryptoProviders ◄── KeyStorage ◄── CertificationAuthorities
                          ▲                     │
                          │                     │
                          └── OCSPResponders ◄──┤
                                                │
                                       ESTAliases
                                                │
                                CertificateTemplates ◄── Certificates ──► KeyStorage
                                                │
                                CertificateRevocationLists (← CertificationAuthorities)

AuditLogs   (system-wide, references Users by id)
Users       (independent — no FKs)
```

### 4.1 `CryptoProviders`

KMS provider rows. Each row is either a `software` provider (keys
KEK-wrapped in `KeyStorage`) or a `pkcs11` provider (keys live on an
HSM token). Full specification in
[kms-specs.md §4.1](kms-specs.md).

| Column | Type | Constraints | Description |
|---|---|---|---|
| `id` | INT | PK, AUTO_INCREMENT | |
| `label` | VARCHAR(255) | NOT NULL, UNIQUE | Operator-facing label |
| `kind` | ENUM | NOT NULL | `software` or `pkcs11` |
| `module_path` | VARCHAR(1024) | | PKCS#11 module path (pkcs11 only) |
| `slot_label` | VARCHAR(255) | | PKCS#11 token label (pkcs11 only) |
| `auth_kind` | ENUM | NOT NULL, DEFAULT `pin` | `pin`, `luna_role`, or `yubihsm_authkey` |
| `auto_activate` | BOOLEAN | NOT NULL, DEFAULT FALSE | Whether to activate on boot |
| `auth_secret_ref` | VARCHAR(512) | NOT NULL | Where to resolve the auth secret (`db:encrypted`, `env:`, `vault:`, `operator:prompt`) |
| `auth_secret_blob` | VARBINARY(1024) | | KEK-wrapped secret when `auth_secret_ref = db:encrypted` |
| `extra_json` | JSON | NOT NULL | Backend-specific extra config |
| `description` | TEXT | | Optional description |
| `is_default` | BOOLEAN | NOT NULL, DEFAULT FALSE | The default provider for new software keys. See §8.1 |
| `created_at` / `updated_at` | TIMESTAMP | Auto-managed | |

### 4.2 `KeyStorage`

Cryptographic key records. Asymmetric keys carry an encrypted
private-key blob plus the public key PEM; symmetric keys carry only
the encrypted blob; HSM keys carry no private material — only the
`hsm_token_id` (CKA_ID) that addresses the on-token object.

| Column | Type | Constraints | Description |
|---|---|---|---|
| `id` | INT | PK, AUTO_INCREMENT | |
| `certificate_id` | INT | | Informational back-reference; not FK-enforced. |
| `provider_id` | INT | FK → `CryptoProviders(id)` | Which provider owns this key. |
| `key_type` | VARCHAR(64) | | Algorithm + parameters (e.g. `RSA-3072`, `ECDSA-P-256`, `Ed25519`, `AES-256`). |
| `private_key` | TEXT | | KEK-wrapped PEM (software) or NULL (HSM). |
| `public_key` | TEXT | | PEM-encoded SubjectPublicKeyInfo. NULL for symmetric. |
| `label` | VARCHAR(255) | | Operator-facing label. |
| `storage_type` | ENUM | NOT NULL | `Encrypted`, `Plain` (legacy), `HSM`, `Symmetric`, `PassphraseEncrypted` |
| `key_owned` | BOOLEAN | NOT NULL, DEFAULT TRUE | TRUE: key created by pyPKI, cascade-delete safe. FALSE: imported, preserved on owner delete. |
| `hsm_slot` | INT | | Legacy. Modern PKCS#11 rows address by token label via provider. |
| `hsm_token_id` | VARCHAR(255) | | CKA_ID for HSM-stored keys. |
| `token_password` | VARCHAR(255) | | Legacy. Modern auth flows through the provider's `auth_secret_ref`. |
| `created_at` | TIMESTAMP | Auto-managed | |

**`storage_type` semantics**

| Value | Used by | Meaning |
|---|---|---|
| `Encrypted` | software KEK | KEK-wrapped plaintext PEM. Re-loadable via the KMS sign path. |
| `Plain` | legacy | Unencrypted PEM. Modern code never produces these. |
| `HSM` | pkcs11 provider | On-token; `private_key` is NULL. |
| `Symmetric` | software KEK | KEK-wrapped raw symmetric bytes. |
| `PassphraseEncrypted` | software KEK | KEK-wrapped *passphrase-encrypted* PEM. Not loadable from KMS sign — supplies the PKCS#12 re-download path with the operator's passphrase. |

### 4.3 `CertificationAuthorities`

One row per managed CA. Full specification in
[ca-management-specs.md §4.1](ca-management-specs.md).

| Column | Type | Constraints | Description |
|---|---|---|---|
| `id` | INT | PK, AUTO_INCREMENT | |
| `name` | VARCHAR(255) | NOT NULL | Display name. Functionally unique but not enforced (§8.1). |
| `state` | ENUM | NOT NULL, DEFAULT `active` | `active` or `pending-issuance` (CR-0001). |
| `description` | TEXT | | |
| `contact_email` | VARCHAR(255) | | |
| `certificate` | TEXT | | CA certificate PEM. NULL while `state='pending-issuance'`. |
| `public_key` | TEXT | | Reserved cache; populated from `certificate` when needed. |
| `ski` | VARCHAR(64) | | Hex SubjectKeyIdentifier; NULL while `state='pending-issuance'`. |
| `private_key` | TEXT | | **Legacy** inline software-key PEM. Modern rows leave this NULL. |
| `private_key_reference` | INT | FK → `KeyStorage(id)` | The KMS key this CA signs with. |
| `key_owned` | BOOLEAN | NOT NULL, DEFAULT TRUE | Cascade-delete control. |
| `certificate_chain` | TEXT | | Concatenated PEM of issuer certs. |
| `pending_csr` | TEXT | | PEM PKCS#10 for external-subordinate phase 1; NULL otherwise. |
| `max_validity` | INT | | Days; `-1` = unlimited. |
| `serial_number_length` | INT | | Bytes; drives random serial generation. |
| `crl_validity` | INT | DEFAULT 365 | Days; CRL `nextUpdate` window. |
| `extensions` | JSON | NOT NULL | Per-CA AIA / CDP defaults. |
| `signing_algorithm` | VARCHAR(32) | NOT NULL | CR-0003 token (e.g. `rsa-sha256`, `ecdsa-sha256`). |
| `is_default` | BOOLEAN | DEFAULT FALSE | Marker for system default. Not enforced unique. |
| `created_at` / `updated_at` | TIMESTAMP | Auto-managed | |

### 4.4 `CertificateTemplates`

Policy documents that control certificate issuance. Full specification
in [certificate-template-specs.md](certificate-template-specs.md).

| Column | Type | Constraints | Description |
|---|---|---|---|
| `id` | INT | PK, AUTO_INCREMENT | |
| `name` | VARCHAR(255) | NOT NULL | Display name; duplicates `definition.template_name` for fast lookup. |
| `definition` | JSON | NOT NULL | Full template document. See [certificate-template-specs.md §7](certificate-template-specs.md). |
| `is_default` | BOOLEAN | DEFAULT FALSE | Reserved; no consumer today. |
| `created_at` / `updated_at` | TIMESTAMP | Auto-managed | |

### 4.5 `Certificates`

Every certificate issued by the system, regardless of CA or template.
Full specification in
[certificate-management-specs.md §4.1](certificate-management-specs.md).

| Column | Type | Constraints | Description |
|---|---|---|---|
| `id` | INT | PK, AUTO_INCREMENT | |
| `ca_id` | INT | FK → `CertificationAuthorities(id)` | NULLable; set to NULL on CA delete (preserves audit trail). |
| `template_id` | INT | FK → `CertificateTemplates(id)` | Which template governed issuance. |
| `serial_number` | VARCHAR(255) | NOT NULL | Hex-encoded serial. |
| `subject_name` | VARCHAR(255) | | RFC 4514 subject DN. |
| `issuer_name` | VARCHAR(255) | | RFC 4514 issuer DN. |
| `not_before` | DATETIME | | |
| `not_after` | DATETIME | | |
| `public_key` | TEXT | | PEM-encoded public key. |
| `private_key_reference` | INT | FK → `KeyStorage(id)` | Set when pyPKI generated the keypair. |
| `is_self_signed` | BOOLEAN | NOT NULL, DEFAULT FALSE | TRUE when subject == issuer and no managing CA. |
| `status` | ENUM | NOT NULL, DEFAULT `Active` | `Active`, `Revoked`, `Expired`. |
| `revoked_at` | TIMESTAMP | | |
| `revocation_reason` | INT | | RFC 5280 reason code; NULL when not revoked. |
| `certificate_data` | TEXT | | PEM-encoded certificate. |
| `fingerprint` | VARCHAR(128) | NOT NULL, UNIQUE | SHA-256 hex fingerprint. |
| `created_at` / `updated_at` | TIMESTAMP | Auto-managed | |

**Unique constraints**
- `fingerprint` — globally unique across the database.
- `uq_ca_serial (ca_id, serial_number)` — RFC 5280 §4.1.2.2:
  serial numbers are unique per issuing CA. The DB constraint is the
  authoritative collision detector; serial generation retries up to
  three times before raising.

**Revocation reason codes** (RFC 5280 §5.3.1)

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

### 4.6 `ESTAliases`

Named EST enrollment profiles (RFC 7030). Each alias binds a CA and a
certificate template; HTTP Basic Auth is optional. Full specification
in [est-specs.md](est-specs.md).

| Column | Type | Constraints | Description |
|---|---|---|---|
| `id` | INT | PK, AUTO_INCREMENT | |
| `name` | VARCHAR(255) | NOT NULL | Alias name embedded in the EST URL path (`/.well-known/est/<name>/…`). |
| `ca_id` | INT | FK → `CertificationAuthorities(id)` | Signing CA. |
| `template_id` | INT | FK → `CertificateTemplates(id)` | Issuance policy. |
| `is_default` | BOOLEAN | DEFAULT FALSE | Selected when the URL has no alias name. |
| `username` | VARCHAR(255) | | HTTP Basic Auth user; empty / NULL means the endpoint is open. |
| `password_hash` | VARCHAR(255) | | Werkzeug PBKDF2-SHA256 hash. Never returned by the API. |
| `cert_fingerprint` | VARCHAR(255) | | Reserved for future mTLS client cert auth. |
| `created_at` / `updated_at` | TIMESTAMP | Auto-managed | |

> The RFC 7030 `cacerts` endpoint is always public regardless of
> `username` (it must be accessible to clients before they have
> credentials). Authentication, when configured, is enforced only on
> `simpleenroll` and `simpleenrollpem`.

### 4.7 `OCSPResponders`

OCSP responder configuration, keyed by issuing CA. Each responder
owns its own signing key and certificate.

| Column | Type | Constraints | Description |
|---|---|---|---|
| `id` | INT | PK, AUTO_INCREMENT | |
| `name` | VARCHAR(255) | NOT NULL | Display name. |
| `ca_id` | INT | FK → `CertificationAuthorities(id)` | The CA whose certs this responder services. |
| `issuer_ski` | VARCHAR(128) | NOT NULL, UNIQUE | Hex SKI of the issuing CA — drives request routing. |
| `issuer_certificate` | TEXT | | PEM-encoded issuer cert (cached for fast loading). |
| `not_after` | DATETIME | | Responder cert expiry. |
| `response_validity` | INT | DEFAULT 1 | **Legacy** days value. |
| `response_validity_hours` | INT | DEFAULT 24 | Modern hours value; used by the API / UI. |
| `nonce_policy` | ENUM | DEFAULT `optional` | `optional`, `required`, or `disabled`. |
| `include_cert_in_response` | BOOLEAN | DEFAULT TRUE | Whether to embed the responder cert in the OCSP response. |
| `responder_id_encoding` | ENUM | DEFAULT `hash` | `hash` or `name`. |
| `hash_algorithm` | ENUM | DEFAULT `sha1` | `sha1` or `sha256`; used in generated responses. |
| `private_key` | TEXT | | **Legacy** inline PEM. Modern rows leave this NULL. |
| `private_key_reference` | INT | FK → `KeyStorage(id)` | Responder signing key. |
| `certificate` | TEXT | | PEM responder certificate. |
| `created_at` / `updated_at` | TIMESTAMP | Auto-managed | |

### 4.8 `CertificateRevocationLists`

Generated CRL blobs with validity metadata. One row per CRL issuance —
historical CRLs are retained until the operator prunes them manually.

| Column | Type | Constraints | Description |
|---|---|---|---|
| `id` | INT | PK, AUTO_INCREMENT | |
| `ca_id` | INT | FK → `CertificationAuthorities(id)` | Issuing CA. |
| `crl_data` | TEXT | | DER or PEM-encoded CRL. |
| `issue_date` | TIMESTAMP | | `thisUpdate`. |
| `next_update` | TIMESTAMP | | `nextUpdate`. |
| `created_at` / `updated_at` | TIMESTAMP | Auto-managed | |

### 4.9 `AuditLogs`

System-wide audit trail. Every CREATE / UPDATE / DELETE / REVOKE the
management surface initiates writes a row here.

| Column | Type | Constraints | Description |
|---|---|---|---|
| `id` | INT | PK, AUTO_INCREMENT | |
| `resource_type` | VARCHAR(64) | NOT NULL | Logical object affected (e.g. `cas`, `certificates`, `templates`, `users`, `crypto_providers`). |
| `resource_id` | INT | | PK of the affected row; NULL for bulk or non-row actions. |
| `action` | VARCHAR(64) | NOT NULL | Verb: `CREATE`, `UPDATE`, `DELETE`, `REVOKE`, etc. |
| `user_id` | INT | NOT NULL, DEFAULT 0 | Acting authenticated user; 0 for system / anonymous actions. |
| `metadata` | JSON | | Optional payload (added by recent migration; partially wired — see §2.2). |
| `created_at` | TIMESTAMP | Auto-managed | |

The web UI surfaces this table on the **Audit Logs** administration
page with pagination, colour-coded action badges, and CSV export
(`out/audit-log-yyyymmddHHMM.csv`).

### 4.10 `Users`

Local user accounts. Always present; even single-operator deployments
have at least the `superadmin` row.

| Column | Type | Constraints | Description |
|---|---|---|---|
| `id` | INT | PK, AUTO_INCREMENT | |
| `username` | VARCHAR(255) | NOT NULL, UNIQUE | |
| `password_hash` | VARCHAR(255) | NOT NULL | Werkzeug PBKDF2-SHA256. |
| `role` | ENUM | NOT NULL, DEFAULT `user` | `superadmin`, `admin`, `user`, `auditor`. |
| `is_active` | BOOLEAN | NOT NULL, DEFAULT TRUE | Deactivated users cannot log in but retain audit history. |
| `last_login` | TIMESTAMP | NULLable | |
| `created_at` / `updated_at` | TIMESTAMP | Auto-managed | |

The `superadmin` row is recreated by `reset_pki.py` with the default
password `password`; operators must rotate it on first login.

---

## 5. Foreign-key map

The schema applies these constraints in `create_database()` after all
tables are built ([db.py:3462–3508](../pypki/db.py#L3462-L3508)):

| Constraint | Table | Column | References |
|---|---|---|---|
| `fk_keystorage_provider_id` | `KeyStorage` | `provider_id` | `CryptoProviders(id)` |
| `fk_cert_authority_private_key_reference` | `CertificationAuthorities` | `private_key_reference` | `KeyStorage(id)` |
| `fk_cert_ca_id` | `Certificates` | `ca_id` | `CertificationAuthorities(id)` |
| `fk_cert_template_id` | `Certificates` | `template_id` | `CertificateTemplates(id)` |
| `fk_cert_private_key_reference` | `Certificates` | `private_key_reference` | `KeyStorage(id)` |
| `fk_estalias_ca_id` | `ESTAliases` | `ca_id` | `CertificationAuthorities(id)` |
| `fk_estalias_template_id` | `ESTAliases` | `template_id` | `CertificateTemplates(id)` |
| `fk_ocspresponders_ca_id` | `OCSPResponders` | `ca_id` | `CertificationAuthorities(id)` |
| `fk_crl_cert_authority` | `CertificateRevocationLists` | `ca_id` | `CertificationAuthorities(id)` |

No `ON DELETE` action is declared; the database refuses any delete
that would orphan a reference, and the application layer pre-computes
the cascade (Decision A in §3.2).

---

## 6. Schema lifecycle

```
            ┌────────────────────────────────────────┐
            │   first run / dev reset                │
fresh ─────►│   reset_pki.py → create_database()     │──► modern schema
            └────────────────────────────────────────┘

            ┌────────────────────────────────────────┐
existing    │   web app boot                          │
install ───►│   PKIDataBase().migrate_schema()        │──► modern schema
            └────────────────────────────────────────┘

            ┌────────────────────────────────────────┐
very old    │   one-shot script(s) from utils/        │──► modern schema
install ───►│   then web app boot → migrate_schema()  │
            └────────────────────────────────────────┘
```

### 6.1 `create_database()`

Drops the configured schema (`CREATE DATABASE` is preceded by
`DROP DATABASE IF EXISTS`), creates the 10 tables from the
`tables_without_fk` dict, then applies the foreign-key constraints
listed in §5. Idempotent against a fresh database; **destructive** against
an existing one.

### 6.2 `migrate_schema()`

Runs at every boot. The body is a sequence of
`SELECT … FROM INFORMATION_SCHEMA.COLUMNS WHERE …` probes; when a
target column / table is missing, the matching `ALTER TABLE` runs.
Each step commits independently so a mid-sequence failure leaves
prior steps applied. The migrations are append-only: no step removes
or renames an existing column. See §2.1 for the current set.

### 6.3 One-shot scripts

Two scripts in `utils/` exist for installs that pre-date in-process
migration:

- `migrate_ocsp_settings.py` — backfills the modern OCSP responder
  columns. Run once, then never again.
- `migrate_template_cdp_aia.py` — rewrites legacy CDP/AIA template
  JSON. Run once.

Both are idempotent (re-runs are no-ops on a current schema). Fresh
installs do not need either.

### 6.4 Reset

`utils/reset_pki.py` is the single supported "wipe and rebuild" entry
point. It calls `create_database()` and then seeds the `superadmin`
row with password `password`. Used in dev and during initial Docker
provisioning. The Docker startup integration calls it conditionally
when the database is empty.

---

## 7. Operational concerns

### 7.1 Backup and restore

Backups are MariaDB-native: `mysqldump` / `mariadb-dump` against the
configured schema. Because key material is KEK-wrapped at the column
level (§3.2 Decision B), a backup file does not directly expose
private keys — but it is *useless* for restore without the matching
master KEK. Operators must back up the KEK source (env var /
secrets-manager entry / HSM-resolved value) alongside the SQL dump.

The UI exposes `POST /api/tools/backup-db` (superadmin only) which
shells out to `mysqldump` and produces a timestamped file in `out/`.
See [tools.html](../web/templates/tools.html).

### 7.2 Restore

Restore is a plain `mariadb < dump.sql` against an empty database;
follow with the matching KEK source and a boot-time
`migrate_schema()` to land on the modern schema if the dump pre-dates
a migration.

### 7.3 Audit-log retention

`AuditLogs` rows are never deleted by the application. The retention
policy is operator-managed; see §10 for the gap on retention
controls.

### 7.4 CRL pruning

`CertificateRevocationLists` accumulates one row per CRL issuance
forever. Operators can prune historical rows with plain SQL; the
application does not currently expose a UI for this. The most recent
row per `ca_id` is what the distribution endpoint serves.

---

## 8. Weaknesses and security risks

This section is the **operator-visible audit** of known data-layer
issues. Each item is either accepted (with mitigation) or scheduled
for closure.

### 8.1 Functional uniqueness not enforced

**Risk:** `CertificationAuthorities.name`, `CertificateTemplates.name`,
and per-table `is_default` flags are functionally unique but not
constrained at the schema level. Two CAs can share a name; two
templates can both have `is_default=TRUE`. The application enforces
neither at insert time.
**Mitigation today:** UI surfaces one default and lists names
alphabetically; collisions are visible but allowed.
**Closure:** add `UNIQUE KEY` constraints on `name`; partial-unique
index on `is_default WHERE is_default = TRUE` (MySQL 8 expression
index or filtered unique-constraint workaround on MariaDB).

### 8.2 Legacy private-key columns retained

**Risk:** `CertificationAuthorities.private_key`,
`OCSPResponders.private_key`, and `KeyStorage.token_password` are
legacy columns. Modern rows leave them NULL, but the columns still
exist and an old-format row inserted by an outdated tool would be
silently accepted.
**Mitigation today:** modern insert paths never populate them.
**Closure:** add `CHECK` constraints that force these columns to NULL
on new rows, or migrate-and-drop them once all installs are confirmed
on the modern path.

### 8.3 No CRL retention policy

**Risk:** `CertificateRevocationLists` grows monotonically. A
long-running CA with daily CRL re-issuance accumulates ~365 rows /
year; large deployments and multi-CA hierarchies multiply the count.
**Mitigation today:** manual SQL pruning.
**Closure:** configurable retention window (keep last N or keep ≥
`nextUpdate` of the latest); cron-style pruner.

### 8.4 No audit-log retention or export controls

**Risk:** `AuditLogs` grows monotonically. Compliance regimes require
retention windows (often 1–7 years); pyPKI imposes none.
**Mitigation today:** the UI exposes CSV export, which an operator
can run periodically.
**Closure:** retention configuration + archive-and-prune job; or
documented external pipeline (ship to SIEM, then prune locally).

### 8.5 `metadata` JSON on audit rows is partially wired

**Risk:** Column exists; only some write paths populate it.
Reconstructing "what changed" on most audit events requires reading
the source code or replaying the request log.
**Mitigation today:** action + resource type are present; full
metadata is missing.
**Closure:** Phase 2 of the audit-log improvement work in
[PROGRESS.md §6](PROGRESS.md).

### 8.6 No schema validation on `JSON` columns

**Risk:** `CertificationAuthorities.extensions`,
`CertificateTemplates.definition`, `CryptoProviders.extra_json`, and
`AuditLogs.metadata` are typed `JSON` but only enforced as
syntactically-valid JSON. Structural mismatches surface at runtime,
not at insert.
**Mitigation today:** application-level validation at the route
layer (for some columns; see §2.2 for the template gap).
**Closure:** add `CHECK (JSON_SCHEMA_VALID(...))` constraints (MySQL
8.0.17+, MariaDB 10.4.3+ where available) once schema-validation
support is consistent across target platforms.

### 8.7 Schema reset is destructive and unauthenticated at the SQL layer

**Risk:** `create_database()` issues `DROP DATABASE IF EXISTS` first.
Wired only behind `reset_pki.py` and the superadmin-only
`POST /api/tools/reset-pki`, but any direct SQL access to the DB user
also has DROP privileges.
**Mitigation today:** restrict the DB user to the configured schema
in deployment; the Docker stack does this.
**Closure:** documentation + a configurable safety flag the
application checks before calling `create_database()` on a non-empty
DB.

### 8.8 No row-level locking on serial generation

**Risk:** Serial numbers are generated randomly and uniqueness is
asserted by the `uq_ca_serial` unique constraint, with three retries
on collision. Under heavy concurrent issuance the probability of
collision is astronomically low at the default byte length but
non-zero.
**Mitigation today:** retry loop + monotonically improbable byte
length (10 bytes by default).
**Closure:** none planned — the math holds. Documented here for
auditor reference.

### 8.9 No partitioning / archival path for `Certificates`

**Risk:** `Certificates` grows monotonically. Single-tenant
deployments stay small (low-thousands); a high-volume EST endpoint
will hit OLTP latency floors after ~10⁷ rows.
**Mitigation today:** acceptable for the current scale.
**Closure:** if pyPKI ever serves an EST volume that warrants it,
add range partitioning on `not_after` or an archive table for
`Expired` rows.

---

## 9. Order of work

The pending items in §2.2 / §8 group into three phases.

**Phase A — Audit and retention**
1. Fully wire `AuditLogs.metadata` on every write path (§8.5).
2. CRL retention configuration + pruner (§8.3).
3. Audit-log retention configuration + archive-and-prune
   integration (§8.4).

**Phase B — Schema tightening**
4. Functional uniqueness constraints (§8.1).
5. JSON-schema check constraints on the four JSON columns
   (§8.6).
6. Drop legacy private-key columns once all installs are confirmed
   migrated (§8.2).

**Phase C — Hierarchy and modelling**
7. `CertificationAuthorities.parent_ca_id` + dedicated
   `is_self_signed BOOLEAN` for CAs (§2.2,
   [ca-management-specs.md §2.2](ca-management-specs.md)).

Phase A delivers operator-visible value with no schema risk. Phase B
tightens invariants once Phase A has populated the audit metadata
needed to verify the tightening. Phase C extends the model.

---

## 10. Acceptance criteria

The schema is **correct** when:

- A fresh install (`reset_pki.py`) produces the schema in §4 with the
  foreign keys in §5.
- An install from any prior shipped version reaches the modern schema
  by running `migrate_schema()` on boot (and, for installs predating
  in-process migration, the one-shot scripts in §6.3).
- Every functional invariant has either a schema constraint or a
  documented enforcement path in the spec it backs.
- Every JSON column has a documented grammar in its owning spec.

A **stable platform** has, in addition:

- Retention controls for `AuditLogs` and `CertificateRevocationLists`.
- `AuditLogs.metadata` populated for every write event.
- Functional uniqueness enforced at the schema level.
- A documented backup procedure that includes the KEK source.

---

## 11. Out of scope for this spec

- Functional behaviour of each table's owning surface — see the
  per-domain specs ([ca-management-specs.md](ca-management-specs.md),
  [certificate-management-specs.md](certificate-management-specs.md),
  [certificate-template-specs.md](certificate-template-specs.md),
  [kms-specs.md](kms-specs.md),
  [hsm-support-specs.md](hsm-support-specs.md)).
- Cryptographic key handling and KEK derivation — see
  [kms-specs.md §6–7](kms-specs.md).
- The REST API surface that drives writes — see the per-domain specs
  and [rest-api.md](rest-api.md).
- Cross-database portability. The schema targets MariaDB / MySQL
  only; PostgreSQL / SQLite are not supported.

---

## 12. Cross-references

- [ca-management-specs.md](ca-management-specs.md) — the
  `CertificationAuthorities` table's owner spec.
- [certificate-management-specs.md](certificate-management-specs.md) —
  the `Certificates` and `CertificateRevocationLists` tables' owner
  spec.
- [certificate-template-specs.md](certificate-template-specs.md) —
  the `CertificateTemplates` table's owner spec, including the
  template JSON grammar.
- [est-specs.md](est-specs.md) — the `ESTAliases` table's owner spec,
  including the RFC 7030 surface and the planned mTLS auth CR.
- [kms-specs.md](kms-specs.md) — the `CryptoProviders` and
  `KeyStorage` tables' owner spec.
- [hsm-support-specs.md](hsm-support-specs.md) — HSM-specific
  contracts that drive the `KeyStorage` HSM columns.
- [PROGRESS.md](PROGRESS.md) — current implementation status.
- [roadmap.md](roadmap.md) — strategic intent.
