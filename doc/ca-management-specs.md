# Certification Authority (CA) Management Specification

This is the consolidated specification for the Certification Authority
management surface in pyPKI. It is the single source of truth for the CA
design: lifecycle, data model, signing pipeline, issuance policy,
revocation / CRL distribution, REST API, management UI, audit logging,
and known weaknesses + security risks the operator should be aware of.

Status of each work item lives in [PROGRESS.md §4](PROGRESS.md); the
strategic intent and cross-area framing live in
[roadmap.md §4](roadmap.md). Cryptographic key handling that backs CA
signing operations is specified in [kms-specs.md](kms-specs.md);
HSM-specific contracts are in
[hsm-support-specs.md](hsm-support-specs.md). This document covers the
*CA layer* only — what sits between the issuance / revocation flows and
the KMS.

A developer reading only this document should have enough to understand
the current behaviour, identify the operator-visible gaps, and plan the
remaining work.

---

## 1. Goals

1. **CA records as first-class entities.** Each CA is a `CertificationAuthorities`
   row carrying its certificate, optional issuer chain, issuance policy
   (max validity, serial-number length, extensions), CRL policy, and
   exactly one signing key reference.
2. **Signing keys live in the KMS, not in the CA row.** The CA does not
   hold key material. Signing always goes through
   `KeyManagementService.sign_digest(key_id, digest)`. The CA merely
   identifies which key id to use.
3. **Multiple CA-creation paths** — PEM import, PKCS#12 import, and
   binding to an existing KMS key. Each path arrives at the same CA
   record shape, with a `key_owned` flag distinguishing CAs that own
   their key (cascade-delete on CA deletion) from CAs bound to a
   pre-existing key (key preserved on CA deletion).
4. **Idempotent CA edits.** `name`, `max_validity`, `serial_number_length`,
   `crl_validity`, and `extensions` are mutable; the certificate, key
   binding, and SKI are immutable after creation.
5. **Safe cascade on deletion.** Dependent OCSP responders, EST aliases,
   and CRLs are deleted; issued certificates are *unlinked* (ca_id set
   to NULL) rather than deleted, preserving the issuance audit trail.
6. **Per-CA CRL generation and distribution** with a per-CA validity
   window.
7. **Operator-visible signing path that never touches plaintext keys**
   in normal operation. Software keys are encrypted at rest under per-
   provider KEKs (see [kms-specs.md §6–7](kms-specs.md)); HSM keys
   never leave the token.

---

## 2. Status

### 2.1 What is in place

**CA record and storage**
- `CertificationAuthorities` table with `name`, `description`,
  `contact_email`, `certificate` (PEM), `public_key`, `ski` (hex),
  `private_key_reference` (FK → `KeyStorage.id`), `key_owned`,
  `certificate_chain` (PEM), `max_validity` (days, `-1` = unlimited),
  `serial_number_length` (bytes), `crl_validity` (days),
  `extensions` (JSON), `is_default`, `created_at`, `updated_at`.
- `private_key_reference` always references a `KeyStorage` row (never
  inline key material). Software keys are stored AES-256-GCM-encrypted
  under the per-provider KEK from
  [kms-specs.md §6–7](kms-specs.md); HSM keys are referenced by their
  `hsm_token_id`.
- SKI is extracted from the certificate's `SubjectKeyIdentifier`
  extension when present; falls back to RFC 5280 §4.2.1.2 Method 1
  (SHA-1 of the BIT STRING value of `SubjectPublicKeyInfo`).

**CA creation paths**
- **PEM upload** (`POST /api/ca`): operator pastes / uploads the CA
  certificate PEM and the private-key PEM. The key is encrypted under
  the default software provider's KEK and inserted as a new
  `KeyStorage` row; the CA row is inserted with `key_owned=TRUE`.
- **PKCS#12 upload** (`POST /api/ca` with `pkcs12_b64` +
  `pkcs12_password`): the route decodes the PKCS#12, extracts the cert
  / private key / additional certs, then proceeds as the PEM path. The
  PKCS#12 chain certificates are concatenated into `certificate_chain`.
- **Bind to existing KMS key** (`POST /api/ca` with `kms_key_id`): the
  CA row is inserted with `key_owned=FALSE` and the existing
  `KeyStorage.id` referenced. Validation enforces (a) the key id
  exists, (b) the certificate's SPKI matches the KMS key's stored
  `public_key`, (c) the key is not already referenced by another CA.
  See [api_adapters.py:130–178](../web/services/api_adapters.py#L130-L178).

**CA edit and deletion**
- `PUT /api/ca/{id}` updates `name`, `max_validity`,
  `serial_number_length`, `crl_validity`, `extensions`. All other
  fields are immutable.
- `DELETE /api/ca/{id}` runs a single transaction with a fixed cascade
  order — OCSPResponders, ESTAliases, CertificateRevocationLists for
  this CA are deleted; Certificates have `ca_id` set to NULL; the CA
  row is deleted; the bound KeyStorage row is deleted only when
  `key_owned=TRUE`. Returns counts per affected table. See
  [db.py:801–872](../pypki/db.py#L801-L872).

**Signing pipeline**
- `CertificationAuthority.sign_tbs_digest(digest)` delegates to
  `KeyManagementService.sign_digest(kms_key_id, digest)`. The CA holds
  no key material. A legacy "local key" fallback exists for
  utility-script offline use; web-path code never exercises it.
- The DER-patching flow (build with a dummy key → extract TBS → sign
  via KMS → splice signature) hides the software-vs-HSM branch from
  callers. Same shape for X.509 issuance and OCSP responder signing.

**Issuance policy and self-signed**
- `max_validity`, `serial_number_length`, and `extensions` drive
  per-CA issuance behaviour. Templates layered on top control
  per-certificate fields (subject, SAN, EKU, etc., specified in
  [certificate-templates.md](certificate-templates.md)).
- Self-signed certificates without a managed CA are supported via the
  sentinel `ca_id ∈ {null, 0}` on the issuance routes. The cert is
  recorded with `ca_id = NULL` and `is_self_signed = TRUE`. See
  [PROGRESS.md §8](PROGRESS.md).

**CRL generation and distribution**
- `POST /api/ca/{id}/crl` generates a fresh CRL for the CA, writes a
  row to `CertificateRevocationLists` with `issue_date` and
  `next_update`, and returns those timestamps.
- `GET /api/ca/{id}/crl` returns the latest CRL in PEM,
  `GET /api/ca/{id}/crl/der` returns DER.
- A background scheduler (`web/services/__init__.py:services_task`)
  re-issues CRLs every `CRL_PUBLICATION_FREQ` seconds (default 600)
  and writes the DER and PEM forms to `out/crl/`.
- The CRL covers all certificates with `Certificates.ca_id = {ca_id}`
  whose status is `Revoked`.

**Read endpoints**
- `GET /api/ca` — list all CAs (id, name, max_validity, crl_validity,
  serial_number_length).
- `GET /api/ca/{id}` — single CA record.
- `GET /api/ca/{id}/full` — single CA enriched with parsed cert
  fields (subject DN, issuer DN, not_before, not_after, cert_serial)
  and latest CRL info.
- `GET /api/ca/{id}/cert` — CA certificate as PEM download.
- `GET /api/ca/{id}/cert/der` — CA certificate as DER download.

**Audit logging**
- `CREATE`, `UPDATE`, and `DELETE` events on `CertificationAuthorities`
  are written to `AuditLogs` with the acting user id.

**Validation at insert / bind time**
- Name is required and non-empty.
- Certificate PEM is required.
- Exactly one of `private_key` or `kms_key_id` is required (mutually
  exclusive).
- KMS-key binding: SPKI match, uniqueness, presence checks (above).

### 2.2 What is pending

**Operator-visible gaps**
- **In-app CA generation.** Today the operator must bring their own
  certificate + key (PEM, PKCS#12, or pre-generated KMS key + cert).
  There is no "Generate Root CA", "Generate Intermediate CA", or
  "Generate CSR for external issuer" wizard that creates a new key
  in the KMS, builds (or requests) the CA certificate, and persists
  the CA row in one flow. Three sub-cases must be covered: self-
  signed root, subordinate signed by an internal CA in this platform,
  and subordinate signed by an external CA via a two-phase
  CSR / install-cert exchange. Designed in [§17.1 CR-0001](#171-cr-0001--in-app-ca-generation).
- **UI for KMS-key-bound CA creation.** The API accepts `kms_key_id`,
  the UI does not surface it. UI offers PEM and PKCS#12 modes only
  (see [ca_add.html](../web/templates/ca_add.html)).
- **Hierarchical CA modelling.** No `parent_ca_id` FK; the certificate
  chain is opaque PEM. Walking a hierarchy programmatically is not
  possible — issued chains rely on the operator pasting the right
  PEM at CA-creation time.
- **CA renewal / rekey workflow.** No flow to roll a CA over to a new
  key + cert while preserving issuance history. Today the only
  off-ramp is delete + recreate.
- **CA decommission state.** No "retired but reachable for revocation
  status / CRL distribution" state. A retired CA must either keep
  serving issuance (wrong) or be deleted (loses CRL hosting).
- **Cross-signing / cross-certification.** Not modelled.

**Validation and integrity gaps**
- **Public-key ↔ certificate match on the PEM upload path.** The
  KMS-key path verifies SPKI match; the PEM upload path does *not*
  check that the supplied private key actually corresponds to the
  certificate's public key. First sign produces an invalid signature.
- **PKCS#12 path public-key match check.** Same gap; relies on the
  PKCS#12 format usually pairing material correctly.
- **Certificate chain validation.** Pasted `certificate_chain` PEM is
  stored verbatim with no check that it actually chains the CA's
  issuer to a self-signed root.
- **Issuer field cross-check.** The certificate's `issuer` DN is not
  cross-checked against any chain entry's `subject`.
- **Self-signed CA flag.** No `is_self_signed` column on
  `CertificationAuthorities` (only on `Certificates`). A root CA is
  inferred from `subject == issuer` at read time, never persisted.
- **`extensions` JSON validation on update.** `update_ca` accepts any
  JSON blob; an invalid extensions schema breaks the next issuance
  silently.
- **`is_default` flag uniqueness.** No DB constraint or write-time
  check that exactly one CA holds `is_default=TRUE`. The
  `default_ca_id` in `config.json` is also not validated against the
  current set of CA ids at startup.

**Lifecycle and auditing gaps**
- **CA expiry awareness.** `not_after` is parsed on demand by the
  read endpoints, never stored as a column, and not surfaced as a
  proactive alert anywhere. There is no scheduled job that warns
  about CAs nearing expiry.
- **CRL generation audit event.** CRL generation is not audit-logged;
  the only trail is the row in `CertificateRevocationLists`.
- **Chain modification audit.** `update_ca` does not allow chain
  edits today (chain is immutable post-create); when chain editing is
  added it must produce an audit event.
- **Deletion preview / confirmation.** `DELETE /api/ca/{id}`
  unconditionally cascades. There is no "you are about to orphan N
  certificates and delete M OCSP responders, M EST aliases, K CRLs"
  preview surfaced to the operator before the destructive action.

**CRL gaps**
- **CRL profile control.** Only `crl_validity` (days) is operator-
  configurable. `CRLNumber` is implicit, no Issuing Distribution
  Point extension, no delta CRL support, no Reason Codes filtering.
- **CRL distribution endpoint.** CRLs are downloadable via
  `GET /api/ca/{id}/crl[/der]` and dumped to `out/crl/`. There is no
  deterministic CDP URL that issued certificates can carry — the
  operator must wire a CDP into the cert at issue time and ensure
  the URL points at the right `/api/ca/{id}/crl/der` (or a separate
  reverse-proxied path).

---

## 3. Architecture

### 3.1 Layered model

```
   web routes / EST / OCSP
              │
              ▼
     PyPKI facade (core.py)             ← resolves CA + template, runs issuance
              │
   ┌──────────┴────────────┐
   ▼                       ▼
CertificationAuthority    CertificateTools
(record + chain +           (template-driven cert builder;
 sign_tbs_digest)            uses CA's sign_tbs_digest)
              │
              ▼
     KeyManagementService            ← single signing entry point
              │
              ▼
   software / pkcs11 backend         ← see kms-specs.md §5
```

- Web routes and EST / OCSP handlers never touch the CA's key
  material. They call into `PyPKI.generate_certificate*` or
  equivalent, which resolves the CA record, builds a
  `CertificationAuthority` instance, and runs the certificate
  generation through `CertificateTools`.
- `CertificationAuthority.sign_tbs_digest` delegates to the KMS,
  which dispatches to the matching backend.
- `CertificationAuthority` is reconstructed per request from the DB
  row; there is no long-lived in-memory CA cache (the previous cache
  was removed because it created cross-worker staleness — see git
  history).

### 3.2 Two design decisions, recorded

**Decision A — CA stores no key material, only a key reference.** A
CA row carries `private_key_reference` pointing at `KeyStorage.id`,
not the PEM. Two consequences:

- A CA cannot exist without a corresponding `KeyStorage` row
  (`private_key_reference` may be NULL only for transitional /
  legacy rows).
- Migrating a software CA to a real HSM is a key-level operation:
  generate the new key on the HSM, re-issue / rebind the CA cert,
  point `private_key_reference` at the new `KeyStorage.id`. The CA
  row's `name`, audit history, and CRL chain are preserved.

**Decision B — `key_owned` controls cascade-on-delete.** When a CA
is created with the PEM / PKCS#12 path, the key was created together
with the CA — `key_owned = TRUE`, deletion cascades to the key. When
a CA is bound to a pre-existing KMS key, `key_owned = FALSE` —
deletion removes only the CA row, the key persists for other uses.

This is the same model that CryptoProviders use for "owned vs
imported" key objects (see
[kms-specs.md §9.2](kms-specs.md#92-key-management-apikmskeys)) and
is the load-bearing reason CAs and KMS keys are separate tables in
the first place.

---

## 4. Data model

### 4.1 `CertificationAuthorities`

| Column | Type | Notes |
|---|---|---|
| `id` | INT PK AI | |
| `name` | VARCHAR(255) NOT NULL | Operator-facing label. Should be unique but not enforced at the schema level today. |
| `state` | ENUM('active','pending-issuance') NOT NULL DEFAULT 'active' | Row lifecycle state per §5. `'pending-issuance'` rows have `certificate` / `ski` NULL and a CSR in `pending_csr`; they cannot sign. |
| `description` | TEXT | |
| `contact_email` | VARCHAR(255) | |
| `certificate` | TEXT | CA certificate PEM. NULL while `state='pending-issuance'`. |
| `public_key` | TEXT | Currently unpopulated by the insert path; the public key is parseable from `certificate`. Reserved for caching. |
| `ski` | VARCHAR(64) | Hex SubjectKeyIdentifier; computed at insert time from the certificate's SKI extension or RFC 5280 §4.2.1.2 Method 1. NULL while `state='pending-issuance'`. |
| `private_key` | TEXT | **Legacy.** Pre-Phase-1 inline software-key PEM. Modern rows leave this NULL and reference `KeyStorage` via `private_key_reference`. |
| `private_key_reference` | INT FK → `KeyStorage(id)` | The KMS key id this CA signs with. |
| `key_owned` | BOOLEAN NOT NULL DEFAULT TRUE | TRUE: key created with CA, deleted on CA delete. FALSE: key pre-existed (KMS-key-bound CA), preserved on CA delete. |
| `certificate_chain` | TEXT | Concatenated PEM of issuer certificates. Stored verbatim; not validated. |
| `pending_csr` | TEXT | PEM-encoded PKCS#10 emitted by phase 1 of the external-subordinate flow; NULL otherwise. Cleared back to NULL by `install-cert`. |
| `max_validity` | INT | Days. `-1` = unlimited (issuance uses GeneralizedTime far-future). |
| `serial_number_length` | INT | Bytes. Drives the random serial generator. |
| `crl_validity` | INT DEFAULT 365 | Days. Sets `nextUpdate` on generated CRLs. |
| `extensions` | JSON NOT NULL | Per-CA issuance defaults; templates override per-certificate. |
| `is_default` | BOOLEAN DEFAULT FALSE | Marker for the system default CA. Not enforced unique. |
| `created_at` / `updated_at` | TIMESTAMP | Auto-managed. |

### 4.2 Foreign-key relationships

- `CertificationAuthorities.private_key_reference` → `KeyStorage(id)`,
  enforced by `fk_cert_authority_private_key_reference`.
- `Certificates.ca_id` → `CertificationAuthorities(id)`. Nullable
  (set to NULL by `delete_ca`).
- `OCSPResponders.ca_id` → `CertificationAuthorities(id)`. Cascade-
  deleted on CA delete.
- `ESTAliases.ca_id` → `CertificationAuthorities(id)`. Cascade-
  deleted on CA delete.
- `CertificateRevocationLists.ca_id` → `CertificationAuthorities(id)`.
  Cascade-deleted on CA delete.

### 4.3 Migrations

- Phase 1 — `private_key_reference` column added; legacy `private_key`
  column kept for back-compat but new inserts leave it NULL.
- Phase 0.1 — `KeyStorage.provider_id` and `CryptoProviders` table
  introduced; CA-bound keys re-encrypted under per-provider KEK by the
  Phase 0.2 migration.
- Recent — `key_owned` column added (idempotent migration in
  [db.py:2341–2356](../pypki/db.py#L2341-L2356)).
- Recent — `state` ENUM and `pending_csr` TEXT columns added
  for in-app CA generation (CR-0001); idempotent migrations
  alongside the `key_owned` block in
  [db.py migrate_schema](../pypki/db.py).
- Pending — `parent_ca_id` FK + `is_self_signed BOOLEAN` for
  hierarchy modelling (see §2.2).

---

## 5. CA lifecycle

A CA has the following states:

| State | Meaning | Transition |
|---|---|---|
| **non-existent** | No row in `CertificationAuthorities`. | `POST /api/ca` → **active**. |
| **active** | Row present, `private_key_reference` resolves to an active KeyStorage row whose provider is active. CA can sign. | `PUT /api/ca/{id}` (edit policy) keeps state. |
| **pending-issuance** | Row present with a generated key bound, CSR stored, `certificate` NULL. CA cannot sign and is invisible to the issuance / CRL pipelines. Used while an external issuer signs the CA cert offline. | `POST /api/ca/{id}/install-cert` (signed cert arrives) → **active**. `DELETE /api/ca/{id}` (operator abandons) → **deleted** (key cascades because `key_owned=TRUE`). Designed in [§17.1 CR-0001](#171-cr-0001--in-app-ca-generation). |
| **key-inactive** | CA row present, but the bound KMS key's provider is deactivated (KEK or PIN unavailable). Reads succeed, signing returns "provider inactive" cleanly. | Provider `POST /activate` returns to **active**. |
| **deleted** | Row removed; OCSP responders / EST aliases / CRLs cascade-deleted; certificates unlinked. | Terminal. |

Transitions not yet modelled (§2.2): **retired** (no new issuance, CRL
distribution continues), **renewing** (rekey in progress, both old and
new keys may be live for a transition window).

---

## 6. CA creation paths

Three paths arrive at the same CA row shape. The data validation
contract is uniform; only the *source* of the cert + key differs.

### 6.1 PEM upload

```json
POST /api/ca
{
  "name": "Acme Root CA",
  "certificate":     "-----BEGIN CERTIFICATE-----\n...",
  "private_key":     "-----BEGIN PRIVATE KEY-----\n...",
  "certificate_chain": "-----BEGIN CERTIFICATE-----\n...",   // optional
  "max_validity":    825,
  "serial_number_length": 16,
  "crl_validity":    7,
  "extensions":      { ... }
}
```

The key is encrypted under the default software provider's KEK and
written as a new `KeyStorage` row. CA is inserted with
`key_owned=TRUE`.

### 6.2 PKCS#12 upload

```json
POST /api/ca
{
  "name": "...",
  "pkcs12_b64":     "<base64-encoded .p12>",
  "pkcs12_password": "...",
  "certificate_chain": "...",   // optional, appended to PKCS#12 chain
  ...policy fields...
}
```

The route extracts cert / private key / additional certs from the
PKCS#12; subsequent processing is identical to §6.1.

### 6.3 Bind to existing KMS key

```json
POST /api/ca
{
  "name": "...",
  "certificate": "-----BEGIN CERTIFICATE-----\n...",
  "kms_key_id":  42,
  "certificate_chain": "...",   // optional
  ...policy fields...
}
```

Validation runs in
[api_adapters.py:_verify_kms_key_for_ca](../web/services/api_adapters.py#L130):
the key id exists, the certificate's SPKI matches the KMS key's
stored public key, and the key is not already bound to another CA.
CA is inserted with `key_owned=FALSE`.

### 6.4 In-app keygen + issuance (pending)

Three sub-modes, all generating the new signing key inside the KMS
so the private key never transits the management API:

- **root** — new key self-signs the CA certificate; single
  transactional flow.
- **internal-subordinate** — new key's CSR is signed by an existing
  CA in this platform; single transactional flow.
- **external-subordinate** — two-phase flow. Phase 1 generates the
  key and emits a CSR; the CA row is inserted in `pending-issuance`
  state (§5). Phase 2 accepts the issuer-signed certificate when
  it returns from the external CA, validates it against the bound
  key, and transitions the row to `active`.

Design under negotiation in §17.1 (CR-0001). Once accepted and
shipped, the canonical request shape and server flow fold into this
subsection.

---

## 7. Signing pipeline

Every CA signing operation flows through:

```
issuance / OCSP / CRL code
       │
       ▼
CertificationAuthority.sign_tbs_digest(digest)
       │
       ▼
KMS.sign_digest(kms_key_id, digest)
       │
       ▼
matching backend (software | pkcs11)
       │
       ▼
returns signature bytes
```

The CA does not implement signing. It owns the digest input contract
(SHA-256 over the TBS bytes) and the key id; the KMS owns the
mechanism, padding, and DER-wrap (RSA → `CKM_SHA256_RSA_PKCS`,
ECDSA → `CKM_ECDSA` + `encode_dss_signature`, see
[hsm-support-specs.md §2](hsm-support-specs.md#2-signing-mechanisms)).

The DER-patching layer in `CertificateTools` runs the actual
construction: build the certificate / OCSP response / CRL with a
dummy signature, extract the TBS, sign via KMS, splice the signature
back in. This keeps the software-vs-HSM branch hidden from CA code.

---

## 8. Issuance policy

CA-level issuance policy controls (per the row in
`CertificationAuthorities`):

- **`max_validity` (days, `-1` = unlimited).** Hard upper bound on the
  validity of any certificate this CA issues. The template's
  `validity_days` is capped against this. `-1` is the "no cap"
  sentinel — the issuance code emits a GeneralizedTime far-future
  `notAfter`.
- **`serial_number_length` (bytes, default 10).** Drives
  `secrets.token_bytes(n)` for the random serial. 10 bytes is the
  conservative middle ground (RFC 5280 §4.1.2.2 says ≤ 20 octets).
- **`crl_validity` (days, default 365).** Sets `nextUpdate` on
  generated CRLs.
- **`extensions` (JSON).** Per-CA defaults that template `extensions`
  layer on top of. Schema defined in
  [certificate-templates.md](certificate-templates.md).

Per-certificate issuance is template-driven; the template carries
subject / SAN / EKU / KU / AIA / CDP. See
[certificate-templates.md](certificate-templates.md).

---

## 9. Revocation and CRL

### 9.1 Per-certificate revocation

Revocation flips `Certificates.status` to `'Revoked'` and stores
`revoked_at` and `revocation_reason` (RFC 5280 reason codes). The
mutation is exposed via `POST /api/certificate/revoke/{cert_id}`.

### 9.2 CRL generation

`POST /api/ca/{id}/crl` rebuilds the CRL for that CA: enumerates
revoked certificates, builds a `CertificateRevocationList` with
`thisUpdate = now`, `nextUpdate = now + crl_validity` days, signs
through the CA's KMS key, and persists the CRL bytes plus timestamps
to `CertificateRevocationLists`.

A background `BackgroundScheduler` job
([web/services/__init__.py:services_task](../web/services/__init__.py#L82))
re-issues CRLs every `CRL_PUBLICATION_FREQ` seconds (default 600).
Per-CA failures are logged but do not abort the pass.

### 9.3 Distribution

- `GET /api/ca/{id}/crl` — PEM-encoded latest CRL.
- `GET /api/ca/{id}/crl/der` — DER-encoded latest CRL.
- `out/crl/` — DER + PEM dumps written by the scheduler. Filename is
  `{ca_name_with_underscores}.crl` / `.pem.crl`.

There is no canonical CDP URL the project commits to. Operators must
wire the CDP extension into the certificate template explicitly.

---

## 10. REST API specification

```
POST   /api/ca                                  create  (PEM / PKCS#12 / kms_key_id paths)
GET    /api/ca                                  list    (id, name, policy fields)
GET    /api/ca/{id}                             read
GET    /api/ca/{id}/full                        read enriched (parsed cert fields + latest CRL)
PUT    /api/ca/{id}                             update  (name, policy fields)
DELETE /api/ca/{id}                             delete  (cascade per §5)

GET    /api/ca/{id}/cert                        download CA cert PEM
GET    /api/ca/{id}/cert/der                    download CA cert DER

POST   /api/ca/{id}/crl                         (re)issue CRL
GET    /api/ca/{id}/crl                         download latest CRL PEM
GET    /api/ca/{id}/crl/der                     download latest CRL DER
GET    /ca/crl/{ca_id}                          unauthenticated public CRL fetch (DER)
```

Role enforcement:
- `POST`, `PUT`, `DELETE` require `superadmin` or `admin`.
- `GET` requires authenticated session (any role).
- The unauthenticated `/ca/crl/{ca_id}` route is an explicit
  public-access surface for CRL distribution.

---

## 11. Management UI

CA management lives under `/cas_and_crls.html` plus three sub-pages:

- **CAs & CRL** — list view with download links for cert and CRL,
  plus per-CA "Issue CRL" / "Edit" / "Delete" actions.
- **Add CA** ([ca_add.html](../web/templates/ca_add.html)) — PEM and
  PKCS#12 upload modes. KMS-key-bound creation is not surfaced.
- **CA Details** — read-enriched view (subject, issuer, serial,
  validity, latest CRL info, chain).
- **Edit CA** — edits the mutable subset.

Pending UI work matching §2.2:
- "Generate CA" wizard (in-app keygen + self-issue / parent-signed).
- KMS-key-bound creation mode in Add CA.
- Deletion preview ("you are about to orphan N certs, delete M
  responders, …").
- CA-expiry banner on the dashboard.

---

## 12. Audit logging

Every successful `CREATE`, `UPDATE`, and `DELETE` on
`CertificationAuthorities` produces an `AuditLogs` row referencing
`resource_type='cas'`, the CA id, and the acting user id.

Pending (per §2.2):
- `CRL_ISSUE` event when a CRL is regenerated.
- `CHAIN_UPDATE` event when chain editing lands.
- `KEY_REKEY` event when CA renewal / rekey lands.

---

## 13. Weaknesses and security risks

This section is the **operator-visible audit** of known issues. Each
item is either accepted (with mitigation) or scheduled for closure.

### 13.1 Plaintext private-key transit at CA creation

**Risk:** PEM upload and PKCS#12 upload paths POST private key
material in cleartext through the management API. KEK-encrypted at
rest after insert; in transit it is plaintext to Flask.
**Mitigation today:** the management API must be deployed behind
TLS. The Docker default does not terminate TLS — operators are
expected to put a reverse proxy in front. README does not currently
make this requirement explicit; see [roadmap.md §5](roadmap.md).
**Closure path:** TLS-required guardrail (config flag rejecting
plaintext binds), plus shifting to the in-app keygen flow (§6.4)
where the key never leaves the server.

### 13.2 No private-key ↔ certificate match check on PEM/PKCS#12 upload

**Risk:** The PEM and PKCS#12 paths do not verify that the supplied
private key actually corresponds to the supplied certificate's
public key. A mismatched pair is accepted; the first sign produces
an invalid signature.
**Mitigation today:** operator discipline.
**Closure:** add a SPKI match check parallel to the
`_verify_kms_key_for_ca` check. Cheap (load both, compare DER
SubjectPublicKeyInfo bytes).

### 13.3 Duplicate-key uploads

**Risk:** Uploading the same private-key PEM twice creates two CA
rows referencing two distinct (encrypted) `KeyStorage` rows. Only
the KMS-key-bound path detects re-binding (via
`get_ca_id_by_key_reference`).
**Mitigation today:** none.
**Closure:** hash the PEM at insert and reject duplicates, or store a
`spki_fingerprint` column on `KeyStorage` and reject inserts whose
fingerprint already exists.

### 13.4 Opaque `certificate_chain`

**Risk:** Pasted chain PEM is stored verbatim with no validation that
it actually chains the CA's issuer to a self-signed root. Certs
issued by this CA may be rejected by relying parties when the
embedded chain is broken.
**Mitigation today:** none.
**Closure:** parse each chain certificate at insert / update; verify
that the CA cert's `issuer` DN matches the first chain entry's
`subject` DN, and each subsequent link chains; reject otherwise.

### 13.5 `max_validity = -1` footgun

**Risk:** The "unlimited" sentinel allows issuing certificates with
GeneralizedTime far-future `notAfter`. Operationally fine for
self-signed dev certs; a real-PKI footgun.
**Mitigation today:** documented in the UI ("-1 = unlimited").
**Closure:** require operator-acknowledgement when setting
`max_validity = -1` (UI confirmation modal); add a deployment-level
config flag that disables the sentinel altogether.

### 13.6 `is_default` not enforced unique

**Risk:** Multiple CAs can hold `is_default=TRUE`. The
`config.json:default_ca_id` is also not validated against existing
CA ids at startup.
**Mitigation today:** operator discipline.
**Closure:** add a write-time guard ("setting `is_default=TRUE` on
this CA clears the flag on all others") and a startup validation
warning when `default_ca_id` does not resolve.

### 13.7 `extensions` JSON not validated on update

**Risk:** `update_ca` accepts any JSON blob in `extensions`; an
invalid schema persists silently and breaks the next issuance.
**Mitigation today:** none.
**Closure:** parse-and-validate the extensions JSON against the
schema documented in
[certificate-templates.md](certificate-templates.md) on every
write.

### 13.8 Deletion silently orphans certificates

**Risk:** `delete_ca` sets `ca_id = NULL` on every issued cert. The
issued certificates remain trusted by relying parties holding them
but become unverifiable from this DB (no issuer linkage, no CRL
hosting after the cascade).
**Mitigation today:** the cascade returns counts in the API
response; the UI surfaces them in a toast.
**Closure:** require an explicit "I have N un-revoked active
certificates issued by this CA, proceed anyway" confirmation, and
expose a "retire CA" alternative that preserves the row in a
non-issuing state with continued CRL hosting (§5 retired state).

### 13.9 CRL-related observability gaps

**Risk:** CRL generation does not produce an audit event; a stalled
scheduler is invisible until a relying party complains. CRL freshness
is not surfaced on the dashboard.
**Mitigation today:** scheduler logs to stdout / `out/app.log`.
**Closure:** add `CRL_ISSUE` audit event + dashboard widget showing
per-CA CRL `nextUpdate` countdown.

### 13.10 Orphan `pending-issuance` CAs (CR-0001)

**Risk:** An operator starts the external-subordinate flow
(§17.1 CR-0001 phase 1), receives a CSR, but never returns with a
signed certificate (issuer rejects, operator changes plan, request
forgotten). The CA row sits in `pending-issuance` forever; the
generated KMS key occupies provider capacity (HSM slot budget,
software KeyStorage rows) and is never signed for.
**Mitigation today:** the row is visible in the CA list with a
muted `pending-issuance` badge, and `DELETE /api/ca/{id}` cleanly
removes both the row and the key (because `key_owned = TRUE`).
**Closure:** stale-pending badge in the UI for rows older than 30
days; optional operator-configurable auto-cancel after N days
(§17.1 open question 8 must resolve before this lands).

### 13.11 No CA-expiry alerting

**Risk:** A CA approaching its own `notAfter` will silently stop
issuing valid certificates (or, worse, issue certs with `notAfter >`
CA's `notAfter`). There is no proactive alert.
**Mitigation today:** the CA Details page shows the CA cert's
validity window.
**Closure:** scheduled job that warns when any CA is within a
configurable window of expiry; per-issuance check that the requested
`notAfter` does not exceed the CA's.

---

## 14. Order of work

Work items grouped by phase. Each phase is independently shippable.

**Phase 1 — Validation and integrity hardening.**
- Pubkey ↔ cert match on PEM / PKCS#12 paths (§13.2).
- Duplicate-key detection (§13.3).
- Chain validation at insert / update (§13.4).
- `extensions` JSON validation on update (§13.7).
- `is_default` uniqueness guard (§13.6).

**Phase 2 — In-app CA generation.**
- "Generate Root CA" wizard: pick provider → generate key → build
  self-signed CA cert → persist CA row in one transactional flow.
- "Generate Intermediate CA" wizard (internal-subordinate): pick
  provider → generate key → pick parent CA → build TBS →
  parent-sign → persist CA row + chain.
- "Generate CA for external issuer" wizard
  (external-subordinate, two-phase): pick provider → generate key →
  emit CSR → persist CA row in `pending-issuance` state. Phase 2:
  operator returns with the issuer-signed certificate → validate
  SPKI match → fill in cert + chain → transition CA to `active`.
- KMS-key-bound mode in the Add CA UI for operators who pre-generate
  keys.

**Phase 3 — Lifecycle: hierarchy and decommission.**
- `parent_ca_id` FK on `CertificationAuthorities`; `is_self_signed`
  column persisted at insert time.
- "Retired" CA state: row preserved, no new issuance, CRL distribution
  continues, OCSP responder continues.
- Deletion preview UI (§13.8).

**Phase 4 — CRL profile and distribution.**
- Issuing Distribution Point support, CRLNumber explicit, optional
  delta CRL.
- `CRL_ISSUE` audit event.
- CRL freshness widget on the dashboard.

**Phase 5 — CA renewal / rekey.**
- "Renew CA" workflow: generate new key → rebuild CA cert (extending
  validity) → persist new key reference, preserve audit history.
- "Rekey CA" workflow: same shape, but rebuilds the cert with a new
  SubjectKeyIdentifier — relying parties must re-establish trust.

**Phase 6 — Expiry awareness.**
- Scheduled per-CA expiry warning.
- Per-issuance check: requested `notAfter` ≤ CA `notAfter`.

---

## 15. Acceptance criteria

For CA management to be considered "feature-complete":

1. A fresh `reset_pki` install yields a configurable default CA
   created via the in-app wizard, no operator-supplied PEM required.
2. Every CA-creation path (PEM, PKCS#12, KMS-key-bound, in-app
   keygen) verifies pubkey ↔ cert match and rejects duplicate keys.
3. `certificate_chain` on every CA is parse-validated and the chain
   actually chains.
4. A CA can be moved from software to HSM and back via the rekey
   workflow without touching application code.
5. Deleting a CA with un-revoked active certificates requires
   explicit operator confirmation; the alternative is "retire CA"
   which preserves CRL hosting.
6. Every CA, key-rebind, CRL issuance, and chain edit produces an
   audit event.
7. The dashboard surfaces upcoming CA expiry and CRL staleness for
   every active CA.
8. The certificate-template-driven CDP extension references a
   deterministic CRL URL hosted by this PKI.

---

## 16. Out of scope for this spec

- **Cross-signing / cross-certification.** Modelled as a separate
  initiative; the data model leaves room (`certificate_chain` is
  free-form) but no concrete workflow is scoped here.
- **External CA proxying.** Acting as a registration authority on
  top of an externally-hosted CA (Sectigo, DigiCert, AWS PCA) is a
  separate product; not in scope.
- **CT log submission.** Not modelled; would be a new sibling to CRL
  distribution.
- **Hardware-attested CA roots.** No support for vendor attestation
  of the CA's signing key beyond what the KMS provider exposes.

---

## 17. Design proposals

This section holds in-progress designs for capabilities listed in
§2.2 that are large enough to reshape existing surface — typically a
new creation path, a new lifecycle state, or a workflow that touches
§5, §6, §11, and §12 together. Smaller hardening items (the §13 risk
list) skip this section and flow directly through the §13 → §14 →
§15 chain.

A proposal lives here only while the design is being negotiated.
Once accepted and shipped, its content is folded into the relevant
canonical sections (§5 for lifecycle, §6 for creation paths, §10
for API surface, §11 for UI, §12 for audit, etc.) and the proposal
entry is removed. The git history of this file carries the design
trail; PR descriptions carry the discussion.

Each proposal follows a fixed shape:

- **Status** — `Proposed`, `Accepted`, or `Implemented (folded into
  §X)`. An implemented proposal stays here only long enough for
  the fold-in commit to land.
- **Motivation** — what gap from §2.2 this closes, and why now.
- **Proposed behaviour** — request / response shapes, server flow,
  UI flow, error modes. Concrete enough to implement.
- **Impact on existing sections** — every section whose canonical
  content changes once this lands.
- **Open questions** — design decisions not yet made; each must be
  resolved before status moves to `Accepted`.
- **Acceptance criteria** — what "done" looks like for this
  proposal, in addition to the global criteria in §15.

Proposals are numbered `CR-NNNN` with zero-padded four-digit ids,
allocated in order of creation; numbers are never reused.

### 17.1 CR-0001 — In-app CA generation

**Status:** Accepted.

**Motivation:** §2.2 and §6.4 — every CA-creation path today
requires the operator to bring a pre-built certificate (PEM,
PKCS#12, or pre-generated KMS key + cert). There is no path that
produces a CA certificate in-app — either against a freshly
generated key or against an existing KMS key whose certificate
the operator does not yet have. This forces operators through
out-of-band tooling (`openssl req`, `step-ca`, etc.) and
re-introduces the §13.1 plaintext-transit risk that an in-app
flow would avoid by construction.

The flow is parameterised on two independent axes:

**Issuance scenario** — who signs the new CA certificate:

1. **Self-signed root.** The CA's own key signs its own
   certificate; one transaction.
2. **Subordinate signed by an internal CA.** An existing `active`
   CA in this platform signs the new CA certificate; one
   transaction.
3. **Subordinate signed by an external CA.** The signer lives
   outside this platform (offline / customer / partner PKI). The
   flow splits in two phases: phase 1 prepares the CA's key and
   emits a CSR for the operator to take to the external CA;
   phase 2 accepts the issuer-signed certificate when it returns
   and transitions the CA to `active`.

**Key source** — where the CA's signing key comes from:

- **Generate** — the platform creates a new key in the KMS as
  part of the transaction; the new CA row is `key_owned = TRUE`
  and the key is rolled back (deleted) if the transaction fails.
  Typical for soft-stored providers or when the operator
  delegates key custody to the platform.
- **Bind existing** — the operator selects a pre-existing
  `KeyStorage` row whose key was created out-of-band (HSM key
  ceremony, vendor CLI, pre-loaded slot). The new CA row is
  `key_owned = FALSE`; the key is never deleted by this flow
  (the platform did not create it). The selected key must be
  *unbound* — no `CertificationAuthorities` row may reference it.

All six (scenario × key-source) combinations are supported by the
same endpoint. The downstream signing pipeline is identical from
step 3 onward; only the initial key-resolution step differs.

**Proposed behaviour:**

Two endpoints. `POST /api/ca/generate` covers all three scenarios
in phase 1 (and is the only call needed for scenarios 1 and 2).
`POST /api/ca/{id}/install-cert` is phase 2, used only in
scenario 3 once the external issuer's signed certificate arrives.

#### Phase 1 — generate

```json
POST /api/ca/generate
{
  "mode":          "root",              // "root" | "internal-subordinate" | "external-subordinate"
  "name":          "Acme Root CA",
  "subject_dn":    "CN=Acme Root,O=Acme,C=CH",
  "validity_days": 7300,                // ignored for "external-subordinate"

  // ── key source: exactly one of the two blocks below ────────────────
  // (a) generate: create a fresh key in the KMS
  "provider_id":   3,                   // KMS provider, must be active
  "key_type":      "ECDSA-P-256",       // see kms-specs.md §9
  "key_label":     "acme-root-2026",    // optional; defaults to name
  // (b) bind existing: reuse a pre-existing KMS key
  "kms_key_id":    42,                  // KeyStorage.id; must be unbound; provider must be active
  // ───────────────────────────────────────────────────────────────────

  // internal-subordinate only:
  "parent_ca_id":  17,

  // standard policy fields (same as POST /api/ca):
  "max_validity":         825,
  "serial_number_length": 16,
  "crl_validity":         7,
  "extensions":           { ... },
  "certificate_chain":    "..."         // internal-subordinate only, optional override
}
```

The presence of `kms_key_id` discriminates: when set, all of
`provider_id`, `key_type`, and `key_label` must be absent and the
request is treated as bind-existing; otherwise `provider_id` and
`key_type` are required and the request is treated as
generate-fresh. Supplying both blocks (or neither) returns 400.

Server flow for `mode ∈ {"root", "internal-subordinate"}` — single
transaction with rollback hooks:

1. Validate inputs (including the key-source XOR above); for
   `internal-subordinate`, resolve `parent_ca_id` and confirm the
   parent is `active` per §5.
2. Resolve the signing key (`signing_key_id`, `key_owned_flag`):
   - **generate** (`provider_id + key_type` supplied):
     `KMS.generate_key(provider_id, key_type, key_label)` → new
     `KeyStorage.id`; `key_owned_flag = TRUE`; treat the returned
     id as the rollback handle.
   - **bind existing** (`kms_key_id` supplied): load the
     `KeyStorage` row, confirm its provider is `active`, confirm
     no `CertificationAuthorities` row references it (left-join
     exclusion, same predicate as `GET /api/kms/keys?unbound=true`
     — see below), confirm the key's algorithm is permitted for
     CA signing by the provider. `key_owned_flag = FALSE`; no
     rollback handle (the key pre-existed).
3. Build the to-be-signed certificate: subject = `subject_dn`,
   issuer = `subject_dn` (root) or parent's subject
   (internal-subordinate), validity = `now → now + validity_days`,
   SPKI read from `signing_key_id`, SKI computed per RFC 5280
   §4.2.1.2 Method 1.
4. Sign:
   - **root** — self-sign via `KMS.sign_digest(signing_key_id, ...)`.
   - **internal-subordinate** — parent-sign via the parent CA's
     `sign_tbs_digest` (§7 pipeline; uses the parent's KMS key).
5. Insert `CertificationAuthorities` row with `state = 'active'`,
   `private_key_reference = signing_key_id`,
   `key_owned = key_owned_flag`, chain = parent's `certificate ||
   parent's certificate_chain` (internal-subordinate) or empty
   (root).
6. Write `CREATE` audit event (§12) with a `generation_mode`
   metadata field distinguishing the (scenario × key-source)
   combination from the upload paths.
7. On any failure between steps 2 and 5: if `key_owned_flag = TRUE`,
   delete the just-generated KMS key (rollback); for
   `key_owned_flag = FALSE` the pre-existing key is left
   untouched. Abort the transaction, return the error.

Returns the new CA's full record (same shape as
`GET /api/ca/{id}/full`).

Server flow for `mode = "external-subordinate"` — single
transaction:

1. Validate inputs (including the key-source XOR). `parent_ca_id`
   and `validity_days` must be absent (the external issuer
   controls both; the operator's request to the external CA is
   the negotiation channel).
2. Resolve the signing key (`signing_key_id`, `key_owned_flag`)
   exactly as in step 2 of the root / internal-subordinate flow
   above — same generate vs. bind-existing branches, same
   unbound / provider-active checks, same rollback semantics.
3. Build a PKCS#10 CertificationRequest: subject = `subject_dn`,
   SPKI read from `signing_key_id`, no requested-extensions
   attribute. The CSR's job is to convey the public key (and
   prove possession via the self-signature); the external issuer
   chooses the resulting certificate's extensions per its own
   policy, and the CA's operational policy is held in the row's
   `extensions` field (used at issuance time, not in the CSR).
   Sign the CSR via `KMS.sign_digest(signing_key_id, ...)`.
4. Insert `CertificationAuthorities` row with
   `state = 'pending-issuance'`,
   `private_key_reference = signing_key_id`,
   `key_owned = key_owned_flag`, `pending_csr` = CSR PEM,
   `certificate` NULL, `certificate_chain` NULL, `ski` NULL
   (computed at install time).
5. Write `GENERATE_REQUEST` audit event with a `generation_mode`
   value reflecting the (scenario × key-source) combination
   (e.g. `generate-external-subordinate` or
   `bind-external-subordinate`).
6. On any failure between steps 2 and 4: if `key_owned_flag = TRUE`,
   delete the just-generated KMS key (rollback); otherwise leave
   the pre-existing key untouched. Abort the transaction, return
   the error.

Returns:

```json
{
  "ca_id":      42,
  "state":      "pending-issuance",
  "csr_pem":    "-----BEGIN CERTIFICATE REQUEST-----\n...",
  "key_label":  "acme-issuing-2026",
  "subject_dn": "CN=Acme Issuing,O=Acme,C=CH"
}
```

The operator takes `csr_pem` to the external CA. While the CSR is
out, the CA row exists but cannot sign (see §5 `pending-issuance`).
Issuance, CRL generation, and OCSP responders refuse to bind to a
`pending-issuance` CA with a typed error.

#### Phase 2 — install issuer-signed certificate

Used only for `external-subordinate` CAs.

```json
POST /api/ca/{id}/install-cert
{
  "certificate":       "-----BEGIN CERTIFICATE-----\n...",
  "certificate_chain": "-----BEGIN CERTIFICATE-----\n..."   // optional
}
```

Server flow — single transaction:

1. Load the CA. Reject with 409 unless
   `state = 'pending-issuance'`.
2. Parse the supplied certificate and validate:
   - The cert's SPKI matches the SPKI of the CA's bound KMS key
     (rejects an issuer who substituted a key — first sign would
     otherwise be invalid).
   - BasicConstraints `cA=TRUE` is asserted (rejects an issuer who
     accidentally issued an end-entity cert).
   - The cert's subject DN is **not** compared against the CSR's
     DN. External issuers routinely canonicalize DNs (RDN order,
     casing, attribute encoding); the issued certificate's DN is
     authoritative and becomes the CA's effective subject going
     forward.
3. Update the CA row: `certificate`, `certificate_chain`
   (operator-supplied chain only — issuer's parents are *not*
   inferred), `ski` (recomputed from the cert),
   `state = 'active'`, `pending_csr = NULL`.
4. Write `INSTALL_CERT` audit event.

Returns the CA's full record.

A `pending-issuance` CA can also be cancelled by
`DELETE /api/ca/{id}`: the existing cascade-delete runs as today.
The KMS key is removed only when `key_owned = TRUE` (the
generate path); for `key_owned = FALSE` (the bind-existing path)
the pre-existing KMS key remains in `KeyStorage` and may be bound
to a different CA later.

#### UI

Extends [ca_add.html](../web/templates/ca_add.html):

- New top-level mode radio "Generate / Issue" alongside "PEM" and
  "PKCS12".
- Inside this mode, two sub-selectors:
  - **Issuance scenario** — "Self-signed (root)", "Signed by an
    internal CA", "Signed by an external CA".
  - **Key source** — "Generate new key in KMS" (default) or
    "Use existing KMS key".
- Key-source = generate: provider dropdown (filtered to `active`),
  key-type dropdown (provider's supported set per
  [kms-specs.md §9](kms-specs.md)), and an optional `key_label`
  input.
- Key-source = existing: a KMS-key dropdown populated from
  `GET /api/kms/keys?unbound=true` (see backend additions below).
  Each entry shows `{label} — {provider name} — {key_type} —
  {spki_fp8}` where `spki_fp8` is the first 8 hex chars of the
  SPKI SHA-256. Inactive-provider keys are filtered out (the
  flow needs the provider to sign / build the CSR).
- Common fields (all scenario × key-source combinations):
  template dropdown (drives the structured subject-DN builder —
  same mechanism the certificate-request UI uses today via
  [certificate_request.html](../web/templates/certificate_request.html);
  the form renders one input per `subject_name.fields` entry,
  applies the template's constraints, and the page composes the
  resulting RFC 4514 DN string before submit), and CA policy
  fields (max_validity, serial_number_length, crl_validity,
  extensions). The API itself accepts `subject_dn` as a string
  (composed by the UI) so direct API callers and scripts can
  bypass the template layer.
- Self-signed scenario: also asks for `validity_days`.
- Internal-subordinate scenario: asks for `validity_days` and a
  parent CA dropdown (filtered to `active` CAs).
- External-subordinate scenario: no `validity_days`. On submit,
  the result page renders the returned `csr_pem` with copy and
  download buttons, and an explanatory banner ("take this CSR to
  your external CA; once they return a signed certificate, come
  back to install it"). The CA row appears in the list view in
  `pending-issuance` state with a muted badge.

CA list view: rows in `pending-issuance` show a dedicated
"Install signed certificate" action (in place of the usual
"Issue CRL" / "Edit" / "Delete" set; "Delete" is still offered so
the operator can abandon the request). The install form accepts a
PEM upload / textarea and an optional chain PEM, then calls
`POST /api/ca/{id}/install-cert`.

**Backend additions:**

- `GET /api/kms/keys?unbound=true` — filtered list of `KeyStorage`
  rows with no `CertificationAuthorities` row referencing them.
  Implementation is a left-join exclusion against
  `CertificationAuthorities.private_key_reference`. Same response
  shape as the existing list endpoint; `unbound` is the only new
  query parameter. Used by the UI to populate the key dropdown
  in bind-existing mode, and shared with the residual byo-cert
  path covered by CR-0002.

**Impact on existing sections:**

- §2.2 — "In-app CA generation" bullet closes (this proposal now
  covers both fresh-generation and bind-existing key sources);
  "Operator-visible gaps" shrinks by one.
- §4.1 — add `state ENUM('active','pending-issuance')` (default
  `'active'`) and `pending_csr TEXT` (nullable); allow
  `certificate` and `ski` to be NULL when
  `state='pending-issuance'`. Idempotent migration in the same
  style as the `key_owned` column add
  ([db.py:2341–2356](../pypki/db.py#L2341-L2356)).
- §5 — `pending-issuance` state added to the lifecycle table
  with documented transitions.
- §6 — promote §6.4 from sketch to a full subsection matching
  the §6.1–§6.3 shape; the request bodies above are canonical;
  document the two-phase external-subordinate flow and both
  key-source paths.
- §10 — add `POST /api/ca/generate`,
  `POST /api/ca/{id}/install-cert`, and the `?unbound=true` query
  parameter on the existing `GET /api/kms/keys` route to the
  route table. The two new POST routes require `superadmin` or
  `admin`; `?unbound=true` reuses the existing list endpoint's
  authorization.
- §11 — "Generate CA" wizard bullet closes; mode-selector
  enumeration grows; the "Generate / Issue" mode exposes the
  key-source sub-selector; list view gains the `pending-issuance`
  badge and "Install signed certificate" action.
- §12 — `CREATE` audit events gain `generation_mode ∈ {pem,
  pkcs12, kms_bind, generate-root, generate-internal-subordinate,
  generate-external-subordinate, bind-root,
  bind-internal-subordinate, bind-external-subordinate}`. Two
  new event types: `GENERATE_REQUEST` (CSR emitted) and
  `INSTALL_CERT` (signed cert installed). Both event types
  also carry the same `generation_mode` value as the
  corresponding `CREATE`.
- §13.1 — note that neither the `generate-*` nor the `bind-*`
  sub-modes transit any plaintext private key (generate-* never
  leaves the KMS; bind-* references a key that was already in
  the KMS), so this risk does not apply to them.
- §13 — add a new risk entry for orphan `pending-issuance` CAs
  (operator emits a CSR, never installs the cert). For the
  `generate-*` variant the freshly-created KMS key also sits
  unused; for `bind-*` the key was pre-existing, so the orphan
  is the CA row alone. Mitigation: no auto-cancellation — the
  row stays until the operator either installs a cert or issues
  `DELETE /api/ca/{id}`; the UI surfaces a "stale pending CA"
  badge once the row is older than 30 days so operators can
  spot abandoned requests.
- §14 — this proposal is the design backing all three bullets of
  Phase 2.

**Resolved decisions:**

1. **New endpoint, not a discriminator on `POST /api/ca`.** Add
   `POST /api/ca/generate` for all three sub-modes; the existing
   `POST /api/ca` contract stays untouched.
2. **`certificate_chain` for internal-subordinates: derive by
   default, allow override.** Default is parent's `certificate ||
   parent's certificate_chain`; the request body's
   `certificate_chain` field overrides when supplied.
3. **Validity capped by parent.** For internal-subordinates,
   reject when `now + validity_days > parent.notAfter`.
4. **Template-driven structured subject-DN builder in the UI**,
   reusing the same template machinery as the certificate-request
   form (one input per `subject_name.fields` entry, template
   constraints enforced). The API still accepts `subject_dn` as a
   composed RFC 4514 string so non-UI callers can bypass the
   template layer.
5. **`key_label` collisions on the chosen provider → reject with
   409.** Applies only to the generate-fresh key source; the
   operator must pick a unique label and no auto-suffix is
   applied. Bind-existing requests do not supply `key_label`
   (the label is already on the `KeyStorage` row).
6. **External-subordinate CSR carries no requested-extensions
   attribute.** The CSR conveys the public key, subject DN, and
   proof of possession; the external issuer chooses the resulting
   certificate's extensions per its own policy. The CA's
   operational policy (`extensions`, `max_validity`, etc.) is
   stored on the row and applied at issuance time, not in the
   CSR — driven by the same template mechanism as decision 4.
7. **`install-cert` does not compare DNs.** The issued
   certificate's subject DN is authoritative and supersedes the
   CSR's DN (external issuers routinely canonicalize RDN order,
   casing, and attribute encoding). SPKI match and
   BasicConstraints `cA=TRUE` are the only structural checks.
8. **No auto-cancel on `pending-issuance` rows.** Deletion stays
   operator-driven; the UI shows a "stale pending CA" badge once
   a row is older than 30 days.
9. **Multiple concurrent `pending-issuance` CAs are allowed.**
   External issuers run on independent timelines; nothing blocks
   parallel requests.
10. **Two key sources on a single endpoint.** `POST /api/ca/generate`
    accepts either `provider_id + key_type [+ key_label]`
    (generate fresh) or `kms_key_id` (bind existing); the
    discriminator is the presence of `kms_key_id`. The downstream
    signing pipeline is identical from step 3 onward. The
    bind-existing variant sets `key_owned = FALSE` on the new CA
    row and never deletes the underlying key, even on failure or
    on `DELETE /api/ca/{id}`. This subsumes the original CR-0002
    scope for CAs whose certificate must still be obtained
    in-app; the residual one-shot "I have both the KMS key and a
    finished cert already" case is handled separately by the
    shrunken CR-0002.

**Acceptance criteria** (in addition to §15):

- All four primary CA-creation paths (PEM, PKCS#12, KMS-bind
  one-shot per CR-0002, in-app issuance per this CR) and the six
  (scenario × key-source) combinations of this CR produce
  structurally identical `CertificationAuthorities` rows once
  the row is `active`; Decision A (§3.2) still holds.
- `key_owned` reflects key origin: `TRUE` for the three
  generate-* sub-modes (key created in this transaction), `FALSE`
  for the three bind-* sub-modes (key pre-existed). Deletion
  cascades to the KMS key per Decision B (§3.2) only when
  `key_owned = TRUE`, including for `pending-issuance` rows.
- Failure between key resolution and the CA insert leaves no
  orphan `KeyStorage` row in the generate-* sub-modes and never
  touches the `KeyStorage` row in the bind-* sub-modes.
- Bind-existing requests targeting a key that is already
  referenced by a `CertificationAuthorities` row, that belongs to
  an inactive provider, or whose algorithm is not permitted for
  CA signing return 400 / 409 with a typed error before any
  state change.
- SPKI match (§13.2) is satisfied by construction for root and
  internal-subordinate (both key-source variants); explicitly
  verified by `install-cert` for external-subordinate.
- A `pending-issuance` CA cannot sign: calls into the signing
  pipeline (§7), the CRL generator (§9), and OCSP responder bind
  raise a typed error before reaching the KMS.
- `POST /api/ca/{id}/install-cert` succeeds only on
  `pending-issuance` rows; a second call on an `active` CA
  returns 409.
- `CREATE` (root, internal-subordinate — both key sources),
  `GENERATE_REQUEST` (external-subordinate phase 1 — both key
  sources), and `INSTALL_CERT` (external-subordinate phase 2)
  audit events are written inside the same transaction as their
  respective DB writes, with a `generation_mode` reflecting the
  (scenario × key-source) combination.

### 17.2 CR-0002 — UI for one-shot KMS-key-and-cert binding

**Status:** Accepted.

**Motivation:** §2.2 and §6.3 — the API has accepted `kms_key_id`
together with a finished `certificate` as a single-call CA-creation
input since Phase 1
([api_adapters.py:130–178](../web/services/api_adapters.py#L130-L178)),
but [ca_add.html](../web/templates/ca_add.html) exposes only PEM
and PKCS#12 modes. CR-0001 covers the case where the certificate
must still be produced in-app (against either a fresh or an
existing KMS key); this CR is the residual one-shot path for
operators who already have *both* materials in hand — typically
migrations from another platform, or HSM operations where the
key ceremony also produced a certificate. Without it, those
operators must `curl` the API directly.

The supporting backend addition
(`GET /api/kms/keys?unbound=true`) is defined in CR-0001 and
shared with the bind-existing key source there; CR-0002 has no
backend changes of its own.

**Proposed behaviour:**

UI-only. Extends [ca_add.html](../web/templates/ca_add.html):

- Add a third top-level mode radio "Bind KMS key + certificate"
  alongside "PEM" and "PKCS12" (becomes the fourth alongside
  "Generate / Issue" from CR-0001).
- Panel exposes:
  - **KMS key dropdown** — populated from
    `GET /api/kms/keys?unbound=true` (defined in CR-0001). Each
    entry shows `{label} — {provider name} — {key_type} —
    {spki_fp8}` where `spki_fp8` is the first 8 hex chars of the
    SPKI SHA-256. Inactive-provider keys are shown with a muted
    badge (this mode never signs in-app, so an inactive provider
    is acceptable as long as the operator only intends to
    register the CA for revocation / OCSP).
  - **CA certificate PEM** upload / textarea (the cert that
    matches the selected key's public key).
  - **Certificate chain PEM** upload / textarea (optional).
- On submit: existing `POST /api/ca` with `name`, `kms_key_id`,
  `certificate`, optional `certificate_chain`, and policy fields.
  No new server route — this mode rides the Phase-1 byo-cert
  contract unchanged.

**Impact on existing sections:**

- §2.2 — "UI for KMS-key-bound CA creation" bullet closes
  (CR-0001 closes the in-app-issuance half; this CR closes the
  byo-cert half).
- §6.3 — unchanged; this proposal exposes the existing path, it
  does not redesign it.
- §10 — the `?unbound=true` parameter is documented under CR-0001;
  no new entries here.
- §11 — mode-selector enumeration grows by one; the "pending UI
  work" list under §11 shrinks by one.

**Resolved decisions:**

1. **SPKI mismatch surfaces as a server 400** from the existing
   `_verify_kms_key_for_ca`. No client-side cert parsing — that
   would add a JS crypto dependency for a single check, and the
   server already enforces the invariant authoritatively.
2. **The KMS-key dropdown includes the 8-char SPKI fingerprint**
   (first 8 hex chars of SPKI SHA-256), rendered as
   `{label} — {provider name} — {key_type} — {spki_fp8}`.
   Operators with many keys per provider can disambiguate at a
   glance. This dropdown is shared with CR-0001's bind-existing
   mode, so the same format applies there.

**Acceptance criteria** (in addition to §15):

- An operator can create a CA via the UI by picking a pre-existing
  KMS key and uploading its matching certificate.
- Keys already bound to a CA do not appear in the dropdown
  (shared `?unbound=true` predicate with CR-0001).
- SPKI mismatch produces a clear in-page error without leaving
  the form.
- No regression in the PEM and PKCS#12 modes.

---

## 18. Cross-references

- [kms-specs.md](kms-specs.md) — KMS specification (provider model,
  backend topology, activation lifecycle, REST API). The CA's
  signing pipeline terminates here.
- [hsm-support-specs.md](hsm-support-specs.md) — HSM-specific
  contracts (PKCS#11 mechanisms, slot addressing, session
  lifecycle, storage-type semantics) that drive HSM-backed CA
  signing.
- [certificate-templates.md](certificate-templates.md) — template
  JSON format that drives per-certificate issuance behaviour on top
  of CA policy.
- [database.md](database.md) — current schema; the
  `CertificationAuthorities` columns referenced here.
- [rest-api.md](rest-api.md) — REST API reference; the routes in §10
  are documented there.
- §17 above — design proposals currently in flight (`CR-NNNN`
  entries); folded back into the canonical sections once accepted
  and shipped.
- [PROGRESS.md §4](PROGRESS.md) — implementation status per work item.
- [roadmap.md §4](roadmap.md) — strategic intent and remaining work.
