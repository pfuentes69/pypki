# Certificate Management Specification

This is the consolidated specification for the end-entity certificate
management surface in pyPKI. It is the single source of truth for the
certificate design: lifecycle, data model, issuance paths, template
enforcement, revocation, distribution formats, REST API, management UI,
audit logging, and known weaknesses + security risks the operator should
be aware of.

Status of each work item lives in [PROGRESS.md §5](PROGRESS.md); the
strategic intent and cross-area framing live in
[roadmap.md §5](roadmap.md). The CA layer that signs these certificates
is specified in [ca-management-specs.md](ca-management-specs.md);
cryptographic key handling that backs the signing operations is in
[kms-specs.md](kms-specs.md); the JSON template format that drives
per-issuance policy is in
[certificate-template-specs.md](certificate-template-specs.md). This document
covers the *certificate layer* only — what sits between the operator /
EST client and the CA signing pipeline.

A developer reading only this document should have enough to understand
the current behaviour, identify the operator-visible gaps, and plan the
remaining work.

---

## 1. Goals

1. **Certificates as first-class entities.** Each issued certificate is
   a `Certificates` row carrying its PEM, its serial number (unique per
   issuing CA), parsed subject / issuer / validity, the public key,
   fingerprint, status, and links to the issuing CA, the certificate
   template that drove issuance, and optionally a `KeyStorage` row when
   the platform also generated the private key.
2. **Two issuance origins for the key.** Either the requester brings a
   public key (CSR upload) or the platform generates the keypair
   server-side and returns the result as a PKCS#12 bundle. Both paths
   converge on the same row shape.
3. **Three issuance scenarios.** CA-signed (the common case), self-signed
   (server-keygen only — the cert signs itself with its own freshly-
   generated key), and EST-protocol enrollment (RFC 7030, a CSR-upload
   variant scoped by an EST alias).
4. **Template-driven enforcement.** Every issuance carries a
   `template_id`; the template controls allowed key algorithms, subject
   DN components, allowed SAN types, included extensions, and the
   maximum validity window. The CA's policy caps validity further;
   neither the operator nor the requester can exceed it.
5. **Idempotent serial allocation per CA.** Serial numbers are random
   and uniqueness is enforced by `uq_ca_serial (ca_id, serial_number)`;
   collisions retry up to three times before raising.
6. **Atomic, one-way revocation.** A revoked certificate stays revoked;
   the revocation timestamp and RFC 5280 reason code are persisted; CRL
   generation reads this set and signs a CRL per issuing CA.
7. **Distribution in standard formats** — PEM, DER, and PKCS#12 (the
   latter only when the platform holds the private key).

---

## 2. Status

### 2.1 What is in place

- **Schema.** `Certificates` table per §4.1: serial, subject / issuer /
  validity, public key, optional `private_key_reference`,
  `is_self_signed`, status enum, revocation columns, fingerprint, the
  PEM blob, and audit timestamps. Unique constraints on `(ca_id,
  serial_number)` and on `fingerprint`.
- **Issuance — CSR upload.** `POST /api/certificate/issue` (CR-signed
  cert from operator-supplied CSR) goes through
  [core.py:generate_certificate_from_csr](../pypki/core.py); template
  is enforced at the route layer (`enforce_template=True`), and the
  CA's KMS-bound signing key produces the signature via the dummy-key +
  patch path in [certificate_tools.py:patch_certificate_signature](../pypki/certificate_tools.py).
- **Issuance — server-side keygen + PKCS#12.**
  `POST /api/certificate/issue-pkcs12` generates a fresh keypair (via
  `KeyTools`), optionally persists it in `KeyStorage`, builds the cert
  through `certificate_tools.generate_certificate_pem`, and returns a
  PKCS#12 bundle of cert + key. The `X-Certificate-Id` response header
  carries the new row id.
- **Self-signed issuance.** Server-keygen path with `ca_id ∈ {null, 0}`
  produces a cert whose subject equals its issuer, signed directly with
  the just-generated private key. Validity is still capped by the
  template's `max_validity`. Self-signing via CSR upload is
  *unsupported* by construction (the server has no access to the
  requester's private key — see §6.3).
- **Issuance — EST (RFC 7030).** `POST /.well-known/est/<alias>/simpleenroll`
  (and the no-alias variant) accept a PEM or PKCS#7-wrapped CSR; the
  alias resolves to a `(ca_id, template_id)` pair; the cert is built
  through the same CSR-upload pipeline with `enforce_template=True`;
  the response is a PKCS#7 envelope. A non-standard
  `…/simpleenrollpem` variant returns the raw PEM.
- **Template enforcement.** [certificate_tools.py:patch_csr](../pypki/certificate_tools.py)
  rebuilds the operator's CSR per the loaded template: the subject is
  composed from `subject_name.fields` (mandatory / optional / default),
  the SAN block is filtered by `allowed_types`, and the extension block
  is regenerated from the template definition (keyUsage,
  extendedKeyUsage, basicConstraints, AIA, CDP, policyIdentifiers,
  OCSPNoCheck, subjectKeyIdentifier). The CA's stored default
  extensions provide the AIA / CDP URL fallbacks when the template
  says `useCADefault: true`; criticality is always the template's
  decision (see [ca-management-specs.md §8](ca-management-specs.md)).
- **Key-algorithm validation.** `validate_key_algorithm(public_key)`
  in [certificate_tools.py](../pypki/certificate_tools.py) rejects keys
  whose algorithm / size / curve falls outside the template's
  `allowed_cryptography.keyAlgorithms` block. Runs before both
  CSR-upload and server-keygen paths.
- **Validity ceiling.** Built cert's `notAfter` is the minimum of
  (operator request, template `max_validity`, CA's `not_valid_after`).
  Enforced in `generate_certificate_from_csr` / `generate_certificate_pem`.
- **Revocation.** `POST /api/certificate/revoke/<id>` runs
  `UPDATE Certificates SET status='Revoked', revoked_at=NOW(),
  revocation_reason=? WHERE id=? AND status != 'Revoked'`. Idempotent
  by construction — a second revoke on an already-revoked row touches
  no rows and returns False. The reason code mapping
  ([PKITools.REVOCATION_REASON_MAPPING](../pypki/pki_tools.py)) follows
  RFC 5280 §5.3.1.
- **CRL membership.** `db.get_revoked_certificates(ca_id)` reads the
  set of `(serial, revoked_at, reason)` tuples for a CA;
  [core.py:generate_crl](../pypki/core.py) builds the CRL, signs it via
  KMS through the same patch-the-dummy-signature path used for certs,
  and stores it in `CertificateRevocationLists`. CRL refresh runs both
  on demand (`POST /api/ca/<id>/crl`) and on a background scheduler
  (see [ca-management-specs.md §9](ca-management-specs.md)).
- **Distribution endpoints.** `GET /api/certificate/pem/<id>` returns
  the PEM; `POST /api/certificate/pkcs12/<id>` reconstructs a PKCS#12
  bundle if the cert has a stored private key. There is no DER route
  for end-entity certs today (only for CA certs — see §13.12).
- **CSR tooling.** `POST /api/certificate/parse-csr` parses a PEM CSR
  and returns a JSON dict with the subject components and SAN. A
  browser-side **CSR Tool** ([web/templates/csr_tool.html](../web/templates/csr_tool.html))
  generates keys + CSRs entirely in-browser via `jsrsasign`; no server
  interaction, the private key never leaves the page.
- **Listing + filtering.** `GET /api/certificate` supports `ca_id`,
  `template_id`, `status`, `expiring_soon` (hard-coded 30-day window),
  with pagination (`page`, `per_page`).
- **UI.** Four templates:
  [certificate_list.html](../web/templates/certificate_list.html) (list
  + filter + per-row actions),
  [certificate_details.html](../web/templates/certificate_details.html)
  (parsed cert view + revoke / download / PKCS#12 export),
  [certificate_request.html](../web/templates/certificate_request.html)
  (template-driven structured DN builder + CSR-upload / server-keygen
  dual mode), and
  [csr_tool.html](../web/templates/csr_tool.html).
- **Audit logging.** `CREATE` and `REVOKE` events are written to
  `AuditLogs` with `resource_type='certificates'` from
  [api_adapters.py](../web/services/api_adapters.py). Inside the same
  request that performs the DB write.

### 2.2 What is pending

These bullets are picked up in §13 (weaknesses) and §14 (order of
work). Designs that require a new lifecycle state, schema change, or
cross-cutting refactor migrate to §17 as `CR-NNNN` proposals.

- **Persisted expiry.** A certificate is `Active` until explicitly
  revoked, even when `not_after < NOW()`. Expiry is computed at query
  time; no scheduled job marks expired rows. Consequences in §13.1.
- **Re-issue / renewal linkage.** No schema slot to record that
  cert X superseded cert Y; operators must revoke + re-issue manually,
  and the audit trail does not link the two events.
- **Audit metadata for certs.** The `AuditLogs.metadata` JSON column
  exists ([ca-management-specs.md §17.1](ca-management-specs.md)) but
  certificate `CREATE` / `REVOKE` events do not populate it. Issuance
  path (csr-upload / server-keygen / est), source (rest / est /
  internal), `template_id`, and `ca_id` are not captured at audit time.
- **Cert download audit trail.** PEM / DER / PKCS#12 downloads and the
  `GET /private-key/<id>` route write no audit log entries — a user
  with the right role can exfiltrate a stored private key without a
  paper trail.
- **Bulk operations.** Revocation, re-issue, and download are per-cert
  in the UI; no bulk actions on the list view.
- **ACME (RFC 8555).** Not in scope today; only EST is implemented.
- **Subject DN policy enforcement.** Template `subject_name.fields`
  carries `mandatory` / `default` markers; the rebuild path in
  `patch_csr` respects them, but there is no second-pass validation
  that the *built* cert's subject still satisfies them after copy-from-
  CSR (an inconsistency a malicious or buggy caller could exploit if
  template enforcement is bypassed — see §6.4 and §13.6).

---

## 3. Architecture

### 3.1 Layered model

```
┌────────────────────────────────────────────────────────────────┐
│                 REST / EST clients, UI forms                    │
├────────────────────────────────────────────────────────────────┤
│ web.routes        — request validation, role check, audit hook │
│ web.services      — adapters (api_adapters, ca_generate)       │
├────────────────────────────────────────────────────────────────┤
│ pypki.core.PyPKI  — orchestration: pick CA, pick template,     │
│                     decide self-signed vs CA-signed, persist   │
├────────────────────────────────────────────────────────────────┤
│ pypki.certificate_tools.CertificateTools                       │
│   - load_certificate_template (per-call)                       │
│   - validate_key_algorithm                                     │
│   - patch_csr  (rebuild CSR with template extensions)          │
│   - generate_certificate_pem  (server-keygen path)             │
│   - generate_certificate_from_csr  (CSR-upload path)           │
│   - parse_csr_to_json  (CSR introspection)                     │
├────────────────────────────────────────────────────────────────┤
│ pypki.ca.CertificationAuthority.sign_tbs_digest                │
│   delegates to KeyManagementService.sign_digest(key_id, sha256)│
├────────────────────────────────────────────────────────────────┤
│ pypki.db.PKIDataBase                                           │
│   insert_certificate / get_certificate_record /                │
│   revoke_certificate / get_revoked_certificates                │
└────────────────────────────────────────────────────────────────┘
```

The certificate layer never touches the KMS directly. Signing is
expressed as "give me a CA, hand it the TBS digest, get the signature
back" via [CertificationAuthority.sign_tbs_digest](../pypki/ca.py); the
CA object resolves the signing key id and dispatches into
[KeyManagementService.sign_digest](../pypki/kms.py). The dummy-key
trick (build the cert with a throw-away matching-algorithm key,
extract the TBS bytes, KMS-sign, patch the signature into the DER) is
shared with the CA-generation path in
[ca-management-specs.md §17.1](ca-management-specs.md).

### 3.2 Two design decisions, recorded

**Decision A — A certificate row is a parse of its PEM.** Subject,
issuer, validity, public key, serial, and fingerprint are extracted
from the certificate at insert time and stored as separate columns.
This costs storage but lets the list view, status endpoint, and CRL
generator answer queries without re-parsing every PEM. The
`certificate_data` column holds the canonical PEM; the parsed columns
are derived state and must stay consistent with it.

**Decision B — Server-stored private keys are an opt-in side-effect of
the server-keygen path, not a separate flow.** When the operator picks
the "Generate key in browser + return PKCS#12" mode, the platform
holds the private key only long enough to ship it; the row's
`private_key_reference` is set only if the operator additionally ticked
"Store key in KMS" on the request form. Re-downloading the PKCS#12
later requires the key still be in `KeyStorage`. Once an operator
discards the original download, there is no way to reproduce it from
the cert alone.

---

## 4. Data model

### 4.1 `Certificates`

| Column | Type | Notes |
|---|---|---|
| `id` | INT PK AI | |
| `ca_id` | INT FK → `CertificationAuthorities(id)` | Nullable. NULL means self-signed (no issuing CA in this platform); also set to NULL by `delete_ca` cascade to preserve the issuance audit trail. |
| `template_id` | INT FK → `CertificateTemplates(id)` | Required; nullable not enforced at schema level today. Template drove the build. |
| `serial_number` | VARCHAR(255) NOT NULL | Hex string. Random per insert (`secrets.token_bytes(serial_number_length)` from the CA's policy). Unique per CA via `uq_ca_serial (ca_id, serial_number)`. |
| `subject_name` | VARCHAR(255) | RFC 4514 DN string parsed from the cert. |
| `issuer_name` | VARCHAR(255) | Same. For self-signed, equal to `subject_name`. |
| `not_before` | DATETIME | Parsed from cert. |
| `not_after` | DATETIME | Parsed from cert. |
| `public_key` | TEXT | PEM-encoded SubjectPublicKeyInfo. Lets the list view show key algorithm without re-parsing the cert. |
| `private_key_reference` | INT FK → `KeyStorage(id)` | Nullable. Set only when the platform generated the key (server-keygen + store-in-KMS). NULL for CSR-upload paths. |
| `is_self_signed` | BOOLEAN NOT NULL DEFAULT FALSE | TRUE when `ca_id IS NULL` and the cert signs itself with its own key. |
| `status` | ENUM('Active','Revoked','Expired') NOT NULL DEFAULT 'Active' | See §5. `'Expired'` is unused today — expiry is query-time only. |
| `revoked_at` | TIMESTAMP | NULL unless `status='Revoked'`. |
| `revocation_reason` | INT | RFC 5280 reason code (0..9). NULL unless revoked. |
| `certificate_data` | TEXT | PEM-encoded certificate. Canonical source for re-derivation. |
| `fingerprint` | VARCHAR(128) NOT NULL UNIQUE | SHA-256 hex. Global uniqueness — duplicate inserts (same cert re-issued) are rejected at the DB layer. |
| `created_at` / `updated_at` | TIMESTAMP | Auto-managed. |

### 4.2 Foreign-key relationships

- `Certificates.ca_id` → `CertificationAuthorities(id)`; nullable on
  delete (cascade SET NULL by `delete_ca`).
- `Certificates.template_id` → `CertificateTemplates(id)`; not enforced
  at the schema level but always populated by issuance code.
- `Certificates.private_key_reference` → `KeyStorage(id)`; nullable.
  When set, deleting the `KeyStorage` row leaves an orphan reference;
  no cascade is wired today (see §13.5).
- Revoked rows feed `CertificateRevocationLists` indirectly through
  `db.get_revoked_certificates(ca_id)`; there is no FK from CRL rows
  back to individual certs.

### 4.3 Migrations

- Phase 1 — `Certificates` table introduced with the per-CA serial
  uniqueness constraint.
- Phase 0.4 (functional) — `is_self_signed BOOLEAN NOT NULL DEFAULT FALSE`
  added so the UI / API can distinguish without a JOIN; idempotent
  migration in [db.py](../pypki/db.py).
- Pending — `metadata JSON` on `Certificates` (or on individual audit
  rows) to capture issuance path / source / template version. See
  §13.7.

---

## 5. Certificate lifecycle

A certificate has the following states:

| State | Meaning | Transition |
|---|---|---|
| **non-existent** | No row in `Certificates`. | `POST /api/certificate/issue` or `/issue-pkcs12` or EST `simpleenroll` → **Active**. |
| **Active** | Row present, `status='Active'`, `not_after` may be future or past. Distribution endpoints serve it; CRL never lists it. | `POST /api/certificate/revoke/<id>` → **Revoked**. Implicit expiry (`now > not_after`) is *not* persisted. |
| **Revoked** | Row present, `status='Revoked'`, `revoked_at` set, `revocation_reason` set. Listed on every CRL generated for the issuing CA from that point forward. | Terminal in this design — no un-revoke. |
| **Expired** (logical) | Computed: `status='Active'` AND `not_after < NOW()`. Surfaced by the UI badge and by `expiring_soon=true` on the list endpoint. Never persisted. | None — remains `Active` in the schema until an explicit revoke. |

Transitions not currently modelled: **superseded** (a renewal cert
explicitly replaces an older one; would need a `replaced_by` /
`replaces` column), **on-hold** (RFC 5280 reason code 6 is accepted at
revoke time but the semantics — temporary suspension, later release —
are not modelled).

---

## 6. Issuance paths

Four entry points produce the same row shape once successful. Validation
contracts (template enforcement, key-algorithm check, validity ceiling)
are uniform; only the *source* of the public key and the *signer*
differ.

### 6.1 CSR upload, CA-signed

```
POST /api/certificate/issue
{
  "csr": "-----BEGIN CERTIFICATE REQUEST-----\n...",
  "ca_id": 17,
  "template_id": 4,
  "validity_days": 365,            // optional; capped by template + CA
  "subject": { ... },              // optional overrides; template-validated
  "subjectAltName": { ... }
}
```

Server flow:
1. Load CA via `_build_ca(ca_id)` (refuses non-`active` CAs — see
   [ca-management-specs.md §17.1](ca-management-specs.md)). Load
   template via `_build_cert_tool(template_id)`.
2. Parse the CSR; remember the original public key (before patching).
3. `validate_key_algorithm(original_public_key)` against
   `template.allowed_cryptography.keyAlgorithms`. Reject on mismatch.
4. `patch_csr(original_csr, request_json, issuing_ca)` rebuilds the
   CSR with the template's subject / SAN / extension block. The result
   is signed with a dummy matching-algorithm key (proof-of-possession
   is moot at this point — the CA validates against the original
   public key).
5. Build the certificate: subject + SAN + extensions from the patched
   CSR, issuer from the CA's cert, validity = min(request,
   template.max_validity, CA.not_after), serial = random per
   `CA.serial_number_length`.
6. Sign via the dummy-key + patch path:
   `CertificationAuthority.sign_tbs_digest` → KMS.
7. Persist via `db.insert_certificate(pem, ca_id, template_id,
   private_key_reference=None, is_self_signed=False)`. Serial
   collisions retry up to 3 times.
8. Write `CREATE` audit event.

Returns: `{certificate_id, certificate_pem}`.

### 6.2 Server-side keygen, CA-signed (PKCS#12 download)

```
POST /api/certificate/issue-pkcs12
{
  "ca_id": 17,
  "template_id": 4,
  "key_algorithm": "ECDSA",        // or "RSA"
  "key_type": "P-256",             // curve name or RSA bit size
  "validity_days": 365,
  "subject": { ... },
  "subjectAltName": { ... },
  "pkcs12_passphrase": "...",      // optional
  "store_key_in_kms": false        // opt-in persistence — §3.2 Decision B
}
```

Server flow:
1. Resolve CA + template (same as §6.1).
2. Generate the keypair via `KeyTools.generate_private_key`.
3. If `store_key_in_kms=true`, insert a `KeyStorage` row (encrypted
   under the default software provider's KEK) and remember the id.
4. Build the cert through `certificate_tools.generate_certificate_pem`
   — subject + SAN are built from the request (not from a CSR), the
   template's extension block is applied, signing goes through the
   dummy-key + KMS path.
5. Persist via `insert_certificate(...,
   private_key_reference=<key_id_or_NULL>, is_self_signed=False)`.
6. Bundle cert + key into a PKCS#12, optionally encrypted under the
   supplied passphrase.
7. Write `CREATE` audit event.

Returns: the PKCS#12 bytes, with the new row's id in the
`X-Certificate-Id` response header.

### 6.3 Server-side keygen, self-signed

Same as §6.2 with `ca_id ∈ {null, 0}`:

- No CA is fetched; `is_self_signed=TRUE`.
- Subject and issuer are identical (composed from the request through
  the template).
- The cert is signed *directly* with the just-generated private key
  (no KMS involvement) — the platform briefly has the key material in
  memory regardless of whether `store_key_in_kms` is set.
- Validity is capped only by `template.max_validity` (no CA ceiling).

**Self-signed via CSR upload is rejected** by construction
([core.py:generate_certificate_from_csr](../pypki/core.py)): the server
has no access to the requester's private key, so the
self-signature cannot be produced. Callers wanting a self-signed cert
must use §6.3.

### 6.4 EST enrollment

```
POST /.well-known/est/<alias>/simpleenroll
Content-Type: application/pkcs10
Authorization: Basic <base64>          # optional, per-alias

<base64 PKCS#10 CSR body>
```

(Non-aliased form `POST /.well-known/est/simpleenroll` uses the EST
alias marked `is_default=TRUE` per [database.md](database.md).)

Server flow:
1. Resolve the EST alias by `<label>` → `(ca_id, template_id,
   username?, password_hash?, cert_fingerprint?)`.
2. If the alias requires Basic Auth, verify the supplied credentials
   against the stored PBKDF2-SHA256 hash. If the alias requires mutual
   TLS, verify the client cert's fingerprint matches.
3. Decode the request body (PKCS#10 in base64 or DER) into a PEM CSR.
4. Run the §6.1 flow with `enforce_template=True` (non-overridable for
   EST).
5. Wrap the resulting cert in a PKCS#7 envelope (base64 in
   `application/pkcs7-mime`).

A non-standard `…/simpleenrollpem` variant returns the cert PEM
directly. `GET /.well-known/est/<alias>/cacerts` returns the alias's CA
cert chain.

### 6.5 Template enforcement (shared by all paths)

The template controls four things, in this order:

1. **Allowed cryptography.** RSA bit size bounds, ECDSA permitted
   curves, optional Ed25519 / Ed448. `validate_key_algorithm` runs
   before any cert build; a rejected key returns 400 with the offending
   constraint named.
2. **Subject DN composition.** Each field in `subject_name.fields` is
   `mandatory` / optional, may carry a `default`, and is filtered by
   regex when present. The UI's structured DN builder renders one input
   per field (template defaults shown as gray placeholders per the
   site-wide UI rule); empty fields fall back to the template default.
   The server-side rebuild in `patch_csr` reapplies the same filter.
3. **SAN composition.** `extensions.subjectAltName.allowed_types`
   filters DNS names, IP addresses, email addresses, URIs. SAN entries
   in the CSR that the template forbids are dropped.
4. **Extension block.** Every extension is independently controlled by
   `include` / `critical` / `useCADefault`. AIA OCSP, AIA caIssuers,
   and CDP can each defer to the CA's stored defaults via
   `useCADefault`; criticality is always a template decision
   ([ca-management-specs.md §8](ca-management-specs.md)).

Detailed template grammar lives in [certificate-template-specs.md](certificate-template-specs.md).

---

## 7. Signing pipeline

A certificate is built, hashed, sent off to be signed, and patched —
identical for §6.1 / §6.2 / §6.4, and skipped only by §6.3 (self-signed,
which signs directly with the cert's own key in memory).

```
       CertificateBuilder
              │
              │  .sign(dummy_key, SHA256)
              ▼
   x509.Certificate  (with bogus signature)
              │
              │  .tbs_certificate_bytes
              ▼
        SHA-256 digest
              │
              │  ca.sign_tbs_digest(digest)
              │     → KMS.sign_digest(key_id, digest)
              ▼
       raw signature bytes
              │
              │  patch_certificate_signature(pre_der, sig, is_ecdsa)
              │     (asn1crypto rewrites the signatureValue field)
              ▼
   x509.Certificate  (with real signature)
```

The dummy key matches the CA's algorithm (and curve, for ECDSA) so the
TBS bytes carry the right `signatureAlgorithm` OID before hashing.
The shared helper is at
[certificate_tools.py:patch_certificate_signature](../pypki/certificate_tools.py).

A `pending-issuance` CA cannot reach this pipeline: `_build_ca`
([core.py](../pypki/core.py)) raises `CAStateError` and the issuance
request fails with 409 before any key generation, CSR parse, or KMS
call is performed.

---

## 8. Issuance policy

Five inputs govern what the final cert looks like:

1. **Operator request** — subject, SAN, validity, key algorithm.
2. **Certificate template** — caps and overrides on all of the above;
   the canonical source for which extensions land in the cert.
3. **Issuing CA's stored defaults** — AIA / CDP URLs used when the
   template defers via `useCADefault` (the CA layer holds only the
   URLs; criticality is the template's call —
   [ca-management-specs.md §8](ca-management-specs.md)).
4. **Issuing CA's policy** — `max_validity` (in days), `not_after`
   (absolute), serial number length in bytes. The cert's `notAfter`
   cannot exceed the CA's `notAfter`.
5. **Random serial** — `secrets.token_bytes(serial_number_length)`,
   retried on collision against the per-CA uniqueness index.

The precedence is: **request → template (filters / caps) → CA policy
(further caps)**. The platform never silently widens — only ever
narrows — what the operator asked for.

---

## 9. Revocation and CRL membership

### 9.1 Per-certificate revocation

`POST /api/certificate/revoke/<id>` with body `{revocation_reason: <int>}`:

```
UPDATE Certificates
   SET status='Revoked',
       revoked_at=NOW(),
       revocation_reason=:reason
 WHERE id=:id AND status != 'Revoked'
```

The `status != 'Revoked'` guard makes revocation idempotent: a second
revoke on the same row touches 0 rows and the route returns 404 with
a clear reason. Reason codes are RFC 5280 §5.3.1: 0=unspecified,
1=keyCompromise, 2=cACompromise, 3=affiliationChanged, 4=superseded,
5=cessationOfOperation, 6=certificateHold, 8=removeFromCRL,
9=privilegeWithdrawn, 10=aACompromise. (Code 7 is reserved per RFC.)

A `REVOKE` audit row is written in the same transaction.

### 9.2 CRL generation

The CRL pipeline lives in the CA layer
([ca-management-specs.md §9](ca-management-specs.md)). From the
certificate layer's point of view: revoked rows expose
`(serial_number, revoked_at, revocation_reason)` via
`db.get_revoked_certificates(ca_id)`, ordered by revocation time;
expired-but-not-revoked certs are *not* included (revocation list per
RFC 5280, not status list).

### 9.3 Status queries

`GET /api/certificate/status/<id>` returns `{status, not_before,
not_after, revoked_at, revocation_reason}` — useful for clients that
want to query revocation without parsing a CRL. This is a status
*query*, not OCSP; for true OCSP responses, see the OCSP responder
([rest-api.md](rest-api.md) /ocsp routes).

---

## 10. REST API specification

All routes require authentication (no anonymous access except where
noted). The authoritative route table lives in [rest-api.md](rest-api.md);
this section captures the contract that this spec relies on.

| Method | Path | Roles | Purpose |
|---|---|---|---|
| `GET` | `/api/certificate` | any | List + filter + paginate |
| `GET` | `/api/certificate/<id>` | any | Parsed cert details |
| `GET` | `/api/certificate/pem/<id>` | any | Download PEM |
| `GET` | `/api/certificate/status/<id>` | any | Status query |
| `POST` | `/api/certificate/issue` | superadmin, admin, user | CSR-upload issuance |
| `POST` | `/api/certificate/issue-pkcs12` | superadmin, admin, user | Server-keygen issuance |
| `POST` | `/api/certificate/revoke/<id>` | superadmin, admin | Revocation |
| `POST` | `/api/certificate/parse-csr` | any | Introspect CSR PEM |
| `GET` | `/api/certificate/private-key/<id>` | superadmin, admin | Plaintext private key, if stored |
| `POST` | `/api/certificate/pkcs12/<id>` | superadmin, admin | Reconstruct PKCS#12 |
| `POST` | `/.well-known/est/<alias>/simpleenroll` | per-alias auth | EST enrollment, PKCS#7 response |
| `POST` | `/.well-known/est/<alias>/simpleenrollpem` | per-alias auth | EST enrollment, PEM response |
| `GET`  | `/.well-known/est/<alias>/cacerts` | any | EST CA cert chain |
| `POST` | `/.well-known/est/simpleenroll` | per-alias auth | EST enroll against default alias |
| `GET`  | `/.well-known/est/cacerts` | any | EST CA cert chain for default alias |

Filter params on `GET /api/certificate`: `ca_id`, `template_id`,
`status ∈ {Active, Revoked, Expired}`, `expiring_soon=true`
(hard-coded 30-day window — see §13.4), `page`, `per_page` (default
10).

---

## 11. Management UI

Four pages, all under `/cas_and_crls`-adjacent navigation:

- **[certificate_list.html](../web/templates/certificate_list.html)** —
  paginated table with status badges, CA / template filter dropdowns,
  expiring-soon toggle, and per-row action menu (View / Download PEM /
  Download PKCS#12 (if key stored) / Revoke (admin+) / Issue similar
  (link to request form pre-filled)). The "Expired" badge is computed
  client-side from `not_after` rather than read from `status`.
- **[certificate_details.html](../web/templates/certificate_details.html)**
   — parsed-cert view: subject DN, serial, fingerprint, validity,
   issuer (linked to CA details), extensions block, revocation status.
   Action buttons: Revoke (admin+, with reason-code dropdown),
   Download PEM, Download PKCS#12 (admin+, if stored key),
   View Private Key (admin+, opens a modal — no audit log entry
   today, see §13.3).
- **[certificate_request.html](../web/templates/certificate_request.html)**
   — dual-mode form. The user picks a CA (or self-signed sentinel), a
   template, then chooses **CSR upload** or **server-side keygen**.
   The template-driven structured DN builder mirrors the one in
   [ca_add.html](../web/templates/ca_add.html); template defaults
   render as gray placeholders site-wide. SAN rows are added /
   removed dynamically per template `allowed_types`.
- **[csr_tool.html](../web/templates/csr_tool.html)** — purely
  client-side keypair + CSR generator using `jsrsasign`. The private
  key never reaches the server. Output is two textareas (private key
  PEM, CSR PEM) with copy / download buttons. Useful for operators who
  want to keep their private key offline and only feed the CSR to the
  request form.

---

## 12. Audit logging

Two event types today:

- `CREATE` — written by both `generate_certificate_from_csr` and
  `generate_pkcs12` adapters in [api_adapters.py](../web/services/api_adapters.py),
  inside the same connection as the `Certificates` insert.
- `REVOKE` — written by `revoke_certificate` adapter inside the same
  transaction as the status update.

Both currently leave `AuditLogs.metadata` NULL. The metadata column
exists (added for CR-0001's `generation_mode`); cert events do not
populate it. See §13.7.

Events *not* logged today (gap, §13.3): PEM / DER / PKCS#12 download,
plaintext private-key fetch, CSR parse, status query.

---

## 13. Weaknesses and security risks

### 13.1 Expiry is never persisted

The `Certificates.status` enum has an `Expired` value but no code path
writes it. A cert with `not_after < NOW()` stays `status='Active'`
forever; the UI computes the expired badge client-side, and the
list-filter `expiring_soon=true` reads `not_after` directly rather
than filtering by status. **Consequences:**
- Reports that count active certs over-report by including expired
  rows.
- No hook to trigger a renewal workflow at the *moment* a cert
  actually expires.
- A future query that wants to ask "show me certs that were active at
  time T" cannot be answered without re-parsing every PEM.

**Mitigation idea (future work):** a periodic job that flips
`Active → Expired` once per day, plus a corresponding lifecycle entry
in §5.

### 13.2 No re-issue / supersession link

Schema has no `replaced_by` / `replaces` columns. When an operator
revokes cert X (reason 4 = superseded) and issues cert Y with the same
subject, the only connection is the audit-log temporal proximity. A
forensic question "which cert replaced X" cannot be answered from the
data model.

### 13.3 Downloads and private-key fetches are not audited

The four read endpoints — PEM, DER, PKCS#12 reconstruction, plaintext
private key — write no `AuditLogs` row. An admin who downloads a
stored private key leaves no paper trail. Especially severe for
`GET /api/certificate/private-key/<id>` (admin-only, but no log).

### 13.4 Hard-coded "expiring soon" window

The `expiring_soon=true` query parameter is locked to 30 days. No way
to ask "what expires in the next 7 days" or "in the next 90 days"
without code change. Should be a `within_days=N` parameter.

### 13.5 Orphan `private_key_reference` on KeyStorage delete

`Certificates.private_key_reference` is an FK to `KeyStorage(id)` with
no cascade configured. If a `KeyStorage` row is deleted directly
(rather than via the CA cascade — and certs aren't on the CA cascade
anyway, only OCSP / EST / CRLs are), the cert row keeps a dangling
reference. PKCS#12 reconstruction then fails with a 500.

### 13.6 Template enforcement is bypassable in core, not just at the route

`generate_certificate_from_csr` accepts `enforce_template=False` as
its default. The REST route hard-codes `True` and EST hard-codes
`True`, but utility scripts and tests can call the core function with
enforcement off and produce a cert whose subject / SAN / extensions
do not respect the template. The DB still has the `template_id`
reference, creating a row that looks template-compliant from the
schema but isn't.

### 13.7 Audit metadata is empty for certificate events

`AuditLogs.metadata` exists per CR-0001 but cert `CREATE` events do
not populate it. Missing context: issuance path
(`csr-upload | server-keygen | est | self-signed`), authentication
source (REST + role | EST alias name), template version (if the
template was edited after issuance, you can't tell which version was
in force), and the public-key fingerprint (which is captured at the
cert level but not surfaced into the audit row for cross-referencing).

### 13.8 PKCS#12 passphrase handling

The passphrase travels as plaintext JSON in the request body and is
held in memory in Python until the PKCS#12 is built. Python strings
are immutable — there's no secure zero-after-use. A core dump or
memory inspection during PKCS#12 build could leak the passphrase.

### 13.9 No rate-limiting on issuance

Both REST issuance routes and EST `simpleenroll` are unthrottled. A
compromised credential could mass-issue certs against any CA + template
the role permits. Logging exists for CREATE but only after the fact.

### 13.10 Subject-DN policy is enforced at *patch* time, not at *build*

`patch_csr` rebuilds the CSR with template-mandated subject fields
filled in. The cert build then copies subject + SAN + extensions from
the patched CSR into the `CertificateBuilder`. There is no second-pass
validation that the *final* cert's subject still satisfies the
template's `mandatory` / regex rules — if `patch_csr` is bypassed
(see §13.6) or a future code path skips it, the policy is silently
violated.

### 13.11 No structured 503 surface for KMS-driven sign failures

CA-side `BackendError` is mapped to a 503 envelope by the global
handler ([web/__init__.py](../web/__init__.py)); cert-issuance routes
inherit that handler so the right code reaches the client. However,
intermediate failures — KMS provider deactivation mid-build, HSM slot
removal during the sign call — propagate without a typed error in the
cert response body (the `description` field carries a stringified
exception). The CR-0005 envelope shape
([kms-specs.md](kms-specs.md)) should extend to cert routes.

### 13.12 No DER download for end-entity certs

CA cert routes expose both PEM and DER
([ca-management-specs.md](ca-management-specs.md)); end-entity certs
only expose PEM via `GET /api/certificate/pem/<id>`. A binary download
is sometimes useful (e.g., importing into a Windows store) and clients
have to base64-decode the PEM themselves today. Trivial fix; parked
in §14 work order.

---

## 14. Order of work

1. **Persist expiry** — the simplest data-quality fix (§13.1). Daily
   background job, idempotent, narrow blast radius. Unblocks accurate
   reporting and the §5 lifecycle table.
2. **Audit metadata for certificate events** — populate
   `AuditLogs.metadata` with `issuance_path`, `source`, `template_id`,
   `ca_id`, `public_key_fp8`. Symmetric with what the CA layer already
   does (§13.7).
3. **Audit downloads / private-key fetches** — close §13.3. New
   `READ` action types: `DOWNLOAD_PEM`, `DOWNLOAD_PKCS12`,
   `READ_PRIVATE_KEY`.
4. **Parameterise the expiring-soon window** — `?within_days=N` plus
   a UI control on the list view (§13.4).
5. **Re-issue / supersession linkage** — `Certificates.replaces` FK,
   surfaced in the UI's "issue similar" path. Probably a CR-NNNN
   proposal in §17 since it changes the §5 lifecycle.
6. **Tighten template enforcement** — drop the
   `enforce_template=False` escape hatch from `core.py`, or make the
   bypass require an explicit "trusted-internal" caller token. Add a
   build-time validator (§13.10).
7. **CR-0005-style 503 envelope for cert routes** — propagate the
   structured `{description, code, key_id, provider_id, recovery}`
   shape to issuance endpoints (§13.11).
8. **Rate-limiting on issuance** — per-user, per-IP, per-CA — §13.9.
9. **ACME (RFC 8555) endpoints** — separate proposal; mentioned for
   roadmap context only.

---

## 15. Acceptance criteria

Functional:

- All four issuance entry points (§6.1 / §6.2 / §6.3 / §6.4) produce
  structurally identical `Certificates` rows once successful: same
  set of populated columns (modulo `private_key_reference` and
  `is_self_signed`), same `fingerprint` algorithm, same serial
  uniqueness contract.
- Template enforcement on the REST issuance routes and on every EST
  path is non-overridable from outside the server: a malformed request
  cannot ship a cert whose subject / SAN / extensions violate the
  template.
- Revocation is idempotent: a second `POST /revoke/<id>` returns the
  same logical "already revoked" result without re-touching `revoked_at`
  or writing a duplicate audit row.
- A revoked certificate appears on every CRL issued by its CA from
  that moment forward, and the CRL's signature verifies against the
  CA's stored certificate without intermediate trust assumptions.
- A failure between key generation and the `Certificates` insert
  leaves no orphan `KeyStorage` row in the server-keygen-with-storage
  path.

Operational:

- `CREATE` and `REVOKE` audit events are written inside the same DB
  transaction as the corresponding `Certificates` write.
- A cert built against an `active` CA succeeds; against a
  `pending-issuance` CA, the request fails with 409 before any KMS
  call (covered by [ca-management-specs.md §17.1](ca-management-specs.md)).
- `GET /api/certificate/status/<id>` returns the same status value
  the CRL would assert at the same instant (modulo the §13.1 expired-
  not-marked gap, which is acknowledged as an outstanding weakness).

---

## 16. Out of scope for this spec

- **ACME (RFC 8555).** Not implemented; not in scope here.
- **CMP / CMC.** Not implemented; not in scope.
- **OCSP responses.** Live in the OCSP responder spec / module; this
  document only references the status query (`/api/certificate/status/<id>`),
  which is a JSON API, not an OCSP protocol response.
- **Certificate transparency (CT) log submission.** Not modelled.
- **External CA proxying** (acting as RA on top of Sectigo / DigiCert /
  AWS PCA). Separate product surface.
- **Bulk operations** (mass revoke, mass renew) — currently not modelled;
  picked up in §14 if demand arises.

---

## 17. Design proposals

This section holds in-progress designs for capabilities listed in §2.2
that are large enough to reshape existing surface — typically a new
lifecycle state, a new issuance entry point, or a workflow that touches
§5, §6, §11, and §12 together. Smaller hardening items (the §13 risk
list) skip this section and flow directly through the §13 → §14 → §15
chain.

A proposal lives here only while the design is being negotiated. Once
accepted and shipped, its content is folded into the relevant canonical
sections and the proposal entry is removed. The git history of this
file carries the design trail; PR descriptions carry the discussion.

Each proposal follows a fixed shape:

- **Status** — `Proposed`, `Accepted`, or `Implemented (folded into §X)`.
- **Motivation** — what gap from §2.2 / §13 this closes, and why now.
- **Proposed behaviour** — request / response shapes, server flow,
  UI flow, error modes. Concrete enough to implement.
- **Impact on existing sections** — every section whose canonical
  content changes once this lands.
- **Open questions** — design decisions not yet made; each must be
  resolved before status moves to `Accepted`.
- **Acceptance criteria** — what "done" looks like for this proposal,
  in addition to the global criteria in §15.

Proposals are numbered `CR-NNNN` with zero-padded four-digit ids,
allocated in order of creation; numbers are never reused.

### 17.1 CR-0001 — Template-driven subject builder in the CSR tool

**Status:** Accepted.

**Motivation:** §6.5 and §11 — the CSR tool
([web/templates/csr_tool.html](../web/templates/csr_tool.html))
is the only path in the WebUI that lets an operator keep the private
key offline (key generation happens entirely in the browser via
`jsrsasign`; nothing reaches the server). Its subject form is
hard-coded to a fixed handful of fields (CN, O, C, serialNumber, one
DNS SAN), with no awareness of the templates the operator's CAs are
configured to issue against. As a result, an operator who needs a
CSR for a specific template has to:

1. Read the template's `subject_name.fields` definition by hand from
   the template editor or the JSON.
2. Mentally translate which fields are mandatory, which have
   defaults, and which RDNs are even allowed.
3. Hope the CSR they paste into
   [certificate_request.html](../web/templates/certificate_request.html)
   passes the patch / validate step, since the rebuild path silently
   drops fields the template doesn't permit and fills in defaults
   they may not have intended.

The structured DN builder used in
[certificate_request.html](../web/templates/certificate_request.html)
and [ca_add.html](../web/templates/ca_add.html) already solves the
"render fields per template" problem. This proposal lifts that
component into the CSR tool so an offline-keyed operator can
generate a CSR that matches the target template by construction.

The privacy contract stays intact: the only network traffic is the
template metadata fetch; the private key is generated and held in
the browser.

**Proposed behaviour:**

UI changes ([csr_tool.html](../web/templates/csr_tool.html)):

- Add a **Template** dropdown at the top of the "Key & Subject"
  card, populated from `GET /api/template`. The dropdown also
  carries a `— Free-form (no template) —` sentinel as its first
  option; selecting it preserves today's hard-coded form.
- When a real template is selected:
  - The subject section is replaced with the structured DN builder
    used in `certificate_request.html`: one input per
    `subject_name.fields` entry, labelled with the same
    `SUBJECT_LABELS` map. Mandatory markers, defaults rendered as
    gray placeholders, regex constraints surfaced as field-level
    validation, exactly per the site-wide rule.
  - The single hard-coded "DNS SAN" input is replaced by a SAN
    block driven by
    `template.extensions.subjectAltName.allowed_types`: one
    dynamic-row group per allowed type (DNS, IP, Email, URI),
    same `addSanRow` / `removeSanRow` machinery as
    `certificate_request.html`. SAN types the template forbids are
    not rendered.
  - The algorithm dropdown is filtered to the template's
    `allowed_cryptography.keyAlgorithms`: RSA shows the permitted
    bit sizes, ECDSA shows the permitted curves, Ed25519 / Ed448
    show as single options if listed. Today's hard-coded
    ECC P-256 + RSA 2048 pair becomes the fallback for free-form
    and for templates with no algorithm constraint.
- When the free-form sentinel is selected, the form reverts to
  today's exact shape (CN / O / C / serialNumber / one DNS SAN +
  algorithm dropdown with ECC P-256 and RSA 2048). No regression
  for operators who never pick a template.
- On submit, the DN string is composed RFC 4514-style from the
  rendered fields (same `composeSubjectDn` pattern as
  [ca_add.html](../web/templates/ca_add.html), with comma /
  equals / plus escaping). For free-form, the existing
  `/CN=…/O=…/C=…` slash format stays.
- SAN entries are folded into the CSR's `extreq` block, one
  `subjectAltName` extension carrying every populated row across
  all permitted types.

No server changes. The tool keeps consuming only `GET /api/template`
(already public-readable) and renders the rest in-browser.

**Impact on existing sections:**

- §2.2 — "structured DN in CSR tool" gap closes (was not previously
  enumerated; this CR also lists it).
- §6.5 — note that the CSR tool now drives subject composition from
  the same template that the issuance pipeline will later enforce,
  so a CSR generated against template T and submitted via
  `POST /certificate/issue` with the same T should round-trip
  without `patch_csr` having to add or override fields.
- §11 — the [csr_tool.html](../web/templates/csr_tool.html) bullet
  gains the template selector, structured DN builder, and
  template-driven algorithm filter.
- §13.10 — the build-time-vs-patch-time inconsistency is partly
  mitigated: a CSR that matches the template at generate time is
  less likely to be silently rewritten at issuance time, making
  template violations easier to spot (the patched CSR's subject
  no longer differs from what the operator typed).

**Resolved decisions:**

1. **Algorithm filter — restrict to the template's permitted set.**
   When a real template is selected, the algorithm dropdown lists
   only the algorithms / key sizes / curves enumerated in
   `template.allowed_cryptography.keyAlgorithms`. Non-permitted
   options are not rendered (no greyed-out items, no warnings — the
   menu simply shows what the template permits). The CSR tool's job
   is to produce a CSR that *will* be accepted, so giving the
   operator any other option is noise.
2. **Library coverage gaps surface as a typed warning.** If the
   template requires an algorithm or curve that the in-browser
   library (`jsrsasign` today — supports RSA + ECDSA P-256 / P-384 /
   P-521; no Ed25519 / Ed448) cannot generate, the tool shows a
   typed warning explaining that the in-browser CSR tool cannot
   generate keys for that algorithm and points the operator to
   server-side keygen instead. The Generate button is disabled while
   the warning is up. This generalises beyond Ed25519: any future
   template requirement the bundled library does not cover follows
   the same pattern.
3. **Subject DN string format follows the library.** The tool uses
   whichever DN string format the chosen library accepts natively.
   `jsrsasign`'s `KJUR.asn1.csr.CSRUtil.newCSRPEM(...)` accepts
   OpenSSL-style `/`-delimited strings via `{subject: {str: "/CN=…"}}`,
   so the structured builder composes that format directly rather
   than introducing an RFC 4514 → OpenSSL translation layer. If the
   library is later swapped for one that prefers RFC 4514, the
   composer changes at one call site; no other code needs to know.
4. **SAN scope mirrors the templates' supported set.** The CSR tool
   renders SAN inputs for exactly the types that templates currently
   model — DNS names, IP addresses, email addresses, URIs — which is
   the same set the cert-request UI already renders. Less-common SAN
   types (`otherName`, `directoryName`, `registeredID`) are not
   modelled by templates today; if templates grow support for them
   later, the CSR tool grows alongside.

**Acceptance criteria** (in addition to §15):

- An operator can pick a certificate template in the CSR tool, fill
  the rendered subject fields, fill any SAN rows, and produce a
  PEM CSR that:
  - Has subject = the RFC 4514 composition of the form, with
    template defaults substituted for blank fields.
  - Carries a `subjectAltName` extension whose entries are exactly
    the SAN rows entered, restricted to the template's
    `allowed_types`.
  - Uses a key algorithm permitted by
    `template.allowed_cryptography.keyAlgorithms`.
- Submitting that CSR to `POST /api/certificate/issue` against the
  same template + a compatible CA succeeds without `patch_csr`
  having to drop or override any operator-supplied field (i.e., the
  CSR and the issued cert have the same subject and SAN).
- The free-form sentinel preserves today's exact form layout and
  submission shape; no observable regression for operators who do
  not select a template.
- The Generate button is disabled with a clear message when the
  selected template requires a key algorithm `jsrsasign` cannot
  generate (see open question 2).
- The private key never reaches the server: a network capture
  during CSR generation shows only the initial `GET /api/template`
  call, no PII or key material in either direction.

---

## 18. Cross-references

- [ca-management-specs.md](ca-management-specs.md) — CA layer that
  signs every cert produced here. The signing pipeline (§7) and the
  CRL pipeline (§9) terminate there.
- [kms-specs.md](kms-specs.md) — KMS specification (provider model,
  backend topology, activation lifecycle, signing API). The signing
  pipeline terminates there indirectly via the CA layer.
- [certificate-template-specs.md](certificate-template-specs.md) — template JSON
  format that drives per-issuance subject / SAN / extension / key-
  algorithm policy.
- [hsm-support-specs.md](hsm-support-specs.md) — HSM-specific contracts
  (PKCS#11 mechanisms, slot addressing, session lifecycle, storage-type
  semantics) that the KMS layer relies on for HSM-backed signing.
- [database.md](database.md) — current schema; the `Certificates`
  columns referenced here.
- [rest-api.md](rest-api.md) — REST API reference; the routes in §10
  are documented there.
- [PROGRESS.md §5](PROGRESS.md) — implementation status per work item.
- [roadmap.md §5](roadmap.md) — strategic intent and remaining work.
