# Certificate Template Management Specification

This is the consolidated specification for the certificate template
management surface in pyPKI. It is the single source of truth for the
template design: lifecycle, data model, JSON grammar, enforcement at
issuance time, REST API, management UI, audit logging, and known
weaknesses + security risks the operator should be aware of.

Status of each work item lives in [PROGRESS.md §6](PROGRESS.md); the
strategic intent and cross-area framing live in
[roadmap.md §5](roadmap.md). The CA layer that consumes templates at
issuance time is specified in
[ca-management-specs.md](ca-management-specs.md); the certificate-issuance
flows that drive template enforcement are in
[certificate-management-specs.md](certificate-management-specs.md). This
document covers the *template layer* only — the policy documents that
sit between the operator's intent and the certificate builder.

A developer reading only this document should have enough to understand
the current behaviour, identify the operator-visible gaps, and plan the
remaining work.

---

## 1. Goals

1. **Templates as first-class entities.** Each template is a
   `CertificateTemplates` row carrying a display name and a JSON
   `definition` that fully specifies the issuance policy: subject DN
   constraints, allowed SAN types, included X.509 extensions, maximum
   validity, and allowed cryptography.
2. **Single source of truth at issuance time.** Only the subject name
   and SAN values come from the certificate request — everything else
   (extensions, criticality, validity ceiling, allowed key algorithms)
   is governed by the template. The CSR-supplied extensions are not
   trusted.
3. **Template-driven subject builder.** Templates declare mandatory /
   optional subject fields with defaults; the issuance UI and REST API
   render forms and compose DNs from those declarations rather than
   accepting free-form DN strings.
4. **Layered validity caps.** Template `max_validity` is the ceiling
   the *template author* commits to. CA `max_validity` is the ceiling
   the *CA operator* commits to. CA certificate `notAfter` is the
   ceiling physics commits to. The issued certificate's `notAfter` is
   the minimum of all three, silently truncated.
5. **CA-default fallback for AIA / CDP.** Templates can declare
   `useCADefault: true` for AIA and CDP entries, letting the CA's
   stored URLs drive issuance and keeping the template portable across
   CAs.
6. **Idempotent template edits.** `template_name` and `definition` are
   mutable in place; templates are referenced by id (not by content
   hash) so updating a template silently changes future issuance
   without rewriting existing certificate rows.
7. **Import / export as plain JSON.** Templates round-trip through
   `POST /api/template` (create) and `GET /api/template/{id}/export`
   (download) as the same JSON document operators edit in the web UI.

---

## 2. Status

### 2.1 What is in place

**Schema and storage**
- `CertificateTemplates` table per §4.1: `id`, `name`, `definition`
  (JSON), `is_default`, audit timestamps. The `definition` JSON is the
  full template document (§7); the `name` column duplicates
  `definition.template_name` for fast lookup.
- Foreign-key incoming: `Certificates.template_id` and
  `ESTAliases.template_id` both reference `CertificateTemplates(id)`
  (see [db.py:3475-3496](../pypki/db.py#L3475-L3496)). Issuance rows
  carry the template id so the audit trail records which policy
  governed the issuance.

**CRUD surface**
- `POST /api/template` — create from JSON body. Role: superadmin /
  admin. Returns the new row id. The body is stored verbatim as
  `definition`; `template_name` is also extracted into the `name`
  column. See [main_routes.py:1369](../web/routes/main_routes.py#L1369).
- `GET /api/template` — list (id, name, audit timestamps only).
- `GET /api/template/{id}` — full record including `definition`.
- `GET /api/template/{id}/export` — download `definition` as a
  pretty-printed JSON file (`<template_name>.json`).
- `PUT /api/template/{id}` — replace name + definition. Role:
  superadmin / admin.
- No `DELETE` endpoint today. Removing a template is currently a
  database-level operation; see §2.2.

**Template loading at issuance time**
- `CertificateTools.load_certificate_template(definition_json)` parses
  the JSON and stores it in `self.__template__` for the lifetime of the
  tool instance.
- `PyPKI._build_cert_tool(template_id)` resolves a template by id on
  every issuance, builds a fresh `CertificateTools`, and loads the
  definition. There is no in-process template cache — each request
  reads the row.

**Subject and SAN composition**
- `CertificateTools.build_subject()` iterates
  `template.subject_name.fields` and, for each declared field, takes the
  request-supplied value when present, the template default when the
  field is mandatory or has a non-empty default, and skips the field
  otherwise. See [certificate_tools.py:123](../pypki/certificate_tools.py#L123).
- `CertificateTools.patch_csr()` rebuilds the operator-supplied CSR so
  that subject and SAN are the template-composed values, the public key
  is the CSR's original key, and the extensions block is regenerated
  per template — extensions copied from the inbound CSR are discarded.
- SAN composition reads `template.extensions.subjectAltName.allowed_types`:
  each type may be declared `allowed`, `mandatory`, `min`, `max`. Values
  for types marked `allowed: false` are dropped.

**Extension assembly**
[certificate_tools.py:build_template_extensions](../pypki/certificate_tools.py#L169)
adds the following extensions when present in the template:

| Extension | Source of values | Notes |
|---|---|---|
| `basicConstraints` | template only | `ca`, `pathLen` controlled by template |
| `keyUsage` | template only | values + criticality from template |
| `extendedKeyUsage` | template `allowed` list | filtered against `OID_MAPPING` |
| `subjectKeyIdentifier` | computed from cert public key | template flag toggles inclusion |
| `authorityKeyIdentifier` | derived from issuing CA (or self for self-signed) | template flag toggles inclusion |
| `policyIdentifiers` | template `values` array | criticality from template |
| `OCSPNoCheck` | template flag | DER-NULL value, never critical |
| `aia` | template per-sub-field, with `useCADefault` falling back to CA's `extensions.aia.authorityInfoAccess[OCSP/caIssuers].url` | sub-fields `ocsp` / `caIssuers` are independent |
| `cdp` | template URL, with `useCADefault` falling back to CA's `extensions.cdp.url` | criticality always template-controlled |
| `subjectAltName` | request-supplied, filtered through `allowed_types` | added by `generate_csr` / `patch_csr`, not by `build_template_extensions` |

**Validity capping**
- `CertificateTools.generate_certificate_from_csr` computes
  `effective_max = min(template.max_validity, ca.max_validity)`
  (treating `-1` / `INFINITE_VALIDITY` as "no cap"); requested
  `validity_days` is capped at `effective_max`.
- `notAfter = now + validity_days` is then capped at the issuing CA's
  certificate `notAfter`. For unlimited (no cap from either),
  `notAfter = 9999-12-31 23:59:59 UTC` (RFC 5280 GeneralizedTime
  far-future).
- All three caps are silent: the issued certificate just gets the
  smaller window; the client is not told its requested validity was
  reduced. See
  [certificate_tools.py:560-590](../pypki/certificate_tools.py#L560-L590).

**Allowed cryptography**
- `CertificateTools.validate_key_algorithm(public_key)` enforces
  `template.allowed_cryptography.keyAlgorithms`: RSA `min_size` /
  `max_size`, ECDSA `curves`, Ed25519 presence. Called at the start of
  every issuance path. When `allowed_cryptography` is absent the
  template accepts any algorithm the CA can sign with.

**Built-in template seed**
- `config/cert_templates/` ships nine reference templates covering the
  common shapes — generic, CA cert, two client variants, server (398-
  day TLS), S/MIME, OCSP responder, IoT device, IoT root CA. See §10.

**Management UI**
- `/template_list.html` — list with import / new / edit / export
  actions; shows max validity and the row's audit timestamps.
- `/template_editor.html` — full structured editor over the JSON
  grammar; switches between numeric `max_validity` and an "unlimited"
  toggle that stores `-1`.
- `/certificate_request.html` integrates the template: selecting a
  template renders the subject + SAN form from the template's
  declarations, and the validity field is silently capped per §1.4.

### 2.2 What is pending

- **No `DELETE /api/template/{id}`.** Removing a template is a
  manual SQL operation today. A delete endpoint with usage-aware
  refusal (rejects when EST aliases or live Certificates reference the
  template) is part of the destructive-action-confirmation work in
  [PROGRESS.md §6](PROGRESS.md).
- **No `is_default` consumer.** The column exists but is not surfaced
  in the UI and not consulted by any route. Either wire it (template
  list defaults the certificate-request dropdown to the default
  template) or drop the column.
- **No schema validation on `definition`.** `POST /api/template` and
  `PUT /api/template/{id}` accept any JSON with a `template_name`
  field. Malformed `definition` documents surface as runtime errors
  during issuance (KeyError, missing keys) rather than 400 at create
  time.
- **Allowed-cryptography enforcement asymmetry.** The CSR-upload path
  validates the operator's CSR key against the template, but the
  server-keygen path also drives key generation off the request body
  (`key_algorithm` / `key_type`); a request that disagrees with the
  template is generated first and only then rejected. Pre-validation
  before key generation would save the wasted keypair.
- **No cross-CA portability check.** A template that references AIA /
  CDP URLs without `useCADefault: true` bakes those URLs into every
  cert it issues, regardless of which CA is used. The UI does not warn
  about this.
- **No template versioning.** Editing a template silently changes
  future issuance; previously-issued certs reference the same
  `template_id` but were built under different rules. The audit row
  records the template id, not the definition snapshot.

---

## 3. Architecture

### 3.1 Layered model

```
   web routes (/template, /certificate/issue*, EST)
              │
              ▼
   PyPKI facade (core.py)            ← resolves template by id, builds cert_tool
              │
              ▼
   CertificateTools                   ← loads template, runs build_subject /
   (template-loaded)                    build_template_extensions / patch_csr
              │
              ▼
   CertificationAuthority             ← provides CA-default AIA/CDP, signs digest
```

- Web routes never touch the template definition; they pass
  `template_id` to the issuance facade.
- `PyPKI._build_cert_tool(template_id)` reads the row, instantiates a
  `CertificateTools`, and calls `load_certificate_template`. There is
  no shared in-process template state — each request gets its own
  tool instance.
- `CertificateTools` is the only module that interprets the template
  grammar. Routes, the CA layer, and the KMS do not parse template
  JSON.

### 3.2 Two design decisions, recorded

**Decision A — Template is policy, request is data.** The certificate
request contributes only the public key, subject field *values*, and
SAN *values*. The template owns everything else: which subject fields
are even legal, which SAN types are allowed, which extensions are
included, their criticality, and the validity ceiling. Extensions on
the inbound CSR are discarded by `patch_csr`. A consequence: a
mis-issuance is a template-author bug, not a requester bug — there is
no way for a requester to elevate a server-auth cert into a CA cert by
crafting the CSR.

**Decision B — Templates are mutable, certificates are
immutable-by-reference.** Issued certificates carry a `template_id`
but do not embed the definition. Editing the template changes future
issuance only; previously-issued certificates remain valid against the
rules that were in force at issuance time, even though those rules are
no longer recoverable from the database. This is intentional — it
matches how operational PKIs are run (the certificate, not the policy
record, is the artifact relying parties consume) — but it means
template edits should be treated as policy changes and audited.

---

## 4. Data model

### 4.1 `CertificateTemplates`

| Column | Type | Notes |
|---|---|---|
| `id` | INT PK AI | |
| `name` | VARCHAR(255) NOT NULL | Display name; duplicated from `definition.template_name` for indexable lookup. |
| `definition` | JSON NOT NULL | Full template document (§7). Stored verbatim. |
| `is_default` | BOOLEAN DEFAULT FALSE | Reserved; no consumer today (see §2.2). |
| `created_at` / `updated_at` | TIMESTAMP | Auto-managed. |

Schema is defined in [db.py:3350-3358](../pypki/db.py#L3350-L3358).

### 4.2 Foreign-key relationships

- `Certificates.template_id` → `CertificateTemplates(id)`, enforced by
  `fk_cert_template_id` (see
  [db.py:3475](../pypki/db.py#L3475)). Issuance records which template
  governed the cert.
- `ESTAliases.template_id` → `CertificateTemplates(id)`, enforced by
  `fk_estalias_template_id` (see
  [db.py:3496](../pypki/db.py#L3496)). EST alias resolution returns
  `(ca_id, template_id)` so EST enrollment runs through the same
  template-driven pipeline as the web UI.

Both FKs are restrictive — the database refuses to delete a referenced
template. That is the reason `DELETE /api/template/{id}` is not
implemented today; the refusal would happen at the SQL level without a
useful error surface.

### 4.3 Migrations

- Initial schema — `CertificateTemplates` introduced together with
  `Certificates` (the FK from `Certificates.template_id` is part of the
  base schema, not a later migration).
- Recent — `is_default` column added; no consumer wired (see §2.2).

---

## 5. Template lifecycle

A template has the following states:

| State | Meaning | Transition |
|---|---|---|
| **non-existent** | No row in `CertificateTemplates`. | `POST /api/template` → **active**. |
| **active** | Row present. Issuance routes can resolve it by id. | `PUT /api/template/{id}` updates name + definition; row stays in this state. |
| **deletion** | Row removal via SQL (no REST surface). | Refused by the FK if any `Certificates` or `ESTAliases` row references it. |

There is no `state` enum on the table today — every row is implicitly
"active". This is fine for a CRUD-only workflow but means there is no
way to deprecate a template (mark it unselectable for new issuance
while keeping existing references intact).

---

## 6. Template CRUD paths

### 6.1 Create from JSON

`POST /api/template` with body = full template definition. The
`template_name` field is required; everything else is implicitly
required at issuance time but not validated at create time.

The implementation
([api_adapters.py:1044-1057](../web/services/api_adapters.py#L1044) →
[db.py:1554-1584](../pypki/db.py#L1554-L1584)) inserts a row with
`name = definition.template_name` and `definition = json.dumps(body)`.
The returned id is what the UI redirects to.

### 6.2 Update

`PUT /api/template/{id}` replaces the row's `name` and `definition`.
Same body shape as create. The implementation
([db.py:1587-1613](../pypki/db.py#L1587-L1613)) does an unconditional
UPDATE; rowcount == 0 returns 404 to the caller.

### 6.3 Export / import

`GET /api/template/{id}/export` returns the stored `definition` as a
pretty-printed JSON file with `Content-Disposition: attachment;
filename="<safe_name>.json"`. The same JSON can be POSTed back to
create a duplicate. There is no auto-naming or conflict detection;
operators must rename if a same-name template already exists.

### 6.4 Delete (pending)

Not implemented (§2.2). The intended behaviour is:

- Refuse with 409 when `Certificates` or `ESTAliases` rows reference
  the template; the error body lists the offending references.
- On success, single DELETE on `CertificateTemplates`. No cascade —
  issued certs carrying a stale `template_id` would orphan the
  reference, which is why the refusal exists.

---

## 7. Template grammar

This section is the operator-facing reference for the JSON document
stored in `CertificateTemplates.definition`. It is the consolidated
home for the grammar; this spec is the single source of truth.

### 7.1 Top-level structure

```json
{
  "template_name": "Server Authentication",
  "max_validity": 398,
  "subject_name": { ... },
  "extensions": { ... },
  "allowed_cryptography": { ... }
}
```

| Field | Type | Required | Description |
|---|---|---|---|
| `template_name` | string | yes | Display name of the template |
| `max_validity` | integer | yes | Maximum certificate validity in days. Use `-1` for unlimited |
| `subject_name` | object | yes | Subject name field configuration |
| `extensions` | object | yes | X.509 extension configuration |
| `allowed_cryptography` | object | no | Allowed key algorithms and sizes |

### 7.2 Subject name

The `subject_name` section defines which Distinguished Name (DN)
attributes are allowed and whether they are required.

```json
"subject_name": {
  "fields": {
    "countryName":            { "mandatory": true,  "default": "US" },
    "stateOrProvinceName":    { "mandatory": false, "default": "" },
    "localityName":           { "mandatory": false, "default": "" },
    "organizationName":       { "mandatory": true,  "default": "" },
    "organizationalUnitName": { "mandatory": false, "default": "" },
    "commonName":             { "mandatory": true,  "default": "" },
    "serialNumber":           { "mandatory": false, "default": "" },
    "emailAddress":           { "mandatory": false, "default": "" }
  }
}
```

#### Available fields

| Field | OID | Notes |
|---|---|---|
| `countryName` | 2.5.4.6 | ISO 3166-1 alpha-2 code (e.g. `"US"`, `"DE"`) |
| `stateOrProvinceName` | 2.5.4.8 | State or province |
| `localityName` | 2.5.4.7 | City or locality |
| `organizationName` | 2.5.4.10 | Organization |
| `organizationalUnitName` | 2.5.4.11 | Organizational unit |
| `commonName` | 2.5.4.3 | Common name (FQDN for server certs, identity for others) |
| `serialNumber` | 2.5.4.5 | Serial number — used for device identity (IoT) |
| `emailAddress` | 1.2.840.113549.1.9.1 | Email address in subject |

#### Field options

| Option | Type | Description |
|---|---|---|
| `mandatory` | boolean | Whether the field must be present in the certificate request |
| `default` | string | Value to use if the field is not provided in the request. Empty string means the field is omitted |

### 7.3 Extensions

#### basicConstraints

Controls whether the certificate is a CA certificate.

```json
"basicConstraints": {
  "critical": true,
  "ca": false,
  "pathLen": null
}
```

| Option | Type | Description |
|---|---|---|
| `critical` | boolean | Whether the extension is marked critical |
| `ca` | boolean | `true` for CA certificates, `false` for end-entity certificates |
| `pathLen` | integer \| null | Maximum CA path length. `null` means unlimited. Only meaningful when `ca` is `true` |

#### keyUsage

Defines the cryptographic operations the certificate key may be used
for.

```json
"keyUsage": {
  "critical": true,
  "values": ["digitalSignature", "keyEncipherment"]
}
```

| Value | Description |
|---|---|
| `digitalSignature` | Signing data, messages, or TLS handshakes |
| `nonRepudiation` | Non-repudiation (content commitment) |
| `keyEncipherment` | Encrypting symmetric keys (RSA key exchange in TLS) |
| `dataEncipherment` | Directly encrypting data (uncommon) |
| `keyAgreement` | Key agreement protocols (ECDH) |
| `keyCertSign` | Signing certificates — required for CA certificates |
| `cRLSign` | Signing Certificate Revocation Lists — required for CA certificates |

#### extendedKeyUsage

Specifies application-level purposes for the certificate key.

```json
"extendedKeyUsage": {
  "critical": false,
  "allowed": ["serverAuth", "clientAuth"]
}
```

| Value | OID | Description |
|---|---|---|
| `serverAuth` | 1.3.6.1.5.5.7.3.1 | TLS server authentication |
| `clientAuth` | 1.3.6.1.5.5.7.3.2 | TLS client authentication |
| `emailProtection` | 1.3.6.1.5.5.7.3.4 | S/MIME email signing and encryption |
| `codeSigning` | 1.3.6.1.5.5.7.3.3 | Code signing |
| `timeStamping` | 1.3.6.1.5.5.7.3.8 | Trusted timestamping authority |
| `ocspSigning` | 1.3.6.1.5.5.7.3.9 | OCSP response signing |
| `smartCardLogon` | 1.3.6.1.4.1.311.20.2.2 | Smart card logon |
| `documentSigning` | 1.3.6.1.4.1.311.10.3.12 | Document signing |
| `anyExtendedKeyUsage` | 2.5.29.37.0 | Any extended key usage (unrestricted) |

#### subjectAltName

Controls which Subject Alternative Name (SAN) types are permitted and
their cardinality.

```json
"subjectAltName": {
  "critical": false,
  "allowed_types": {
    "dnsNames": {
      "allowed": true,
      "mandatory": false,
      "min": 1,
      "max": 5
    },
    "ipAddresses": {
      "allowed": true,
      "mandatory": false,
      "min": 0,
      "max": 3
    },
    "emailAddresses": {
      "allowed": false,
      "mandatory": false
    }
  }
}
```

| SAN Type | Description |
|---|---|
| `dnsNames` | DNS domain names (e.g. `www.example.com`) |
| `ipAddresses` | IPv4 or IPv6 addresses |
| `emailAddresses` | RFC 822 email addresses |

Options per SAN type:

| Option | Type | Description |
|---|---|---|
| `allowed` | boolean | Whether this SAN type may be included |
| `mandatory` | boolean | Whether at least one value of this type is required |
| `min` | integer | Minimum number of values (optional) |
| `max` | integer | Maximum number of values (optional) |

#### subjectKeyIdentifier

Includes the Subject Key Identifier extension, which contains a hash of
the public key.

```json
"subjectKeyIdentifier": {
  "include": true
}
```

#### authorityKeyIdentifier

Includes the Authority Key Identifier extension, linking the
certificate to the issuing CA's key.

```json
"authorityKeyIdentifier": {
  "include": true,
  "critical": false
}
```

#### OCSPNoCheck

Includes the `id-pkix-ocsp-nocheck` extension. Used exclusively on
OCSP responder certificates to indicate that the OCSP responder
certificate itself should not be checked for revocation.

```json
"OCSPNoCheck": {
  "include": true
}
```

#### policyIdentifiers

Includes the Certificate Policies extension with one or more policy
OIDs.

```json
"policyIdentifiers": {
  "critical": false,
  "values": ["2.23.140.1.2.2", "1.3.6.1.4.1.11129.2.5.1"]
}
```

Common policy OIDs:

| OID | Description |
|---|---|
| `2.23.140.1.2.2` | CA/Browser Forum OV (Organization Validated) |
| `2.23.140.1.2.1` | CA/Browser Forum DV (Domain Validated) |
| `2.23.140.1.2.3` | CA/Browser Forum IV (Individual Validated) |
| `2.5.29.32.0` | anyPolicy |

#### cdp

Includes a CRL Distribution Point extension pointing to the location
where the CRL can be fetched. When `useCADefault: true` the URL is
taken from the issuing CA's stored `extensions.cdp.url` instead of the
template's `url` field — the criticality is always template-controlled.

```json
"cdp": {
  "include": true,
  "useCADefault": false,
  "url": "http://crl.example.com/root.crl",
  "critical": false
}
```

#### aia

Includes the Authority Information Access extension with OCSP and/or
CA Issuers URLs. Each sub-field (`ocsp`, `caIssuers`) is independently
toggled. When `useCADefault: true` the URL is taken from the issuing
CA's stored
`extensions.aia.authorityInfoAccess[OCSP|caIssuers].url`.

```json
"aia": {
  "critical": false,
  "ocsp": {
    "include": true,
    "useCADefault": false,
    "url": "http://ocsp.example.com"
  },
  "caIssuers": {
    "include": true,
    "useCADefault": false,
    "url": "http://ca.example.com/ca.crt"
  }
}
```

| Field | Description |
|---|---|
| `ocsp.url` | URL of the OCSP responder for this certificate's CA |
| `caIssuers.url` | URL where the issuing CA certificate can be downloaded |

Either or both sub-fields may be omitted.

### 7.4 Allowed cryptography

Specifies which key algorithms are accepted in certificate requests
for this template. If this section is omitted, all algorithms supported
by the CA are allowed.

```json
"allowed_cryptography": {
  "keyAlgorithms": [
    { "name": "RSA", "min_size": 2048, "default_size": 3072, "max_size": 8192 },
    { "name": "ECDSA", "curves": ["P-256", "P-384", "P-521"] },
    { "name": "Ed25519" }
  ]
}
```

#### RSA

| Option | Type | Description |
|---|---|---|
| `name` | string | Must be `"RSA"` |
| `min_size` | integer | Minimum key size in bits |
| `default_size` | integer | Suggested default key size |
| `max_size` | integer | Maximum key size in bits |

#### ECDSA

| Option | Type | Description |
|---|---|---|
| `name` | string | Must be `"ECDSA"` |
| `curves` | array | Allowed elliptic curves: `"P-256"`, `"P-384"`, `"P-521"` |

#### Ed25519

```json
{ "name": "Ed25519" }
```

No additional options — Ed25519 has a fixed key size.

---

## 8. Template enforcement

### 8.1 Validity capping (silent)

At issuance time, the effective `notAfter` is computed as the minimum
of three caps. Each cap is applied silently — the requester is not
informed that its requested window was reduced.

| Cap | Source | Behaviour |
|---|---|---|
| Requested validity | `validity_days` in the issuance request, or `-1` (unlimited) when absent | Starting point. |
| Template ceiling | `template.max_validity` | If positive, caps the requested value. |
| CA policy ceiling | `ca.max_validity` | If positive, further caps the requested value. The smaller of `template.max_validity` and `ca.max_validity` wins. |
| CA cert expiry | `issuing_ca.notAfter` | Final cap on the computed `notAfter`. A cert cannot outlive its issuer. |

For unlimited results (every cap is `-1`), the issued certificate's
`notAfter` is set to `9999-12-31 23:59:59 UTC` (RFC 5280
GeneralizedTime far-future). See
[certificate_tools.py:560-590](../pypki/certificate_tools.py#L560-L590).

### 8.2 Subject DN composition

`build_subject` walks `subject_name.fields` in declaration order and:

- If the request supplies a non-empty value for the field, that value
  is used.
- Otherwise, if the template's `default` is non-empty, it is used.
- Otherwise, if `mandatory: false`, the field is omitted.
- Otherwise, the issuance fails with `ValueError`.

`patch_csr` then rebuilds the CSR with this composed subject, signs it
with a throw-away key, and the CA signs the final certificate built
from the patched CSR. The original CSR's subject is discarded.

### 8.3 SAN filtering

SAN composition reads
`template.extensions.subjectAltName.allowed_types`. For each SAN type
in the request:

- If the type is not declared in the template or is declared
  `allowed: false`, its values are dropped.
- If the type is declared `mandatory: true` and the request supplies
  zero values, issuance fails.
- `min` / `max` cardinality constraints are accepted in the grammar
  but not currently enforced at issuance time (see §11.4).

### 8.4 Extension regeneration

Extensions copied from the inbound CSR are not trusted.
`build_template_extensions` regenerates the full extension block from
the template definition (table in §2.1). The certificate-tools layer
adds:

- `basicConstraints` — verbatim from template.
- `keyUsage` / `extendedKeyUsage` — values + criticality from template.
- `policyIdentifiers` — values + criticality from template.
- `OCSPNoCheck` — DER-NULL value, criticality always `false`.
- `subjectKeyIdentifier` — computed from the CSR's public key when
  the template flag is set.
- `authorityKeyIdentifier` — from the issuing CA's public key (or
  from the cert's own SKI for self-signed) when the template flag is
  set.
- `aia` / `cdp` — per §7.3, with `useCADefault: true` pulling the URL
  from the issuing CA's stored `extensions` JSON.

### 8.5 Allowed-cryptography enforcement

`validate_key_algorithm(public_key)` is called once per issuance,
against the public key the certificate will carry:

- For CSR upload: against the CSR's public key.
- For server-side keygen: against the freshly-generated key, *after*
  generation. Mis-aligned `key_algorithm` / `key_type` in the request
  results in a key being generated and then rejected — see §2.2.

A template with no `allowed_cryptography` block accepts any algorithm
supported by the CA signing pipeline.

---

## 9. REST API specification

```
POST   /api/template                           create from JSON body
GET    /api/template                           list (id, name, audit timestamps)
GET    /api/template/{id}                      read full record
GET    /api/template/{id}/export               download definition as JSON file
PUT    /api/template/{id}                      replace name + definition
```

Role enforcement:
- `POST` and `PUT` require `superadmin` or `admin`.
- `GET` requires an authenticated session (any role, since templates
  are not secret).

No `DELETE` endpoint today (§2.2). The FK from `Certificates` and
`ESTAliases` would refuse the delete at the SQL level anyway; a usage-
aware refusal at the REST surface is the intended replacement.

The grammar accepted by `POST` / `PUT` is §7. The server stores the
body verbatim; downstream issuance is what enforces structural
correctness.

---

## 10. Management UI

Template management lives under `/template_list.html` plus the editor:

- **Templates list** ([template_list.html](../web/templates/template_list.html))
  — list with import / new / edit / export actions per row. Shows
  `name`, `max_validity` (with `"Unlimited"` substituted for `-1`),
  and audit timestamps.
- **Template editor** ([template_editor.html](../web/templates/template_editor.html))
  — full structured editor: name, validity (numeric input plus
  "unlimited" toggle that swaps the value to `-1`), per-subject-field
  include/mandatory/default rows, per-extension toggles with
  criticality, AIA / CDP URL fields with the `useCADefault` flag,
  policy-OID rows, and allowed-cryptography algorithm rows.
- **Issuance integration** ([certificate_request.html](../web/templates/certificate_request.html))
  — selecting a template renders the subject + SAN form from the
  template's declared fields and SAN types; the "Validity (days)"
  field is silently capped per §8.1; help text states the cap chain.

Built-in templates ship in `config/cert_templates/` (see §10.1) and are
loaded on first run.

### 10.1 Built-in template files

Located in [config/cert_templates/](../config/cert_templates/):

| File | Purpose |
|---|---|
| `template_base.json` | Generic template showing all available options |
| `ca_cert_template.json` | CA certificate (keyCertSign, cRLSign) |
| `client_cert_template.json` | TLS client authentication |
| `client_cert_template_v2.json` | Minimal client template |
| `server_cert_template.json` | TLS server (398-day max, serverAuth) |
| `smime_cert_template.json` | S/MIME email protection (825-day max) |
| `ocsp_responder_cert_template.json` | OCSP responder (ocspSigning + OCSPNoCheck) |
| `iot_device_cert_template.json` | IoT device client certificates |
| `iot_rootca_cert_template.json` | IoT root CA (ECDSA only) |

### 10.2 Pending UI work matching §2.2

- Inline validation on the template form (`max_validity` >= -1,
  extension OID syntax, AIA / CDP URL syntax, allowed-cryptography
  consistency).
- Destructive-action confirmation on delete (when the delete endpoint
  lands) showing reference counts.
- "Default template" surface — picker + dashboard indicator — once
  the `is_default` consumer is wired.

---

## 11. Audit logging

Every successful `CREATE` and `UPDATE` on `CertificateTemplates`
produces an `AuditLogs` row referencing `resource_type='templates'`,
the template id, and the acting user id.

Pending (per §2.2):
- `DELETE` event when the delete endpoint lands.
- Snapshot of the previous `definition` on `UPDATE` so the audit row
  is a useful artifact for incident response. Today the audit row is
  metadata-only; the previous content is unrecoverable.

---

## 12. Weaknesses and security risks

This section is the **operator-visible audit** of known issues. Each
item is either accepted (with mitigation) or scheduled for closure.

### 12.1 No schema validation on `definition`

**Risk:** Malformed template JSON is accepted at create / update time
and surfaces only as a `KeyError` at issuance time. The 500 leaks
internal field names; the failure happens on the first issuance, not
on the change.
**Mitigation today:** operators manually compare against `template_base.json`.
**Closure:** validate `definition` against a JSON Schema (or an
explicit dataclass-based parser) at `POST` / `PUT`; return 400 with
the offending path on mismatch.

### 12.2 Template edits are silent policy changes

**Risk:** Updating a live template silently changes the policy for
future issuance. Past certificates reference the same `template_id`
but were built under different rules; the audit row records the id,
not the snapshot. Reconstructing "what rules applied to cert X" is
impossible without external bookkeeping.
**Mitigation today:** none.
**Closure paths:** (a) snapshot the `definition` on each
`UPDATE` into the audit row body; (b) move to immutable template
versions with explicit supersession (`template.previous_id`) — bigger
change.

### 12.3 No `DELETE` surface

**Risk:** Templates accumulate. Operators can mark unused rows but
not remove them via the REST API; manual SQL is required, and the FK
will refuse anyway when the template is referenced.
**Mitigation today:** rename obsolete templates with a `[deprecated]`
prefix.
**Closure:** `DELETE /api/template/{id}` per §6.4, with usage-aware
refusal.

### 12.4 SAN cardinality is declared but not enforced

**Risk:** `subjectAltName.allowed_types.<type>.min` /
`.max` is accepted in the grammar but the issuance path does not
enforce it. A template that says `max: 3` will happily issue a cert
with five SAN entries.
**Mitigation today:** UI-side validation only.
**Closure:** enforce min / max on `build_san` / `patch_csr`; reject at
issuance time with a 400.

### 12.5 Cross-CA URL portability

**Risk:** Templates that bake AIA / CDP URLs (no `useCADefault`)
issue certificates carrying those URLs regardless of which CA signed
them. A template designed for one CA can issue from another and
produce certificates that point to the wrong OCSP responder / CRL
endpoint. The UI does not warn.
**Mitigation today:** template-author discipline.
**Closure:** UI banner when a non-`useCADefault` URL is set; consider
warning in the issuance flow when the chosen CA's defaults differ from
the template's baked URLs.

### 12.6 Server-keygen path wastes a keypair on policy rejection

**Risk:** The PKCS#12 path (`POST /api/certificate/issue-pkcs12`)
generates the keypair *before* `validate_key_algorithm`. A request
with `key_algorithm` / `key_type` outside the template's
`allowed_cryptography` produces a keypair, then 4xxs. For HSM-backed
keygen this is more than a wasted CPU cycle — it consumes a slot or
emits an HSM operation.
**Mitigation today:** UI restricts the keygen dropdown to the
template's allowed set.
**Closure:** validate the requested algorithm against
`allowed_cryptography` at the route layer, before key generation.

### 12.7 Template enforcement bypassable in `core.py`, not just at the route

**Risk:** `core.generate_certificate_from_csr(..., enforce_template=False)`
is a legal call. Routes always pass `enforce_template=True`, but a
utility script or future caller can opt out. There is no audit trail of
the bypass.
**Mitigation today:** routes always enforce; utility-script use is
operator-controlled.
**Closure:** make `enforce_template=True` the only public surface;
move the bypass behind a private helper used only by self-signed root
issuance (which legitimately needs the bypass because subject == issuer
trivially satisfies the template).

### 12.8 `is_default` column has no consumer

**Risk:** Column exists, can be set via SQL, but nothing reads it.
Operators may assume marking a template default has an effect.
**Mitigation today:** UI does not expose the flag.
**Closure:** either wire it (issuance UI defaults the dropdown when
unset) or drop the column.

---

## 13. Order of work

The pending items in §2.2 / §12 group into three phases.

**Phase A — Validation and safety (small, high-value)**
1. JSON-schema validation of `definition` on `POST` / `PUT` (§12.1).
2. SAN-cardinality enforcement (§12.4).
3. Pre-keygen policy check on the PKCS#12 path (§12.6).

**Phase B — Lifecycle gaps**
4. `DELETE /api/template/{id}` with usage-aware refusal (§6.4 / §12.3).
5. Snapshot `definition` into the `UPDATE` audit-row body (§12.2).
6. Decide on `is_default`: wire or drop (§12.8).

**Phase C — Policy clarity**
7. UI warning when a template bakes non-`useCADefault` URLs (§12.5).
8. Move `enforce_template=False` behind a private helper (§12.7).

Phase A keeps the surface area unchanged but turns runtime failures
into create-time 400s. Phase B reshapes the lifecycle. Phase C
addresses policy-author footguns once the lifecycle is sound.

---

## 14. Acceptance criteria

A template lifecycle is **correct** when, for every template the
operator manages through the REST API or UI:

- The stored `definition` round-trips through export → re-import →
  export with byte-identical JSON (modulo formatting).
- A template that fails JSON-schema validation is rejected at
  `POST` / `PUT` with a 400 naming the bad path — never reaches
  issuance.
- The audit log on `UPDATE` contains the previous `definition`
  snapshot, so operators can answer "what rules applied to cert X"
  from data already in the database.
- Issuance failures from template mismatch surface as 4xx responses
  with the specific offending field; 5xx is reserved for genuine
  server faults.
- `DELETE` returns 409 with a reference manifest when the template is
  in use; on success the row is gone and no orphaned `template_id`
  remains in `Certificates` or `ESTAliases`.

A **stable platform** has, in addition:

- Allowed-cryptography validation runs before keygen on every issuance
  path.
- Template-baked AIA / CDP URLs are flagged in the UI when they
  diverge from the issuing CA's defaults.

---

## 15. Out of scope for this spec

- The certificate issuance pipeline that consumes templates — see
  [certificate-management-specs.md](certificate-management-specs.md).
- CA-level issuance policy (`max_validity`, `serial_number_length`,
  `extensions` JSON) — see
  [ca-management-specs.md](ca-management-specs.md).
- Key generation and signing operations triggered by template
  enforcement — see [kms-specs.md](kms-specs.md).
- Template-driven EST enrollment — covered in
  [certificate-management-specs.md §6.4](certificate-management-specs.md).

---

## 16. Cross-references

- [ca-management-specs.md](ca-management-specs.md) — CA layer that
  consumes templates at issuance time; CA `max_validity` is one of
  the validity caps in §8.1.
- [certificate-management-specs.md](certificate-management-specs.md) —
  end-entity issuance flows (CSR upload, server-keygen, EST) that all
  drive through template enforcement.
- [kms-specs.md](kms-specs.md) — KMS surface that signs the resulting
  certificate; allowed-cryptography enforcement upstream determines
  which KMS operations are reachable.
- [est-specs.md](est-specs.md) — EST service specification; aliases
  reference templates via `ESTAliases.template_id` and run the same
  enforcement pipeline.
- [database-specs.md](database-specs.md) — `CertificateTemplates` schema and the
  FKs from `Certificates` / `ESTAliases`.
- [PROGRESS.md](PROGRESS.md) — current implementation status.
- [roadmap.md](roadmap.md) — strategic intent.
