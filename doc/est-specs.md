# EST Service Specification

This is the consolidated specification for the Enrollment over Secure
Transport (EST) surface in pyPKI. It is the single source of truth for
the EST design: the protocol subset implemented, the alias model that
binds enrollment URLs to CA + template + auth policy, the REST surface
that manages those aliases, the management UI, audit logging, known
weaknesses + security risks, and the change requests that extend
authentication beyond HTTP Basic.

Status of each work item lives in [PROGRESS.md §2](PROGRESS.md); the
strategic intent and cross-area framing live in
[roadmap.md §2](roadmap.md). The certificate-issuance pipeline that
EST drives is specified in
[certificate-management-specs.md](certificate-management-specs.md);
the template enforcement applied to every EST issuance is in
[certificate-template-specs.md](certificate-template-specs.md); the
CA layer that signs the resulting certificate is in
[ca-management-specs.md](ca-management-specs.md). This document covers
the *EST layer* only — what sits between an RFC 7030 client and the
internal issuance pipeline.

A developer reading only this document should have enough to
understand the current behaviour, identify the operator-visible gaps,
and plan the remaining work.

---

## 1. Goals

1. **Standards-conformant enrollment.** Expose a useful subset of
   RFC 7030 (`cacerts`, `simpleenroll`) so any compliant EST client
   can request and receive certificates without bespoke integration.
2. **Aliases as first-class entities.** Each enrollment profile is an
   `ESTAliases` row binding a CA, a template, an authentication
   policy, and an optional `is_default` marker. Different clients can
   enroll under different URL paths with different policies against
   the same pyPKI instance.
3. **Non-bypassable template enforcement.** Every EST issuance runs
   through the same template pipeline as the management UI, with
   `enforce_template=True` always set. The CSR's subject, SAN, and
   extensions are recomposed from the template; the CSR contributes
   only the public key and the request-supplied identity values.
4. **Pluggable authentication.** HTTP Basic Auth is the only currently
   wired authenticator, but the alias schema reserves a
   `cert_fingerprint` column for mTLS client-cert auth (CR-0001).
   `cacerts` is always public per RFC 7030 §4.1.
5. **Operator surface parity.** EST aliases are CRUD-managed through
   the same REST + UI vocabulary as CAs, templates, and OCSP
   responders. There is no separate config file or environment-only
   path.
6. **Auditable issuance.** EST enrollments produce the same
   `AuditLogs` rows as web-UI issuance, tagged with the resolving
   alias and the resulting certificate id.

---

## 2. Status

### 2.1 What is in place

**RFC 7030 endpoints**
- `GET /.well-known/est/<label>/cacerts` and `GET /.well-known/est/cacerts`
  — returns the alias's CA certificate. Always public (no auth) per
  RFC 7030 §4.1. Response body is PEM today (see §10.1 weakness),
  served as `application/x-pem-file` with `Content-Disposition`.
  See [est_routes.py:49-71](../web/routes/est_routes.py#L49-L71).
- `POST /.well-known/est/<label>/simpleenroll` and the no-label form —
  accepts a PEM-encoded PKCS#10 CSR in the body, validates Basic Auth
  when the alias requires it, runs the §5 template-driven issuance,
  and returns a PKCS#7 SignedData envelope (DER, base64-encoded) with
  `Content-Type: application/pkcs7-mime; smime-type=certs-only` and
  `Content-Transfer-Encoding: base64`. RFC 7030 §4.2.3-compliant.
  See [est_routes.py:74-119](../web/routes/est_routes.py#L74-L119).
- `POST /.well-known/est/<label>/simpleenrollpem` — **non-standard**
  variant of `simpleenroll` that returns the issued certificate as
  raw PEM. Useful for tooling that does not parse PKCS#7. Clearly
  flagged as non-standard in the source. See
  [est_routes.py:126-167](../web/routes/est_routes.py#L126-L167).

**Alias resolution**
- The `<label>` path segment resolves to an `ESTAliases` row by `name`.
  Missing label → row with `is_default=TRUE`.
- The resolver returns `(ca_id, template_id, username,
  password_hash, cert_fingerprint)` — `cert_fingerprint` is wired
  through end-to-end but not yet enforced (CR-0001).
- Unknown labels return 404 with the literal body `Invalid label`.

**Authentication (Basic)**
- When the alias has a non-empty `username`, every `simpleenroll` /
  `simpleenrollpem` request must carry an HTTP Basic Authorization
  header. Credentials are verified against the stored
  `password_hash` (Werkzeug `pbkdf2:sha256`).
- When the alias has no `username` set, the endpoint is open. This is
  an explicit operator choice — the schema does not force auth.
- 401 responses include a `WWW-Authenticate: Basic realm="EST"`
  challenge **only on the first** un-authenticated request (no
  `Authorization` header present). Once credentials have been
  presented and rejected, the challenge is suppressed so browsers do
  not pop up the native Basic-Auth dialog. See
  [est_routes.py:36-47](../web/routes/est_routes.py#L36-L47).
- `cacerts` is always reachable regardless of `username`.

**Alias management (admin REST API)**
- `GET /api/est` — list aliases (id, name, ca_id, template_id,
  username, is_default — `password_hash` stripped).
- `POST /api/est` — create alias. Required: `name`, `ca_id`,
  `template_id`, `username`, `password`. Optional: `cert_fingerprint`.
- `GET /api/est/{id}` — full alias record (password_hash stripped).
- `PUT /api/est/{id}` — update alias. Password is re-hashed only when
  the `password` field is non-empty; omit to preserve the existing
  hash.
- `DELETE /api/est/{id}` — delete alias.
- `POST /api/est/{id}/set-default` — clear the `is_default` flag on
  every other row and set it TRUE on this one.

All write endpoints require role `superadmin` or `admin`. See
[main_routes.py:827-901](../web/routes/main_routes.py#L827-L901).

**Template enforcement (always on)**
- The EST path passes the request through
  `api_adapters.generate_certificate_from_csr`, which sets
  `enforce_template=True` non-overridably. The CSR's subject, SAN, and
  extensions are recomposed by the template (see
  [certificate-template-specs.md §8](certificate-template-specs.md)).

**Management UI**
- `/est_list.html` — list view with default-alias radio,
  default-badge, edit and delete row actions, "New Endpoint" header
  button.
- `/est_editor.html` — create / edit form with three cards: Endpoint
  (name, CA, template), Basic Authentication (username, password),
  and "mTLS (future)" — visible field for `cert_fingerprint`,
  permanently disabled with a "Not enforced yet" badge.
- `/est_test.html` — operator-facing tester that pulls
  `cacerts` and runs `simpleenroll` against any configured alias from
  the browser.

**Audit logging**
- Every `CREATE` / `UPDATE` / `DELETE` on `ESTAliases` produces an
  `AuditLogs` row with `resource_type='est_aliases'`,
  `resource_id=<alias_id>`, and the acting user id. See
  [api_adapters.py:305-366](../web/services/api_adapters.py#L305-L366).
- EST `simpleenroll` / `simpleenrollpem` writes the same certificate
  audit rows as the web-UI CSR path (see
  [certificate-management-specs.md §12](certificate-management-specs.md)).

### 2.2 What is pending

- **mTLS client-certificate authentication.** Schema field
  (`cert_fingerprint`), UI placeholder, and adapter plumbing exist;
  the enforcement step is not wired. Tracked in
  [roadmap.md §2](roadmap.md) and
  [PROGRESS.md §2](PROGRESS.md); detailed in §15.1 (CR-0001) below.
- **`simplereenroll` (RFC 7030 §4.2.2).** Not implemented; PROGRESS
  reference test coverage mentions it as a target but the route does
  not exist.
- **`csrattrs` (RFC 7030 §4.5).** Not implemented; clients cannot
  query the server for required CSR attributes.
- **`serverkeygen` (RFC 7030 §4.4).** Not implemented; the
  server-side keygen path is wired for the management UI
  (`/api/certificate/issue-pkcs12`) but not exposed over EST.
- **`cacerts` PKCS#7 envelope.** The current response is raw PEM.
  RFC 7030 §4.1.3 prescribes a PKCS#7 SignedData wrapper with
  `application/pkcs7-mime; smime-type=certs-only`. The current shape
  is compatible with most tooling but technically non-compliant.
- **CA chain on `cacerts`.** The endpoint returns only the leaf CA
  certificate, not the issuer chain. Strict clients that build a
  trust path top-down receive an incomplete bundle.
- **EST inline form validation.** Listed in
  [PROGRESS.md §6](PROGRESS.md) — `username` / `password` /
  `cert_fingerprint` cross-field rules not validated client-side.
- **EST alias delete confirmation in UI.** Standard list-row delete
  with confirm modal exists; refusal-on-references is not modelled
  (deleting an alias never refuses, even if clients are actively
  enrolling).

---

## 3. Architecture

### 3.1 Layered model

```
    EST client (PEM / DER PKCS#10)
              │
              ▼
   web.routes.est_routes               ← alias lookup, auth check,
              │                          MIME wrapping
              ▼
   web.services.api_adapters
   .generate_certificate_from_csr      ← enforces template
              │
              ▼
   pypki.core.PyPKI                    ← issuance pipeline:
              │                          template + CA + KMS
              ▼
   CertificateTools (template-loaded)
              │
              ▼
   CertificationAuthority → KMS        ← sign_tbs_digest
```

- EST routes own the protocol-level concerns: URL parsing, auth gate,
  MIME wrapping. They do not touch keys, templates, or the database
  directly.
- The adapter is the single integration point with the rest of the
  system. EST and the management UI share the same adapter call
  (`generate_certificate_from_csr`), so any policy change applies to
  both surfaces.
- Alias resolution happens once per request via
  `api_adapters.get_ca_and_template_id_by_alias_name(label)`, which
  returns either the full alias row or `None`.

### 3.2 Two design decisions, recorded

**Decision A — Alias is the policy boundary.** All EST policy
(CA, template, auth) lives on the `ESTAliases` row. A `(ca, template)`
pair can be exposed at multiple URLs with different auth, and a single
URL has exactly one policy stance. Clients are identified only by
what they prove against that policy — there is no per-client
configuration on top of the alias.

This is what makes mTLS extensible (CR-0001): the alias already
carries `cert_fingerprint`, so enforcing it is a route-layer change,
not a schema change.

**Decision B — `enforce_template=True` is non-overridable for EST.**
The management UI accepts a `subject` / `san` override that the
operator can use to compose the DN from form fields when the CSR's
subject is empty. EST passes neither: the request body is just the
CSR, and the template's `subject_name.fields` defaults are what fill
gaps. This is intentional — EST clients are remote and not
necessarily trusted to send a clean subject; the template gets the
last word.

Decision A is the "what governs this request" decision; Decision B is
the "how rigorously is it governed" decision.

---

## 4. Data model

### 4.1 `ESTAliases`

Reproduced here for convenience; the authoritative definition lives
in [database-specs.md §4.6](database-specs.md).

| Column | Type | Constraints | Description |
|---|---|---|---|
| `id` | INT | PK, AUTO_INCREMENT | |
| `name` | VARCHAR(255) | NOT NULL | Alias name; appears in the URL path. Functionally unique but not enforced (§10.2). |
| `ca_id` | INT | FK → `CertificationAuthorities(id)` | Signing CA. |
| `template_id` | INT | FK → `CertificateTemplates(id)` | Issuance policy. |
| `is_default` | BOOLEAN | DEFAULT FALSE | Selected when the URL has no label. |
| `username` | VARCHAR(255) | | Basic Auth user. Empty / NULL → endpoint is open. |
| `password_hash` | VARCHAR(255) | | Werkzeug PBKDF2-SHA256 hash. Never returned by the API. |
| `cert_fingerprint` | VARCHAR(255) | | **Reserved** for mTLS client-cert auth (CR-0001). |
| `created_at` / `updated_at` | TIMESTAMP | Auto-managed. | |

### 4.2 Foreign-key relationships

- `ESTAliases.ca_id` → `CertificationAuthorities(id)` via
  `fk_estalias_ca_id`. Refuses CA delete by SQL; the
  CA-delete cascade in
  [db.py:932-1000](../pypki/db.py#L932-L1000) deletes the alias row
  before the CA row.
- `ESTAliases.template_id` → `CertificateTemplates(id)` via
  `fk_estalias_template_id`. Refuses template delete by SQL; templates
  have no delete endpoint today (see
  [certificate-template-specs.md §6.4](certificate-template-specs.md)).

---

## 5. Issuance pipeline

The end-to-end flow for an authenticated `simpleenroll`:

1. **Route dispatch.** Flask routes `<path:label>` so labels with
   slashes are tolerated. The dispatcher distinguishes label-less and
   labelled variants by route order.
2. **Alias resolution.**
   `get_ca_and_template_id_by_alias_name(label)` → row dict or
   `None`. `None` + label set → 404. `None` + label unset → fall
   through to the default alias.
3. **Auth gate.** `_check_basic_auth(est_config)` returns:
   - `True` when `username` is empty / NULL (open endpoint).
   - `True` when the Authorization header carries a Basic credential
     whose `(username, password)` matches the stored hash.
   - `False` otherwise → 401, with the challenge header included
     only on the first un-authenticated request.
4. **CSR decode.** Raw request body is treated as a PEM CSR. No
   conversion to DER is performed; the body must be PEM. (RFC 7030
   §4.2.1 prescribes base64-encoded DER on the wire; today pyPKI
   accepts PEM, which most tooling produces. Tracked under §10.4.)
5. **Issuance.**
   `api_adapters.generate_certificate_from_csr(est_config, csr_pem)`
   runs the §6.1 flow from
   [certificate-management-specs.md](certificate-management-specs.md):
   - Template enforcement (subject, SAN, extensions regenerated).
   - Validity capping (template / CA `max_validity` / CA `notAfter`).
   - CA's KMS-bound signing key produces the signature via the
     dummy-key + DER-patch pipeline.
   - A `Certificates` row is inserted with `(ca_id, template_id,
     fingerprint, …)`.
6. **Response envelope.**
   - `simpleenroll` → `pkcs7.serialize_certificates([new_cert])` →
     base64 → `application/pkcs7-mime; smime-type=certs-only` +
     `Content-Transfer-Encoding: base64`.
   - `simpleenrollpem` → `new_cert.public_bytes(Encoding.PEM)` →
     `application/x-pem-file` with `Content-Disposition: attachment`.
7. **Audit.** The certificate insert path writes the standard
   `Certificates` audit row; the EST route itself does not write a
   separate audit row.

Errors:
- `BackendError` (KMS / HSM) re-raises so the application-level
  error handler produces the structured 503 surface (CR-0005 decision
  3 — same shape as the web-UI path).
- Any other exception returns `400` with the body
  `Error: <repr>`. This is coarse — §10.6.

---

## 6. Authentication

### 6.1 Basic Auth (current)

`Authorization: Basic <base64(user:pass)>` is verified against the
alias's stored `password_hash`. The hash format is Werkzeug
PBKDF2-SHA256, the same one used by management UI users — so an
operator can recycle credential management practices across the two
surfaces.

The 401 challenge suppression is deliberate: it makes EST clients
that drive the API from scripts behave correctly (they get a clean
401 without the browser-prompt protocol), while still being
discoverable on the first request from a browser.

### 6.2 Open endpoint (current)

`username = NULL` or empty disables the auth gate entirely for that
alias. This is useful for trusted-network deployments where mTLS at
the transport layer or IP allow-listing in the reverse proxy provides
the authentication boundary.

### 6.3 mTLS client-certificate auth (planned — CR-0001)

The `cert_fingerprint` column is reserved and threaded through the
management surface but not yet enforced. The full design is in §15.1.

### 6.4 `cacerts` (always public)

Per RFC 7030 §4.1, `cacerts` MUST be reachable without authentication
so that clients can establish trust before presenting credentials.
The auth gate is skipped on this route regardless of `username` /
`cert_fingerprint` on the alias.

---

## 7. Template enforcement specifics for EST

The general template-enforcement contract is in
[certificate-template-specs.md §8](certificate-template-specs.md).
For EST specifically:

- **No subject overrides on the wire.** EST clients submit only the
  CSR. There is no companion `subject` / `san` JSON object the way
  the management UI's `/api/certificate/issue` accepts. The
  template's `subject_name.fields` defaults are applied directly to
  CSR-missing fields.
- **Extensions on the inbound CSR are discarded.** `patch_csr`
  regenerates the extension block from the template; a CSR carrying
  `basicConstraints: CA=TRUE` does not produce a CA cert.
- **`enforce_template=True` is non-negotiable.** Routes pass it
  explicitly; the adapter does not expose a flag to disable it on the
  EST path.
- **Allowed-cryptography enforcement.**
  `validate_key_algorithm(csr.public_key())` runs before signing.
  Templates with an `allowed_cryptography` block reject keys outside
  the declared set; templates without the block accept any algorithm
  the CA can sign with.

---

## 8. REST API specification

### 8.1 Alias management (admin surface)

```
GET    /api/est                                  list aliases
POST   /api/est                                  create alias
GET    /api/est/{id}                             read alias
PUT    /api/est/{id}                             update alias
DELETE /api/est/{id}                             delete alias
POST   /api/est/{id}/set-default                 set as default alias
```

Role enforcement:
- `POST`, `PUT`, `DELETE`, `set-default` require `superadmin` or
  `admin`.
- `GET` requires an authenticated session (any role; aliases are not
  secret beyond the `password_hash` which is stripped).

The legacy unauthenticated `GET /api/getestaliases` exists for
backwards compatibility; it returns the same shape as `GET /api/est`.

### 8.2 EST protocol surface

```
GET    /.well-known/est/cacerts                  default-alias cacerts
GET    /.well-known/est/{label}/cacerts          labelled cacerts
POST   /.well-known/est/simpleenroll             default-alias enrollment (PKCS#7)
POST   /.well-known/est/{label}/simpleenroll     labelled enrollment (PKCS#7)
POST   /.well-known/est/simpleenrollpem          default-alias enrollment (PEM, non-standard)
POST   /.well-known/est/{label}/simpleenrollpem  labelled enrollment (PEM, non-standard)
```

Status codes:
- `200` — success.
- `401` — Basic Auth required and credentials missing / wrong.
- `404` — unknown label (`Invalid label`).
- `400` — anything else (CSR parse failure, template rejection, …).
  Per §10.6 the body is informational, not structured.
- `503` — structured KMS / HSM failure (CR-0005).

The label-less form on `simpleenroll[pem]` resolves to the alias with
`is_default=TRUE`. If no row has the flag set, the request 500s on
the implicit `None` config — §10.7.

---

## 9. Management UI

EST management lives under `/est_list.html`:

- **EST Config list**
  ([est_list.html](../web/templates/est_list.html)) — table with
  default-alias radio, default badge, edit and delete row actions,
  "New Endpoint" header button.
- **EST Editor**
  ([est_editor.html](../web/templates/est_editor.html)) — create /
  edit form. Three cards:
  - *Endpoint* — name (used in URL), CA dropdown, template dropdown.
  - *Basic Authentication* — username + password. Password optional
    on update (blank preserves the stored hash; mandatory on
    create).
  - *mTLS (future)* — `cert_fingerprint` field, **permanently
    disabled** in the current build, with a "Not enforced yet" badge.
    The field is wired through `POST` / `PUT` so a value submitted
    via the REST API persists, but the UI does not let an operator
    set it. CR-0001 will toggle the disabled state once enforcement
    lands.
- **EST Test** ([est_test.html](../web/templates/est_test.html)) —
  operator-facing tester. Pick an alias from a dropdown, see the
  computed `cacerts` / `simpleenroll` URLs, paste a CSR, run the
  request from the browser. Credentials are entered live and never
  persisted.

---

## 10. Weaknesses and security risks

This section is the **operator-visible audit** of known issues. Each
item is either accepted (with mitigation) or scheduled for closure.

### 10.1 `cacerts` does not return a PKCS#7 envelope

**Risk:** RFC 7030 §4.1.3 prescribes
`application/pkcs7-mime; smime-type=certs-only` for the cacerts
response, with the CA chain wrapped in PKCS#7 SignedData. pyPKI
returns raw PEM. Strict EST clients refuse the response.
**Mitigation today:** common tooling (curl, openssl, custom scripts)
handles raw PEM out of the box.
**Closure:** wrap the response in PKCS#7 the same way `simpleenroll`
does, and include the CA chain (not just the leaf).

### 10.2 Alias `name` functional uniqueness not enforced

**Risk:** Two aliases can share a `name`. The resolver picks the
first match, which is implementation-defined. Operators creating
typo'd duplicates do not see a collision warning.
**Mitigation today:** UI surfaces all rows; the operator can spot
duplicates visually.
**Closure:** `UNIQUE KEY` on `ESTAliases.name`; see
[database-specs.md §8.1](database-specs.md).

### 10.3 `is_default` is not unique

**Risk:** Multiple aliases can have `is_default=TRUE` if SQL is
issued directly. The default-resolution query returns the
implementation-defined first row.
**Mitigation today:** `POST /api/est/{id}/set-default` clears the
flag on all other rows transactionally; the UI uses this endpoint
exclusively.
**Closure:** filtered `UNIQUE` constraint on `is_default WHERE
is_default = TRUE`; see [database-specs.md §8.1](database-specs.md).

### 10.4 Wire format leniency on `simpleenroll`

**Risk:** RFC 7030 §4.2.1 prescribes base64-encoded DER in the
request body. pyPKI accepts PEM directly, deviating from the spec.
**Mitigation today:** PEM is the format most tooling produces,
and pyPKI's behaviour is the more forgiving direction.
**Closure:** accept both PEM and base64-encoded DER (detect by
inspecting the first bytes); reject anything else with 400.

### 10.5 No `simplereenroll` / `csrattrs` / `serverkeygen`

**Risk:** Clients that follow RFC 7030 strictly cannot:
- Reenroll an existing certificate (`simplereenroll`).
- Query the server for required attributes before composing the CSR
  (`csrattrs`).
- Request server-side keygen (`serverkeygen`).
**Mitigation today:** `simpleenroll` covers the primary enrollment
flow.
**Closure:** add `simplereenroll` (largely the same code path with
the old cert presented as auth proof — synergises with CR-0001's
mTLS work); add `csrattrs` reading from the template's subject /
allowed-cryptography blocks; add `serverkeygen` reusing the
management UI's PKCS#12 keygen path.

### 10.6 Coarse error responses

**Risk:** `simpleenroll` / `simpleenrollpem` return
`400 Error: <repr(exception)>` for any non-`BackendError`,
non-`AuthFailure` path. This leaks Python representation strings and
provides no machine-parseable error code. RFC 7030 §4.2.3 expects
structured failures.
**Mitigation today:** logged server-side at error level.
**Closure:** map common failures (CSR parse, template rejection,
algorithm rejection, validity rejection) to specific status codes
and structured bodies, matching the JSON envelope used by the
management-UI routes.

### 10.7 No `is_default` alias guard

**Risk:** Hitting `/.well-known/est/simpleenroll` (no label) when no
alias is marked `is_default` causes the route to pass `None` into
the adapter and 500. There is no operator-friendly hint.
**Mitigation today:** the UI surfaces the default flag prominently,
making missing-default visible during configuration.
**Closure:** detect missing-default at route entry, return a clear
404 with the body listing the available alias names.

### 10.8 Password rotation has no operator visibility

**Risk:** Rotating an alias password is a single `PUT` request that
silently changes the hash. There is no record of when the password
was last rotated, no expiry policy, and no warning when a stale
password is in use.
**Mitigation today:** rotation is operator-driven; the audit log
captures the `UPDATE` action.
**Closure:** add a `password_updated_at` column and surface it in the
list view; optionally a configurable rotation reminder.

### 10.9 Open endpoints are silent

**Risk:** An alias with `username = NULL` is fully open — any CSR
that the template accepts results in an issued certificate. The UI
shows the empty username column but does not visually flag the
endpoint as unauthenticated.
**Mitigation today:** template enforcement still caps what can be
issued.
**Closure:** UI badge ("OPEN") on aliases with no auth configured;
optional global toggle that refuses to create open aliases.

---

## 11. Order of work

The pending items in §2.2 / §10 group into three phases.

**Phase A — Standards alignment**
1. PKCS#7 envelope on `cacerts` with full chain (§10.1).
2. Accept base64-DER on `simpleenroll` alongside PEM (§10.4).
3. Structured error bodies on `simpleenroll[pem]` (§10.6).
4. Missing-default detection (§10.7).

**Phase B — Authentication**
5. **CR-0001 — mTLS client-cert authentication** (§15.1). The
   highest-leverage change; unlocks `simplereenroll` and aligns with
   the [roadmap.md §2](roadmap.md) item.
6. `password_updated_at` + rotation surface (§10.8).
7. Open-endpoint UI badge (§10.9).

**Phase C — Protocol completeness**
8. `simplereenroll` (§10.5), riding on CR-0001's mTLS.
9. `csrattrs` (§10.5), reading from the template.
10. `serverkeygen` (§10.5), reusing the management UI path.

Phase A is the smallest, lowest-risk path to a more conformant
endpoint surface. Phase B is where the security story improves
materially. Phase C is the "complete RFC 7030 subset" milestone.

---

## 12. Acceptance criteria

The EST surface is **correct** when:

- A compliant EST client (e.g. libest / `est-client` / `step ca`)
  can complete `cacerts` + `simpleenroll` against a labelled alias
  without protocol-level deviations.
- `simpleenroll` against an alias with `username` set returns 401
  without credentials, 200 with correct credentials, and 401 with
  wrong credentials.
- `simpleenroll` against an alias with `cert_fingerprint` set (after
  CR-0001) returns 401 without a matching client cert and 200 with a
  matching client cert.
- Template enforcement applies to every enrollment; a CSR with
  `basicConstraints: CA=TRUE` against a leaf-cert template results
  in a leaf cert.
- Audit logs record `CREATE` / `UPDATE` / `DELETE` on aliases and
  the certificate row for every issuance.

A **stable platform** has, in addition:

- PKCS#7 envelope on `cacerts` (§10.1).
- Structured 4xx bodies on issuance errors (§10.6).
- mTLS authentication wired and documented (CR-0001).
- `simplereenroll` (§10.5).

---

## 13. Out of scope for this spec

- The template grammar — see
  [certificate-template-specs.md](certificate-template-specs.md).
- The CA signing pipeline — see
  [ca-management-specs.md](ca-management-specs.md).
- The certificate row and revocation lifecycle — see
  [certificate-management-specs.md](certificate-management-specs.md).
- Transport-level TLS termination (reverse proxy, certificate
  provisioning for the management endpoint itself). The Docker stack
  does not terminate TLS; operators are expected to put a reverse
  proxy in front. CR-0001 below depends on this transport being
  configured to request and forward the client certificate.
- ACME (RFC 8555). Not implemented; only EST is.

---

## 14. Design proposals

In-flight design proposals are recorded here in long form. Closed
proposals can be left in place as historical reference or folded
back into the main body of the spec, at the spec author's discretion.

### 14.1 CR-0001 — mTLS client-certificate authentication

**Goal**

Authenticate EST enrollment requests against an X.509 client
certificate fingerprint stored on the alias, complementing (or
replacing) HTTP Basic Auth. This is the
[roadmap.md §2](roadmap.md) item and the
[PROGRESS.md §2](PROGRESS.md) entry titled "EST client-certificate
authentication".

**Motivation**

EST clients in the field are typically not interactive users —
they are devices, services, or build pipelines. Static passwords
shared across many clients are operationally awkward and weaken the
audit story. mTLS gives every enrollee a unique provable identity
that can be revoked, observed, and rotated independently. The
`ESTAliases` schema already reserves `cert_fingerprint`; the
plumbing is in place to make this a route-layer change.

**Scope**

- Enforce `cert_fingerprint` at request time on `simpleenroll` and
  `simpleenrollpem`.
- Keep `cacerts` always public (RFC 7030 §4.1).
- Permit three authentication modes per alias:
  1. **Basic-only** — current behaviour. `username` set,
     `cert_fingerprint` NULL.
  2. **mTLS-only** — `username` NULL, `cert_fingerprint` set.
     Request must present a matching client cert; the Authorization
     header is ignored.
  3. **Basic-AND-mTLS** — both set. Request must pass both gates.
     This is the strongest stance and is the operator-visible
     default for new aliases once the change ships.
- `cert_fingerprint` is a hex SHA-256 of the client cert DER, case-
  insensitive, optionally separated by colons. Validation at write
  time strips separators and lower-cases.

**Out of scope for the first iteration**

- Trust-path validation. The fingerprint match is the only
  enforcement; pyPKI does not walk the client cert's chain. This is
  intentional — fingerprint pinning lets operators issue client
  certs from any CA without configuring trust anchors in pyPKI. A
  future iteration can layer on issuer-chain validation when needed.
- CRL / OCSP checking of the client cert. Same reasoning — pinning
  is the contract.
- Revocation surface (`/api/est/{id}/revoke-client`). Out of scope;
  operators rotate by updating the fingerprint on the alias.
- Multiple fingerprints per alias. The schema column is a single
  string; an explicit "one cert per alias" stance keeps the
  semantics simple. Multi-fingerprint can be a follow-up via a
  side-table.
- `simplereenroll` (RFC 7030 §4.2.2). The natural companion to mTLS
  enrollment but tracked separately; see §10.5.

**Transport assumptions**

The client cert reaches the Flask app one of two ways:

1. **TLS terminated in Flask.** `request.environ['SSL_CLIENT_CERT']`
   (PEM) is set by the WSGI server (e.g. gunicorn behind a TLS
   wrapper). Practical for development; rare in production.
2. **TLS terminated at a reverse proxy.** The proxy verifies the
   client cert against its configured trust anchors and forwards
   the verified PEM in a header. nginx convention is
   `X-SSL-Client-Cert` (URL-encoded PEM) and `X-SSL-Client-Verify`
   (`SUCCESS` / `FAILED:<reason>` / `NONE`). The operator must
   ensure the header cannot be forged from outside (proxy strips
   inbound headers of the same name before forwarding).

The proposal picks **header-driven transport** as the primary mode
because it matches how production deployments are described in
[roadmap.md §5](roadmap.md). The Flask-terminated case is supported
as a fallback when `SSL_CLIENT_CERT` is set and the headers are not.
Both are read by a single helper.

**Configuration**

A new top-level config key (already discussed in the spec but
nominally introduced by CR-0001):

```toml
[est]
# Header that carries the URL-encoded PEM of the verified client cert.
# Set empty to disable header-driven mTLS.
client_cert_header = "X-SSL-Client-Cert"

# Header that carries the verification verdict from the reverse proxy.
# When non-empty, the value must equal client_cert_verify_success to accept.
client_cert_verify_header = "X-SSL-Client-Verify"
client_cert_verify_success = "SUCCESS"
```

Defaults match nginx conventions; operators using a different proxy
override per their convention. Empty `client_cert_header` disables
header-driven mTLS entirely (falling back to
`SSL_CLIENT_CERT` if present, otherwise refusing every mTLS-required
alias).

**Route changes**

`_check_basic_auth(est_config)` is renamed to
`_authenticate(est_config)` and:

1. Always returns `True` for `cacerts`.
2. Reads the alias's `username` and `cert_fingerprint`.
3. **Basic-only path** (`cert_fingerprint` NULL, `username` set):
   unchanged from today.
4. **mTLS path** (`cert_fingerprint` set):
   - Resolve the client cert from header or `SSL_CLIENT_CERT`.
   - If `client_cert_verify_header` is configured, require the
     verify-success value; else assume Flask-terminated.
   - Compute SHA-256 of the client cert DER, hex-encode.
   - Compare case-insensitively, ignoring colons, against the
     stored fingerprint.
   - On mismatch / missing cert: 401 with body
     `Client certificate required` (no `WWW-Authenticate: Basic`
     challenge — that would mis-prompt browsers when the gate is
     mTLS).
5. **Basic-AND-mTLS** (both set): require both. On either failure,
   401 with the same body as the failing gate.
6. Open path (`username` NULL, `cert_fingerprint` NULL): unchanged
   from today — endpoint is open.

The decision table:

| `username` | `cert_fingerprint` | Behaviour |
|---|---|---|
| NULL / empty | NULL / empty | Open (auth not required). |
| set | NULL / empty | Basic only (current behaviour). |
| NULL / empty | set | mTLS only. |
| set | set | Basic AND mTLS. |

**Audit trail**

The successful-auth path emits no auth audit row today. With
mTLS, the issuance row already includes the certificate id; the
client cert's subject DN and fingerprint should be folded into the
audit row's `metadata` JSON (the column was added by the
[database-specs.md §2.1](database-specs.md) migration but is only
partially wired — this is one of the surfaces to wire). Schema:

```json
{
  "auth": "mTLS",
  "client_subject": "CN=device-001,OU=fleet,O=Acme",
  "client_fingerprint": "ab:cd:ef:..."
}
```

`auth` is `"basic"`, `"mTLS"`, `"basic+mTLS"`, or `"open"`.

**UI changes**

- `est_editor.html` — un-disable the `cert_fingerprint` field;
  rename the card from "mTLS (future)" to "mTLS authentication"
  and remove the "Not enforced yet" badge. Add a small helper
  button that pastes the SHA-256 fingerprint of a PEM the operator
  drops in.
- `est_list.html` — column for the auth mode (Open / Basic /
  mTLS / Basic+mTLS).
- `est_test.html` — accept a client-cert / key pair, present them
  on the test request. Optional; a `curl` example in the help
  panel is sufficient for the first iteration.

**Validation**

- `cert_fingerprint` write-time validation:
  - Strip `:` separators, lower-case.
  - Reject anything that isn't 64 hex characters (SHA-256 length).
  - 400 on validation failure, with the offending value echoed back.

**Test plan**

- Unit: `_authenticate` against the four-cell decision table; the
  fingerprint normaliser; the header parser.
- Integration: end-to-end `simpleenroll` against an alias with each
  of the three new modes. Use a self-signed client cert generated
  inside the test.
- Regression: existing Basic-Auth tests must pass unchanged.

**Migration**

`cert_fingerprint` column exists. No schema change. Existing aliases
default to the new behaviour for `cert_fingerprint NULL` —
Basic-only or open per their `username`. No operator action required
on upgrade.

**Open questions for review**

- **Should the trust-anchor check be opt-in from day one?** The
  proposal above is fingerprint-only. A `cert_trust_chain` JSON column
  could be added later, but it expands scope significantly (CRL /
  OCSP, intermediate cert handling, etc.). Defer unless an operator
  raises a concrete need.
- **Should `simplereenroll` be in the same CR?** It needs mTLS to be
  useful (the previous cert authenticates the renewal); but the
  reenroll-specific logic (re-bind the new cert to the same row,
  retire the old one) is its own design. Track separately; ship CR-0001
  first.
- **`X-SSL-Client-Cert` header forgery.** If pyPKI is exposed
  directly to the internet without a reverse proxy, a client can set
  `X-SSL-Client-Cert` themselves. The mitigation is operator
  responsibility (always front pyPKI with a TLS-terminating proxy
  that strips inbound copies of the configured header). Documented
  here so the responsibility is explicit.

---

## 15. Cross-references

- [ca-management-specs.md](ca-management-specs.md) — CA layer that
  signs EST-issued certificates.
- [certificate-management-specs.md](certificate-management-specs.md) —
  end-entity issuance pipeline EST drives; §6.4 covers EST
  specifically.
- [certificate-template-specs.md](certificate-template-specs.md) —
  template grammar and enforcement applied to every EST issuance.
- [kms-specs.md](kms-specs.md) — KMS that backs the signing key for
  the alias's CA.
- [database-specs.md](database-specs.md) — `ESTAliases` schema (§4.6).
- [rest-api.md](rest-api.md) — REST API summary; the EST routes are
  documented there in §EST Service.
- [PROGRESS.md](PROGRESS.md) — current implementation status.
- [roadmap.md](roadmap.md) — strategic intent.
