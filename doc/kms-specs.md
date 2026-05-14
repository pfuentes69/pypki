# KMS Specification

This is the consolidated specification for the Key Management Service (KMS)
layer in pyPKI. It is the single source of truth for the KMS design:
architecture, data model, backend contract, activation lifecycle, REST API,
management UI, PKCS#11 conformance subset, development environment, and the
order in which the work is to be carried out.

Status of each work item lives in [PROGRESS.md §3](PROGRESS.md); the
strategic intent and cross-area framing live in [roadmap.md §3](roadmap.md).
HSM-specific contracts (PKCS#11 mechanisms, slot addressing, session
lifecycle, storage-type semantics) are specified in
[hsm-support-specs.md](hsm-support-specs.md).

A developer reading only this document should have everything needed to
start implementation.

---

## 1. Goals

1. A single signing entry point — `KeyManagementService` — through which all
   X.509 issuance, OCSP signing, and key generation must pass. Already in
   place; preserved.
2. **Software keys and HSM keys treated symmetrically** at the abstraction
   layer the operator interacts with. Operators see "providers" (software
   cryptotokens or PKCS#11-backed HSM tokens). Keys belong to providers.
3. **Multi-HSM support out of the box** — a deployment can host a Luna
   partition for the root CA, a YubiHSM for an issuing CA, and a SoftHSM2
   fixture for development simultaneously, configured by data, not by code.
4. **Defensible secret-handling story** — no plaintext PINs in the database,
   no plaintext PEMs in the database, with a per-provider activation
   lifecycle and an explicit auto-activation choice.
5. **Portable PKCS#11 implementation** — code that works against SoftHSM2 in
   CI must work against YubiHSM 2 and Thales Luna without rewrites; the
   conservative subset of PKCS#11 the implementation uses is part of this
   spec.
6. **End-to-end management surface** — REST endpoints and management-UI
   pages to create, edit, activate/deactivate, and inspect providers, and to
   list, generate, and delete keys within them.

---

## 2. Status

### What is in place (Phases 0–6 complete)

- `CryptoProviders` data model with `kind ∈ {software, pkcs11}`, full
  CRUD via the management API + UI, activation lifecycle, audit logging.
- `SoftwareBackend` and `PKCS11Backend` implement the
  ``CryptoBackend`` Protocol; `KeyManagementService` dispatches through
  it. CAs / OCSP responders never see PKCS#11.
- Software keys encrypted at rest under per-provider KEKs derived from
  `HSM_PIN_KEK` via HKDF-SHA256; AES-256-GCM wrap.
- HSM signing produces correct, verifiable signatures: RSA via
  `CKM_RSA_PKCS` with the SHA-256 DigestInfo prefix; ECDSA via
  `CKM_ECDSA` with `(r, s)` DER-encoded.
- One PKCS#11 session per `pkcs11` provider, opened on activation,
  closed on deactivation/shutdown, reconnect-on-session-invalid.
- `auth_secret_ref` resolvers: `db:encrypted` (master KEK from
  `HSM_PIN_KEK`), `env:NAME`, `operator:prompt`. `vault:` reserved.
- `auto_activate` enforced at validation time; `operator:prompt` is
  exclusive with `auto_activate=TRUE`.
- Provider activation API: `POST /activate` (with operator PIN body
  for `operator:prompt`), `POST /deactivate`, `GET /status`. Auto-
  activation runs at app startup; failures are logged loudly but do
  not block boot.
- Provider-aware key API: `POST /api/kms/keys` (generate),
  `POST /api/kms/keys/import` (register existing on-token key),
  `DELETE /api/kms/keys/{id}` (refused with 409 if in-use; honours
  `key_owned` so imported keys leave the on-token objects intact).
- Mandatory CKA_* attribute set enforced on every PKCS#11-generated
  key (kms-specs.md §8.2).
- Pytest suite parametrised over both backends; 54 tests covering the
  full API surface, multi-threaded sign safety, lifecycle invariants,
  and Phase 6 hardening (hex validation, symmetric-type rejection,
  dead-code regressions).
- **Token-aware key listing.** `PKCS11Backend.list_keys()` enumerates
  every `CKO_PRIVATE_KEY` on the open session, returning per-row
  algorithm metadata, the paired public key PEM (when present), and
  an ``unimportable_reason`` discriminator. `GET /api/kms/keys` scoped
  to a `pkcs11` provider returns a merged envelope
  `{keys, token_enumeration}`; each row carries a `state` field
  (`registered_and_present` / `present_only` / `registered_only`)
  that drives the UI's state-badge column and the per-row Import
  affordance for unregistered on-token keys.
- **Drift detection beyond the list.** `KMS.probe_key_on_token`
  performs an on-demand `find_key_by_id` against the token for a
  single `KeyStorage` row, returning a structured
  `{available, present, reason}` envelope. The key details endpoint
  uses it so opening `/key_details.html?id=…` for an HSM-backed key
  flips the row to `state="registered_only"` and renders a
  prominent "Key is missing on the HSM" banner when the on-token
  object has been deleted out-of-band.
- **Classified activation failures + mid-session reclassification.**
  `PKCS11Backend.open` and the broader reconnect path in
  `sign_digest` share a single `_open_session_classified` helper so
  the same typed subclasses surface whether the failure shows up at
  activation or in the middle of a session:
  - `SlotNotFound` — the configured `slot_label` is not on the
    module (token deleted, hardware removed, misconfigured label,
    or token went missing mid-session via
    `softhsm2-util --delete-token` etc.).
  - `AuthenticationFailed` — login rejected (wrong PIN, PIN locked,
    token reinitialised with a new PIN, role mismatch).
  - `ModuleLoadFailed` — the PKCS#11 shared library could not be
    loaded (path wrong, ABI mismatch).
  All three remain subclasses of `BackendNotActive` so existing
  catches stay backwards-compatible. `sign_digest`'s single-retry
  reconnect path covers `CKR_SESSION_HANDLE_INVALID`,
  `CKR_SESSION_CLOSED`, `CKR_DEVICE_REMOVED`, `CKR_DEVICE_ERROR`,
  `CKR_TOKEN_NOT_PRESENT`, `CKR_TOKEN_NOT_RECOGNIZED`; if the
  reconnect itself fails, its typed exception propagates.
  `list_keys` and `find_key_by_id` do *not* retry — diagnostic
  callers want the typed reason immediately. The KMS evicts the
  cached backend on any hard failure (CR-0004 decision 3) so the
  next call re-runs activation cleanly once the slot / PIN is
  fixed. The token-aware envelope on `GET /api/kms/keys` and the
  `token_check` envelope on `GET /api/kms/keys/{id}` carry the
  matching reasons (`slot-missing`, `auth-failed`, `module-error`)
  for both activation-time and mid-session failures.
- **Typed signing-time failure + structured route surface.**
  `PKCS11Backend._find_private_by_id` raises `KeyMissingOnToken`
  (subclass of `BackendError` / `RuntimeError`) when the on-token
  object is gone; `KMS.sign_digest` / `KMS.load_key` propagate it
  unchanged. All `BackendError` subclasses now carry optional
  `key_id` and `provider_id` attributes attached at the throw site
  (`PKCS11Backend.load_key` enriches `KeyMissingOnToken` with the
  `KeyStorage.id` at the layer that knows it). An app-level Flask
  error handler registered in `web.create_app` turns any
  `BackendError` raised from any blueprint (main, ocsp, est) into
  a structured 503 with the shape
  `{description, code, key_id, provider_id, recovery}` —
  `code ∈ {key_missing_on_token, slot-missing, auth-failed,
  module-error, provider-inactive, backend-error}`, `recovery`
  points at `/key_details.html?id=…` when `key_id` is known.
  Consumer routes (cert issuance, PKCS#12 issuance, OCSP, EST,
  CRL regeneration) re-raise `BackendError` from their broad
  `except` blocks so the typed exception reaches the handler
  instead of getting flattened to a generic 500. The background
  CRL scheduler logs the typed failure class + key_id + provider_id
  at WARN and continues with the next CA instead of aborting the
  pass. Existing `except RuntimeError:` catches remain
  backwards-compatible.
- **Key export (software, owned).** `POST /api/kms/keys/{id}/export`
  returns a passphrase-encrypted PKCS#8 PEM under PBES2 (PBKDF2-
  HMAC-SHA256 + AES-256-CBC via the `cryptography` library's
  `BestAvailableEncryption`). Body: `{"passphrase": "≥12 chars"}`.
  Response: raw PEM with `Content-Type: application/x-pem-file`
  and a `Content-Disposition: attachment` header so the browser
  downloads it without client-side parsing.
  Refused with 409 for HSM-backed rows (CKA_EXTRACTABLE=FALSE per
  §8.2) and for imported software (`key_owned=FALSE`). Role gate
  is `superadmin`-only — stricter than the destructive-action
  gate. Every outcome writes a `kms_keys` audit event:
  `EXPORT` on success, `EXPORT_REFUSED_HSM` /
  `EXPORT_REFUSED_IMPORTED` / `EXPORT_FAILED` on refusal — visible
  in the key details page audit panel. The Export button on
  `/key_details.html` is gated client-side to the same eligible
  set (superadmin + software + owned + not registered_only); the
  server enforces independently.
- **Public-key recovery for orphaned on-token private keys.**
  `_read_public_key_pem_attributes(session, handle, normalised)`
  works on either a public-key or a private-key handle and tries
  three reconstruction paths in order: PKCS#11 v3
  `CKA_PUBLIC_KEY_INFO`, RSA `CKA_MODULUS` + `CKA_PUBLIC_EXPONENT`,
  EC `CKA_EC_POINT`. `PKCS11Backend.list_keys()` and
  `find_key_by_id()` fall back to reading the private-key handle
  when the paired `CKO_PUBLIC_KEY` is missing — covers the
  out-of-band `pkcs11-tool --delete-object --type pubkey` case so
  the row becomes importable rather than read-only. Rows whose
  vendor blocks both paths (Luna crypto-user with restricted
  public attributes, etc.) keep surfacing as
  `unimportable_reason="public_key_unavailable"`; the diagnosis
  lives in a `logger.warning`.
- **Key details page.** `GET /api/kms/keys/{id}` returns the full
  record enriched with `provider_label`, `state`, and
  `usage = {count, items: [{type, id, name, …}]}` — the named
  dependents (CAs / certificates / OCSP responders) that block
  deletion. The new `/key_details.html` page hosts the public-key
  panel, the usage table, the audit-log trail (sourced from
  `/api/audit-logs?resource_type=kms_keys&resource_id=…`), and the
  destructive / export actions. The keys list (`/kms_keys.html`) and
  the per-provider keys table on `/crypto_provider_details.html` no
  longer surface destructive actions inline.
- **`POST /api/kms/keys/{id}/export` reserved.** Returns 501 with a
  documented description; the UI's Export button wires to it so the
  affordance is discoverable.

### What is pending

- **Phase 7 — fidelity pass against real-vendor PKCS#11 implementations**
  (YubiHSM 2, Thales DPoD, AWS CloudHSM). **Indefinitely deferred** —
  no real-HSM access is planned by the project. SoftHSM2 stays the
  canonical regression target. See §13 Phase 7 for what the work
  would entail if access ever materialises.
- `vault:` resolver — placeholder in the data model; raises
  `NotImplementedError`. Concrete implementation is a separate
  initiative.
- **EST-specific error mapping for backend failures.** Hook for a
  future EST service spec. The current EST surface is not
  production-grade (no enforced TLS client authentication, no
  RFC-8951 error encoding, RA semantics not formalised). When an
  EST spec is drafted, it should pick up the EST-specific mapping
  of `KeyMissingOnToken` / `SlotNotFound` / `AuthenticationFailed`
  to RFC-7030 / RFC-8951 error shapes; CR-0005 deferred this so
  the KMS spec does not pre-commit a wire format the EST spec
  will own. Tracked here only — no CR number allocated until the
  EST spec lands.

The HSM-specific contracts (mechanisms, slot addressing, session
lifecycle, storage types) are specified in
[hsm-support-specs.md](hsm-support-specs.md).

---

## 3. Architecture

### 3.1 Layered model

```
   web routes / CA / OCSP / EST
              │
              ▼
     KeyManagementService                ← public signing API
              │
              ▼
     CryptoProviders row                 ← which provider owns the key?
     (kind = software | pkcs11)
              │
   ┌──────────┴───────────┐
   ▼                      ▼
SoftwareBackend       PKCS11Backend      ← siblings under one contract
(libcrypto;           (one shared session
 PEM blob in           per (module, slot,
 KeyStorage,           auth) tuple;
 encrypted at rest     SoftHSM2 / Luna /
 under provider KEK)   YubiHSM / cloud HSM)
```

- Callers (CAs, OCSP responders, web routes) only ever touch
  `KeyManagementService`. They never see PKCS#11.
- `KeyManagementService` looks up the `KeyStorage` row, resolves its
  provider, dispatches to the matching backend, returns the signature.
- Backends are siblings of the same internal contract (Section 5).

### 3.2 Two design decisions, recorded

These decisions reshape the data model and several of the gaps. They are not
re-litigated in implementation discussions.

**Decision A — sibling backends, not unified PKCS#11.** Software keys go
through libcrypto in-process; HSM keys go through PKCS#11. Both are reached
via a `CryptoProviders` row of the matching kind. The alternative considered
(routing software keys through SoftHSM2 too, single PKCS#11 path) was
rejected because:

- Performance overhead of routing every signature through `softhsm2`'s `.so`
  boundary is unjustified when libcrypto is already linked into the process.
- Making `softhsm2` a hard dependency in every environment (CI, contributor
  laptops, minimal Docker bases) adds operational friction with no
  user-visible benefit.
- Existing PEM and PKCS#12 import flows ([web/routes/main_routes.py:108-139](../web/routes/main_routes.py#L108-L139))
  assume libcrypto-shaped keys; PKCS#11 import + `CKA_EXTRACTABLE` semantics
  make these strictly harder.
- Migration cost: every existing software CA would need re-homing into a
  SoftHSM token.

The test-parity argument for unification ("HSM bugs surface on every test
run") is recovered without unifying — the same test suite is run a second
time in CI configured against a SoftHSM2 `pkcs11` provider. Same tests, two
backends, same class of regression caught.

This is the same shape EJBCA uses (`SoftCryptoToken` / `PKCS11CryptoToken`
siblings under one `CryptoToken` interface).

**Decision B — providers are the unit of operator-visible isolation.** Both
kinds of providers carry a PIN, an activation lifecycle, and an
`auto_activate` setting. Software providers encrypt their keys at rest under
a per-provider KEK derived from the PIN; HSM providers use the PIN to
authenticate to the token. This gives software keys the same security
properties as HSM keys: PIN compromise unlocks only that provider's keys, an
idle (deactivated) provider has its keys sealed, multiple providers give
real isolation between CAs.

Migrating a software CA to a real HSM later is a config-time operation:
change the provider's `kind` from `software` to `pkcs11`, point at the
module, re-issue the keys on the token. CA records, audit trails, and the
keys' identity in pyPKI are preserved.

---

## 4. Data model

### 4.1 `CryptoProviders` (new table)

```
CryptoProviders
├── id                   INT PRIMARY KEY AUTO_INCREMENT
├── label                VARCHAR(255) NOT NULL UNIQUE
├── kind                 ENUM('software', 'pkcs11') NOT NULL
├── module_path          VARCHAR(1024) NULL    -- absolute path to the .so/.dylib
│                                              -- NULL when kind='software'
├── slot_label           VARCHAR(255) NULL     -- token label or numeric slot
│                                              -- NULL when kind='software'
├── auth_kind            ENUM('pin','luna_role','yubihsm_authkey') NOT NULL DEFAULT 'pin'
├── auto_activate        BOOLEAN NOT NULL DEFAULT FALSE
├── auth_secret_ref      VARCHAR(512) NOT NULL    -- "db:encrypted" | "env:NAME" |
│                                                  -- "vault:path"   | "operator:prompt"
├── auth_secret_blob     VARBINARY(1024) NULL     -- encrypted PIN, only when
│                                                  -- auth_secret_ref='db:encrypted'
├── extra_json           JSON NOT NULL DEFAULT '{}'  -- vendor-specific (authkey id,
│                                                     -- crypto-officer role, …)
├── description          TEXT NULL
├── is_default           BOOLEAN NOT NULL DEFAULT FALSE
├── created_at           TIMESTAMP DEFAULT CURRENT_TIMESTAMP
└── updated_at           TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP
```

Constraints:

- Exactly one provider may have `is_default = TRUE` at a time. The seeded
  `software-default` provider holds it on a fresh install.
- `auto_activate = TRUE` requires `auth_secret_ref` to resolve without
  human interaction (`db:encrypted`, `env:`, `vault:`). Enforced by
  application validation.
- `auth_secret_blob IS NOT NULL` iff `auth_secret_ref = 'db:encrypted'`.
  Enforced by application validation.
- Deletion is rejected by application validation if any `KeyStorage` row
  references the provider.

### 4.2 `KeyStorage` (changed)

Existing columns, new columns, and removals:

```
KeyStorage
├── id                   INT PRIMARY KEY AUTO_INCREMENT
├── provider_id          INT NOT NULL
│                            FK → CryptoProviders(id)
│                            (was: NULLABLE; now required)
├── storage_type         ENUM('Plain','Encrypted','HSM','Symmetric') NOT NULL
│                            -- 'Encrypted' means software, encrypted at rest under
│                            --   the provider's KEK (the new normal for software)
│                            -- 'Plain' is preserved only for the migration window
│                            --   and removed once all rows are converted
│                            -- 'HSM' means the key lives on the token;
│                            --   private_key column is unused
│                            -- 'Symmetric' (new) means an AES key, stored b64
├── private_key          MEDIUMTEXT NULL
│                            -- For Encrypted/Symmetric: the encrypted blob
│                            -- For HSM: NULL
├── public_key           TEXT NULL
│                            -- Always populated for asymmetric keys, regardless
│                            -- of where the private material lives
├── key_type             VARCHAR(32) NOT NULL
│                            -- "RSA-3072" | "ECDSA-P-256" | "Ed25519" | "AES-256" | …
├── hsm_token_id         VARBINARY(255) NULL
│                            -- CKA_ID on the token, raw bytes (was: hex VARCHAR)
│                            -- Validated as well-formed at insert
├── label                VARCHAR(255) NULL
│                            -- CKA_LABEL on the token; arbitrary tag for software
├── created_at           TIMESTAMP DEFAULT CURRENT_TIMESTAMP
└── updated_at           TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP
```

Removed columns: `hsm_slot`, `token_password`. Their data moves to the
provider record. The `private_key` column for `'Plain'` software rows is
re-encrypted under the default provider's KEK as part of the migration and
the `storage_type` is updated to `'Encrypted'`.

### 4.3 Migration plan

Idempotent, runs at app startup via the existing `migrate_schema()` hook:

1. Create `CryptoProviders` table if absent.
2. Insert the seeded `software-default` provider (label, kind=software,
   `auto_activate=TRUE`, `auth_secret_ref='env:HSM_PIN_KEK'`, `is_default=TRUE`)
   if no row has `is_default=TRUE`.
3. Add `KeyStorage.provider_id` (nullable for the migration step).
4. For each `KeyStorage` row with `storage_type='Plain'` and
   `provider_id IS NULL`:
   - Encrypt `private_key` (PEM) under the default provider's KEK.
   - Set `provider_id` to the default provider's id.
   - Set `storage_type='Encrypted'`.
5. For each `KeyStorage` row with `storage_type='HSM'`:
   - Find or create the matching `pkcs11` provider — first migration creates
     a `legacy-hsm` provider populated from the (then-still-present)
     `hsm_slot` / `token_password` columns and a configured `module_path`.
   - Set `provider_id` to that provider's id.
6. Make `KeyStorage.provider_id` NOT NULL.
7. Drop `KeyStorage.hsm_slot` and `KeyStorage.token_password`.
8. Validate that every row now has a non-null `provider_id`; if not, the
   migration aborts and logs the offending rows.

Step 4's KEK comes from `HSM_PIN_KEK` env-var. If the env var is missing,
the migration fails fast with a clear error pointing at the install
documentation. **The migration never falls back to the application
`secret_key`.**

---

## 5. Internal backend contract

`KeyManagementService` dispatches to one of two backend implementations
based on the provider's `kind`:

```python
class CryptoBackend(Protocol):
    def open(self, provider: ProviderRecord, secret: bytes) -> None: ...
    def close(self) -> None: ...
    def is_active(self) -> bool: ...
    def generate_key(self, key_type: str, label: str, **kwargs) -> KeyHandle: ...
    def import_key(self, public_key_pem: str, label: str, **kwargs) -> KeyHandle: ...
    def find_key(self, key_id_or_label: bytes | str) -> KeyHandle | None: ...
    def list_keys(self) -> list[KeyHandle]: ...
    def delete_key(self, handle: KeyHandle) -> None: ...
    def sign(self, handle: KeyHandle, mechanism: SignMech, data: bytes) -> bytes: ...
    def get_public_key_der(self, handle: KeyHandle) -> bytes: ...
```

- `SoftwareBackend` — wraps `cryptography` / libcrypto. `open(secret)`
  derives the KEK from the PIN, used to decrypt PEMs from `KeyStorage` on
  demand; held in a memory cache keyed by `KeyStorage.id` until `close()`.
- `PKCS11Backend` — wraps PyKCS11. `open(secret)` opens one session against
  the configured `(module_path, slot, auth)` tuple, logs in, and stays open
  until `close()`. **One backend instance per provider** (not per cached
  key) — closes Gap 6.

`KeyHandle` is an opaque object that carries enough information to identify
a key within the backend (PKCS#11 object handle for HSM, dict-cache key for
software). Never returned to callers above KMS.

---

## 6. Activation lifecycle

A provider has two operational states, independent of its database row, and
the same shape applies to both kinds.

| State | Meaning |
|---|---|
| **inactive** | Row exists; backend not opened. For `pkcs11`, no PKCS#11 session is open. For `software`, the per-provider KEK is not in memory and encrypted PEMs cannot be decrypted. CAs / OCSP responders bound to keys on this provider cannot sign. A first sign attempt returns a clear "provider is inactive" error, not a backend-specific error. |
| **active** | Backend opened. For `pkcs11`, session open and logged-in. For `software`, KEK loaded; per-key plaintext is decrypted on demand and held in memory. |

Transitions:

- **Startup:** every provider with `auto_activate=TRUE` is activated. Failure
  to activate any one of them is logged loudly but does not block app
  startup; CAs bound to the failing provider report "provider unavailable"
  on first sign. This is intentional — a bad PIN must not take down the
  whole service.
- **Operator activate (`auto_activate=FALSE`):** `POST
  /api/crypto-providers/{id}/activate` with the PIN in the body. PIN held in
  memory only, discarded on shutdown or explicit deactivate.
- **Operator deactivate:** `POST /api/crypto-providers/{id}/deactivate`.
  Backend is closed; cached keys are evicted; for `pkcs11`, the session is
  closed.

Toggling `auto_activate` is an audit-logged action. The default for
operator-created providers is `FALSE`. The seeded `software-default` is the
only provider that ships with `auto_activate=TRUE` so out-of-the-box
deployments work without operator configuration.

---

## 7. Secret resolution backends (`auth_secret_ref`)

The reference is opaque text with a small set of supported prefixes. The
resolver runs at activation time:

| Backend | Form | Behavior |
|---|---|---|
| `db:encrypted` | `db:encrypted` | PIN encrypted in `auth_secret_blob` on the provider row. Decrypted at activation using the `HSM_PIN_KEK` env var. **Never the application `secret_key`.** Enables auto-activation. |
| `env:NAME` | `env:HSM_PIN_PROD` | Read from the named environment variable at activation time. |
| `vault:path` | `vault:secret/pki/hsm/prod-root` | Fetched from a configured secret store (Vault, AWS Secrets Manager, k8s secret) at activation time. Implementation pluggable; out-of-scope for first cut. |
| `operator:prompt` | `operator:prompt` | Operator submits PIN via `POST /api/crypto-providers/{id}/activate`. Held in memory only. Used when `auto_activate=FALSE`. |

There is no fully zero-input form of auto-activation that also protects the
PIN against database-only compromise. `db:encrypted` makes the
"something out of band" explicit (the KEK), and lets the operator decide
where it lives (env var, systemd `EnvironmentFile`, secret manager).

The `HSM_PIN_KEK` env var is used:

- For `db:encrypted` PINs (HSM and software providers alike).
- As the seeded `software-default` provider's resolved PIN
  (`auth_secret_ref='env:HSM_PIN_KEK'`).
- To derive the KEK for software-key PEM at-rest encryption.

This is intentional: there is exactly **one** deployment-wide secret to
manage out-of-band, regardless of how many providers exist. Operators who
want stronger isolation can configure separate `env:` references per
provider.

---

## 8. PKCS#11 conformance

To keep SoftHSM2-tested code portable to YubiHSM 2 and Thales Luna, the
implementation restricts itself to the intersection of what all three
support.

### 8.1 Conservative algorithm subset

- **Asymmetric:** RSA 2048 / 3072 / 4096; ECDSA P-256 / P-384.
- **Hash:** SHA-256 / SHA-384.
- **Mechanisms:** `CKM_SHA256_RSA_PKCS`, `CKM_SHA384_RSA_PKCS`, `CKM_ECDSA`
  (with pre-computed digest). PSS variants only on providers that explicitly
  declare support — YubiHSM 2 does not implement `CKM_RSA_PKCS_PSS` in all
  configurations.
- **Symmetric (if added):** AES-256 with `CKM_AES_KEY_WRAP_PAD` (AES-KWP).

Any mechanism outside this list is gated behind an explicit feature check
performed against the provider's `C_GetMechanismList` at activation time.

### 8.2 Mandatory private-key attributes (PKCS#11 backend)

Every CA / OCSP signing key generated on a token must be created with:

- `CKA_PRIVATE = TRUE`
- `CKA_SENSITIVE = TRUE`
- `CKA_EXTRACTABLE = FALSE`
- `CKA_TOKEN = TRUE`
- `CKA_SIGN = TRUE`
- `CKA_DECRYPT = FALSE`, `CKA_ENCRYPT = FALSE`

Luna rejects keys missing these flags; SoftHSM2 silently accepts weaker
combinations. Code that relies on SoftHSM2 defaults breaks on first contact
with real hardware. The attribute set is hard-coded in
`PKCS11Backend.generate_key` and asserted by the test fixture.

### 8.3 Vendor portability constraints

The implementation must isolate each of these behind a config knob, not
hard-code SoftHSM behavior:

- **Mechanism availability** — probe with `C_GetMechanismList` at
  activation; fail fast with a clear error if a required mechanism is
  missing.
- **Login model** — Luna partitions use role-based login (Crypto Officer /
  Crypto User); YubiHSM 2 authenticates via numeric authkey IDs in addition
  to a PIN. The provider's `auth_kind` and `extra_json` carry these.
- **Session limits** — YubiHSM 2 caps concurrent sessions at 16 per
  authkey. Reinforces the "one shared session per provider, not per cached
  key" rule (Gap 6).
- **Slot identification** — slot numeric IDs are not stable across
  reboots/reinitialisations. Always address by `slot_label`, never by
  numeric slot.

---

## 9. REST API specification

All endpoints under `/api/crypto-providers` and `/api/kms` require an
authenticated session. Role gates are noted per endpoint.

### 9.1 Provider management (`/api/crypto-providers`)

| Method | Path | Role | Description |
|---|---|---|---|
| GET | `/api/crypto-providers` | any authenticated | List providers. Returns `id`, `label`, `kind`, `auto_activate`, activation state, key count. Does not return secrets. |
| GET | `/api/crypto-providers/{id}` | any authenticated | Provider details (full record minus `auth_secret_blob`). |
| POST | `/api/crypto-providers` | superadmin | Create a provider. Body: `label`, `kind`, `module_path?`, `slot_label?`, `auth_kind`, `auto_activate`, `auth_secret_ref`, `auth_secret?` (when `db:encrypted`), `extra_json?`, `description?`. |
| PUT | `/api/crypto-providers/{id}` | superadmin | Update mutable fields: `label`, `module_path`, `slot_label`, `auto_activate`, `auth_secret_ref`, `auth_secret?`, `extra_json`, `description`. `kind` is immutable after creation; promoting software → pkcs11 requires deleting and recreating with key migration. |
| DELETE | `/api/crypto-providers/{id}` | superadmin | Delete a provider. Rejected with 409 if any `KeyStorage` row references it. |
| POST | `/api/crypto-providers/{id}/activate` | admin | Activate the provider. Body: `pin?` (required for `operator:prompt`, ignored otherwise). 200 on success, 503 on backend failure. |
| POST | `/api/crypto-providers/{id}/deactivate` | admin | Close the backend, evict cached keys. 200 on success. |
| GET | `/api/crypto-providers/{id}/status` | any authenticated | Returns `state` (`active` / `inactive`), `last_activated_at`, `last_error`, `mechanism_list` (when `kind=pkcs11`). |

### 9.2 Key management (`/api/kms/keys`)

The existing `/api/kms/generate-key` endpoint is replaced by the
provider-aware shape below. The old endpoint remains as an alias that maps
to the default provider for one release, then is removed.

| Method | Path | Role | Description |
|---|---|---|---|
| GET | `/api/kms/keys` | any authenticated | List keys. Optional query: `provider_id`, `key_type`. Response is the *token-aware merged* envelope `{keys: [...], token_enumeration: {available, reason}}`. Each row carries a `state` ∈ {`registered_and_present`, `present_only`, `registered_only`} plus `unimportable_reason` for `present_only` rows that the UI must surface but cannot import (`null` ⇒ importable; `"unsupported_key_type"`, `"public_key_unavailable"`, or `"duplicate_cka_id"` ⇒ read-only). Every on-token `CKO_PRIVATE_KEY` surfaces as its own row — when two or more share a `CKA_ID`, the first-iterated entry is the canonical one (paired with a DB row if present, otherwise importable) and the rest carry `duplicate_cka_id`. `present_only` rows only appear when the query is scoped to an active `pkcs11` provider; the global view (no `provider_id`) is DB-only. `token_enumeration.reason ∈ {null, "no_provider_scope", "not_applicable", "provider-inactive", "slot-missing", "auth-failed", "module-error", "backend-error"}` so the UI can render specific guidance when activation fails. Private material is never returned. |
| GET | `/api/kms/keys/{key_id}` | any authenticated | Key details. On top of the `KeyStorage` columns the response carries `provider_label`, `state`, `usage = {count, items: [{type, id, name, …}]}` — the named CAs / certificates / OCSP responders that block deletion — and `token_check = {available, present, reason}` from a per-key on-demand probe of the token. For HSM-backed rows whose `pkcs11` provider is active, a missing on-token object flips `state` to `"registered_only"` so the details page renders the drift banner (§10.5). Software keys and rows on inactive providers carry `available=false` with a diagnostic `reason`. The 409 path of `DELETE /api/kms/keys/{id}` checks the same set of relations as `usage.items`. |
| POST | `/api/kms/keys` | admin | Generate a new key. Body: `provider_id`, `key_type` (`RSA-3072`, `ECDSA-P-256`, …), `label`. Provider must be `active`. |
| POST | `/api/kms/keys/import` | superadmin | Register an existing on-token key into `KeyStorage` (no key material generated). Body: `provider_id` (must be `kind=pkcs11`), `hsm_token_id`, `label?`. Public key is read from the token. Also called by the keys list's per-row Import affordance for `present_only` rows. |
| POST | `/api/kms/keys/{key_id}/export` | superadmin | Export an owned software key as a passphrase-encrypted PKCS#8 PEM. Body: `{"passphrase": "<UTF-8, ≥12 chars>"}`. Response: raw PEM body with `Content-Type: application/x-pem-file` and `Content-Disposition: attachment; filename="key-{id}.pem"`. Refused with 409 for HSM-backed rows (non-extractable by §8.2) and for `key_owned=FALSE` rows. 400 for missing / too-short passphrase. Every outcome audits as `kms_keys / EXPORT[_REFUSED_HSM|_REFUSED_IMPORTED|_FAILED]`. |
| DELETE | `/api/kms/keys/{key_id}` | admin | Delete a key. For `kind=pkcs11`, deletes the on-token object too unless `key_owned=FALSE` (imported keys preserve the on-token material). Rejected with 409 if any CA / certificate / OCSP responder still references the key. |

### 9.3 Errors

Errors follow the existing pyPKI error shape (`{"description": "…"}` with
appropriate HTTP status). Provider-specific errors use 503 (provider
inactive / backend failure), 409 (in-use key or provider), 400
(validation), 404 (unknown id).

**Backend errors (CR-0005).** When any view function raises a
`BackendError` subclass (`KeyMissingOnToken`, `SlotNotFound`,
`AuthenticationFailed`, `ModuleLoadFailed`, or the base
`BackendNotActive`), the app-level handler registered in
`web.create_app` returns 503 with the structured body:

```json
{
  "description": "<operator-facing message>",
  "code":        "<see table>",
  "key_id":      <int|null>,
  "provider_id": <int|null>,
  "recovery":    "/key_details.html?id=<key_id>"   // only when key_id is set
}
```

The `code` vocabulary matches the values that `token_check.reason`
on `GET /api/kms/keys/{id}` produces:

| `code` | Exception class | Operator-facing description |
|---|---|---|
| `key_missing_on_token` | `KeyMissingOnToken` | The bound on-token object is gone; restore it or delete the row. |
| `slot-missing` | `SlotNotFound` | The configured slot is no longer on the module. |
| `auth-failed` | `AuthenticationFailed` | The PIN was rejected by the token. |
| `module-error` | `ModuleLoadFailed` | The PKCS#11 module could not be loaded. |
| `provider-inactive` | `BackendNotActive` | The bound provider is not active. |
| `backend-error` | other `BackendError` | Generic backend failure. |

The same shape covers every blueprint (main / ocsp / est) — EST
clients receive the JSON 503 until a future EST service spec defines
its own RFC-7030 / RFC-8951 error mapping (see §2.2 EST hook).

---

## 10. Management UI

A new sidebar section, **KMS**, replaces the existing single "Key
Generation" entry with two pages plus a settings shortcut.

### 10.1 Crypto Providers page (`/crypto_providers.html`)

- **List view** — table with columns: label, kind (badge), state (active /
  inactive), auto-activate toggle, key count, last error. Filter by kind.
  Buttons: "Add provider," "Activate," "Deactivate," "View," "Edit," "Delete."
- **Add / Edit** (modal or dedicated page `/crypto_provider_editor.html`):
  - Label (text)
  - Kind (radio: software / pkcs11; **disabled on edit**)
  - For `pkcs11`: module_path (text with the platform default as
    placeholder), slot_label (text), auth_kind (dropdown), extra_json
    (collapsible JSON editor for authkey id, role)
  - Auto-activate (checkbox)
  - Auth secret source (dropdown: db:encrypted / env / vault /
    operator:prompt) + value field (only for env / vault / db:encrypted)
  - Description (textarea)
  - Save button validates: auto_activate + operator:prompt is rejected;
    db:encrypted requires a PIN value entered in this form (which the
    backend will encrypt under `HSM_PIN_KEK`).
- **Provider detail** (`/crypto_provider_details.html`):
  - Header: label, kind, state, "Activate" / "Deactivate" button.
  - Activation modal: PIN input (operator:prompt) or just a confirmation
    button (other resolvers).
  - Linked keys table — same columns as the global key list, scoped to this
    provider, with "Generate," "Import" (pkcs11 only), and "Delete" buttons.
  - For `pkcs11` providers: declared mechanism list (from `C_GetMechanismList`).

### 10.2 Keys page (`/kms_keys.html`)

Replaces the existing `kms_keygen.html`.

- **List view** — token-aware table with columns: id, **state**,
  provider, type, label, storage, HSM CKA_ID, usage, created,
  actions. Filter by provider and key type. Header buttons:
  "Generate key" and "Import HSM key" (the latter kept as a fallback
  for tokens whose enumeration fails). For `pkcs11`-scoped lookups,
  the table merges `KeyStorage` rows with on-token objects so
  unregistered keys are visible.
  - `state` rendering:
    - `registered_and_present` — no badge.
    - `present_only` + `unimportable_reason = null` — "Not
      registered" badge + per-row **Import** button. Clicking opens
      a one-field prompt pre-filled from the row's `CKA_LABEL`
      (decision 5); confirming POSTs `/api/kms/keys/import` without
      leaving the page.
    - `present_only` + `unimportable_reason ∈
      {"unsupported_key_type", "public_key_unavailable",
      "duplicate_cka_id"}` — muted badge with the matching label;
      **no action**. `unsupported_key_type` is the CKA_KEY_TYPE
      conservative-subset rule. `public_key_unavailable` is the
      residual case after CR-0003: the paired `CKO_PUBLIC_KEY` is
      missing *and* the private-handle reconstruction fallback
      (CKA_PUBLIC_KEY_INFO → CKA_MODULUS/CKA_EC_POINT) also failed,
      typically because vendor policy blocks reading public
      components under the active role. `duplicate_cka_id` covers
      the pathological case where multiple on-token objects share
      a `CKA_ID` and pyPKI cannot address them individually until
      the operator cleans up the slot.
    - `registered_only` — "Missing on token" muted-red badge; the
      operator opens the details page to investigate.
  - `Details` button per registered row → `/key_details.html?id=…`.
    No destructive action is offered inline.
  - When `token_enumeration.available=false`, the page renders a
    banner whose severity and copy depend on the reason —
    `slot-missing` / `auth-failed` / `module-error` are red and
    name the diagnosis (token deleted; PIN rejected; module won't
    load); `provider-inactive` is yellow and prompts the operator
    to activate the provider. The registered keys are still shown
    in every case so the operator can navigate to the details
    page.
- **Generate modal** — provider dropdown (pre-filtered to active
  providers), key type dropdown (RSA-2048/3072/4096, ECDSA-P-256/P-384,
  Ed25519, AES-256), label.
- **Import modal** (PKCS#11 providers only) — provider dropdown,
  hsm_token_id (hex), optional label. The system reads the public key from
  the token to populate `KeyStorage.public_key`.

### 10.3 Hooks into existing pages

- **CA editor / Add CA** — the existing key-source picker gains a "Provider"
  dropdown when generating or selecting an existing KMS key. Uploading a PEM
  CA still goes through the default software provider (existing behavior
  preserved; key gets encrypted at rest under that provider's KEK on import).
- **OCSP responder editor** — same: provider dropdown for the key source.
- **Audit log viewer** — new event types listed in §11 surface here.

### 10.4 Settings

`HSM_PIN_KEK` is configured outside the application (environment, systemd
EnvironmentFile, container env). A read-only **Settings → KMS** page shows
whether the KEK is present (boolean only — the value is never displayed)
and the active resolver backends, so an operator can confirm the deployment
is wired up correctly.

### 10.5 Key details page (`/key_details.html?id=…`)

Owns key-level inspection and the destructive / export actions; the
list views in §10.2 and the per-provider keys table on the Crypto
Provider Details page link here for anything non-trivial.

- **Header** — label, key-type badge, `state` badge (with the same
  semantics as in §10.2), `key_owned` indicator
  (`pyPKI-owned` / `Imported`) for HSM keys.
- **Drift / verification banner** — driven by the `token_check`
  envelope on `GET /api/kms/keys/{id}` (see §9.2). For HSM-backed
  rows the endpoint runs `KMS.probe_key_on_token` and surfaces:
  - `{available: true, present: false}` — drift. A red banner
    explains the on-token object is missing, that sign / issuance
    operations will fail with `KeyMissingOnToken`, and recommends
    either restoring the material or deleting the row. The Export
    button is suppressed in the action bar.
  - `{available: false, reason: "slot-missing"}` — red banner
    "Slot is missing on the PKCS#11 module" with the same
    recovery framing (sign / issuance will fail; reconfigure the
    provider against an existing slot).
  - `{available: false, reason: "auth-failed"}` — red banner
    "Provider authentication failed" — token may have been
    reinitialised with a new PIN.
  - `{available: false, reason: "module-error"}` — red banner
    pointing the operator at the provider's `module_path`.
  - `{available: false, reason: "provider-inactive"}` — yellow
    banner noting the operator must activate the provider to
    revalidate the key.
  - `{available: false, reason: "unknown_provider" | "backend-error"}`
    — yellow "could not verify" banner.
  - Software keys and rows without `hsm_token_id` get
    `reason="not_applicable"`; no banner.
- **Info card** — provider link, storage type, HSM CKA_ID, created
  timestamp.
- **Public key panel** — read-only textarea + copy and
  "Download PEM" buttons.
- **Usage panel** — table of dependents from
  `GET /api/kms/keys/{id}.usage.items`. Each row links to the
  dependent's detail page (CA, certificate, OCSP responder). The
  set is identical to the relations that drive the 409-rejection
  path of `DELETE /api/kms/keys/{id}`.
- **Audit trail panel** — events for this key, newest first, from
  `GET /api/audit-logs?resource_type=kms_keys&resource_id=…`.
  Reuses the existing audit-log surface (decision 6); no new event
  types are introduced. Non-auditor users see a graceful "audit
  trail unavailable" notice rather than a hard failure.
- **Action bar** —
  - **Export** (CR-0002, superadmin-only) — opens a passphrase
    prompt modal (confirm-passphrase + ≥12 char client-side
    validation), then POSTs `/api/kms/keys/{id}/export` and saves
    the returned PEM via a `Blob`-backed download so server-side
    4xx errors render in the modal rather than as a page
    navigation. Hidden for any of: non-superadmin caller, HSM
    storage, imported software (`key_owned=FALSE`), or
    `registered_only` drift rows; the server enforces the same
    rules with 409 so direct API callers cannot side-step them.
    Success refreshes the audit panel so the new `EXPORT` event
    is visible immediately.
  - **Delete** — opens a confirmation modal that lists the named
    dependents (if any) and the HSM-cascade implication for owned
    vs imported HSM keys, then calls `DELETE /api/kms/keys/{id}`.
    Honours the existing 409 rejection.

---

## 11. Audit logging

The following events write to `AuditLogs`:

| Event | Fields |
|---|---|
| `provider_create` | provider_id, label, kind, auto_activate, auth_secret_ref kind |
| `provider_update` | provider_id, changed fields (no secret values) |
| `provider_delete` | provider_id, label |
| `provider_activate` | provider_id, method (`auto` / `operator-prompt` / `env` / `vault` / `db:encrypted`), success |
| `provider_deactivate` | provider_id, reason (`operator` / `shutdown`) |
| `provider_auto_activate_toggled` | provider_id, new value |
| `key_generate` | key_id, provider_id, key_type, label |
| `key_import` | key_id, provider_id, hsm_token_id |
| `key_delete` | key_id, provider_id |
| `key_export` | key_id, action ∈ {`EXPORT`, `EXPORT_REFUSED_HSM`, `EXPORT_REFUSED_IMPORTED`, `EXPORT_FAILED`} (CR-0002). Distinct row per refusal class so audit consumers can distinguish policy denial from runtime failure. |

`sign_digest` calls are *not* audit-logged by default — they happen on every
issuance, every CRL, every OCSP response, and would dominate the log. CA-
and OCSP-level audit events already cover the high-level operations.

---

## 12. Development environment

### 12.1 Two-tier strategy

- **Tier 1 — SoftHSM2 (daily dev + CI).** Free, packaged on every Linux
  distro, runs in a Docker container alongside the app, fast enough to use
  as a unit-test fixture. Permissive: accepts attribute combinations and
  mechanisms that real HSMs reject, so it cannot be the only test target.
- **Tier 2 — fidelity check before each release.** Run the full HSM test
  suite against:
  - the **YubiHSM 2 simulator** (ships with the Yubico SDK), and / or
  - a **Thales DPoD trial** (real Luna firmware behind their API; the only
    realistic Luna-equivalent without owning hardware).

  AWS CloudHSM (Luna under the hood) is a fallback if DPoD trial access
  expires. No general-purpose offline Luna emulator is available outside the
  vendor's customer SDK.

### 12.2 SoftHSM2 in the pyPKI Docker image

Already in place (Dockerfile, docker-entrypoint.sh, docker-compose.yml).
Token state persists in `data/softhsm/tokens/`; default token `pypki-dev`,
PIN `1234`, SO-PIN `5678`. The full operator manual lives in
[softhsm2-manual.md](softhsm2-manual.md).

### 12.3 Test fixtures

- A `pytest` fixture opens a session against the dev SoftHSM2 token, yields
  it to the test, and tears down on exit.
- The full signing test suite is parameterised over backends: every test
  runs once with the default `software-default` provider and once with a
  `softhsm-dev` `pkcs11` provider. Mechanism / attribute / session bugs
  surface against both backends on every CI run.

### 12.4 Library choice

Stay on **PyKCS11**. It is a thin, literal binding that exposes the raw
PKCS#11 surface — useful when debugging vendor-specific quirks. Switching to
`python-pkcs11` is a separate decision and not a prerequisite for any of
the work in this spec.

---

## 13. Order of work

The work is sequenced so each phase produces a working, testable
intermediate state. Each phase ends with passing tests.

**Phase 0 — provider model + dev environment.**

- Introduce `CryptoProviders` table; add migration (Section 4.3).
- Migrate `KeyStorage`: add `provider_id`, drop `hsm_slot` and
  `token_password`, encrypt-at-rest existing `Plain` rows, set `provider_id`
  on every row.
- Seed `software-default`.
- Extract `SoftwareBackend` and `PKCS11Backend` as siblings under the
  `CryptoBackend` Protocol; route `KeyManagementService` through the
  contract.
- Stand up the SoftHSM2 dev environment as the first `pkcs11` provider row
  (via the `legacy-hsm` migration entry, then renamed to `softhsm-dev`).
- `pytest` fixture for the SoftHSM provider; two passing tests (one per
  backend) signing through the same KMS API.

Closes Gap 4 (no provider abstraction). Without this, every subsequent gap
is fixed against the wrong shape.

**Phase 1 — fix HSM signing.**

- Gap 1 (RSA mechanism: switch to `CKM_SHA256_RSA_PKCS`, pass TBS bytes).
- Gap 2 (ECDSA branch: `CKM_ECDSA` over digest, DER-encode `(r, s)`).
- Sign-and-verify tests for both algorithms against the SoftHSM provider.

**Phase 2 — slot selection.**

- Gap 3 (`hsm_slot` ignored): thread `slot_label` through the provider →
  PKCS11Backend → `open_session()`. Probe by label, not numeric slot.

**Phase 3 — concurrency + session lifecycle.**

- Gap 7 (per-key lock around `load_key`).
- Gap 6 (one shared backend session per provider; close on
  deactivate/shutdown; reconnect on `CKR_SESSION_HANDLE_INVALID` /
  `CKR_DEVICE_REMOVED`).
- Multi-threaded SoftHSM stress test in CI.

**Phase 4 — secret handling.**

- Gap 5: `auth_secret_ref` resolvers — `db:encrypted` (using `HSM_PIN_KEK`),
  `env:`, `operator:prompt`. `vault:` deferred. `auto_activate` enforced.
- Activation API endpoints (Section 9.1).

**Phase 5 — operator UX.**

- Gap 8: HSM-backed key generation and import via API and UI.
- Provider management API + UI pages (Sections 9–10).
- Audit-log events (Section 11).

**Phase 6 — hardening + cleanup.**

- Gap 9 (`hsm_token_id` validated at insert/load).
- Gap 10 (`'Encrypted'` storage type now actually encrypts; or — given Phase
  0 already converted everything, this gap is closed by construction;
  confirm and mark resolved).
- Gap 11 (`Symmetric` storage type with its own load branch).
- Gap 12 (stale `migrate_keys_to_kms.py` reference in OCSP error path).
- Expand SoftHSM-based test coverage.

**Phase 8 — token-aware key listing + key details page** (CR-0001,
accepted 2026-05-12, shipped). Closes the §2.2 bullets about visible
on-token keys and a dedicated key details surface.

- `PKCS11Backend.list_keys()` enumerates every `CKO_PRIVATE_KEY` on
  the open session; `SoftwareBackend.list_keys()` returns `[]`.
- `GET /api/kms/keys` returns the merged envelope `{keys,
  token_enumeration}` with per-row `state` and `unimportable_reason`.
- `GET /api/kms/keys/{id}` returns `provider_label`, `state`, and
  the named `usage.items` list.
- `POST /api/kms/keys/{id}/export` reserved (501).
- New `/key_details.html` page hosts the public-key panel, the
  usage table, the audit-log trail, and the destructive / export
  actions; both list views drop the inline `Delete` button.
- `GET /api/audit-logs` gains optional `resource_type` and
  `resource_id` filters so the details page can fetch a single
  key's trail.
- Public-key recovery fallback (CR-0003, accepted 2026-05-12):
  `_read_public_key_pem_attributes` works on either a public or a
  private handle (CKA_PUBLIC_KEY_INFO → algorithm-specific
  attributes); `list_keys` and `find_key_by_id` invoke it as a
  fallback when the paired `CKO_PUBLIC_KEY` is missing. Rows
  surface as importable when reconstruction succeeds and keep
  `unimportable_reason="public_key_unavailable"` for the residual
  vendor-restricted case.
- Key export (CR-0002, accepted 2026-05-12):
  `KMS.export_software_key(key_id, passphrase)` decrypts the
  KEK-protected blob via the bound `SoftwareBackend` and re-wraps
  the plaintext under `BestAvailableEncryption(passphrase)` (PBES2
  / AES-256-CBC). The `POST /api/kms/keys/{id}/export` route
  enforces a 12-char minimum passphrase, gates on `superadmin`,
  refuses HSM rows and `key_owned=FALSE` rows with 409, and writes
  one of `EXPORT` / `EXPORT_REFUSED_HSM` /
  `EXPORT_REFUSED_IMPORTED` / `EXPORT_FAILED` to `AuditLogs` on
  every outcome. UI on `/key_details.html` adds a passphrase modal
  with confirm-passphrase + length check and downloads the PEM via
  a `Blob` so server 4xx errors render in the modal rather than
  as a page navigation.
- Mid-session classification + cache eviction (CR-0004, accepted
  2026-05-12): shared `_open_session_classified` helper covers
  both activation and reconnect paths; `sign_digest` reconnect
  widens to the full set of session-stale CKR codes;
  `_classify_pkcs11_error_midsession` wraps `list_keys` /
  `find_key_by_id` (no retry — diagnostic). The KMS evicts the
  cached backend on `SlotNotFound` / `AuthenticationFailed` /
  `ModuleLoadFailed` via the `_evict_on_hard_failure` context
  manager so the next call re-runs activation cleanly.
- Structured backend-error surface (CR-0005, accepted 2026-05-12):
  `BackendError` subclasses carry `key_id` / `provider_id`
  attached at the throw site. App-level Flask handler
  (`web.create_app`) renders any `BackendError` as the structured
  503 envelope documented in §9.3. Consumer routes (cert
  issuance, PKCS#12, OCSP, EST) re-raise `BackendError` from their
  broad catches so the handler sees it. Background CRL scheduler
  logs typed failure class + key_id + provider_id at WARN and
  continues with the next CA.

**Phase 7 — fidelity pass.** *Indefinitely deferred — no real-HSM
access planned by the project.*

The pyPKI KMS layer (Phases 0–6 + Phase 8) is feature-complete and
exercised end-to-end against SoftHSM2 in CI. Phase 7 — running the
same suite against real-vendor implementations to confirm portability
— requires hands-on access to one of:

- a **YubiHSM 2** (hardware or simulator from the Yubico SDK), or
- a **Thales DPoD trial** (real Luna firmware behind their API), or
- an **AWS CloudHSM** instance (Luna under the hood; chargeable).

None of these are on the project's procurement path. The phase
stays in §13 as a record of *what would be done* if access ever
materialises (run the parametrised pytest matrix against a
`kind='pkcs11'` provider pointing at the new module, gate any
vendor-specific findings behind `extra_json` flags rather than code
branches, refresh the §8.1 conservative-subset table if anything
gets rejected), but no calendar commitment is implied.

Until then, treat the SoftHSM2 suite as the canonical regression
target. Operators deploying against a real HSM should expect the
implementation to work given the §8 conformance constraints, but
the formal "release-ready against vendor X" claim cannot be made
from inside this project.

---

## 14. Acceptance criteria

For the consolidated plan to be considered "done":

1. A fresh `reset_pki` install yields exactly one provider
   (`software-default`, active) and the existing CA-creation flow works
   without operator intervention beyond `HSM_PIN_KEK` being set.
2. An operator can create a `pkcs11` provider pointing at the SoftHSM2 dev
   container, activate it, generate an RSA-3072 and an ECDSA-P-256 key on
   it, bind them to two CAs, and issue certificates that verify against
   third-party tools (`openssl verify`, `certutil`).
3. Restarting the container reactivates auto-activated providers, leaves
   non-auto providers inactive, and CAs bound to inactive providers report
   "provider unavailable" cleanly on first sign attempt — no PKCS#11-level
   exception leaks.
4. The same test suite passes against both backends in CI.
5. No `KeyStorage` row contains a plaintext private key (`storage_type=Plain`
   no longer exists in operational data; `private_key` for `Encrypted` /
   `Symmetric` rows is encrypted under a provider KEK).
6. `KeyStorage.token_password` and `KeyStorage.hsm_slot` columns no longer
   exist.
7. Audit log entries are produced for every provider lifecycle and key
   lifecycle event.
8. **Token-aware key surface** (CR-0001): an operator can scope the keys
   page to a `pkcs11` provider, see every on-token object — registered
   or not — in one merged table, and import an unregistered row without
   typing a CKA_ID anywhere. No destructive button lives on any list
   view; deletion and (future) export are reached through
   `/key_details.html`, which lists named dependents and the key's
   audit trail.
9. *(deferred)* The fidelity-pass test suite passes against YubiHSM 2
   simulator (Thales DPoD optional but documented). Held back until the
   simulator / trial is available — see Phase 7 in §13.

---

## 15. Out of scope for this spec

- **Cloud KMS (AWS KMS, Azure Key Vault, GCP KMS) as a provider kind.**
  The data model leaves room (`kind` enum extension, `extra_json` for
  endpoint/role config), but no concrete backend is scoped here.
- **Key rotation with cert re-issuance.** A separate workflow that uses but
  does not require any KMS changes.
- **Per-caller access control on `sign_digest`.** Currently any code path
  inside the app can sign with any active key. Tightening this requires
  thinking about CA / OCSP / EST identity propagation — separate effort.
- **`vault:path` resolver.** Listed in the API but not implemented in the
  initial cut; placeholder returns 501.
- **HSM hardware procurement.** The Tier 2 fidelity targets (YubiHSM 2,
  Thales DPoD) are validation environments, not production deployment
  guidance.

---

## 16. Cross-references

- [hsm-support-specs.md](hsm-support-specs.md) — HSM-specific contracts
  (PKCS#11 mechanisms, slot addressing, session lifecycle, storage
  types) on top of this KMS spec.
- [softhsm2-manual.md](softhsm2-manual.md) — operator manual for the
  SoftHSM2 dev environment.
- [database-specs.md](database-specs.md) — current schema; the
  `CryptoProviders` and `KeyStorage` tables specified there back this
  spec.
- [rest-api.md](rest-api.md) — REST API reference; will be extended with the
  endpoints in Section 9.
- [roadmap.md](roadmap.md) — broader project roadmap; the HSM section
  references this spec.

---

## 17. Future direction — Signing Services

A planned extension that turns the KMS from an internal-only signing
substrate for X.509 / OCSP / EST into one that can also expose
**signing services to external callers**. Captured here so the
abstraction boundary is preserved when the work lands; not in scope for
the current spec. Tracked in [roadmap.md §8](roadmap.md) and
[PROGRESS.md §8](PROGRESS.md).

### 17.1 Concept

A **Signing Service** is a configurable consumer of the KMS, addressable
over the REST API, that:

- is bound to **one** KMS signing key (`KeyStorage.id`);
- has a configured **signature type** (see §17.4);
- has its own **access policy** (which callers may invoke it, with
  what audit identity);
- can be enabled / disabled independently of the underlying key.

Signing services sit at the same architectural tier as CAs, OCSP
responders, and EST aliases — they are *consumers* of the KMS, not
part of it. The `CryptoBackend` contract (§5), the provider model
(§4), and the activation lifecycle (§6) are unchanged. The only
KMS-internal extension is that a key can now be referenced by
something other than a CA or an OCSP responder.

### 17.2 Why a sibling service rather than a new KMS endpoint

The current `/api/kms/keys` surface is key-CRUD, not an operation
surface — it intentionally hides the signing primitive from external
callers because access to it is implicit (CAs and OCSP responders
running inside the app are trusted). Exposing
`POST /api/kms/keys/{id}/sign` directly would create an unbounded,
per-key external signing surface with no policy, no audit identity
contract, and no usage scoping. Signing Services give each external
use case a **named, configured, audited** entry point on top of the
same primitive.

### 17.3 Data model addition

A new `SigningServices` table joins the existing data model:

| Column | Notes |
|---|---|
| `id` | PK. |
| `name` | Unique, operator-facing. |
| `key_id` | FK → `KeyStorage(id)`. `ON DELETE RESTRICT` — a key bound to a service may not be silently deleted. |
| `signature_type` | Enum (initially `raw_hash`; see §17.4). |
| `signature_config` | JSON. Type-specific parameters (e.g. allowed hash algorithms, digest-length policy). |
| `is_enabled` | BOOLEAN. Disabled services return 503 cleanly without touching the KMS. |
| `auth_policy` | JSON. Per-service auth (token scopes / roles / mTLS subject patterns). Specifics deferred to the implementation phase. |
| `created_at`, `updated_at` | Timestamps. |

`KeyStorage.usage` (today implicit "signing") becomes explicit so a
key bound to a CA cannot also be bound to a signing service unless
the operator opts in — preserving the auditability of which key
signed which artefact.

### 17.4 Signature types

Signature types are pluggable. The initial type is intentionally
minimal:

- **`raw_hash` (initial).** Caller submits a pre-computed digest plus
  a hash-algorithm identifier; the service returns the raw signature
  bytes (RSA PKCS#1 v1.5 or ECDSA `(r,s)` DER per the key's
  algorithm — the same primitive the X.509 path already uses). No
  envelope, no certificate embedding, no timestamping.

Subsequent types (each its own ticket) layer formatting on top:

- `cms_detached` — RFC 5652 detached CMS signature.
- `rfc3161_timestamp` — TSA response. Also needs a TSA certificate,
  response policy OID config, and a trusted time source.
- `jose_jws` — RFC 7515 compact JWS over a caller-supplied payload.
- `pe_authenticode`, `jar`, `rpm` — code-signing format wrappers.
- `pdf`, `xmldsig` — document-signing format wrappers.

Each new type is data-driven (`signature_type` enum value plus a
type-specific `signature_config` schema); none requires changes to
`CryptoBackend`.

### 17.5 REST API additions (sketch)

```
POST   /api/signing-services                    create
GET    /api/signing-services                    list
GET    /api/signing-services/{id}               read
PATCH  /api/signing-services/{id}               update (incl. enable/disable)
DELETE /api/signing-services/{id}               delete

POST   /api/signing-services/{id}/sign          invoke
```

The invocation endpoint dispatches on `signature_type` and routes the
final `sign()` call through the existing KMS path. It enforces the
service's own `auth_policy` against the caller, independently of the
management-API role check used by the CRUD endpoints.

### 17.6 Audit

Every successful or failed `/sign` invocation MUST produce an audit
log entry referencing the signing service id, the caller identity
(resolved per §17.3 `auth_policy`), the key id, and an integrity hash
of the input digest. Volume is per-operation rather than per-PKI-event,
so a separate retention policy from the existing audit log is likely.

### 17.7 Out of scope for this future direction

- **Encryption services.** A second sibling surface (encrypt / decrypt)
  is a distinct initiative; it requires `verify` / `encrypt` / `decrypt`
  on `CryptoBackend` (§5) and a parallel key-purpose story
  (`KeyStorage.usage`). Tracked separately if pursued.
- **Format-specific code-signing engines.** PE Authenticode, JAR, RPM,
  etc. are follow-up `signature_type`s, not part of the initial
  signing-service scaffold.
- **Hardware-attested signing claims.** No vendor-attestation
  envelopes; `raw_hash` returns the bare signature.

---

## 18. Design proposals

This section holds in-progress designs for capabilities listed in
§2.2 that reshape the existing API or UI surface. A proposal lives
here only while the design is being negotiated. Once accepted and
shipped, its content is folded into the relevant canonical sections
(§5 for the backend contract, §9 for API, §10 for UI, §11 for audit,
§13 for the phase plan) and the proposal entry is removed.

Each proposal follows a fixed shape: **Status**, **Motivation**,
**Proposed behaviour**, **Impact on existing sections**, **Action
plan**, **Open questions**, **Acceptance criteria**. Proposals are
numbered `CR-NNNN` with zero-padded four-digit ids, allocated in
order of creation; numbers are never reused. This is the same
convention used in
[ca-management-specs.md §17](ca-management-specs.md).

**Implemented (folded in).**
- CR-0001 (token-aware key listing + key details page) — accepted
  2026-05-12; folded into §2.1, §9.2, §10.2, §10.5, §13 (Phase 8),
  and §14.
- CR-0002 (key export semantics) — accepted 2026-05-12; folded into
  §2.1, §9.2, §10.5, §11, and §13 (Phase 8).
- CR-0003 (public-key recovery for orphaned on-token private keys)
  — accepted 2026-05-12; folded into §2.1, §10.2, and §13 (Phase 8).
- CR-0004 (mid-session token / slot-loss recovery) — accepted
  2026-05-12; folded into §2.1 and §13 (Phase 8).
- CR-0005 (structured `KeyMissingOnToken` surfacing at consumer
  routes) — accepted 2026-05-12; folded into §2.1, §9.3, and §13
  (Phase 8).

**In flight.** *(none — all CRs shipped.)*

