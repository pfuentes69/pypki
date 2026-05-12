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

### What is pending

- **Phase 7 — fidelity pass against real-vendor PKCS#11 implementations**
  (YubiHSM 2 simulator, Thales DPoD, AWS CloudHSM). Held back until
  the hardware / SDK becomes available to the project. SoftHSM2 is
  the canonical regression target until then. See §13 Phase 7.
- **Token-aware key listing.** `GET /api/kms/keys` and the
  per-provider keys table on the Crypto Provider Details page
  enumerate only rows in `KeyStorage`. For `pkcs11` providers there
  is no way to *see* keys that exist on the token but have not been
  registered in pyPKI yet — an operator cannot tell from the UI
  which on-token objects are importable. The generic "Import HSM
  key" button asks the operator to type the `CKA_ID` from memory.
  Designed in [§18.1 CR-0001](#181-cr-0001--token-aware-key-listing--key-details-page).
- **Key details page.** Today the keys list surfaces a `Delete`
  button inline and a single `usage` count; there is no view that
  shows the public key, the bound CAs / certificates / OCSP
  responders by name, or that scopes destructive and (future)
  export actions away from the bulk list. Designed in
  [§18.1 CR-0001](#181-cr-0001--token-aware-key-listing--key-details-page).
- `vault:` resolver — placeholder in the data model; raises
  `NotImplementedError`. Concrete implementation is a separate
  initiative.

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
| GET | `/api/kms/keys` | any authenticated | List keys. Optional query: `provider_id`, `key_type`. Response: id, provider_id, key_type, label, created_at, public_key (PEM), `usage` (CA / OCSP responder bindings, if any). Private material never returned. |
| GET | `/api/kms/keys/{key_id}` | any authenticated | Key details. |
| POST | `/api/kms/keys` | admin | Generate a new key. Body: `provider_id`, `key_type` (`RSA-3072`, `ECDSA-P-256`, …), `label`. Provider must be `active`. |
| POST | `/api/kms/keys/import` | superadmin | Register an existing on-token key into `KeyStorage` (no key material generated). Body: `provider_id` (must be `kind=pkcs11`), `hsm_token_id`, `label?`. Public key is read from the token. |
| DELETE | `/api/kms/keys/{key_id}` | admin | Delete a key. For `kind=pkcs11`, deletes the on-token object too. Rejected with 409 if any CA or OCSP responder still references the key. |

### 9.3 Errors

Errors follow the existing pyPKI error shape (`{"description": "…"}` with
appropriate HTTP status). Provider-specific errors use 503 (provider
inactive / backend failure), 409 (in-use key or provider), 400
(validation), 404 (unknown id).

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

- **List view** — table: id, provider, key type, label, created, usage
  (CA/OCSP binding count). Filter by provider, key type. Buttons: "Generate
  key," "Import HSM key," "Delete."
- **Generate modal** — provider dropdown (pre-filtered to active
  providers), key type dropdown (RSA-2048/3072/4096, ECDSA-P-256/P-384,
  Ed25519, AES-256), label.
- **Import modal** (PKCS#11 providers only) — provider dropdown,
  hsm_token_id (hex), optional label. The system reads the public key from
  the token to populate `KeyStorage.public_key`.
- **Delete confirmation** — refuses if usage count > 0; shows which CAs /
  OCSP responders reference the key.

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

**Phase 7 — fidelity pass.** *Pending hardware/SDK availability.*

The pyPKI KMS layer (Phases 0–6) is feature-complete and exercised
end-to-end against SoftHSM2 in CI. Phase 7 — running the same suite
against real-vendor implementations to confirm portability — is held
back until at least one of the following becomes available to the
project:

- the **YubiHSM 2 simulator** (Yubico SDK, requires a developer
  download), or
- a **Thales DPoD trial** (real Luna firmware behind their API;
  registration required), or
- an **AWS CloudHSM** instance (Luna under the hood; chargeable).

When any of those is available, the work is:

- Run the full HSM test suite (the parametrised pytest matrix from
  Phase 0.4 plus the Phase 5 generate / import / delete tests) against
  the new provider with `kind='pkcs11'` and the appropriate
  `module_path`.
- Document any vendor-specific findings; gate exceptions behind
  provider `extra_json` flags rather than code branches.
- Update the conservative-subset table in §8.1 if a target rejects any
  of the listed mechanisms.

Until then, treat the SoftHSM2 suite as the canonical regression target.
Operators deploying against a real HSM today should expect the
implementation to work given the §8 conformance constraints, but the
formal "release-ready against vendor X" claim is pending.

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
8. *(deferred)* The fidelity-pass test suite passes against YubiHSM 2
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
- [database.md](database.md) — current schema; will be regenerated when the
  `CryptoProviders` migration lands.
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

### 18.1 CR-0001 — Token-aware key listing + key details page

**Status:** Accepted (2026-05-12). Implementation pending; entry stays
here until the fold-in commit lands per the §18 preamble.

**Motivation:** §2.2 — the keys surface today (the global
`/kms_keys.html` page and the per-provider keys table on
`/crypto_provider_details.html`) only shows rows that already exist
in `KeyStorage`. For `pkcs11` providers this is half the picture:
keys that live on the token but have never been registered in
pyPKI are invisible. The only way to register one today is the
"Import HSM key" modal, which requires the operator to remember
and type the `CKA_ID` hex.

At the same time, the list view exposes a per-row "Delete" button
and reduces *usage* (which CAs / certificates / OCSP responders
hold the key) to a single integer. There is no view that names
the dependents, no place to land a future "Export" action (§15
out-of-scope today, but the surface needs a home), and the
destructive action is one mis-click away inline.

This proposal closes both gaps with one design: a token-aware list
view that merges KMS-registered keys with on-token objects, and a
dedicated key details page that owns key-level actions.

**Proposed behaviour:**

#### Backend — on-token enumeration

`CryptoBackend.list_keys()` already appears in the Protocol (§5)
but `PKCS11Backend.list_keys()` is unimplemented. Implement it as
a `C_FindObjectsInit` / `C_FindObjects` / `C_FindObjectsFinal`
sweep over `CKO_PRIVATE_KEY` objects, returning per key:

- raw `CKA_ID` bytes
- `CKA_LABEL` (may be empty)
- algorithm + parameter set (`RSA-3072`, `ECDSA-P-256`, …),
  derived from `CKA_KEY_TYPE` + `CKA_MODULUS_BITS` /
  `CKA_EC_PARAMS`. When the algorithm cannot be parametrised
  against the conservative subset (§8.1), the field is set to
  `null` and the row carries `unimportable_reason =
  "unsupported_key_type"` (see API below).
- public-key DER **only** when a paired `CKO_PUBLIC_KEY` object
  exists on the token. The raw-attribute fallback
  (`CKA_MODULUS` / `CKA_EC_POINT`) is intentionally deferred to
  a follow-up — when the paired object is missing the row is
  surfaced with `unimportable_reason = "public_key_unavailable"`
  and no PEM.

`SoftwareBackend.list_keys()` returns the empty set — software
keys are 100% DB-backed, so `KeyStorage` is authoritative; there
is no parallel store to enumerate.

Enumeration runs only when the provider is `active` (§6). On an
inactive `pkcs11` provider the API returns the DB rows alone plus
an envelope flag (see API below).

#### API — `GET /api/kms/keys` (merged listing)

Behaviour depends on the query:

- **`?provider_id=<software>`** — unchanged. Returns `KeyStorage`
  rows for the provider; every row is `registered_and_present`.
- **`?provider_id=<pkcs11>`, provider active** — returns the
  *merged* set:
  - every `KeyStorage` row for the provider, joined against the
    backend's `list_keys()` by `hsm_token_id`;
  - every on-token key with no matching `KeyStorage` row.
- **`?provider_id=<pkcs11>`, provider inactive** — returns DB
  rows only, with `token_enumeration.available = false`.
- **No `provider_id`** — returns DB rows across all providers
  (the existing behaviour). On-token-only entries are **never**
  merged into the global view; the operator must scope to a
  `pkcs11` provider to see unregistered on-token keys.

Each row carries a `state` field:

| `state` | Meaning |
|---|---|
| `registered_and_present` | In `KeyStorage`; for `pkcs11`, also found on the token. Normal case. |
| `present_only` | On the token, no `KeyStorage` row. `id = null`, `usage = null`, `created_at = null`. Carries an additional `unimportable_reason ∈ {null, "unsupported_key_type", "public_key_unavailable"}`; when `null` the row is importable, otherwise it is visible but read-only. |
| `registered_only` | `KeyStorage` row exists; for `pkcs11`, the matching `hsm_token_id` was *not* found on the token. Drift / error state — surfaced so the operator can investigate, detected on every list call (no separate "verify keys" probe in this proposal). |

Response envelope additions:

```json
{
  "keys": [ … ],
  "token_enumeration": {
    "available": true,
    "reason":   null            // when available=false: "provider-inactive" | "backend-error"
  }
}
```

#### API — `GET /api/kms/keys/{key_id}` (details)

Already listed in §9.2; expanded to return the dependent objects
by name, not just a count:

```json
{
  "id":            42,
  "provider_id":   3,
  "provider_label":"hsm-root",
  "key_type":      "ECDSA-P-256",
  "label":         "acme-root-2026",
  "hsm_token_id":  "0a1b2c…",        // pkcs11 only
  "public_key":    "-----BEGIN PUBLIC KEY-----\n…",
  "state":         "registered_and_present",
  "key_owned":     true,
  "created_at":    "2026-04-12T08:30:00Z",
  "usage": {
    "count": 2,
    "items": [
      {"type": "ca",              "id": 5,  "name": "Acme Root CA"},
      {"type": "certificate",     "id": 12, "name": "service.acme.ch", "ca_id": 5},
      {"type": "ocsp_responder",  "id": 1,  "name": "Acme OCSP Responder"},
      {"type": "signing_service", "id": 2,  "name": "Code-signing", "note": "reserved, §17"}
    ]
  }
}
```

The `usage.items` array is the authoritative list of objects
preventing deletion (the 409-rejection path checks the same
relations).

#### API — `POST /api/kms/keys/{key_id}/export`

New endpoint, reserved. Returns **501 Not Implemented** with
`{"description": "export action will be specified separately"}`.
Scoped here only so the route exists and the UI can wire a
"coming soon" button to a real endpoint id; the actual export
semantics (formats, allowed key types, allowed providers,
authorisation) are defined in a follow-up proposal.

#### UI — keys list (`/kms_keys.html` and per-provider table)

- Replace the per-row `Delete` button with a `Details` button
  that navigates to `/key_details.html?id=<key_id>` (registered
  rows) or opens the import flow pre-populated (unregistered
  rows; see below).
- Drop the global `Delete` bulk action. Deletion lives on the
  details page.
- New row state column rendering `state`:
  - `registered_and_present` — no badge.
  - `present_only`, `unimportable_reason = null` — "Not
    registered" badge + an inline `Import` button. Clicking
    opens a one-field prompt pre-filled with the row's
    `CKA_LABEL`; the operator confirms (or renames) and the
    handler POSTs `POST /api/kms/keys/import` with
    `provider_id`, `hsm_token_id`, and the (possibly edited)
    `label`. The prompt is inline — it does not leave the keys
    list. On success the row rerenders as
    `registered_and_present` with its new `id`.
  - `present_only`, `unimportable_reason = "unsupported_key_type"`
    — muted "Unsupported key type" badge. The row is visible so
    the operator knows the slot has something there, but no
    inline action is offered (no Import, no Details — the row
    has no `id` to address).
  - `present_only`, `unimportable_reason = "public_key_unavailable"`
    — muted "Public key unavailable" badge. Same affordance as
    above: visible, no action. The fallback that would recover
    the public key from raw attributes is a follow-up; until it
    lands, these rows stay read-only.
  - `registered_only` — "Missing on token" badge in muted red.
    No inline action (the operator opens the details page to
    investigate or delete).
- The existing "Import HSM key" button is kept as a fallback for
  pasting a `CKA_ID` directly (e.g. for a token where
  enumeration failed). The merged listing is the primary path.
- When the scoped `pkcs11` provider is inactive, render a banner
  "Token enumeration unavailable — activate the provider to see
  unregistered keys" sourced from
  `token_enumeration.reason = "provider-inactive"`.

#### UI — new key details page (`/key_details.html?id=<key_id>`)

- Header: label, key type, provider (with link), state badge,
  `key_owned` indicator.
- Public-key panel: PEM display + copy / download buttons.
- For `pkcs11` rows: token attributes (`hsm_token_id` hex,
  `CKA_LABEL` from the token if different from `label`).
- Usage panel: a table of the dependents from `usage.items` with
  per-row links to the dependent's detail page (CA, certificate,
  OCSP responder, future signing service).
- Audit-log panel: the key's lifecycle trail (`key_generate`,
  `key_import`, `key_export` when implemented, `key_delete`)
  filtered from `AuditLogs` by `resource_type='kms_key'` and
  the key's id, newest first. Sourced from the existing audit
  endpoint; no new event types are introduced by this proposal.
- Action bar at the bottom:
  - **Export** — calls `POST /api/kms/keys/{id}/export`; the
    501 surfaces as a "Export is not yet implemented" toast.
    Button stays visible so the affordance is discoverable.
  - **Delete** — confirms with the dependents enumerated in the
    usage panel; calls `DELETE /api/kms/keys/{id}`, which still
    refuses with 409 when `usage.count > 0`. On success,
    redirects to the keys list.
- For `registered_only` rows (drift), the details page replaces
  the usage panel with a "Key missing on token" notice and
  surfaces only the Delete action — Export is hidden because
  there is no private material to export.

**Impact on existing sections:**

- §2.2 — both pending bullets close.
- §5 — `PKCS11Backend.list_keys()` becomes a required
  implementation, not "future Phase 5 work" in the docstring at
  [base.py:12](../pypki/backends/base.py#L12).
- §9.2 — `GET /api/kms/keys` response gains `state` per row and a
  `token_enumeration` envelope; `GET /api/kms/keys/{id}` response
  shape grows to include the named `usage.items`;
  `POST /api/kms/keys/{id}/export` (reserved, 501) is added to the
  route table.
- §10.2 — keys page loses the inline `Delete` button; gains the
  `Details` button, the `state` badge column, the per-row
  `Import` action for `present_only` rows.
- §10 — add §10.5 *Key details page* describing the new page.
- §11 — `key_export` event reserved (no rows written today;
  endpoint returns 501 before any audit).
- §14 — acceptance criteria gain "operator can see and import an
  on-token key without typing the CKA_ID" and "no destructive key
  action lives on a list view".

**Action plan:**

Each step ends with passing tests.

1. **Backend — `PKCS11Backend.list_keys()`.** Implement the
   `CKO_PRIVATE_KEY` sweep + public-key resolution.
   Add a pytest fixture that generates two keys on the SoftHSM
   token outside pyPKI's import path and asserts both come back
   from `list_keys()` with usable algorithm metadata and PEM
   public keys. `SoftwareBackend.list_keys()` returns `[]`
   explicitly.
2. **API — merged listing for pkcs11 providers.** Extend
   `list_kms_keys` in
   [api_adapters.py:735](../web/services/api_adapters.py#L735)
   to call the backend's `list_keys()` when scoped to a `pkcs11`
   provider, merge by `hsm_token_id`, attach the `state` per
   row. Add the `token_enumeration` envelope. Inactive-provider
   case returns DB rows only with `available=false`. Pytest
   parametrised over backends; the SoftHSM fixture verifies all
   three `state` values surface (generate one via pyPKI, one
   directly on the token, then delete the on-token copy of a
   third pre-registered key to produce `registered_only`).
3. **API — details endpoint.** Implement
   `GET /api/kms/keys/{key_id}` returning the expanded shape with
   `usage.items`. The same query that today produces the `usage`
   integer is widened to fetch the dependent rows' names. Pytest:
   create a CA + a certificate + an OCSP responder bound to one
   key, hit the details endpoint, assert all three appear.
4. **API — export placeholder.** Wire
   `POST /api/kms/keys/{key_id}/export` to a handler that
   returns 501 with the documented description. One test
   asserting the status and body.
5. **UI — keys list.** Modify
   [kms_keys.html](../web/templates/kms_keys.html) to:
   render the `state` column with the three badges; replace the
   per-row Delete with a Details link; for `present_only` rows,
   render an inline Import button that POSTs the prefilled
   `import` request. Inactive-provider banner. Visual regression
   test (Playwright or similar) on the three states.
6. **UI — key details page.** New
   `web/templates/key_details.html` plus a route in
   `web/routes/main_routes.py` (`GET /key_details.html`) that
   renders the page. Implement Export (501 toast) and Delete
   (confirm + DELETE) actions. Reuse the existing
   confirm-with-dependents component from
   `crypto_provider_details.html` where applicable.
7. **UI — per-provider keys table.** Apply the same row
   changes to the keys table embedded in
   [crypto_provider_details.html](../web/templates/crypto_provider_details.html).
   Verify the inactive-provider banner is consistent.
8. **Docs cleanup.** Fold the canonical bits of this proposal
   into §5, §9.2, §10.2, §10 (new §10.5), §11, §13, §14; remove
   §18.1 entry; update [PROGRESS.md §3](PROGRESS.md) and
   [roadmap.md §3](roadmap.md) to reference the closed work.

**Resolved decisions** (settled 2026-05-12, folded into the
proposed behaviour above):

1. **Global keys list — DB-only.** When no `provider_id` is
   supplied, `present_only` rows are not merged into the
   response. Operators scope to a `pkcs11` provider to see
   unregistered on-token keys. Keeps the global view bounded
   and paginatable.
2. **Drift — detect on list only.** `registered_only` is
   surfaced on every list call against a `pkcs11` provider by
   comparing `KeyStorage.hsm_token_id` to the backend's
   `list_keys()` output. No separate "verify keys" probe ships
   in this proposal; if drift becomes operationally noisy, a
   follow-up adds an explicit check button.
3. **Unsupported key types — visible, muted, no action.** Rows
   whose `CKA_KEY_TYPE` does not map to the §8.1 conservative
   subset render with a "Unsupported key type" badge and no
   Import / Details affordance. The operator sees that the slot
   has something there; pyPKI does not pretend it can manage it.
4. **Paired-object public keys only — no raw-attribute
   fallback.** Step 1 of the action plan reads public-key DER
   exclusively from a paired `CKO_PUBLIC_KEY` object on the
   token. Private keys whose paired object is missing surface
   as `present_only` with `unimportable_reason =
   "public_key_unavailable"`; recovering them via raw attribute
   reads is a follow-up.
5. **Per-row Import — one-field prompt, pre-filled from
   `CKA_LABEL`.** Clicking Import on a `present_only` row opens
   an inline prompt with the row's `CKA_LABEL` already filled
   in; the operator confirms or renames and the request POSTs
   without leaving the list view.
6. **Audit-log trail on the details page — yes.** The details
   page renders the key's `AuditLogs` history below the usage
   panel. No new event types are introduced — the existing
   `key_generate`, `key_import`, and `key_delete` events
   already cover the trail; the reserved `key_export` event
   joins it when the export action lands.

**Acceptance criteria** (in addition to §14):

- An operator can land on a `pkcs11` provider's details page,
  see every key on the slot in one table (including those not
  in pyPKI), and click Import on an unregistered row without
  typing a `CKA_ID` anywhere.
- The keys list in
  [kms_keys.html](../web/templates/kms_keys.html) and the keys
  table embedded in
  [crypto_provider_details.html](../web/templates/crypto_provider_details.html)
  surface no destructive button inline. Destructive actions
  live on the details page only.
- The details page lists every dependent (CA, certificate, OCSP
  responder, signing service when §17 lands) by name. The set is
  identical to the relations that drive the
  `DELETE /api/kms/keys/{id}` 409 path.
- The Export button is visible on the details page for
  registered keys and returns the documented 501 with a
  user-visible "not yet implemented" toast. No partial export
  flow exists.
- Provider deactivation does not break the list view; rows
  registered in `KeyStorage` remain visible with the documented
  envelope flag, only on-token-only rows disappear.
- The parametrised test suite (Phase 0 §13) covers both backends
  and exercises all three `state` values on the `pkcs11` side.
