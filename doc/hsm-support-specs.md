# HSM Support Specification

This document specifies the HSM (PKCS#11) support contracts in pyPKI: the
signing mechanisms, slot addressing, session lifecycle, concurrency rules,
and storage-type semantics that the PKCS#11 backend must honour to be
portable across SoftHSM2, YubiHSM 2, and Thales Luna.

It is the HSM-specific companion to [kms-specs.md](kms-specs.md), which
holds the broader KMS architecture (provider model, backend topology,
activation lifecycle, REST API, management UI). Where a contract is
co-owned with the general KMS, this document references the matching
section there rather than restating it.

Status of each contract (implemented / pending / deferred) lives in
[PROGRESS.md §3](PROGRESS.md). Strategic intent and cross-area framing
live in [roadmap.md §3](roadmap.md).

---

## 1. Scope

This spec covers the HSM-specific behaviour of the `PKCS11Backend` sibling
defined in [kms-specs.md §5](kms-specs.md#5-internal-backend-contract):

- which PKCS#11 mechanisms are used to produce X.509-grade signatures
  (§2);
- how a token slot is addressed at session-open time (§3);
- when sessions are opened, closed, and reconnected (§6);
- how concurrent first-uses of the same key are serialised (§7);
- the storage-type contracts (`hsm_token_id` format, `Encrypted` /
  `Symmetric` semantics, §9).

Behaviour shared with the software backend (provider records, secret
resolution, REST API surface, key generation API, mandatory CKA_*
attributes) is specified in [kms-specs.md](kms-specs.md) and pointed at
from the relevant section here.

---

## 2. Signing mechanisms

The HSM signing path produces signatures that verify against the X.509
algorithm identifiers `sha256WithRSAEncryption` and `ecdsa-with-SHA256`,
matching what the libcrypto path produces for the corresponding software
keys.

### 2.1 RSA

- **Mechanism:** `CKM_SHA256_RSA_PKCS`.
- **Input:** the TBS bytes (the token hashes and PKCS#1-v1.5-wraps).

Rationale: `CKM_RSA_PKCS` does *not* prepend the SHA-256 `DigestInfo`
ASN.1 envelope; it performs raw PKCS#1 v1.5 padding over whatever bytes
are supplied. Sending a bare 32-byte SHA-256 digest under `CKM_RSA_PKCS`
produces a signature that does not verify against
`sha256WithRSAEncryption`. `CKM_SHA256_RSA_PKCS` does the digest and the
DigestInfo wrap inside the token, removing a magic prefix from
application code.

A future PSS mechanism would follow the same shape: switch to
`CKM_SHA256_RSA_PKCS_PSS` and supply PSS parameters at sign time.

### 2.2 ECDSA

- **Mechanism:** `CKM_ECDSA`.
- **Input:** the SHA-256 digest (32 bytes for P-256, 48 for P-384).
- **Output transform:** the token returns a fixed-width `r || s`
  concatenation; the backend DER-encodes it with
  `cryptography.hazmat.primitives.asymmetric.utils.encode_dss_signature`
  before splicing into the certificate or OCSP response.

Rationale: `CKM_ECDSA` requires a pre-computed digest as input.
`CKM_ECDSA_SHA256` would also work but is not universally supported —
SoftHSM2 supports it, some hardware tokens do not. Hashing in-process and
sending the digest is the portable path.

### 2.3 Mechanism-selection logic

Backend code must dispatch on the `KeyStorage.key_type` value, not on the
mechanism set declared by the token. Tokens that advertise more
mechanisms than this contract uses must still be driven through this
narrow, portable subset.

---

## 3. Slot addressing

Sessions are addressed by **token label**, not by numeric slot id.

- The provider record carries a `slot_label` string (specified in
  [kms-specs.md §4.1](kms-specs.md#41-cryptoproviders-new-table)).
- `PKCS11Backend.open` enumerates the module's slots and matches by
  `CK_TOKEN_INFO.label`.
- A numeric `slot_num` may be accepted as a fallback when no label is
  configured, but is not the primary contract.

Rationale: SoftHSM2 randomises slot ids at `--init-token` time
specifically to discourage numeric-slot addressing; YubiHSM 2 and Luna
multi-partition deployments routinely have more than one slot per
module. Hard-coding `slots[0]` works on day 1 and breaks on day 2 when
a second token is initialised.

---

## 4. Provider abstraction

PKCS#11 modules, slots, and authentication PINs are owned by the
`CryptoProviders` table, not by individual `KeyStorage` rows. The
schema, validation rules, and mutation semantics are specified in
[kms-specs.md §3–4](kms-specs.md#3-architecture).

The HSM-specific obligations on top of that:

- A `pkcs11` provider's `module_path` must be a path readable by the
  app process. Validation runs at provider create / update time, not at
  first sign.
- Providers cannot be deleted while any `KeyStorage` row references
  them (FK enforcement; cascading deletion is rejected at the API
  layer with a 409).

---

## 5. Secret handling

PINs and per-provider KEKs are resolved through `auth_secret_ref` —
specified in
[kms-specs.md §7](kms-specs.md#7-secret-resolution-backends-auth_secret_ref).

The HSM-specific obligations on top of that:

- A PIN is held in memory only between activation and deactivation.
  Backend code must not log the PIN, must not write it to disk, and
  must zero its buffer on `close()` where the language allows.
- An `operator:prompt` provider with `auto_activate=TRUE` is rejected
  at validation time — there is no operator at startup to prompt.

---

## 6. Session lifecycle

One PKCS#11 session per provider, opened at activation, closed at
deactivation or shutdown.

- `PKCS11Backend.open(provider, secret)` opens the session, calls
  `C_Login`, and stores the session handle on the backend instance.
- `PKCS11Backend.close()` calls `C_Logout` (where applicable) and
  `C_CloseSession`. Idempotent.
- `KMS.unload_key(key_id)` evicts the in-memory cache entry only; it
  does *not* close the session. Session lifetime is provider-scoped,
  not key-scoped.

### 6.1 Reconnect

On `CKR_SESSION_HANDLE_INVALID` or `CKR_DEVICE_REMOVED` during a sign
operation, the backend reopens the session **once** with the cached
secret and retries the operation. A second consecutive failure raises
to the caller.

Rationale: a single transparent reconnect handles the common case (token
unplugged briefly, intermediate process restarted upstream, session
table flushed). Looping reconnects mask genuine token failures and
extend the request beyond useful timeouts.

### 6.2 Session limits

Constrained tokens (YubiHSM 2 caps at 16 concurrent sessions per
authkey) require that a long-running app process holds at most one
session per provider — never one per cached key. This is the load-
bearing reason for the provider-scoped lifecycle above; per-key
sessions exhaust the token within minutes under realistic load.

---

## 7. Concurrency

`KMS.load_key` uses double-checked locking around its in-memory cache;
`KMS.sign_digest` serialises sign calls per backend with an `RLock`.

- The cache check is `if key_id not in cache: lock; if key_id not in
  cache: load_key`. Both checks are required.
- Per-backend `RLock` (not per-key) — PKCS#11 sessions are
  single-threaded; concurrent sign calls on the same session interleave
  unpredictably on some tokens.
- Software backends acquire the same `RLock` for symmetry, which costs
  nothing measurable and keeps the contract uniform.

Rationale: Flask runs requests in threads. Two concurrent first-uses of
the same key both miss the cache, both call `load_key`, and on HSM
keys both open a session and run `C_Login`. The double-checked lock
collapses this to one. Per-backend (rather than per-key) serialisation
of sign calls avoids token-level races without the bookkeeping cost of
per-key locks.

---

## 8. Key generation and import

The provider-scoped key API is specified in
[kms-specs.md §9.2](kms-specs.md#92-key-management-apikmskeys).
HSM-specific obligations:

- `POST /api/kms/keys` against a `pkcs11` provider generates the
  keypair on the token. The mandatory CKA_* attribute set
  ([kms-specs.md §8.2](kms-specs.md#82-mandatory-private-key-attributes-pkcs11-backend))
  is enforced; tokens that reject any required attribute fail loudly
  at generation time, not at first sign.
- `POST /api/kms/keys/import` registers a *pre-existing* on-token key
  into `KeyStorage`. The `key_owned` column is set FALSE; subsequent
  `DELETE /api/kms/keys/{id}` removes the registration but leaves the
  token object intact.

---

## 9. Storage-type contracts

### 9.1 `hsm_token_id` hex format

- Type: hex-text (lowercase or uppercase, even length).
- Validated at the API boundary by
  `pypki.backends.pkcs11._validate_cka_id_hex` on insert / import /
  delete. Empty, odd-length, and non-hex values produce a `ValueError`
  with the offending value before any PKCS#11 call.
- Not stored as raw `VARBINARY`: a per-row migration delivers no
  operational benefit beyond a small storage saving. Hex-text is the
  long-term contract.

### 9.2 `Encrypted` software keys

- `KeyStorage.private_key` for `storage_type='Encrypted'` rows holds
  AES-256-GCM ciphertext under the per-provider KEK
  ([kms-specs.md §6–7](kms-specs.md#6-activation-lifecycle)).
- `SoftwareBackend.load_key` decrypts via `decrypt_pem(blob, kek)`.
- A defensive fallback handles legacy rows where `Encrypted` was set
  but the blob is plaintext PEM (operators upgrading from a
  pre-Phase-0 deployment): the row is loaded with a loud warning
  until the encrypt-at-rest migration runs again with `HSM_PIN_KEK`
  configured.

### 9.3 `Symmetric` keys

- AES keys are persisted with `storage_type='Symmetric'`.
- `SoftwareBackend.load_key` rejects `'Symmetric'` explicitly with a
  message pointing at the missing API surface — symmetric-key signing,
  wrapping, and unwrapping are out of scope for the current KMS
  contract.
- This is an explicit boundary, not a placeholder: when symmetric-key
  operations are added, this rejection becomes a dispatch.

### 9.4 `PassphraseEncrypted` end-entity escrow keys

- `generate_pkcs12(store_key=True, passphrase=...)` writes the key as
  `storage_type='PassphraseEncrypted'`: the PEM is KEK-wrapped under
  the per-provider KEK like an `Encrypted` row, but is decryptable
  only with the operator-supplied passphrase the original PKCS#12
  carried.
- `SoftwareBackend.load_key` refuses `'PassphraseEncrypted'` with a
  pointer to the re-download flow. The KMS does not hold the
  passphrase; this storage type is a parking spot for escrowed keys,
  not a sign-path key.

---

## 10. Cross-references

- [kms-specs.md](kms-specs.md) — the full KMS specification (provider
  model, backend topology, activation lifecycle, REST API, management
  UI, PKCS#11 conformance subset).
- [softhsm2-manual.md](softhsm2-manual.md) — operator manual for the
  SoftHSM2 dev environment that this spec is regression-tested
  against.
- [database.md](database.md) — current schema; the `KeyStorage` and
  `CryptoProviders` definitions referenced here.
- [PROGRESS.md §3](PROGRESS.md) — implementation status per contract.
- [roadmap.md §3](roadmap.md) — strategic intent and remaining work.
