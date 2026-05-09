# HSM Support — Gap Analysis (Punch-List)

This document catalogues the concrete defects in pyPKI's HSM (PKCS#11)
support that must be closed before HSM-backed keys are production-ready. It
is the bug-tracker companion to [kms-strategy.md](kms-strategy.md) — the
strategy document holds the architecture, data model, API, UI, and order of
work; this document holds the file/line-level pointers to each remaining
issue and a brief recommended fix.

The review covers: [pypki/kms.py](../pypki/kms.py),
[pypki/key_tools.py](../pypki/key_tools.py),
[pypki/pkcs11_helper.py](../pypki/pkcs11_helper.py), the `KeyStorage` schema
and helpers in [pypki/db.py](../pypki/db.py), and the signing call sites in
[pypki/ca.py](../pypki/ca.py) and
[pypki/ocsp_responder.py](../pypki/ocsp_responder.py).

---

## What works today

- `KeyManagementService` is the single signing entry point. CAs and OCSP
  responders call `kms.sign_digest(key_id, digest)`; they no longer hold key
  material.
- A `KeyStorage` row with `storage_type='HSM'`, `hsm_token_id`, and
  `token_password` is loadable by the KMS and produces a `KeyTools` whose
  `sign_digest()` dispatches to PyKCS11.
- The DER-patching flow (build with a dummy key → extract TBS → sign via
  KMS → splice signature) works for both X.509 issuance and OCSP responses,
  so the "software vs HSM" branch is hidden from the higher-level callers.

Everything below is a real or latent defect in that pipeline. The
architectural reshape that addresses several of them at once — provider
records, encrypted-at-rest software keys, and a sibling-backend topology —
is specified in [kms-strategy.md](kms-strategy.md).

---

## Gap 1 — RSA-on-HSM signature is malformed

**Where:** [pypki/key_tools.py:158](../pypki/key_tools.py#L158)

The HSM branch sends a bare 32-byte SHA-256 digest to the token using
mechanism `CKM_RSA_PKCS`. PKCS#11 `CKM_RSA_PKCS` performs raw PKCS#1 v1.5
padding over the bytes supplied — it does **not** prepend the SHA-256
`DigestInfo` (the ASN.1 `AlgorithmIdentifier + OCTET STRING` envelope
required by PKCS#1 v1.5 signatures). The signature produced will not verify
against an `sha256WithRSAEncryption` certificate.

**Fix:** switch to `CKM_SHA256_RSA_PKCS` and pass the TBS bytes (HSM hashes
and wraps). Matches what `CKM_SHA256_RSA_PKCS_PSS` would do for the PSS
variant and avoids a magic prefix in application code.

**Severity:** blocker for HSM-backed RSA CAs. Targeted in Phase 1 of the
strategy doc.

---

## Gap 2 — ECDSA-on-HSM is not implemented

**Where:** [pypki/key_tools.py:155-162](../pypki/key_tools.py#L155-L162)

The HSM branch has only the RSA mechanism. There is no `if ec` arm. An
ECDSA key resident on the token will be signed with `CKM_RSA_PKCS` and
either fail at the token or return garbage.

**Fix:** key-type-aware mechanism selection — RSA via
`CKM_SHA256_RSA_PKCS`, ECDSA via `CKM_ECDSA` over the SHA-256 digest with
`(r, s)` DER-encoded before splicing. The patching layer already
DER-encodes ECDSA signatures in `_patch_ocsp_signature`; the gap is purely
in `KeyTools`.

**Severity:** blocker for HSM-backed ECDSA CAs. Targeted in Phase 1.

---

## Gap 3 — `hsm_slot` is ignored

**Where:** [pypki/pkcs11_helper.py:33-39](../pypki/pkcs11_helper.py#L33-L39)

`open_session()` always picks `slots[0]`. The `hsm_slot` column in
`KeyStorage` and the `slot_num` argument plumbed through
[pypki/kms.py:69](../pypki/kms.py#L69) and
[pypki/key_tools.py:24-27](../pypki/key_tools.py#L24-L27) are dead. Multi-slot
tokens, or hosts with more than one PKCS#11 device, cannot be addressed.

SoftHSM2 also assigns randomised slot IDs at `--init-token` time
specifically to force apps to address by label rather than numeric slot.
Hard-coding `slots[0]` works on day 1 and breaks on day 2.

**Fix:** thread the provider's `slot_label` through `open_session()` and
match by `CK_TOKEN_INFO.label`, not numeric slot id. Numeric slot only as a
fallback when no label is configured.

**Severity:** blocker for any host with more than one slot. Targeted in
Phase 2.

---

## Gap 4 — No crypto provider abstraction

**Where:** [pypki/pkcs11_helper.py:11](../pypki/pkcs11_helper.py#L11),
`KeyStorage` schema in [pypki/db.py:1842](../pypki/db.py#L1842), and the
`KMS.load_key` call in [pypki/kms.py:65-71](../pypki/kms.py#L65-L71).

Three faces of the same gap:

- The PKCS#11 module path is a module-level constant (`/usr/local/lib/pkcs11/libeTPkcs11.dylib`
  — the macOS SafeNet driver). It will not load on Linux, in Docker, on
  Windows, or with any other vendor's module.
- The schema embeds `hsm_slot`, `hsm_token_id`, and `token_password`
  directly on every HSM `KeyStorage` row, so a single deployment cannot host
  keys on more than one HSM without duplicating connection details.
- Software keys have no grouping at all — flat plaintext PEM blobs with no
  activation lifecycle.

**Fix:** the `CryptoProviders` model specified in
[kms-strategy.md §3–4](kms-strategy.md#3-architecture). Closes this gap and
unblocks Gaps 5, 6 cleanly. Targeted in Phase 0.

**Severity:** blocker for Docker deployment, blocker for any host with more
than one HSM, prerequisite for Gap 5.

---

## Gap 5 — Token PIN is stored in clear in MySQL

**Where:** `KeyStorage.token_password VARCHAR(255)` — schema in
[pypki/db.py:1842](../pypki/db.py#L1842), read in
[pypki/kms.py:65-71](../pypki/kms.py#L65-L71).

The activation PIN is stored in clear next to the token key id. Anyone with
read access to the database can activate the token. The same column is also
overloaded with three implicit meanings (NULL / empty / non-empty), making
audit and rotation painful.

The parallel exposure is the software side: `KeyStorage.private_key` stores
PEM in plaintext for `storage_type='Plain'` rows. DB-only compromise leaks
software CA private keys directly.

**Fix:** the secret-handling story specified in
[kms-strategy.md §7](kms-strategy.md#7-secret-resolution-backends-auth_secret_ref)
— PIN moves to the provider record as `auth_secret_ref`, an opaque
reference resolved at activation time (`db:encrypted` / `env:` / `vault:` /
`operator:prompt`), with `auto_activate` controlling whether human
interaction is required at startup. The same migration encrypts software
PEMs at rest under the provider KEK.

**Severity:** security — must be fixed before any production rollout.
Targeted in Phase 4 (with scaffolding in Phase 0).

---

## Gap 6 — One PKCS#11 session per cached key, never closed

**Where:** [pypki/key_tools.py:22-28](../pypki/key_tools.py#L22-L28),
[pypki/kms.py:79-83](../pypki/kms.py#L79-L83)

`KeyTools.__init__` constructs a fresh `PKCS11Helper`, opens a session, and
logs in. Two HSM keys in the cache = two sessions. `KMS.unload_key()` only
deletes the dictionary entry; it does not call `close_session()`. Sessions
leak to the token and may eventually exhaust limits on constrained tokens
(YubiHSM 2 caps at 16 concurrent sessions per authkey). There is also no
reconnect logic if the token is unplugged.

**Fix:** the sibling-backend contract specified in
[kms-strategy.md §5](kms-strategy.md#5-internal-backend-contract) —
one `PKCS11Backend` instance per provider, opened at activation, closed at
deactivation/shutdown. `unload_key()` evicts only the in-memory cache entry;
the session lifecycle is provider-scoped, not key-scoped. Reconnect on
`CKR_SESSION_HANDLE_INVALID` / `CKR_DEVICE_REMOVED` once before failing.

**Severity:** stability — leaks sessions in long-running processes.
Targeted in Phase 3.

---

## Gap 7 — `load_key` is not thread-safe

**Where:** [pypki/kms.py:97-100](../pypki/kms.py#L97-L100)

```python
if key_id not in self.__key_cache:
    self.load_key(key_id)
```

Classic check-then-act. Flask runs requests in threads; two concurrent
first-uses of the same key both miss the cache and both call `load_key`.
For software keys this is wasteful; for HSM keys it opens two sessions and
runs two `C_Login` operations against the token.

**Fix:** a `threading.Lock` guarding the cache, or per-key locks keyed by
`key_id`. Apply globally — the symmetric case has the same shape.

**Severity:** correctness under concurrency. Targeted in Phase 3.

---

## Gap 8 — No HSM-backed key generation through the KMS

**Where:** [pypki/kms.py:147-159](../pypki/kms.py#L147-L159) (algo
dispatch), `PKCS11Helper.generate_private_key` exists at
[pypki/pkcs11_helper.py:83](../pypki/pkcs11_helper.py#L83) but is never
called from the KMS, the web routes, or the CLI utilities.

Consequences:

- `generate_key` always writes `storage_type='Plain'` (see
  [pypki/kms.py:174](../pypki/kms.py#L174),
  [pypki/kms.py:188](../pypki/kms.py#L188), etc.).
- The `kms_keygen.html` UI and `/api/kms/generate-key` endpoint cannot
  create an HSM-resident key.
- There is no `import_hsm_key()` to register a *pre-existing* on-token key
  into `KeyStorage`. HSM rows must be inserted by hand-crafted SQL today.

**Fix:** the API and UI specified in
[kms-strategy.md §9–10](kms-strategy.md#9-rest-api-specification) —
`POST /api/kms/keys` (provider-scoped generate), `POST /api/kms/keys/import`
(register existing on-token key). Generated keys carry the mandatory
attribute set from
[kms-strategy.md §8.2](kms-strategy.md#82-mandatory-private-key-attributes-pkcs11-backend).

**Severity:** feature gap — without this, HSM is read-only and
operator-unfriendly. Targeted in Phase 5.

---

## Gap 9 — `hsm_token_id` contract is unchecked  ✅ CLOSED (Phase 6)

**Was:** [pypki/pkcs11_helper.py:184](../pypki/pkcs11_helper.py#L184)
called `bytes.fromhex(key_id)` deep in the sign path, so a typo at insert
or import time produced a confusing PKCS#11 error on first sign rather
than a clear validation failure.

**Now:** validation lives at the API boundaries — `KMS.import_pkcs11_key`
and `PKCS11Backend` (load / find / delete) all route through
`pypki.backends.pkcs11._validate_cka_id_hex`, which checks for
non-empty + even-length + all-hex and produces a `ValueError` with the
offending value. The hex-text contract is documented; storing as raw
`VARBINARY` was deferred (would require a per-row migration with no
operational benefit beyond size).

---

## Gap 10 — `storage_type='Encrypted'` is enum-only, no decrypt path  ✅ CLOSED (Phase 0.2 + Phase 6)

**Was:** `load_key` treated `'Encrypted'` exactly like `'Plain'` — ran
`load_pem_private_key()` on the raw column.

**Now:** `'Encrypted'` is a real, exercised storage type:
- Phase 0.2 migration encrypts `'Plain'` software rows under the per-
  provider KEK and rewrites them as `'Encrypted'`. `KMS._finalise` and
  the inline insert paths in `insert_ca` / OCSP creation also write
  `'Encrypted'` for any new asymmetric software key.
- `SoftwareBackend.load_key` decrypts `'Encrypted'` via
  `decrypt_pem(blob, kek)`, with a defensive fallback that detects
  legacy plaintext-PEM-in-Encrypted rows (operators who upgraded from a
  pre-Phase-0 deployment) and loads them as plaintext with a loud
  warning until the migration runs again with a configured `HSM_PIN_KEK`.
- The Phase 0.2 migration also picks up those legacy plaintext-in-
  Encrypted rows and re-encrypts them properly when the KEK is available.

---

## Gap 11 — AES key entries cannot round-trip through the cache  ✅ CLOSED (Phase 6)

**Was:** `KMS._finalise_symmetric` wrote AES keys with `storage_type='Plain'`
and the load path tried to parse them as PEM private keys, crashing.

**Now:** `_finalise_symmetric` writes `'Symmetric'`. The Phase 0.1 schema
already had `'Symmetric'` in the `KeyStorage.storage_type` enum;
`SoftwareBackend.load_key` now rejects it explicitly with a clear message
(`"the asymmetric load/sign path does not handle these. Symmetric-key
operations are not yet exposed through the KMS API."`) instead of silently
crashing the PEM parser. Symmetric-key signing / wrapping / unwrapping is
out of scope for the current KMS contract; the rejection is the explicit
contract boundary.

---

## Gap 12 — Stale documentation reference in OCSP error  ✅ CLOSED (Phase 6)

The OCSP responder's "no KMS key" error now points at the management API
(`OCSPResponders.private_key_reference`) instead of the long-retired
`migrate_keys_to_kms.py` script.
