# HSM Support — Gap Analysis

This document records the current state of HSM (PKCS#11) support in PyPKI and the
gaps that must be closed before HSM-backed keys can be considered production-ready.
It complements [kms-strategy.md](kms-strategy.md), which describes the KMS layering
that is already in place, and feeds the HSM section of [roadmap.md](roadmap.md).

The review covers: [pypki/kms.py](../pypki/kms.py),
[pypki/key_tools.py](../pypki/key_tools.py),
[pypki/pkcs11_helper.py](../pypki/pkcs11_helper.py), the `KeyStorage` schema and
helpers in [pypki/db.py](../pypki/db.py), and the signing call sites in
[pypki/ca.py](../pypki/ca.py) and [pypki/ocsp_responder.py](../pypki/ocsp_responder.py).

---

## What works today

- `KeyManagementService` is the single signing entry point. CAs and OCSP responders
  no longer hold key material; they call `kms.sign_digest(key_id, digest)`.
- A `KeyStorage` row with `storage_type='HSM'`, `hsm_token_id`, and `token_password`
  is loadable by the KMS and produces a `KeyTools` whose `sign_digest()` dispatches
  to PyKCS11.
- The DER-patching flow (build with a dummy key → extract TBS → sign via KMS →
  splice signature) works for both X.509 issuance and OCSP responses, so the
  "software vs HSM" branch is hidden from the higher-level callers.

Everything below is a real or latent defect in that pipeline.

---

## HSM provider model

A design decision that reshapes Gaps 4 and 5 and is a prerequisite for several
others. Recording it here so all downstream work targets the same shape.

The current schema is single-HSM-shaped: each `KeyStorage` row carries its own
`hsm_slot`, `hsm_token_id`, and `token_password`. That does not generalise. A
realistic deployment can have several HSMs side by side — e.g. a Luna partition
for the root CA, a YubiHSM for an issuing CA, a SoftHSM2 fixture in the dev
container — each with a different module path, login model, and credential
source. Encoding HSM connection details inline per key would force every key on
the same partition to duplicate that information and make rotation,
multi-vendor, and per-HSM auth model variations painful.

Instead, introduce a separate provider record (table, or config-file section,
to be decided when the work is scheduled) — sketch:

```
HSMProviders
├── id
├── label              e.g. "luna-prod-root", "yubi-issuing-1", "softhsm-dev"
├── module_path        absolute path to the PKCS#11 .so / .dylib
├── slot_label         partition name / token label / numeric slot
├── auth_kind          pin | luna_role | yubihsm_authkey
├── auth_secret_ref    opaque reference: "env:HSM_PIN_PROD",
│                      "vault:secret/pki/hsm/prod-root", "operator:prompt", …
└── extra_json         vendor-specific knobs (auth-key id for YubiHSM,
                       crypto-officer role for Luna, etc.)
```

`KeyStorage` then gains a `provider_id` foreign key and drops the inline
`hsm_slot` / `hsm_token_id` / `token_password` columns. The internal
`HSMBackend` contract (see Gap 6 design note) is opened per provider, not per
key.

Implications for the gaps below:

- **Gap 4** (hard-coded module path) becomes "introduce the provider record;
  read the module path from it." Multi-HSM falls out for free.
- **Gap 5** (PIN in MySQL) becomes "the `auth_secret_ref` is a *reference*;
  the value is resolved per provider via env / vault / operator-supplied at
  startup, never stored in MySQL."
- **Gap 6** (one session per `(module, slot, auth)`) maps cleanly: one shared
  session per provider id.
- **Phase 0 of the order-of-work** is the natural moment to introduce the
  provider model, since the SoftHSM2 dev environment is just the first
  provider row.

Env vars do not disappear — they become one possible value of
`auth_secret_ref` (`env:HSM_PIN_DEV`), alongside vault references, AWS
Secrets Manager ARNs, or "operator-supplied at startup." They stop being the
schema.

---

## Gap 1 — RSA-on-HSM signature is malformed

**Where:** [pypki/key_tools.py:158](../pypki/key_tools.py#L158)

The HSM branch sends a bare 32-byte SHA-256 digest to the token using mechanism
`CKM_RSA_PKCS`. PKCS#11 `CKM_RSA_PKCS` performs raw PKCS#1 v1.5 padding over the
bytes supplied — it does **not** prepend the SHA-256 `DigestInfo` (the ASN.1
`AlgorithmIdentifier + OCTET STRING` envelope required by PKCS#1 v1.5 signatures).

The signature produced therefore will not verify against an `sha256WithRSAEncryption`
certificate. Two correct fixes:

1. Switch to `CKM_SHA256_RSA_PKCS` and pass the TBS bytes (HSM hashes and wraps).
2. Keep `CKM_RSA_PKCS` but prepend the SHA-256 DigestInfo prefix to the digest
   before calling `session.sign(...)`.

Option (1) is preferable because it matches what `CKM_SHA256_RSA_PKCS_PSS` would
do for the PSS variant and avoids the magic prefix in application code.

**Severity:** blocker for HSM-backed RSA CAs.

---

## Gap 2 — ECDSA-on-HSM is not implemented

**Where:** [pypki/key_tools.py:155-162](../pypki/key_tools.py#L155-L162)

The HSM branch has a single mechanism (the RSA one). There is no `if ec` arm. An
ECDSA key resident on the token will be signed with `CKM_RSA_PKCS` and either fail
at the token or return garbage.

The fix is a key-type-aware mechanism selection:

- RSA → `CKM_SHA256_RSA_PKCS` (or DigestInfo + `CKM_RSA_PKCS`)
- ECDSA → `CKM_ECDSA` over the SHA-256 digest, then DER-encode `(r, s)` before
  splicing into the certificate.

Note that `_patch_ocsp_signature` already DER-encodes ECDSA signatures, so the
patching layer is fine; the gap is purely in `KeyTools`.

**Severity:** blocker for HSM-backed ECDSA CAs.

---

## Gap 3 — `hsm_slot` is ignored

**Where:** [pypki/pkcs11_helper.py:33-39](../pypki/pkcs11_helper.py#L33-L39)

`open_session()` always picks `slots[0]`. The `hsm_slot` column in `KeyStorage`
and the `slot_num` argument plumbed through
[pypki/kms.py:69](../pypki/kms.py#L69) and
[pypki/key_tools.py:24-27](../pypki/key_tools.py#L24-L27) are dead.

Multi-slot tokens, or hosts with more than one PKCS#11 device, cannot be addressed.

**Fix:** thread `slot_num` into `open_session()`; fall back to `slots[0]` only when
no slot is configured.

**Severity:** blocker for any host with more than one slot.

---

## Gap 4 — No HSM provider abstraction

**Where:** [pypki/pkcs11_helper.py:11](../pypki/pkcs11_helper.py#L11),
`KeyStorage` schema in [pypki/db.py:1842](../pypki/db.py#L1842), and the
`KMS.load_key` call in [pypki/kms.py:65-71](../pypki/kms.py#L65-L71).

The PKCS#11 module path is a module-level constant:

```python
PKCS11_LIB = "/usr/local/lib/pkcs11/libeTPkcs11.dylib"
```

This is the SafeNet eToken driver on macOS — it will not load on Linux, in the
Docker target, on Windows, or with any other vendor's module (SoftHSM2,
YubiHSM, Luna, AWS CloudHSM, …). At the same time, the schema embeds
`hsm_slot`, `hsm_token_id`, and `token_password` directly on every
`KeyStorage` row, which means a single deployment cannot host keys on more
than one HSM without duplicating connection details across rows.

These are two faces of the same gap: there is no *HSM provider* concept. The
fix is the provider model described in the "HSM provider model" section above —
introduce `HSMProviders`, give `KeyStorage` a `provider_id` foreign key, drop
the per-key connection columns, and resolve the module path (and slot, and
auth) from the provider record at load time.

This subsumes the previous "make `PKCS11_MODULE` an env-var override" framing:
the provider record is the schema, and env vars become one possible
`auth_secret_ref` resolution mode (see Gap 5).

**Severity:** blocker for Docker deployment, blocker for any host with more
than one HSM, and a prerequisite for closing Gap 5 cleanly.

---

## Gap 5 — Token PIN is stored in clear in MySQL

**Where:** `KeyStorage.token_password VARCHAR(255)` — schema in
[pypki/db.py:1842](../pypki/db.py#L1842), read in
[pypki/kms.py:65-71](../pypki/kms.py#L65-L71).

Storing the activation PIN next to the token key ID in plaintext defeats most of
the security advantage of having the key material in an HSM. Anyone with read
access to the database can activate the token.

The same column is also overloaded with three implicit meanings:
NULL → fall back to caller-supplied PIN; empty string → unauthenticated; non-empty
→ real PIN. This makes audit and key rotation harder than it should be.

**Fix:** the activation secret moves to the provider record (see "HSM provider
model" above) as `auth_secret_ref` — an opaque reference, never the secret
itself. The reference is resolved at provider-open time by a small set of
backends, in increasing strength:

- `env:NAME` → read from the named environment variable.
- `vault:path` → fetch from a secret store (Vault, AWS Secrets Manager,
  Kubernetes secret).
- `operator:prompt` → operator-supplied at startup, cached in memory for the
  process lifetime only.

The `token_password` column on `KeyStorage` is dropped as part of the same
migration that introduces `provider_id` (Gap 4). Per-provider rotation, audit
trails, and mixed-vendor auth models (Luna roles, YubiHSM authkeys) all flow
naturally from this — none of which the per-row `token_password` column
supported.

**Severity:** security — must be fixed before any production rollout.

---

## Gap 6 — One PKCS#11 session per cached key, never closed

**Where:** [pypki/key_tools.py:22-28](../pypki/key_tools.py#L22-L28),
[pypki/kms.py:79-83](../pypki/kms.py#L79-L83)

`KeyTools.__init__` constructs a fresh `PKCS11Helper`, opens a session, and logs
in. Two HSM keys in the cache = two sessions. `KMS.unload_key()` only deletes the
dictionary entry; it does not call `close_session()`. The same is true on process
shutdown — sessions are leaked to the token and may eventually exhaust limits on
constrained tokens.

There is also no reconnect logic if the token is unplugged or the session is
invalidated by the driver.

**Fix:**

- Share a single `PKCS11Helper` per `(module_path, slot, pin)` tuple at the KMS
  level rather than per `KeyTools`.
- Have `unload_key()` close the underlying session if it is the last reference.
- Detect `CKR_SESSION_HANDLE_INVALID` / `CKR_DEVICE_REMOVED` at sign time and
  reconnect once before failing.

**Design note — internal HSM backend contract.** The vendor-neutral signing API
already exists at the `KeyManagementService` level: callers invoke
`kms.sign_digest(key_id, digest)` and never see PKCS#11. What does *not* yet
exist is a clean contract one level lower, between the KMS and the PKCS#11
implementation. Today `KMS.load_key` constructs `KeyTools` directly with
PKCS#11-specific arguments (`key_id`, `slot_num`, `token_password`), so KMS
holds vendor-shaped state.

While fixing this gap, extract an internal `HSMBackend` contract — roughly
`open(module, slot, auth) / generate(...) / find(label) / sign(handle, mech,
data) / close()` — and make `KeyTools` (or its replacement) the sole
implementation. Two payoffs:

- **Session sharing (this gap)** is naturally expressed as "one backend instance
  per `(module, slot, auth)`," which is exactly what the contract scopes.
- **Future flexibility:** swapping PyKCS11 for `python-pkcs11`, or supporting a
  non-PKCS#11 HSM (e.g., a cloud HSM REST API), becomes a new backend
  implementation rather than changes inside KMS.

This is a refactor scoped to the same files that fix Gap 6, not a new public
abstraction. Do **not** introduce a parallel `KeyStore` interface above KMS —
that would duplicate the abstraction that already exists.

**Severity:** stability — leaks sessions in long-running processes.

---

## Gap 7 — `load_key` is not thread-safe

**Where:** [pypki/kms.py:97-100](../pypki/kms.py#L97-L100)

```python
if key_id not in self.__key_cache:
    self.load_key(key_id)
```

Classic check-then-act. Flask runs requests in threads; two concurrent first-uses
of the same key both miss the cache and both call `load_key`. For software keys
this is wasteful; for HSM keys it opens two sessions and runs two `C_Login`
operations against the token.

**Fix:** a `threading.Lock` guarding the cache, or per-key locks keyed by
`key_id`. Worth doing globally rather than just for HSM, because the symmetric
case is the same shape.

**Severity:** correctness under concurrency.

---

## Gap 8 — No HSM-backed key generation through the KMS

**Where:** [pypki/kms.py:147-159](../pypki/kms.py#L147-L159) (algo dispatch),
`PKCS11Helper.generate_private_key` exists at
[pypki/pkcs11_helper.py:83](../pypki/pkcs11_helper.py#L83) but is never called from
the KMS, the web routes, or the CLI utilities.

Consequences:

- `generate_key` always writes `storage_type="Plain"` (see
  [pypki/kms.py:174](../pypki/kms.py#L174),
  [pypki/kms.py:188](../pypki/kms.py#L188), etc.).
- The `kms_keygen.html` UI and `/kms/generate-key` endpoint cannot create an
  HSM-resident key.
- There is also no `import_hsm_key()` to register a *pre-existing* on-token key
  into `KeyStorage`. HSM rows must be inserted by hand-crafted SQL today.

**Fix:**

- Add an `hsm` storage option to `generate_key` with a slot/label/key-type
  selector. On success, persist a `KeyStorage` row with `storage_type='HSM'`,
  `hsm_slot`, `hsm_token_id`, `key_type`, and the public key.
- Add `kms.import_hsm_key(slot, hsm_token_id, key_type, public_key=None)` that
  registers an existing on-token key without generating new material.
- Surface both in the UI (`kms_keygen.html`) and in `/kms/generate-key`.

**Severity:** feature gap — without this, HSM is read-only and operator-unfriendly.

---

## Gap 9 — `hsm_token_id` contract is unchecked

**Where:** [pypki/pkcs11_helper.py:184](../pypki/pkcs11_helper.py#L184)

`PKCS11Helper.get_key_by_id` calls `bytes.fromhex(key_id)`. The schema column is
`VARCHAR(255)` with no validation, and `KeyManagementService.load_key` does not
sanity-check the value before passing it through. A non-hex value crashes at
first sign, not at load time.

**Fix:** validate the hex string in `KMS.load_key` (or in `insert_key` /
`import_hsm_key`) and produce a clear error. Decide whether to keep CKA_ID as
hex-text or store the raw bytes — either is fine, but the contract must be
explicit.

**Severity:** ergonomics — fail-late instead of fail-early.

---

## Gap 10 — `storage_type='Encrypted'` is enum-only, no decrypt path

**Where:** schema [pypki/db.py:1839](../pypki/db.py#L1839);
load handling [pypki/kms.py:57](../pypki/kms.py#L57).

`load_key` treats `'Encrypted'` exactly like `'Plain'` — it runs
`load_pem_private_key()` on the raw column. If anything ever stores a real
encrypted blob there, the load crashes. No `generate_key` path produces this
storage type.

This is not strictly an HSM gap but is part of the same key-storage design and
needs to be either implemented or removed to avoid foot-guns.

**Severity:** latent — only bites if someone uses the value.

---

## Gap 11 — AES key entries cannot round-trip through the cache

**Where:** [pypki/kms.py:237](../pypki/kms.py#L237) writes AES keys with
`storage_type='Plain'`; [pypki/kms.py:62](../pypki/kms.py#L62) loads `'Plain'` rows
by calling `load_pem_private_key()`.

Calling `kms.load_key(<AES id>)` will throw because the column contains base64,
not PEM. No caller does this today, so it is latent — but it shows that the
storage-type taxonomy needs a `Symmetric` value (or equivalent) and a separate
load branch.

**Severity:** latent — only bites if symmetric keys are ever loaded.

---

## Gap 12 — Stale documentation reference in OCSP error

**Where:** [pypki/ocsp_responder.py:175](../pypki/ocsp_responder.py#L175)

The error message instructs the operator to run `migrate_keys_to_kms.py`, which
is no longer shipped (the strategy doc explicitly notes this). Update the message
to point at the current procedure (insert into `KeyStorage` and set
`private_key_reference`).

**Severity:** doc rot.

---

## Cross-cutting observation — no automated HSM tests

`tests/pkcs11_test.py` is an interactive smoke test that prints token contents.
There is no automated coverage for HSM-backed signing. Closing the gaps above
should be paired with at least one CI-runnable test against
[SoftHSM2](https://www.opendnssec.org/softhsm/) so regressions in mechanism
selection or session handling fail fast. The strategy for that test target is
laid out in the next section.

---

## Development environment — SoftHSM2 first

Daily development and CI run against [SoftHSM2](https://www.opendnssec.org/softhsm/);
real-hardware fidelity is validated against a higher-faithfulness target before
each release. The ultimate deployment targets are YubiHSM 2 and Thales Luna —
both are in scope, and the implementation must be portable to either.

### Two-tier strategy

- **Tier 1 — SoftHSM2 (daily dev + CI).** Free, packaged on every Linux distro,
  runs in a Docker container, fast enough to use as a unit-test fixture. Permissive:
  accepts attribute combinations and mechanisms that real HSMs reject, so it
  cannot be the only test target.
- **Tier 2 — fidelity check before each release.** Run the full HSM test suite
  against:
  - the **YubiHSM 2 simulator** (ships with the Yubico SDK, behaves like the
    real device), and / or
  - a **Thales DPoD** trial (real Luna firmware behind their API; the only
    realistic Luna-equivalent without owning hardware).

  No general-purpose offline Luna emulator is available outside the
  vendor's customer SDK. AWS CloudHSM is Luna under the hood and is a fallback
  if DPoD trial access expires.

### Conservative PKCS#11 subset

To keep SoftHSM2-tested code portable to YubiHSM 2 and Luna, the implementation
must restrict itself to the intersection of what all three support:

- **Asymmetric:** RSA 2048 / 3072 / 4096; ECDSA P-256 / P-384.
- **Hash:** SHA-256 / SHA-384.
- **Mechanisms:** `CKM_SHA256_RSA_PKCS`, `CKM_SHA384_RSA_PKCS`, `CKM_ECDSA`
  (with pre-computed digest), and PSS variants only where explicitly verified on
  each target — YubiHSM 2 does not support `CKM_RSA_PKCS_PSS` in all
  configurations.
- **Symmetric (if/when added):** AES-256 with `CKM_AES_KEY_WRAP_PAD` (AES-KWP).

Anything outside this list — vendor-specific mechanisms, exotic curves, RSA-OAEP
with non-default parameters — must be treated as a portability liability and
gated behind explicit feature checks.

### Mandatory private-key attributes

Every CA / OCSP signing key generated on the token must be created with:

- `CKA_PRIVATE = TRUE`
- `CKA_SENSITIVE = TRUE`
- `CKA_EXTRACTABLE = FALSE`
- `CKA_TOKEN = TRUE`
- `CKA_SIGN = TRUE`
- `CKA_DECRYPT = FALSE`, `CKA_ENCRYPT = FALSE`

Luna rejects keys missing these flags; SoftHSM2 silently accepts weaker
combinations. Code that relies on SoftHSM2 defaults breaks on first contact with
real hardware. The attribute set must be encoded in
`PKCS11Helper.generate_private_key`
([pypki/pkcs11_helper.py:83](../pypki/pkcs11_helper.py#L83)) and asserted in the
test fixture.

### Vendor portability gotchas to design around

The issues most likely to surface during the SoftHSM → real-hardware transition.
Each must be isolated behind a config knob rather than hard-coded:

- **Mechanism availability.** Luna requires explicit per-partition mechanism
  enabling; YubiHSM 2 ships a narrower mechanism list than SoftHSM. Probe at
  startup with `C_GetMechanismList` and fail fast with a clear error rather than
  at first sign.
- **Login model.** Luna partitions use role-based login (Crypto Officer /
  Crypto User); YubiHSM 2 authenticates via numeric authkey IDs in addition to a
  PIN. The config layer (Gap 4 + Gap 5) needs to grow beyond `(module, slot, pin)`
  to optionally carry an auth-key id and role.
- **Session limits.** YubiHSM 2 caps concurrent sessions at 16 per authkey.
  Reinforces Gap 6 — share one session per `(module, slot, auth)` tuple, not one
  per cached key.
- **Attribute strictness.** See the previous subsection. Enforce in
  `KeyTools` / `PKCS11Helper`, do not assume vendor defaults.

### Docker layout (sketch)

The SoftHSM2 dev environment is a single container layered onto the existing
image, with token state on a named volume so generated keys persist across
container restarts:

- **`Dockerfile`** — `apt-get install softhsm2 opensc`, initialize a token at
  build time (`softhsm2-util --init-token --slot 0 --label dev-token --pin … --so-pin …`),
  and set `PKCS11_MODULE=/usr/lib/softhsm/libsofthsm2.so` in the env.
- **`docker-compose.yml`** — add a `softhsm-tokens` named volume mounted at
  `/var/lib/softhsm/tokens`. The app service reads `PKCS11_MODULE`,
  `PKCS11_SLOT_LABEL`, and `PKCS11_PIN` from environment (resolved by the
  config-driven module path that closes Gap 4).
- **`pytest` fixture** — opens a session against the dev token, yields it to the
  test, and closes/logs out on teardown. Used to drive HSM-backed signing tests
  in CI.

The dev environment is a prerequisite for closing Gaps 1, 2, 6, 7 with
confidence: without a working HSM-like target running locally and in CI,
mechanism-selection and concurrency fixes cannot be regression-tested.

### Library choice

Stay on **PyKCS11** for now (already in use across
[pypki/pkcs11_helper.py](../pypki/pkcs11_helper.py) and
[pypki/key_tools.py](../pypki/key_tools.py)). It is a thin, literal binding that
exposes the raw PKCS#11 surface — useful when debugging vendor-specific quirks,
which the portability gotchas above guarantee will happen.
[`python-pkcs11`](https://python-pkcs11.readthedocs.io/) is a more Pythonic
alternative; switching is a separate decision and not a prerequisite for any of
the gaps in this document.

---

## Suggested order of work

0. **Phase 0 — provider model + dev environment (Gap 4 + SoftHSM2 setup).**
   Introduce the `HSMProviders` record described in the "HSM provider model"
   section and migrate `KeyStorage` to a `provider_id` foreign key. Stand up
   the SoftHSM2 Docker container as the *first provider row*, write the
   `pytest` fixture that opens a session against it, and add a single passing
   "sign and verify with a software-generated key" test. Without this, every
   subsequent gap is fixed blind, and the provider model defers no longer than
   it has to — the longer code is written against the inline `hsm_slot` /
   `token_password` columns, the more painful the eventual rewrite.
1. **Gaps 1 + 2** (RSA mechanism + ECDSA branch). Add SoftHSM-driven
   sign-and-verify tests for both algorithms as part of the fix — these are
   exactly the regressions the test fixture is built to catch.
2. **Gap 3** (slot selection). Required for any host with more than one slot;
   small once Gap 4 is done.
3. **Gap 7** (per-key lock in `load_key`) and **Gap 6** (session lifecycle).
   Stability under concurrency and long-running deployments. Test by hammering
   the SoftHSM fixture from multiple threads.
4. **Gap 5** (PIN out of MySQL). Required before any production rollout. The
   config layer should already have grown enough scaffolding from Phase 0 to
   make this a small addition.
5. **Gap 8** (HSM-backed key generation + import API + UI). Operator UX.
   Generated keys must carry the mandatory attribute set described above.
6. **Gaps 9, 10, 11, 12** plus expanding the SoftHSM-based test coverage.
   Hardening and cleanup.
7. **Fidelity pass.** Run the full HSM test suite against the YubiHSM 2
   simulator and (if available) Thales DPoD before declaring HSM support
   release-ready.
