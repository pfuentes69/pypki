# KMS Integration Strategy

## Overview

This document describes the strategy for introducing a Key Management Service (KMS) layer into PyPKI. The goal is to centralise all private key storage and all signing operations behind a single internal service so that future security improvements (encrypted storage, remote KMS, HSM consolidation, key generation, key export) can be made without touching the signing callers.

The implementation was split into three phases, all now complete:

| Phase | Scope | Status |
|---|---|---|
| 1 | DB migration: move keys into `KeyStorage` | Done — `utils/migrate_keys_to_kms.py` |
| 2 | KMS module: new internal service class | Done — `pypki/kms.py` |
| 3 | Sign-through: route all signing calls via KMS | Done |

Keys remain in clear text. Security hardening (encrypted storage, remote KMS) is out of scope and will follow in a separate initiative.

---

## Current State

Private keys are stored in two separate tables and loaded directly by the objects that use them:

```
CertificationAuthorities.private_key  (TEXT, PEM)
OCSPResponders.private_key            (TEXT, PEM)
```

Both tables also had `private_key_reference INT` (FK → `KeyStorage`) and HSM fields (`token_slot`, `token_key_id`, `token_password`). After the migration: `private_key_reference` is always populated; `token_slot/token_key_id/token_password` have been dropped from both tables (HSM PIN is now in `KeyStorage.token_password`).

### Current signing paths

**Certificate issuance** (`pypki/certificate_tools.py`)
- Software: `cert_builder.sign(private_key=signing_private_key.get_private_key(), algorithm=hashes.SHA256())`
- HSM: build with dummy key → extract TBS bytes → hash → `KeyTools.sign_digest(tbs_digest)` → patch DER

**OCSP response** (`pypki/ocsp_responder.py`)
- `builder.sign(private_key=self.get_private_key(), algorithm=hashes.SHA256())`

Both callers hold the `KeyTools` object directly. The KMS will sit between callers and `KeyTools`.

---

## Phase 1 — Database Migration

### Objective

Populate `KeyStorage` with the existing private keys of all CAs and OCSP responders, then update `private_key_reference` in both tables to point to the new rows. The `private_key` column in each table is left intact for now and nulled out in Phase 3.

### Migration script — `utils/migrate_keys_to_kms.py`

```
For each row in CertificationAuthorities:
    1. Read private_key (PEM string)
    2. Determine storage_type:
         - if token_key_id is not empty → "HSM"
         - else → "Plain"
    3. INSERT INTO KeyStorage (private_key, storage_type, hsm_slot, hsm_token_id)
    4. UPDATE CertificationAuthorities SET private_key_reference = <new_id> WHERE id = <ca_id>

For each row in OCSPResponders:
    Same four steps as above.
```

The migration is idempotent: if `private_key_reference` is already set, skip the row.

### Schema changes needed

None — both `private_key_reference` columns already exist. No `ALTER TABLE` is required.

### Rollback

Set `private_key_reference = NULL` on affected rows. The application will continue to read from `private_key` as it does today until Phase 3 is deployed.

---

## Phase 2 — KMS Module

### Objective

Introduce `pypki/kms.py` — a new class `KeyManagementService` that owns all interactions with `KeyStorage`. This class is the single entry point for:
- Loading a key by its `KeyStorage` ID
- Signing a digest (the only signing primitive needed by callers today)

Future operations (key generation, key export, key rotation) will be added to this class.

### Class design

```python
# pypki/kms.py

class KeyManagementService:

    def __init__(self, db: PKIDataBase):
        self.__db = db
        self.__key_cache: dict[int, KeyTools] = {}   # key_id → KeyTools

    # ── Key loading ──────────────────────────────────────────────

    def load_key(self, key_id: int) -> None:
        """Load a key from KeyStorage into the in-memory cache."""
        record = self.__db.get_private_key_record(key_id)       # new DB method
        if not record:
            raise KeyError(f"Key {key_id} not found in KeyStorage")
        storage_type = record["storage_type"]
        if storage_type in ("Plain", "Encrypted"):
            kt = KeyTools(private_key_pem=record["private_key"])
        elif storage_type == "HSM":
            kt = KeyTools(
                token_slot=record["hsm_slot"],
                token_key_id=record["hsm_token_id"],
                token_password=record.get("token_password")
            )
        else:
            raise ValueError(f"Unknown storage_type: {storage_type}")
        self.__key_cache[key_id] = kt

    def unload_key(self, key_id: int) -> None:
        """Remove a key from the in-memory cache."""
        self.__key_cache.pop(key_id, None)

    # ── Signing ──────────────────────────────────────────────────

    def sign_digest(self, key_id: int, tbs_digest: bytes) -> bytes:
        """Sign a pre-computed digest using the key identified by key_id.

        The caller is responsible for computing the digest (SHA-256 of the
        TBS bytes). The KMS returns the raw signature bytes.
        """
        if key_id not in self.__key_cache:
            self.load_key(key_id)
        return self.__key_cache[key_id].sign_digest(tbs_digest)

    def sign_data(self, key_id: int, data: bytes) -> bytes:
        """Convenience: hash data with SHA-256 then sign the digest."""
        digest = hashes.Hash(hashes.SHA256())
        digest.update(data)
        return self.sign_digest(key_id, digest.finalize())

    # ── Future operations (stubs) ────────────────────────────────

    def generate_key(self, algorithm: str, **kwargs) -> int:
        """Generate a new key, store it, return its KeyStorage ID."""
        raise NotImplementedError

    def export_key(self, key_id: int) -> bytes:
        """Export a key in PEM format (subject to policy)."""
        raise NotImplementedError
```

### New DB method needed

Add `get_private_key_record(key_id)` to `PKIDataBase` (mirrors the existing pattern of `get_cert_template_record_by_id`):

```python
def get_private_key_record(self, key_id: int):
    """Retrieve a row from KeyStorage by ID."""
    ...
    query = "SELECT * FROM KeyStorage WHERE id = %s"
    ...
```

### Integration point in `core.py`

`PyPKI` (the orchestrator in `pypki/core.py`) should own the single `KeyManagementService` instance and expose it to CAs and OCSP responders:

```python
# pypki/core.py  (additions)

class PyPKI:
    def __init__(self, ...):
        ...
        self.__kms = KeyManagementService(self.__db)

    def get_kms(self) -> KeyManagementService:
        return self.__kms
```

---

## Phase 3 — Route Signing Through the KMS

### Objective

Replace direct `KeyTools`/private-key usage in `CertificationAuthority` and `OCSPResponder` with KMS calls. After this phase:

- Neither `CertificationAuthority` nor `OCSPResponder` holds a `KeyTools` object.
- Neither reads the `private_key` PEM column directly.
- All signing goes through `KeyManagementService.sign_digest()`.

### Changes per component

#### `CertificationAuthority` (`pypki/ca.py`)

**Before (current)**
```python
self.__signing_key = KeyTools(...)   # loaded from private_key PEM or HSM params
```

**After**
```python
self.__kms_key_id = config["crypto"]["kms_key_id"]   # integer, from private_key_reference
# __signing_key is removed
```

The signing call in `certificate_tools.py` already handles the HSM path by calling `signing_private_key.sign_digest(tbs_digest)`. That call becomes:

```python
# certificate_tools.py — unified signing path
tbs_digest = sha256(cert_builder.tbs_bytes())
signature = kms.sign_digest(kms_key_id, tbs_digest)
final_der = self.patch_certificate_signature(pre_cert_der, signature, is_ecdsa=...)
return x509.load_der_x509_certificate(final_der)
```

The software/HSM branch inside `certificate_tools.py` is removed — the KMS handles both internally via `KeyTools`.

#### `OCSPResponder` (`pypki/ocsp_responder.py`)

The `cryptography` library's `OCSPResponseBuilder.sign()` requires the private key object directly; it does not accept pre-computed signatures. The approach follows the same pattern already used for HSM certificate signing:

1. Build the OCSP response with a throw-away key to obtain the DER bytes.
2. Extract the TBS (to-be-signed) portion.
3. Call `kms.sign_digest(key_id, sha256(tbs))`.
4. Patch the signature into the DER (extend `patch_certificate_signature` or add an equivalent `patch_ocsp_signature`).

```python
# ocsp_responder.py — after Phase 3
def generate_response(self, ...):
    dummy_key = ec.generate_private_key(ec.P256())
    pre_response = builder.sign(private_key=dummy_key, algorithm=hashes.SHA256())
    tbs = pre_response.tbs_response_bytes
    signature = self.__kms.sign_digest(self.__kms_key_id, sha256(tbs))
    return patch_ocsp_signature(pre_response, signature)
```

#### `core.py` — loading CAs and OCSP responders

When `select_ca_by_id()` reconstructs a `CertificationAuthority` from the DB row, instead of passing the PEM key it passes the `private_key_reference` ID:

```python
# core.py — select_ca_by_id (after Phase 3)
crypto_config = {
    "certificate":      row["certificate"],
    "certificate_chain": row["certificate_chain"],
    "kms_key_id":       row["private_key_reference"],   # ← new
    # private_key, token_slot, token_key_id, token_password removed
}
ca = CertificationAuthority()
ca.load_config({"ca_name": row["name"], "crypto": crypto_config, ...})
ca.set_kms(pki.get_kms())
```

---

## Summary of File Changes

| File | Change |
|---|---|
| `utils/migrate_keys_to_kms.py` | **New** — migration script (Phase 1) |
| `pypki/db.py` | **Add** `get_private_key_record(key_id)` (Phase 2) |
| `pypki/kms.py` | **New** — `KeyManagementService` class (Phase 2) |
| `pypki/core.py` | Instantiate KMS; pass `kms_key_id` when loading CAs/OCSP responders (Phase 3) |
| `pypki/ca.py` | Replace `KeyTools` with `kms_key_id` + KMS reference (Phase 3) |
| `pypki/certificate_tools.py` | Remove software/HSM branch; always sign via KMS (Phase 3) |
| `pypki/ocsp_responder.py` | Replace direct signing with dummy-key + KMS patch approach (Phase 3) |
| `pypki/__init__.py` | Export `KeyManagementService` (Phase 2) |

The `private_key` column in `CertificationAuthorities` and `OCSPResponders` can be nulled out after Phase 3 is stable. Dropping the columns entirely is a separate, optional cleanup step.

---

## Future Phases (out of scope for now)

| Capability | Notes |
|---|---|
| Encrypted key storage | `storage_type = 'Encrypted'`; KMS decrypts with a master key before loading into memory |
| Key generation via KMS | `kms.generate_key(algorithm, size)` → stores in `KeyStorage`, returns ID |
| Key export | `kms.export_key(key_id)` → PEM or PKCS#12, subject to policy |
| Remote/cloud KMS | Swap `KeyTools` backend for AWS KMS, Azure Key Vault, HashiCorp Vault, etc. — callers unchanged |
| Key rotation | Generate new key, re-issue certificate, update `private_key_reference` |
| Access control | Gate `sign_digest` and `export_key` per caller identity |
| KMS audit log | Write to `AuditLogs` on every `sign_digest` call |
