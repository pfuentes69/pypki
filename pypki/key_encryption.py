"""
Per-provider Key-Encryption-Key (KEK) derivation and software-key
encryption-at-rest helpers.

A `software` CryptoProvider has a PIN, resolved via its ``auth_secret_ref``
(`env:` / `vault:` / `db:encrypted` / `operator:prompt` — see
[kms-specs.md §7](../doc/kms-specs.md)). The PIN is then run through
HKDF-SHA256 to derive a per-provider 256-bit KEK, which is used with
AES-256-GCM to encrypt PEM-encoded private keys for at-rest storage in
``KeyStorage.private_key``.

On-disk format (base64-encoded text in the ``private_key`` TEXT column):

    base64( nonce(12) || ciphertext || tag(16) )

The ``storage_type='Encrypted'`` ENUM value marks a row as being in this
format. ``Plain`` rows are plaintext PEM and are migrated to ``Encrypted``
by the schema migration introduced in Phase 0.2.

Resolver scope at this phase:
    - ``env:NAME``        — implemented
    - ``operator:prompt`` — placeholder; raises KEKUnavailable
    - ``db:encrypted``    — reserved for a later phase; raises NotImplementedError
    - ``vault:path``      — reserved for a later phase; raises NotImplementedError
"""
import base64
import os

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from .log import logger


# ── Constants ─────────────────────────────────────────────────────────────────

# HKDF "info" string. Bumping the version invalidates every existing
# encrypted-at-rest blob; do not change without a corresponding migration.
_KEK_INFO = b"pypki:provider-kek:v1"

# Master-KEK domain separation. The master KEK wraps provider PINs stored
# under `auth_secret_ref='db:encrypted'` (see kms-specs.md §7). It is
# derived from the same `HSM_PIN_KEK` env var as the per-provider KEKs but
# with a distinct salt+info so the two key families never collide.
_MASTER_KEK_ENV_VAR = "HSM_PIN_KEK"
_MASTER_KEK_SALT = b"pypki:master-kek"
_MASTER_KEK_INFO = b"pypki:master-kek:v1"


# ── Errors ────────────────────────────────────────────────────────────────────

class KEKUnavailable(RuntimeError):
    """Raised when a provider's PIN/KEK cannot be resolved (env var missing,
    operator-prompt provider not yet activated, etc.)."""


# ── Secret resolution ─────────────────────────────────────────────────────────

def resolve_provider_secret(provider_record: dict) -> bytes:
    """
    Resolve a provider's ``auth_secret_ref`` to the underlying PIN bytes.

    Raises :class:`KEKUnavailable` on resolvable-but-missing references
    (env var unset, operator-prompt awaiting input, db:encrypted blob
    missing or unreadable).
    Raises :class:`NotImplementedError` for resolver kinds not yet wired up.
    Raises :class:`ValueError` for malformed references.
    """
    ref = (provider_record.get("auth_secret_ref") or "").strip()
    label = provider_record.get("label") or "<unknown>"

    if ref.startswith("env:"):
        var_name = ref[4:].strip()
        if not var_name:
            raise ValueError(
                f"Provider '{label}': empty env var name in auth_secret_ref"
            )
        value = os.environ.get(var_name)
        if not value:
            raise KEKUnavailable(
                f"Provider '{label}': environment variable {var_name} is not set. "
                f"Set it to a strong, deployment-wide secret kept outside the database "
                f"(see doc/kms-specs.md §7)."
            )
        return value.encode("utf-8")

    if ref == "operator:prompt":
        raise KEKUnavailable(
            f"Provider '{label}': awaiting operator PIN (auto_activate=FALSE). "
            f"Activate via POST /api/crypto-providers/{{id}}/activate."
        )

    if ref == "db:encrypted":
        blob = provider_record.get("auth_secret_blob")
        if not blob:
            raise KEKUnavailable(
                f"Provider '{label}': auth_secret_ref='db:encrypted' but "
                f"auth_secret_blob is empty"
            )
        try:
            master_kek = get_master_kek()
        except KEKUnavailable:
            raise
        try:
            return decrypt_blob(blob, master_kek)
        except Exception as e:
            raise KEKUnavailable(
                f"Provider '{label}': failed to decrypt auth_secret_blob — the "
                f"stored PIN was encrypted under a different HSM_PIN_KEK ({e})"
            ) from e

    if ref.startswith("vault:"):
        raise NotImplementedError(
            "auth_secret_ref='vault:…' resolver is reserved for a later phase."
        )

    raise ValueError(
        f"Provider '{label}': unknown auth_secret_ref scheme: {ref!r}"
    )


def encrypt_provider_pin(pin: bytes) -> bytes:
    """
    Encrypt a provider PIN under the master KEK so it can be stored in
    ``CryptoProviders.auth_secret_blob`` (auth_secret_ref='db:encrypted').
    Returns raw bytes for the VARBINARY column (the encoded blob is short
    enough to skip base64 here). The format mirrors :func:`encrypt_pem`:
    ``nonce(12) || ciphertext || tag(16)`` — but raw, not base64.
    """
    if not isinstance(pin, (bytes, bytearray)) or not pin:
        raise ValueError("encrypt_provider_pin: pin must be non-empty bytes")
    kek = get_master_kek()
    nonce = os.urandom(12)
    ct = AESGCM(kek).encrypt(nonce, bytes(pin), associated_data=None)
    return nonce + ct


def decrypt_provider_pin(blob: bytes) -> bytes:
    """Inverse of :func:`encrypt_provider_pin`. Returns the PIN bytes."""
    kek = get_master_kek()
    return _decrypt_raw(blob, kek)


def encrypt_blob(data: bytes, kek: bytes) -> bytes:
    """Generic AES-256-GCM wrap returning raw bytes (for VARBINARY columns)."""
    if len(kek) != 32:
        raise ValueError(f"KEK must be 32 bytes, got {len(kek)}")
    nonce = os.urandom(12)
    ct = AESGCM(kek).encrypt(nonce, data, associated_data=None)
    return nonce + ct


def decrypt_blob(blob, kek: bytes = None) -> bytes:
    """
    Decrypt a blob produced by :func:`encrypt_blob` or
    :func:`encrypt_provider_pin`. Accepts either raw bytes (preferred) or
    a base64-encoded ASCII string for legacy callers. When ``kek`` is None,
    the master KEK is used — convenient for `db:encrypted` resolution.
    """
    if kek is None:
        kek = get_master_kek()
    if isinstance(blob, str):
        # Legacy text form — try base64 first.
        import base64 as _b64
        try:
            raw = _b64.b64decode(blob.encode("ascii"))
        except Exception as e:
            raise ValueError(f"decrypt_blob: not valid base64: {e}")
    elif isinstance(blob, (bytes, bytearray)):
        raw = bytes(blob)
    else:
        raise ValueError(f"decrypt_blob: unsupported blob type {type(blob).__name__}")
    return _decrypt_raw(raw, kek)


def _decrypt_raw(raw: bytes, kek: bytes) -> bytes:
    if len(kek) != 32:
        raise ValueError(f"KEK must be 32 bytes, got {len(kek)}")
    if len(raw) < 12 + 16:
        raise ValueError("Encrypted blob too short to contain nonce + tag")
    nonce, ct = raw[:12], raw[12:]
    return AESGCM(kek).decrypt(nonce, ct, associated_data=None)


# ── Master KEK derivation ─────────────────────────────────────────────────────

def get_master_kek() -> bytes:
    """
    Derive the master KEK from the ``HSM_PIN_KEK`` environment variable.
    The master KEK wraps provider PINs stored under
    ``auth_secret_ref='db:encrypted'``. Distinct domain (salt+info) from the
    per-provider KEKs that wrap software keys — same env var, separate
    derivation paths, no cross-domain collision.

    Raises :class:`KEKUnavailable` if ``HSM_PIN_KEK`` is unset.
    """
    value = os.environ.get(_MASTER_KEK_ENV_VAR)
    if not value:
        raise KEKUnavailable(
            f"Master KEK: environment variable {_MASTER_KEK_ENV_VAR} is not set. "
            f"It is required for `db:encrypted` provider PINs and for software-key "
            f"encryption-at-rest (see doc/kms-specs.md §7)."
        )
    hkdf = HKDF(
        algorithm=hashes.SHA256(),
        length=32,
        salt=_MASTER_KEK_SALT,
        info=_MASTER_KEK_INFO,
    )
    return hkdf.derive(value.encode("utf-8"))


# ── KEK derivation ────────────────────────────────────────────────────────────

def derive_kek(pin: bytes, provider_id: int) -> bytes:
    """
    Derive a 256-bit KEK from a provider's PIN using HKDF-SHA256.
    The provider id is used as a salt so each provider gets a distinct KEK
    even when they share the same PIN.
    """
    salt = f"pypki-provider-{int(provider_id)}".encode("utf-8")
    hkdf = HKDF(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        info=_KEK_INFO,
    )
    return hkdf.derive(pin)


def get_provider_kek(provider_record: dict) -> bytes:
    """Resolve a provider's PIN and derive its KEK in one step."""
    pin = resolve_provider_secret(provider_record)
    return derive_kek(pin, provider_record["id"])


# ── AES-256-GCM wrap / unwrap ─────────────────────────────────────────────────

def encrypt_pem(pem: bytes, kek: bytes) -> str:
    """
    Encrypt PEM bytes under the given 32-byte KEK using AES-256-GCM with a
    random 96-bit nonce. Returns ``base64(nonce || ciphertext || tag)`` as
    ASCII text suitable for storage in the ``KeyStorage.private_key`` TEXT
    column.
    """
    if len(kek) != 32:
        raise ValueError(f"KEK must be 32 bytes, got {len(kek)}")
    nonce = os.urandom(12)
    ct = AESGCM(kek).encrypt(nonce, pem, associated_data=None)
    return base64.b64encode(nonce + ct).decode("ascii")


def decrypt_pem(blob: str, kek: bytes) -> bytes:
    """
    Decrypt a base64 ciphertext produced by :func:`encrypt_pem`. Returns
    PEM bytes.
    """
    if len(kek) != 32:
        raise ValueError(f"KEK must be 32 bytes, got {len(kek)}")
    raw = base64.b64decode(blob.encode("ascii"))
    if len(raw) < 12 + 16:
        raise ValueError("Encrypted blob too short to contain nonce + tag")
    nonce, ct = raw[:12], raw[12:]
    return AESGCM(kek).decrypt(nonce, ct, associated_data=None)
