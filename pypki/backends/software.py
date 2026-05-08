"""
SoftwareBackend — libcrypto in-process, PEMs encrypted at rest under a
per-provider KEK.

Activation derives the KEK from the provider's PIN (resolved via
``auth_secret_ref``). Loading a key decrypts its ciphertext blob with
that KEK and constructs a :class:`KeyTools` with the resulting PEM.
``generate_key`` produces a fresh keypair, encrypts the PEM, and returns
the material the KMS persists.
"""
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec, ed25519, rsa
from cryptography.hazmat.primitives.serialization import (
    Encoding, NoEncryption, PrivateFormat, PublicFormat,
    load_pem_private_key,
)

from ..key_encryption import (
    decrypt_pem,
    derive_kek,
    encrypt_pem,
    get_provider_kek,
    KEKUnavailable,
)
from ..key_tools import KeyTools
from ..log import logger
from .base import BackendNotActive, KeyHandle


# Same conservative subset enforced in PKCS11Backend (kms-strategy.md §8.1).
_RSA_SIZES = {2048, 3072, 4096}
_EC_CURVES = {
    "P-256": ec.SECP256R1(),
    "P-384": ec.SECP384R1(),
}


class SoftwareBackend:
    """In-process software signing backend. See :class:`CryptoBackend`."""

    def __init__(self):
        self._provider: dict | None = None
        self._kek: bytes | None = None

    # ── lifecycle ────────────────────────────────────────────────────────────

    def open(self, provider: dict, secret_override: bytes = None) -> None:
        if self._kek is not None:
            return  # already active; no-op
        try:
            if secret_override is not None:
                if not isinstance(secret_override, (bytes, bytearray)) or not secret_override:
                    raise ValueError("secret_override must be non-empty bytes")
                kek = derive_kek(bytes(secret_override), provider["id"])
            else:
                kek = get_provider_kek(provider)
        except KEKUnavailable as e:
            raise BackendNotActive(
                f"SoftwareBackend: cannot activate provider id={provider.get('id')} "
                f"('{provider.get('label')}'): {e}"
            ) from e
        self._provider = provider
        self._kek = kek
        logger.info(
            f"SoftwareBackend: activated provider id={provider.get('id')} "
            f"('{provider.get('label')}')"
            + (" [operator-supplied PIN]" if secret_override is not None else "")
        )

    def close(self) -> None:
        if self._kek is None:
            return
        # Best-effort scrub of the KEK reference; Python does not give us
        # deterministic memory wiping, but at least we drop the reference.
        self._kek = None
        provider = self._provider
        self._provider = None
        if provider is not None:
            logger.info(
                f"SoftwareBackend: deactivated provider id={provider.get('id')} "
                f"('{provider.get('label')}')"
            )

    def is_active(self) -> bool:
        return self._kek is not None

    # ── key operations ───────────────────────────────────────────────────────

    def load_key(self, record: dict) -> KeyHandle:
        if not self.is_active():
            raise BackendNotActive("SoftwareBackend.load_key: backend is not open")
        storage_type = record.get("storage_type")
        key_id = record.get("id")

        # Gap 11: symmetric keys cannot be loaded through the asymmetric
        # signing path. Fail early with a clear message rather than letting
        # `load_pem_private_key` crash on a base64-encoded AES key.
        if storage_type == "Symmetric":
            raise ValueError(
                f"SoftwareBackend: KeyStorage id={key_id} is a symmetric key "
                f"(storage_type='Symmetric'); the asymmetric load/sign path "
                f"does not handle these. Symmetric-key operations are not yet "
                f"exposed through the KMS API."
            )

        # End-entity key escrow regime: the row holds a KEK-wrapped PEM that
        # is *also* passphrase-encrypted with an operator-supplied PKCS#12
        # password. Loading it requires that passphrase, which the KMS sign
        # path does not have. Refuse cleanly and point at the right flow.
        if storage_type == "PassphraseEncrypted":
            raise ValueError(
                f"SoftwareBackend: KeyStorage id={key_id} is a passphrase-"
                f"encrypted end-entity key (storage_type='PassphraseEncrypted'); "
                f"the asymmetric signing path does not handle these. Use "
                f"PyPKI.build_pkcs12_for_certificate() with the operator-"
                f"supplied PKCS#12 passphrase to access the key material."
            )

        if storage_type == "Encrypted":
            blob = record.get("private_key")
            if not blob:
                raise ValueError(
                    f"SoftwareBackend: KeyStorage id={key_id} has empty private_key"
                )
            # Legacy mislabel detection (Gap 10). Pre-Phase-0 pypki had
            # 'Encrypted' as an enum value but stored plaintext PEM in the
            # column — `load_key` treated 'Encrypted' identically to
            # 'Plain'. Tolerate that here: if the column looks like a PEM
            # private key, load it as plaintext and log a warning so the
            # operator knows to set HSM_PIN_KEK and re-run migrations.
            if _looks_like_pem(blob):
                logger.warning(
                    f"SoftwareBackend: key_id={key_id} marked storage_type='Encrypted' "
                    f"but private_key column holds plaintext PEM (legacy Gap 10). "
                    f"Loading as plaintext; set HSM_PIN_KEK and restart to encrypt-at-rest."
                )
                pem = blob.encode("utf-8") if isinstance(blob, str) else blob
            else:
                pem = decrypt_pem(blob, self._kek)
        elif storage_type == "Plain":
            # Legacy plaintext PEM. Tolerated during the migration window;
            # the Phase 0.2 migration converts these to 'Encrypted'.
            pem_text = record.get("private_key")
            if not pem_text:
                raise ValueError(
                    f"SoftwareBackend: KeyStorage id={key_id} has empty private_key"
                )
            logger.warning(
                f"SoftwareBackend: key_id={key_id} stored as plaintext PEM "
                f"(storage_type='Plain'); set HSM_PIN_KEK and re-run migrations"
            )
            pem = pem_text.encode("utf-8") if isinstance(pem_text, str) else pem_text
        else:
            raise ValueError(
                f"SoftwareBackend: cannot load storage_type={storage_type!r} "
                f"(key_id={key_id})"
            )

        kt = KeyTools()
        kt.set_private_key(load_pem_private_key(pem, password=None))
        return KeyHandle(
            key_id=key_id,
            provider_id=self._provider["id"],
            state=kt,
        )

    def unload_key(self, handle: KeyHandle) -> None:
        # Software keys are released when the handle is dropped; nothing
        # provider-scoped to clean up per-key.
        pass

    def sign_digest(self, handle: KeyHandle, tbs_digest: bytes) -> bytes:
        if not self.is_active():
            raise BackendNotActive("SoftwareBackend.sign_digest: backend is not open")
        kt: KeyTools = handle._state
        return kt.sign_digest(tbs_digest)

    # ── Generation / deletion (Phase 5a) ──────────────────────────────────────

    def generate_key(self, key_type: str, label: str = None) -> dict:
        """
        Generate a fresh asymmetric keypair, encrypt the PEM under this
        provider's KEK, and return a dict the KMS uses to persist a
        ``KeyStorage`` row::

            {
                "storage_type":   "Encrypted",
                "private_key":    <ciphertext str>,
                "public_key":     <PEM str>,
                "key_type":       <normalised label, e.g. "RSA-3072">,
                "label":          <provided label or None>,
            }

        ``key_type`` accepts the canonical labels documented in
        kms-strategy.md §8.1: RSA-2048/3072/4096, ECDSA-P-256/P-384,
        Ed25519. The dict shape is intentionally flat so the KMS can pass
        it straight to ``PKIDataBase.insert_key``.
        """
        if not self.is_active():
            raise BackendNotActive("SoftwareBackend.generate_key: backend is not open")

        kt = (key_type or "").strip()
        priv, normalised = _generate_software_keypair(kt)

        pem = priv.private_bytes(Encoding.PEM, PrivateFormat.PKCS8, NoEncryption())
        public_pem = priv.public_key().public_bytes(
            Encoding.PEM, PublicFormat.SubjectPublicKeyInfo
        ).decode()
        blob = encrypt_pem(pem, self._kek)
        return {
            "storage_type": "Encrypted",
            "private_key": blob,
            "public_key": public_pem,
            "key_type": normalised,
            "label": label,
        }

    def delete_key(self, handle: KeyHandle) -> None:
        """No on-disk side effects — the KMS deletes the ``KeyStorage`` row.
        Provided so the backend contract is uniform with PKCS11Backend."""
        return


def _looks_like_pem(blob) -> bool:
    """Return True if the value looks like a *plaintext* PEM-armoured
    private key — the Gap 10 legacy state where ``KeyStorage.private_key``
    holds raw PEM under ``storage_type='Encrypted'``.

    Excludes passphrase-encrypted PEM (PKCS#8 ``-----BEGIN ENCRYPTED
    PRIVATE KEY-----`` and PKCS#1 / SEC1 ``Proc-Type: 4,ENCRYPTED``) so
    the migration doesn't double-encrypt rows whose ``Encrypted`` label
    actually meant "passphrase-encrypted PEM" (the regime collision
    documented in roadmap §2 / PROGRESS §2).
    """
    if not isinstance(blob, (str, bytes, bytearray)):
        return False
    s = blob.decode("utf-8", "ignore") if isinstance(blob, (bytes, bytearray)) else blob
    s = s.lstrip()
    if not s.startswith("-----BEGIN "):
        return False
    if s.startswith("-----BEGIN ENCRYPTED PRIVATE KEY-----"):
        return False
    # PKCS#1 / SEC1 carry an explicit "Proc-Type: 4,ENCRYPTED" line in the
    # header when password-protected. Inspect only the first 300 bytes —
    # the marker is always near the top.
    if "Proc-Type: 4,ENCRYPTED" in s[:300]:
        return False
    return True


def _generate_software_keypair(key_type: str):
    """Map a canonical key-type label to a ``(private_key, normalised_label)``
    pair. Restricted to the conservative subset shared with PKCS#11."""
    kt = (key_type or "").strip()

    if kt.upper().startswith("RSA"):
        # Accept "RSA-2048" or "RSA2048"; normalise both to "RSA-<bits>".
        suffix = kt.upper().replace("RSA-", "").replace("RSA", "")
        try:
            bits = int(suffix)
        except ValueError:
            raise ValueError(f"Invalid RSA key_type {key_type!r}")
        if bits not in _RSA_SIZES:
            raise ValueError(
                f"Invalid RSA size {bits}; choose from {sorted(_RSA_SIZES)}"
            )
        return rsa.generate_private_key(public_exponent=65537, key_size=bits), f"RSA-{bits}"

    if kt.upper().startswith("ECDSA"):
        # Accept "ECDSA-P-256", "ECDSA-P256", "ECDSA-secp256r1".
        suffix = kt[len("ECDSA"):].lstrip("-").upper()
        normalised_curve = (
            "P-256" if "256" in suffix else
            "P-384" if "384" in suffix else
            None
        )
        if normalised_curve not in _EC_CURVES:
            raise ValueError(
                f"Invalid ECDSA curve {key_type!r}; choose from {list(_EC_CURVES)}"
            )
        return (
            ec.generate_private_key(_EC_CURVES[normalised_curve]),
            f"ECDSA-{normalised_curve}",
        )

    if kt.lower() == "ed25519":
        return ed25519.Ed25519PrivateKey.generate(), "Ed25519"

    raise ValueError(
        f"Unsupported key_type {key_type!r}. Choose from: "
        f"RSA-2048, RSA-3072, RSA-4096, ECDSA-P-256, ECDSA-P-384, Ed25519."
    )
