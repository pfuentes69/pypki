"""
Software-key wrapper used by :class:`pypki.backends.SoftwareBackend`.

After Phase 6 this is purely an in-memory `cryptography`-private-key
holder with a SHA-256-digest signing primitive. The HSM construction
path that previously lived here (open a PKCS#11 session, log in, find
the on-token object, sign via PyKCS11) is gone — :class:`PKCS11Backend`
owns the entire HSM signing path now, with a per-provider shared
session, mandatory CKA_* attributes, locking, and reconnect logic.
"""
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric import rsa, ec, padding
from cryptography.hazmat.primitives.asymmetric.utils import Prehashed


class KeyTools:
    """Holds a single in-memory ``cryptography`` private key and exposes
    the SHA-256-prehashed signing primitive that ``SoftwareBackend`` and
    the legacy direct-signing path on :class:`CertificationAuthority`
    consume."""

    def __init__(self, private_key=None):
        self.__private_key = private_key
        self.__public_key = None

    def has_private_key(self) -> bool:
        return self.__private_key is not None

    def is_hsm(self) -> bool:
        # Retained as a stable contract bit; HSM-resident keys never flow
        # through this class anymore (PKCS11Backend handles them).
        return False

    def generate_private_key(self, algorithm: str, key_type: str):
        """
        Generate a private key in memory. Kept for the few callers that
        still construct keys directly outside the KMS path; the canonical
        provider-aware generation lives in
        ``KMS.generate_key_in_provider``.
        """
        if algorithm == "RSA":
            key_size = int(key_type)
            if key_size not in {2048, 3072, 4096}:
                raise ValueError("Invalid RSA key size")
            self.__private_key = rsa.generate_private_key(
                public_exponent=65537, key_size=key_size, backend=default_backend()
            )
        elif algorithm == "ECDSA":
            curve_mapping = {
                "P-256": ec.SECP256R1(),
                "P-384": ec.SECP384R1(),
                "P-521": ec.SECP521R1(),
            }
            if key_type not in curve_mapping:
                raise ValueError("Invalid ECDSA curve")
            self.__private_key = ec.generate_private_key(
                curve_mapping[key_type], backend=default_backend()
            )
        else:
            raise ValueError("Unsupported algorithm")

        self.__public_key = self.__private_key.public_key()
        return self.__private_key

    def get_private_key(self):
        return self.__private_key

    def set_private_key(self, private_key) -> None:
        self.__private_key = private_key
        self.__public_key = self.__private_key.public_key()

    def set_public_key(self, public_key) -> None:
        """Set just a public key — for objects that exist only to expose a
        public key (e.g. when verifying signatures)."""
        self.__public_key = public_key

    def get_public_key(self):
        return self.__public_key

    def get_private_key_pem(self, password: bytes = None):
        """Securely export the private key in PEM format. Encrypted under
        ``password`` if supplied, otherwise unencrypted."""
        if not self.__private_key:
            return None
        encryption_algorithm = (
            serialization.BestAvailableEncryption(password)
            if password else serialization.NoEncryption()
        )
        return self.__private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=encryption_algorithm,
        )

    def get_public_key_pem(self):
        if not self.__private_key:
            return None
        return self.__private_key.public_key().public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo,
        )

    def sign_digest(self, tbs_digest: bytes) -> bytes:
        """
        Sign a pre-computed SHA-256 digest with the in-memory private key.
        RSA → PKCS#1 v1.5; ECDSA → fixed nonce per ``cryptography``'s
        defaults. The signature shape matches what
        :class:`PKCS11Backend.sign_digest` produces, so callers above the
        backend layer don't need to branch on the backend kind.
        """
        if isinstance(self.__private_key, rsa.RSAPrivateKey):
            return self.__private_key.sign(
                tbs_digest, padding.PKCS1v15(), Prehashed(hashes.SHA256())
            )
        if isinstance(self.__private_key, ec.EllipticCurvePrivateKey):
            return self.__private_key.sign(
                tbs_digest, ec.ECDSA(Prehashed(hashes.SHA256()))
            )
        raise ValueError(f"Unsupported key type: {type(self.__private_key)!r}")
