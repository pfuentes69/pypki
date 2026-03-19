import os
import base64

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.serialization import load_pem_private_key, Encoding, PrivateFormat, PublicFormat, NoEncryption
from cryptography.hazmat.primitives.asymmetric import rsa, ec, ed25519

from .db import PKIDataBase
from .key_tools import KeyTools
from .log import logger


# Valid symmetric key sizes in bits
_AES_SIZES = {128, 192, 256, 512}

# Valid RSA key sizes in bits
_RSA_SIZES = {2048, 3072, 4096, 8192}

# Valid ECDSA curves
_EC_CURVES = {
    "P-256": ec.SECP256R1(),
    "P-384": ec.SECP384R1(),
    "P-521": ec.SECP521R1(),
}


class KeyManagementService:
    """
    Central service for key generation, storage, and signing operations.

    Keys are identified by their KeyStorage.id and cached in memory
    after the first load. The backend (software or HSM) is transparent to
    the caller — sign_digest() works the same regardless of storage type.
    """

    def __init__(self, db: PKIDataBase):
        self.__db = db
        self.__key_cache: dict[int, KeyTools] = {}   # key_id → KeyTools

    # ── Key loading ──────────────────────────────────────────────────────────

    def load_key(self, key_id: int, token_password: str = None) -> None:
        """Load a key from KeyStorage into the in-memory cache.

        For HSM keys the token_password is read from the KeyStorage record.
        The token_password parameter is accepted for backwards compatibility
        but the stored value takes precedence when present.
        """
        with self.__db.connection():
            record = self.__db.get_key_record(key_id)

        if not record:
            raise KeyError(f"KMS: key_id={key_id} not found in KeyStorage")

        storage_type = record.get("storage_type")

        if storage_type in ("Plain", "Encrypted"):
            pem = record.get("private_key")
            if not pem:
                raise ValueError(f"KMS: key_id={key_id} has no private_key in KeyStorage")
            kt = KeyTools()
            kt.set_private_key(load_pem_private_key(pem.encode("utf-8"), password=None))

        elif storage_type == "HSM":
            stored_password = record.get("token_password")
            kt = KeyTools(
                private_key=None,
                key_id=record.get("hsm_token_id"),
                slot_num=record.get("hsm_slot"),
                token_password=stored_password if stored_password is not None else (token_password or "")
            )

        else:
            raise ValueError(f"KMS: unsupported storage_type '{storage_type}' for key_id={key_id}")

        self.__key_cache[key_id] = kt
        logger.info(f"KMS: loaded key_id={key_id} (storage_type={storage_type})")

    def unload_key(self, key_id: int) -> None:
        """Remove a key from the in-memory cache."""
        if key_id in self.__key_cache:
            del self.__key_cache[key_id]
            logger.info(f"KMS: unloaded key_id={key_id}")

    def is_loaded(self, key_id: int) -> bool:
        return key_id in self.__key_cache

    # ── Signing ──────────────────────────────────────────────────────────────

    def sign_digest(self, key_id: int, tbs_digest: bytes) -> bytes:
        """
        Sign a pre-computed SHA-256 digest.

        The key is loaded on first use and cached for subsequent calls.
        Returns the raw signature bytes.
        """
        if key_id not in self.__key_cache:
            self.load_key(key_id)
        logger.debug(f"KMS: sign_digest key_id={key_id}")
        return self.__key_cache[key_id].sign_digest(tbs_digest)

    def sign_data(self, key_id: int, data: bytes) -> bytes:
        """Hash data with SHA-256 then sign the digest."""
        digest = hashes.Hash(hashes.SHA256())
        digest.update(data)
        return self.sign_digest(key_id, digest.finalize())

    # ── Key generation ───────────────────────────────────────────────────────

    def generate_key(
        self,
        algorithm: str,
        persist: bool = True,
        **kwargs
    ) -> dict:
        """
        Generate a cryptographic key.

        Parameters
        ----------
        algorithm : str
            Key algorithm. One of:
              Asymmetric — "RSA", "ECDSA", "Ed25519"
              Symmetric  — "AES"
        persist : bool
            If True (default) the key is stored in KeyStorage and the
            returned dict contains ``key_id``.
            If False the key material is returned in clear inside the dict
            and nothing is written to the database.
        **kwargs
            Algorithm-specific parameters:
              RSA   → key_size (int): 2048 | 3072 | 4096 | 8192
              ECDSA → curve (str):    "P-256" | "P-384" | "P-521"
              AES   → key_size (int): 128 | 192 | 256 | 512

        Returns
        -------
        dict
            Persisted:    {"key_id": int, "algorithm": str, ...metadata...}
            Not persisted: {"algorithm": str, "key_material": str, ...metadata...}
              - Asymmetric: key_material is PEM-encoded PKCS#8 private key,
                            public_key is PEM-encoded SubjectPublicKeyInfo
              - Symmetric:  key_material is base64-encoded raw key bytes (no public_key)
        """
        algo = algorithm.upper()

        if algo == "RSA":
            return self._generate_rsa(persist, **kwargs)
        elif algo == "ECDSA":
            return self._generate_ecdsa(persist, **kwargs)
        elif algo == "ED25519":
            return self._generate_ed25519(persist)
        elif algo == "AES":
            return self._generate_aes(persist, **kwargs)
        else:
            raise ValueError(
                f"Unsupported algorithm '{algorithm}'. "
                "Choose from: RSA, ECDSA, Ed25519, AES."
            )

    # ── RSA ──────────────────────────────────────────────────────────────────

    def _generate_rsa(self, persist: bool, key_size: int = 3072, **_) -> dict:
        key_size = int(key_size)
        if key_size not in _RSA_SIZES:
            raise ValueError(f"Invalid RSA key_size {key_size}. Choose from {sorted(_RSA_SIZES)}.")

        private_key = rsa.generate_private_key(public_exponent=65537, key_size=key_size)
        pem = private_key.private_bytes(Encoding.PEM, PrivateFormat.PKCS8, NoEncryption()).decode()
        pub_pem = private_key.public_key().public_bytes(Encoding.PEM, PublicFormat.SubjectPublicKeyInfo).decode()
        key_type = f"RSA-{key_size}"
        meta = {"algorithm": "RSA", "key_size": key_size}
        logger.info(f"KMS: generated {key_type}")
        return self._finalise(pem, "Plain", persist, meta, pub_pem, key_type)

    # ── ECDSA ─────────────────────────────────────────────────────────────────

    def _generate_ecdsa(self, persist: bool, curve: str = "P-256", **_) -> dict:
        if curve not in _EC_CURVES:
            raise ValueError(f"Invalid curve '{curve}'. Choose from {list(_EC_CURVES)}.")

        private_key = ec.generate_private_key(_EC_CURVES[curve])
        pem = private_key.private_bytes(Encoding.PEM, PrivateFormat.PKCS8, NoEncryption()).decode()
        pub_pem = private_key.public_key().public_bytes(Encoding.PEM, PublicFormat.SubjectPublicKeyInfo).decode()
        key_type = f"ECDSA-{curve}"
        meta = {"algorithm": "ECDSA", "curve": curve}
        logger.info(f"KMS: generated {key_type}")
        return self._finalise(pem, "Plain", persist, meta, pub_pem, key_type)

    # ── Ed25519 ───────────────────────────────────────────────────────────────

    def _generate_ed25519(self, persist: bool) -> dict:
        private_key = ed25519.Ed25519PrivateKey.generate()
        pem = private_key.private_bytes(Encoding.PEM, PrivateFormat.PKCS8, NoEncryption()).decode()
        pub_pem = private_key.public_key().public_bytes(Encoding.PEM, PublicFormat.SubjectPublicKeyInfo).decode()
        key_type = "Ed25519"
        meta = {"algorithm": "Ed25519"}
        logger.info("KMS: generated Ed25519")
        return self._finalise(pem, "Plain", persist, meta, pub_pem, key_type)

    # ── AES ───────────────────────────────────────────────────────────────────

    def _generate_aes(self, persist: bool, key_size: int = 256, **_) -> dict:
        key_size = int(key_size)
        if key_size not in _AES_SIZES:
            raise ValueError(f"Invalid AES key_size {key_size}. Choose from {sorted(_AES_SIZES)}.")

        raw_key = os.urandom(key_size // 8)
        # Store symmetric keys as base64 in the private_key TEXT column
        b64_key = base64.b64encode(raw_key).decode()
        key_type = f"AES-{key_size}"
        meta = {"algorithm": "AES", "key_size": key_size}
        logger.info(f"KMS: generated {key_type}")
        return self._finalise_symmetric(b64_key, persist, meta, key_type)

    # ── Helpers ───────────────────────────────────────────────────────────────

    def _finalise(self, pem: str, storage_type: str, persist: bool, meta: dict,
                  public_key: str = None, key_type: str = None) -> dict:
        """Common finalisation for asymmetric keys."""
        if persist:
            with self.__db.connection():
                key_id = self.__db.insert_key(pem, storage_type, public_key, key_type)
            logger.info(f"KMS: persisted key → KeyStorage id={key_id}")
            return {**meta, "key_id": key_id, "persisted": True}
        else:
            result = {**meta, "key_material": pem, "persisted": False}
            if public_key:
                result["public_key"] = public_key
            return result

    def _finalise_symmetric(self, b64_key: str, persist: bool, meta: dict,
                            key_type: str = None) -> dict:
        """Common finalisation for symmetric keys."""
        if persist:
            with self.__db.connection():
                key_id = self.__db.insert_key(b64_key, "Plain", public_key=None, key_type=key_type)
            logger.info(f"KMS: persisted symmetric key → KeyStorage id={key_id}")
            return {**meta, "key_id": key_id, "persisted": True}
        else:
            return {**meta, "key_material": b64_key, "persisted": False}

    # ── Export ────────────────────────────────────────────────────────────────

    def export_key(self, key_id: int, password: bytes = None) -> bytes:
        """
        Export a key in PEM format, optionally encrypted with password.
        Planned for a future phase.
        """
        raise NotImplementedError("KMS.export_key is not yet implemented")
