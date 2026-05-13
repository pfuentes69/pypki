import json
import secrets
from cryptography import x509
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.serialization import load_pem_private_key

from .key_tools import KeyTools
from . import signing_algorithm as _sa


class CertificationAuthority:
    def __init__(self):
        """Initialize the CertificationAuthority class."""
        self.__config = {}
        self.__kms = None
        self.__kms_key_id = None
        self.__local_key: KeyTools = None   # direct key when KMS is not used
        self.__certificate: x509.Certificate = b""
        self.__certificate_chain_pem: str = ""
        self.__signing_algorithm: str = None


    def load_config_json(self, ca_config_json: str):
        """
        Load CA configuration from a JSON string.

        Accepts two config shapes:
        - KMS path (runtime, after Phase 1 migration): crypto.kms_key_id is set.
          Signing goes through the injected KeyManagementService.
        - Direct path (offline / initial setup): crypto.private_key (PEM) is
          present. The key is loaded into a local KeyTools instance so
          signing works without a database or KMS.
        """
        self.__config = json.loads(ca_config_json)
        crypto = self.__config["crypto"]

        self.__kms_key_id = crypto.get("kms_key_id")

        self.__certificate = x509.load_pem_x509_certificate(
            crypto["certificate"].encode("utf-8")
        )
        chain = crypto.get("certificate_chain") or ""
        self.__certificate_chain_pem = chain.encode("utf-8") if chain else b""

        # Build a local KeyTools for direct signing when no KMS key ID is configured.
        self.__local_key = None
        if self.__kms_key_id is None and crypto.get("private_key"):
            kt = KeyTools()
            kt.set_private_key(
                load_pem_private_key(crypto["private_key"].encode("utf-8"), password=None)
            )
            self.__local_key = kt

        # CR-0003: pick up the per-CA signing algorithm. Required by the
        # API layer at creation time; for offline / utility-script callers
        # without a runtime DB we derive a reasonable default from the
        # cert's signatureAlgorithm OID so direct config loading still
        # works.
        self.__signing_algorithm = self.__config.get("signing_algorithm")
        if not self.__signing_algorithm:
            try:
                self.__signing_algorithm = _sa.token_from_certificate(self.__certificate)
            except _sa.UnknownSigningAlgorithm:
                self.__signing_algorithm = _sa.default_token_for_public_key(
                    self.__certificate.public_key()
                )


    def set_kms(self, kms) -> None:
        """Inject the KeyManagementService instance used for signing operations."""
        self.__kms = kms


    def get_signing_algorithm(self) -> str:
        """Return the CR-0003 `signing_algorithm` token bound to this CA."""
        return self.__signing_algorithm


    def sign_tbs_digest(self, tbs_digest: bytes) -> bytes:
        """
        Sign a pre-computed digest under the CA's `signing_algorithm`
        (CR-0003).

        The digest's hash function must match the CA's `signing_algorithm`
        — callers are expected to use ``signing_algorithm.hash_for_token``
        when building both the TBS bytes and the digest, so the embedded
        ``signatureAlgorithm`` OID and the hash agree.

        Priority:
          1. KMS (when set_kms() has been called and kms_key_id is configured).
          2. Local KeyTools (when a private_key was supplied in the config).
        """
        if self.__kms is not None and self.__kms_key_id is not None:
            return self.__kms.sign_digest(
                self.__kms_key_id, tbs_digest,
                signing_algorithm=self.__signing_algorithm,
            )

        if self.__local_key is not None:
            return self.__local_key.sign_digest(
                tbs_digest, signing_algorithm=self.__signing_algorithm
            )

        raise RuntimeError(
            f"No signing method available for CA '{self.__config.get('ca_name')}'. "
            "Either provide private_key in the config or call set_kms() with a valid kms_key_id."
        )


    def generate_unique_serial(self):
        return int.from_bytes(
            secrets.token_bytes(self.__config["serial_number_length"]), "big"
        )


    def get_certificate(self) -> x509.Certificate:
        return self.__certificate


    def get_certificate_chain_pem(self) -> str:
        return self.__certificate_chain_pem


    def get_serial(self) -> bytes:
        return x509.random_serial_number()


    def get_config(self) -> dict:
        return self.__config
