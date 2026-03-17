import json
import secrets
from cryptography import x509
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.serialization import load_pem_private_key

from .key_tools import KeyTools


class CertificationAuthority:
    def __init__(self):
        """Initialize the CertificationAuthority class."""
        self.__config = {}
        self.__kms = None
        self.__kms_key_id = None
        self.__local_key: KeyTools = None   # direct key when KMS is not used
        self.__certificate: x509.Certificate = b""
        self.__certificate_chain_pem: str = ""
        self.__issued_serials = set()


    def load_config_json(self, ca_config_json: str):
        """
        Load CA configuration from a JSON string.

        Accepts two config shapes:
        - KMS path (runtime, after Phase 1 migration): crypto.kms_key_id is set.
          Signing goes through the injected KeyManagementService.
        - Direct path (offline / initial setup): crypto.private_key or
          crypto.token_key_id is present. The key is loaded into a local KeyTools
          instance so signing works without a database or KMS.
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
        if self.__kms_key_id is None:
            if crypto.get("private_key"):
                kt = KeyTools()
                kt.set_private_key(
                    load_pem_private_key(crypto["private_key"].encode("utf-8"), password=None)
                )
                self.__local_key = kt
            elif crypto.get("token_key_id"):
                self.__local_key = KeyTools(
                    private_key=None,
                    key_id=crypto.get("token_key_id"),
                    slot_num=crypto.get("token_slot"),
                    token_password=crypto.get("token_password") or ""
                )


    def set_kms(self, kms) -> None:
        """Inject the KeyManagementService instance used for signing operations."""
        self.__kms = kms


    def sign_tbs_digest(self, tbs_digest: bytes) -> bytes:
        """
        Sign a pre-computed SHA-256 digest.

        Priority:
          1. KMS (when set_kms() has been called and kms_key_id is configured).
          2. Local KeyTools (when a private_key or token_key_id was in the config).
        """
        if self.__kms is not None and self.__kms_key_id is not None:
            return self.__kms.sign_digest(self.__kms_key_id, tbs_digest)

        if self.__local_key is not None:
            return self.__local_key.sign_digest(tbs_digest)

        raise RuntimeError(
            f"No signing method available for CA '{self.__config.get('ca_name')}'. "
            "Either provide private_key in the config or call set_kms() with a valid kms_key_id."
        )


    def load_serials(self, initial_serials: set):
        if not isinstance(initial_serials, set):
            raise TypeError("initial_serials must be a set")
        self.__issued_serials.update(initial_serials)


    def generate_unique_serial(self):
        while True:
            serial = int.from_bytes(
                secrets.token_bytes(self.__config["serial_number_length"]), "big"
            )
            if serial not in self.__issued_serials:
                self.__issued_serials.add(serial)
                return serial


    def get_certificate(self) -> x509.Certificate:
        return self.__certificate


    def get_certificate_chain_pem(self) -> str:
        return self.__certificate_chain_pem


    def get_serial(self) -> bytes:
        return x509.random_serial_number()


    def get_config(self) -> dict:
        return self.__config
