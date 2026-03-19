import json
from datetime import datetime, timedelta, timezone

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa, ec
from cryptography.hazmat.primitives.asymmetric.utils import encode_dss_signature, decode_dss_signature
from cryptography.x509.ocsp import OCSPResponseBuilder, OCSPResponderEncoding
from cryptography import x509

from asn1crypto import ocsp as asn1_ocsp
from asn1crypto.core import OctetBitString

from .log import logger


def _patch_ocsp_signature(
    pre_response_der: bytes,
    real_signature: bytes,
    is_ecdsa: bool = False
) -> bytes:
    """
    Replace the dummy signature in a DER-encoded OCSPResponse with the real one.

    The OCSPResponse wraps a BasicOCSPResponse inside a ResponseBytes.response
    OctetString. We parse the outer structure, parse the inner BasicOCSPResponse,
    replace its signature field, re-encode, and reassemble.
    """
    outer = asn1_ocsp.OCSPResponse.load(pre_response_der)
    inner_bytes = bytes(outer['response_bytes']['response'])
    basic = asn1_ocsp.BasicOCSPResponse.load(inner_bytes)

    if is_ecdsa:
        r, s = decode_dss_signature(real_signature)
        der_sig = encode_dss_signature(r, s)
    else:
        der_sig = real_signature

    basic['signature'] = OctetBitString(der_sig)
    outer['response_bytes']['response'] = basic.dump()

    return outer.dump()


class OCSPResponder:
    def __init__(
        self,
        name: str = "UNASSIGNED",
        issuer_ski: str = "",
        issuer_certificate: str = "",
        response_validity: int = 1,
        certificate_pem: str = "",
        kms_key_id: int = None,
        ca_id: int = None
    ):
        """
        Initialise an OCSPResponder.

        kms_key_id: the KeyStorage.id of the responder's signing key.
                    Set by db.get_ocsp_responders_collection() from private_key_reference.
        ca_id: the CertificationAuthorities.id of the issuing CA this responder serves.
               Used to scope certificate status queries to the correct CA.
        """
        self.__config = {}
        self.__name = name
        self.__issuer_ski = issuer_ski
        self.__response_validity = response_validity
        self.__kms = None
        self.__kms_key_id = kms_key_id
        self.__ca_id = ca_id

        if issuer_certificate:
            self.__issuer_certificate = x509.load_pem_x509_certificate(
                issuer_certificate.encode("utf-8")
            )
        else:
            self.__issuer_certificate = b""

        if certificate_pem:
            self.__certificate = x509.load_pem_x509_certificate(
                certificate_pem.encode("utf-8")
            )
        else:
            self.__certificate = b""


    def load_config_json(self, ocsp_config_json: str):
        self.__config = json.loads(ocsp_config_json)
        self.__name = self.__config["name"]
        self.__issuer_ski = self.__config["issuer_ski"]
        self.__response_validity = self.__config["response_validity"]

        if self.__config.get("issuer_certificate"):
            self.__issuer_certificate = x509.load_pem_x509_certificate(
                self.__config["issuer_certificate"].encode("utf-8")
            )

        if self.__config["crypto"].get("certificate"):
            self.__certificate = x509.load_pem_x509_certificate(
                self.__config["crypto"]["certificate"].encode("utf-8")
            )

        # KMS key ID comes from private_key_reference (KeyStorage.id) after Phase 1 migration.
        # During initial setup from config files this is not yet set.
        self.__kms_key_id = self.__config["crypto"].get("kms_key_id")


    def set_kms(self, kms) -> None:
        """Inject the KeyManagementService instance used for signing."""
        self.__kms = kms


    def set_kms_key_id(self, key_id: int) -> None:
        self.__kms_key_id = key_id


    def get_issuer_ski(self):
        return self.__issuer_ski

    def get_ca_id(self) -> int:
        return self.__ca_id

    def get_certificate(self) -> x509.Certificate:
        return self.__certificate


    def get_config(self) -> dict:
        return self.__config


    def generate_response(self, cert_to_check, cert_status, revocation_time, revocation_reason):
        """
        Build and sign an OCSP response via the KMS.

        Because OCSPResponseBuilder.sign() requires a private key object directly,
        we use the dummy-key + patch approach:
          1. Build the response and sign with a throw-away key of the same algorithm
             as the responder certificate, so the signatureAlgorithm field is correct.
          2. Extract tbs_response_bytes, hash with SHA-256.
          3. Send the digest to the KMS for signing.
          4. Patch the signature field in the DER-encoded BasicOCSPResponse.
        """
        if self.__kms is None:
            raise RuntimeError(
                f"KMS not set on OCSPResponder '{self.__name}'. "
                "Call set_kms() before generating responses."
            )
        if self.__kms_key_id is None:
            raise RuntimeError(
                f"No KMS key ID for OCSPResponder '{self.__name}'. "
                "Run the Phase 1 migration (migrate_keys_to_kms.py) first."
            )

        builder = OCSPResponseBuilder()
        builder = builder.add_response(
            cert=cert_to_check,
            issuer=self.__issuer_certificate,
            algorithm=hashes.SHA1(),
            cert_status=cert_status,
            this_update=datetime.now(timezone.utc),
            next_update=datetime.now(timezone.utc) + timedelta(days=self.__response_validity),
            revocation_time=revocation_time,
            revocation_reason=revocation_reason,
        )
        builder = builder.responder_id(
            encoding=OCSPResponderEncoding.HASH,
            responder_cert=self.__certificate
        )

        # Generate a dummy key matching the responder certificate's algorithm
        # so the signatureAlgorithm field in the TBS is correct.
        responder_pub_key = self.__certificate.public_key()
        if isinstance(responder_pub_key, ec.EllipticCurvePublicKey):
            dummy_key = ec.generate_private_key(responder_pub_key.curve)
            is_ecdsa = True
        else:
            dummy_key = rsa.generate_private_key(
                public_exponent=65537,
                key_size=responder_pub_key.key_size
            )
            is_ecdsa = False

        pre_response = builder.sign(private_key=dummy_key, algorithm=hashes.SHA256())

        # Hash the TBS bytes and sign via KMS
        digest = hashes.Hash(hashes.SHA256())
        digest.update(pre_response.tbs_response_bytes)
        tbs_digest = digest.finalize()

        real_signature = self.__kms.sign_digest(self.__kms_key_id, tbs_digest)

        # Patch the signature in the DER and return a proper OCSPResponse
        patched_der = _patch_ocsp_signature(
            pre_response_der=pre_response.public_bytes(serialization.Encoding.DER),
            real_signature=real_signature,
            is_ecdsa=is_ecdsa
        )
        from cryptography.x509.ocsp import load_der_ocsp_response
        return load_der_ocsp_response(patched_der)
