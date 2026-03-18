import json
import os
import glob
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.x509 import (
    CertificateRevocationListBuilder,
    RevokedCertificateBuilder,
)
from datetime import datetime, timezone, timedelta

from cryptography.hazmat.primitives.asymmetric import rsa, ec

from .db import PKIDataBase
from .certificate_tools import CertificateTools
from .pki_tools import PKITools
from .key_tools import KeyTools
from .kms import KeyManagementService
from .ca import CertificationAuthority
from .ocsp_responder import OCSPResponder
from .log import logger

class PyPKI:
    def __init__(self, config_file_json:str = None):
        """Initialize the PKI Utilities class."""
        self.__config = {}
        self.__db = PKIDataBase()
        self.__kms = KeyManagementService(self.__db)
        self.__ca_active = CertificationAuthority()
        self.__cert_tool = CertificateTools()
        self.__ca_id = 0
        self.__cert_template_id = 0
        self.__ocsp_responders = []
        self.__ca_collection = []
        self.__template_collection = []

        if config_file_json:
            with open(config_file_json, "rb") as config_file:
                pki_config_json = config_file.read()
            self.load_config_json(pki_config_json)


    def load_config_json(self, config_json: str):
        self.__config = json.loads(config_json)
        self.__db.load_config(self.__config["db_config"])


    def reset_pki(self):
        with self.__db.connection():
            self.__db.create_database()

        for template_path in glob.glob(os.path.join(self.__config["template_folder"], "*.json")):
            with open(template_path, "r") as template_file:
                template_json = template_file.read()
            self.create_cert_template_from_json(template_json)

        for ca_store_path in glob.glob(os.path.join(self.__config["ca_store_folder"], "*.json")):
            with open(ca_store_path, "rb") as config_file:
                ca_config_json = config_file.read()
            self.create_ca_from_config_json(ca_config_json)

        for ocsp_path in glob.glob(os.path.join(self.__config["ocsp_responder_folder"], "*.json")):
            with open(ocsp_path, "rb") as config_file:
                ocsp_config_json = config_file.read()
            self.create_ocsp_from_config_json(ocsp_config_json)


    def get_db(self):
        return self.__db

    def get_kms(self) -> KeyManagementService:
        return self.__kms


    def create_ca_from_config_json(self, config_json: str):
        ca = CertificationAuthority()
        ca.load_config_json(config_json)
        with self.__db.connection():
            self.__db.insert_ca(ca)


    def load_ca_collection(self):
        with self.__db.connection():
            self.__ca_collection = self.__db.get_ca_collection()


    def get_ca_collection(self):
        return self.__ca_collection


    def get_ca_by_id(self, ca_id: int) -> CertificationAuthority:
        with self.__db.connection():
            ca_record = self.__db.get_ca_record_by_id(ca_id)
        return ca_record


    def select_ca_by_name(self, ca_name: str) -> CertificationAuthority:
        self.__ca_id = 0
        self.__ca_active = None
        if self.__ca_collection:
            for ca_item in self.__ca_collection:
                if ca_item.get("name") == ca_name:
                    logger.info(f"CA {ca_name} selected")
                    return self.select_ca_by_id(ca_item.get("id"))

        logger.info(f"CA {ca_name} not found!")
        return None


    def _build_ca(self, ca_id: int) -> CertificationAuthority:
        """Build and return a local CertificationAuthority for *ca_id*.

        Does NOT mutate any shared instance state, so it is safe to call
        concurrently from multiple request threads.
        """
        for ca_item in self.__ca_collection:
            if ca_item.get("id") == ca_id:
                ca = CertificationAuthority()
                ca_config = {
                    "ca_name": ca_item.get("name"),
                    "max_validity": ca_item.get("max_validity"),
                    "serial_number_length": ca_item.get("serial_number_length"),
                    "crl_validity": ca_item.get("crl_validity"),
                    "extensions": json.loads(ca_item.get("extensions", "{}")),
                    "crypto": {
                        "certificate": ca_item.get("certificate"),
                        "certificate_chain": ca_item.get("certificate_chain"),
                        "kms_key_id": ca_item.get("private_key_reference"),
                    }
                }
                ca.load_config_json(json.dumps(ca_config, indent=2))
                ca.set_kms(self.__kms)
                with self.__db.connection():
                    ca.load_serials(self.__db.fetch_used_serials())
                return ca
        return None

    def _build_cert_tool(self, template_id: int) -> CertificateTools:
        """Build and return a local CertificateTools for *template_id*.

        Does NOT mutate any shared instance state.
        """
        for template in self.__template_collection:
            if template.get("id") == template_id:
                cert_tool = CertificateTools()
                cert_tool.load_certificate_template(template.get("definition"))
                return cert_tool
        return None

    def select_ca_by_id(self, ca_id: int) -> CertificationAuthority:
        """Select a CA by ID, storing it as the active CA (single-threaded / legacy use only).

        Web-API code should call the operation methods with an explicit *ca_id*
        instead of relying on this shared selection.
        """
        logger.info(f"Select CA ID = {ca_id}")
        self.__ca_id = 0
        self.__ca_active = None
        ca = self._build_ca(ca_id)
        if ca is not None:
            self.__ca_id = ca_id
            self.__ca_active = ca
        return self.__ca_active


    def create_ocsp_from_config_json(self, config_json: str):
        ocsp_resp = OCSPResponder()
        ocsp_resp.load_config_json(config_json)
        with self.__db.connection():
            self.__db.insert_ocsp_responder(ocsp_resp)


    def load_ocsp_responders(self):
        with self.__db.connection():
            self.__ocsp_responders = self.__db.get_ocsp_responders_collection()
        for responder in self.__ocsp_responders:
            responder.set_kms(self.__kms)


    def get_ocsp_responder_by_issuer_ski(self, issuer_ski):
        for responder in self.__ocsp_responders:
            if responder.get_issuer_ski() == issuer_ski:
                return responder
        return None


    def create_cert_template_from_json(self, config_json: str):
        cert_template = json.loads(config_json)
        with self.__db.connection():
            self.__db.insert_cert_template(cert_template)


    def load_template_collection(self):
        with self.__db.connection():
            self.__template_collection = self.__db.get_template_collection()


    def get_template_collection(self):
        return self.__template_collection


    def select_cert_template_by_name(self, cert_template_name: str) -> CertificateTools:
        self.__cert_template_id = 0
        self.__cert_tool = None
        if self.__template_collection:
            for template in self.__template_collection:
                if template.get("name") == cert_template_name:
                    logger.info(f"Certificate Template {cert_template_name} selected")
                    return self.select_cert_template_by_id(template.get("id"))

        logger.info(f"Certificate Template {cert_template_name} not found!")
        return None


    def select_cert_template_by_id(self, cert_template_id: int) -> CertificateTools:
        """Select a template by ID, storing it as the active template (single-threaded / legacy use only).

        Web-API code should call the operation methods with an explicit *template_id*
        instead of relying on this shared selection.
        """
        logger.info(f"Select Template ID = {cert_template_id}")
        self.__cert_template_id = 0
        self.__cert_tool = None
        cert_tool = self._build_cert_tool(cert_template_id)
        if cert_tool is not None:
            self.__cert_template_id = cert_template_id
            self.__cert_tool = cert_tool
        return self.__cert_tool


    def generate_certificate_and_key(self,
        request_json:str,
        ca_id: int = None,
        template_id: int = None,
        use_active_ca=True,
        validity_days=PKITools.INFINITE_VALIDITY,
        key_algorithm="RSA",
        key_type="2048",
        return_certificate = True
    ):
        certificate_key = KeyTools()
        certificate_key.generate_private_key(algorithm=key_algorithm, key_type=key_type)

        # Resolve CA and template: prefer explicit IDs (thread-safe); fall back to
        # stored active selection for single-threaded utility-script callers.
        if ca_id is not None:
            issuing_ca = self._build_ca(ca_id)
            cert_tool = self._build_cert_tool(template_id)
            used_ca_id = ca_id
            used_template_id = template_id
        elif use_active_ca:
            issuing_ca = self.__ca_active
            cert_tool = self.__cert_tool
            used_ca_id = self.__ca_id
            used_template_id = self.__cert_template_id
        else:
            issuing_ca = None
            cert_tool = self.__cert_tool
            used_ca_id = None
            used_template_id = self.__cert_template_id

        new_cert_pem = cert_tool.generate_certificate_pem(
            request_json=request_json,
            issuing_ca=issuing_ca,
            certificate_key=certificate_key,
            validity_days=validity_days,
            enforce_template=True
        )

        if new_cert_pem:
            with self.__db.connection():
                new_cert_id = self.__db.insert_certificate(new_cert_pem, used_ca_id, used_template_id, private_key_reference=None)
        else:
            logger.error("Problem generating new certificate")
            return None

        if return_certificate is True:
            return new_cert_pem
        else:
            return new_cert_id


    def generate_certificate_from_csr(
            self,
            csr_pem: bytes,
            ca_id: int = None,
            template_id: int = None,
            request_json: str = None,
            use_active_ca: bool = True,
            validity_days=PKITools.INFINITE_VALIDITY,
            enforce_template: bool = False,
            return_certificate = True
        ):
        # Resolve CA and template: prefer explicit IDs (thread-safe); fall back to
        # stored active selection for single-threaded utility-script callers.
        if ca_id is not None:
            issuing_ca = self._build_ca(ca_id)
            cert_tool = self._build_cert_tool(template_id)
            used_ca_id = ca_id
            used_template_id = template_id
        elif use_active_ca:
            issuing_ca = self.__ca_active
            cert_tool = self.__cert_tool
            used_ca_id = self.__ca_id
            used_template_id = self.__cert_template_id
        else:
            issuing_ca = None
            cert_tool = self.__cert_tool
            used_ca_id = None
            used_template_id = self.__cert_template_id

        new_cert = cert_tool.generate_certificate_from_csr(
            csr_pem=csr_pem,
            request_json=request_json,
            issuing_ca=issuing_ca,
            validity_days=validity_days,
            enforce_template=enforce_template)

        if new_cert:
            new_cert_pem = new_cert.public_bytes(serialization.Encoding.PEM)
            with self.__db.connection():
                new_cert_id = self.__db.insert_certificate(new_cert_pem, used_ca_id, used_template_id, private_key_reference=None)
        else:
            logger.error("Problem generating new certificate")
            return None

        if return_certificate is True:
            return new_cert
        else:
            return new_cert_id


    def generate_certificate_pem_from_csr(
            self,
            csr_pem: bytes,
            ca_id: int = None,
            template_id: int = None,
            request_json: str = None,
            use_active_ca: bool = True,
            validity_days=PKITools.INFINITE_VALIDITY,
            enforce_template: bool = False
        ):

        new_cert = self.generate_certificate_from_csr(
            csr_pem=csr_pem,
            ca_id=ca_id,
            template_id=template_id,
            request_json=request_json,
            use_active_ca=use_active_ca,
            validity_days=validity_days,
            enforce_template=enforce_template,
            return_certificate=True
        )

        if new_cert is None:
            return None

        return new_cert.public_bytes(serialization.Encoding.PEM)


    def get_ca_certificate(self, ca_id: int = None):
        if ca_id is not None:
            ca = self._build_ca(ca_id)
            return ca.get_certificate() if ca else None
        return self.__ca_active.get_certificate()


    def get_certificate_id(self, serial_number=None, fingerprint=None, ca_id=None):
        with self.__db.connection():
            id = self.__db.get_certificate_id(serial_number=serial_number, ca_id=ca_id, fingerprint=fingerprint)
        return id


    def get_certificate_details(self, certificate_id=None, serial_number=None, fingerprint=None, ca_id=None):
        with self.__db.connection():
            cert_details = self.__db.get_certificate_record(certificate_id=certificate_id, serial_number=serial_number, ca_id=ca_id, fingerprint=fingerprint)
        return cert_details


    def get_certificate_pem(self, certificate_id=None, serial_number=None, fingerprint=None, ca_id=None):
        with self.__db.connection():
            cert_details = self.__db.get_certificate_record(certificate_id=certificate_id, serial_number=serial_number, ca_id=ca_id, fingerprint=fingerprint)

        if cert_details:
            return cert_details["certificate_data"]
        else:
            return None


    def revoke_certificate(self, certificate_id, revocation_reason):
        with self.__db.connection():
            status = self.__db.revoke_certificate(certificate_id, revocation_reason)
        return status


    def generate_crl(self, ca_id: int = None):
        # Resolve CA: prefer explicit ca_id (thread-safe); fall back to stored
        # active selection for single-threaded utility-script callers.
        if ca_id is not None:
            ca = self._build_ca(ca_id)
            used_ca_id = ca_id
        else:
            ca = self.__ca_active
            used_ca_id = self.__ca_id

        if ca is None or used_ca_id is None:
            return None

        logger.info(f"Generating CRL for {ca.get_config()['ca_name']}")

        crl_builder = CertificateRevocationListBuilder()
        crl_builder = crl_builder.issuer_name(ca.get_certificate().subject)
        crl_builder = crl_builder.last_update(datetime.now(timezone.utc))
        crl_builder = crl_builder.next_update(datetime.now(timezone.utc) + timedelta(days=ca.get_config()["crl_validity"]))

        with self.__db.connection():
            revoked_certificates = self.__db.get_revoked_certificates(used_ca_id)

        for serial_number, revocation_time, reason_code in revoked_certificates:
            try:
                reason_enum = PKITools.REVOCATION_REASON_MAPPING.get(reason_code, x509.ReasonFlags.unspecified)
            except ValueError:
                raise ValueError(f"Invalid revocation reason: {reason_code}")
            revoked_cert = RevokedCertificateBuilder().serial_number(serial_number).revocation_date(revocation_time)
            if reason_code != 0:
                revoked_cert = revoked_cert.add_extension(x509.CRLReason(x509.ReasonFlags(reason_enum)), critical=False)
            revoked_cert = revoked_cert.build()
            crl_builder = crl_builder.add_revoked_certificate(revoked_cert)

        # Sign with a dummy key matching the CA's algorithm so the
        # signatureAlgorithm field in the TBS bytes is correct.
        ca_pub_key = ca.get_certificate().public_key()
        if isinstance(ca_pub_key, ec.EllipticCurvePublicKey):
            dummy_key = ec.generate_private_key(ca_pub_key.curve)
            is_ecdsa = True
        else:
            dummy_key = rsa.generate_private_key(
                public_exponent=65537,
                key_size=ca_pub_key.key_size
            )
            is_ecdsa = False

        pre_crl = crl_builder.sign(private_key=dummy_key, algorithm=hashes.SHA256())

        digest = hashes.Hash(hashes.SHA256())
        digest.update(pre_crl.tbs_certlist_bytes)
        tbs_digest = digest.finalize()

        real_signature = ca.sign_tbs_digest(tbs_digest)

        final_der = CertificateTools().patch_crl_signature(
            pre_crl_der=pre_crl.public_bytes(serialization.Encoding.DER),
            real_signature=real_signature,
            is_ecdsa=is_ecdsa
        )
        crl = x509.load_der_x509_crl(final_der)

        crl_pem = crl.public_bytes(serialization.Encoding.PEM).decode("utf-8")
        with self.__db.connection():
            self.__db.upsert_crl(
                ca_id=used_ca_id,
                crl_pem=crl_pem,
                issue_date=crl.last_update_utc.replace(tzinfo=None),
                next_update=crl.next_update_utc.replace(tzinfo=None)
            )

        return crl
