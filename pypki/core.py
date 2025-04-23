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

from .db import PKIDataBase
from .certificate_tools import CertificateTools
from .pki_tools import PKITools
from .key_tools import KeyTools
from .ca import CertificationAuthority
from .ocsp_responder import OCSPResponder
from .log import logger

class PyPKI:
    def __init__(self, config_file_json:str = None):
        """Initialize the PKI Utilities class."""
        self.__config = {}
        self.__db = PKIDataBase()
        self.__ca_active = CertificationAuthority()
        self.__cert_tool = CertificateTools()
        self.__ca_id = 0
        self.__cert_template_id = 0
        self.__ocsp_responders = []

        if config_file_json:
            with open(config_file_json, "rb") as config_file:
                pki_config_json = config_file.read()  # Read bytes from file
            self.load_config_json(pki_config_json)
        pass


    def load_config_json(self, config_json: str):
        self.__config = json.loads(config_json)
        # Load DB config
        self.__db.load_config(self.__config["db_config"])
        pass


    def reset_pki(self):
        self.__db.connect_to_db()
        self.__db.create_database()

        # Iterate over all JSON files in the folder
        for template_path in glob.glob(os.path.join(self.__config["template_folder"], "*.json")):
            with open(template_path, "r") as template_file:
                template_json = template_file.read()
            self.create_cert_template_from_json(template_json)

        # Load existing CAs config from files
        for ca_store_path in glob.glob(os.path.join(self.__config["ca_store_folder"], "*.json")):
            with open(ca_store_path, "rb") as config_file:
                ca_config_json = config_file.read()  # Read bytes from file
            self.create_ca_from_config_json(ca_config_json)

        # Load existing OCSP Responder config from files
        for ocsp_path in glob.glob(os.path.join(self.__config["ocsp_responder_folder"], "*.json")):
            with open(ocsp_path, "rb") as config_file:
                ocsp_config_json = config_file.read()  # Read bytes from file
            self.create_ocsp_from_config_json(ocsp_config_json)

        self.__db.close_db()
        pass


    def get_db(self):
        return self.__db


    def create_ca_from_config_json(self, config_json: str):
        ca = CertificationAuthority()
        # Load existing CA config from file
        ca.load_config_json(config_json)
        self.__db.connect_to_db()
        self.__db.insert_ca(ca)
        self.__db.close_db()
        pass


    def select_ca_by_name(self, ca_name: str) -> CertificationAuthority:
        self.__db.connect_to_db()
        ca_id = self.__db.get_ca_id_by_name(ca_name)
        self.__ca_active = None
        if ca_id:
            self.__ca_id = ca_id
            self.__ca_active = self.select_ca_by_id(ca_id)
            logger.info(f"CA {ca_name} selected")
        else:
            self.__ca_id = 0
            logger.info(f"CA {ca_name} not found!")
        self.__db.close_db()
        return self.__ca_active


    def select_ca_by_id(self, ca_id: int) -> CertificationAuthority:
        # Load CA config from DB
        logger.info(f"Select CA ID = {ca_id}")
        self.__db.connect_to_db()
        ca_record = self.__db.get_ca_record_by_id(ca_id)
        self.__ca_active = None
        if ca_record:
            self.__ca_id = ca_id
            self.__ca_active = CertificationAuthority()
            # Build config JSON string
            ca_config = {
                "ca_name": ca_record.get("name"),
                "max_validity": ca_record.get("max_validity"),
                "serial_number_length": ca_record.get("serial_number_length"),
                "crl_validity": ca_record.get("crl_validity"),
                #"extensions": ca_record.get("extensions"),
                "extensions": json.loads(ca_record.get("extensions", "{}")),  # FIXED
                "crypto": {
                    "certificate": ca_record.get("certificate"),
                    "private_key": ca_record.get("private_key"),
                    "certificate_chain": ca_record.get("certificate_chain"),
                    "token_slot": ca_record.get("token_slot"),
                    "token_key_id": ca_record.get("token_key_id"),
                    "token_password": ca_record.get("token_password")
                }
            }
            ca_config_json = json.dumps(ca_config, indent=2)
            self.__ca_active.load_config_json(ca_config_json)
            self.__ca_active.load_serials(self.__db.fetch_used_serials())
        else:
            self.__ca_id = 0

        self.__db.close_db()
        return self.__ca_active


    def get_ca_collection(self):
        self.__db.connect_to_db()
        ca_collection = self.__db.get_ca_collection()
        self.__db.close_db()
        return ca_collection


    def get_ca_by_id(self, ca_id: int) -> CertificationAuthority:
        # Get CA config from DB
        self.__db.connect_to_db()
        ca_record = self.__db.get_ca_record_by_id(ca_id)
        self.__db.close_db()
        return ca_record


    def create_ocsp_from_config_json(self, config_json: str):
        ocsp_resp = OCSPResponder()
        # Load existing CA config from file
        ocsp_resp.load_config_json(config_json)
        self.__db.connect_to_db()
        self.__db.insert_ocsp_responder(ocsp_resp)
        self.__db.close_db()
        pass


    def load_ocsp_responders(self):
        self.__db.connect_to_db()
        self.__ocsp_responders = self.__db.get_ocsp_responders_collection()
        self.__db.close_db()
        pass

    def get_ocsp_responder_by_issuer_ski(self, issuer_ski):
        for responder in self.__ocsp_responders:
            if responder.get_issuer_ski() == issuer_ski:
                return responder
        return None

    def create_cert_template_from_json(self, config_json: str):
        # Load existing CA config from file
        cert_template = json.loads(config_json)
        self.__db.connect_to_db()
        self.__db.insert_cert_template(cert_template)
        self.__db.close_db()
        pass


    def select_cert_template_by_name(self, cert_template_name: str) -> CertificateTools:
        self.__db.connect_to_db()
        cert_template_id = self.__db.get_cert_template_id_by_name(cert_template_name)
        self.__cert_tool = None
        if cert_template_id:
            self.__cert_template_id = cert_template_id
            self.__cert_tool = self.select_cert_template_by_id(cert_template_id)
            logger.info(f"Certificate Template {cert_template_name} selected")
        else:
            self.__cert_type_id = 0
            logger.info(f"Certificate Template {cert_template_name} not found!")
        self.__db.close_db()
        return self.__cert_tool


    def select_cert_template_by_id(self, cert_template_id: int) -> CertificateTools:
        logger.info(f"Select Template ID = {cert_template_id}")
        self.__db.connect_to_db()
        cert_template_record = self.__db.get_cert_template_record_by_id(cert_template_id)
        self.__cert_tool = None
        if cert_template_record:
            self.__cert_template_id = cert_template_id
            self.__cert_tool = CertificateTools()
            cert_template_json = cert_template_record.get("definition")
            self.__cert_tool.load_certificate_template(cert_template_json)
        else:
            self.__cert_type_id = 0

        return self.__cert_tool


    def generate_certificate_and_key(self, 
        request_json:str, 
        use_active_ca=True, 
        validity_days=PKITools.INFINITE_VALIDITY,
        key_algorithm="RSA",
        key_type="2048",
        return_certificate = True
    ):
        certificate_key = KeyTools()
        certificate_key.generate_private_key(algorithm=key_algorithm, key_type=key_type)

        if use_active_ca:
            ca_id = self.__ca_id
            new_cert_pem = self.__cert_tool.generate_certificate_pem(
                request_json=request_json,
                issuing_ca=self.__ca_active,
                certificate_key=certificate_key,
                validity_days=validity_days,
                enforce_template=True
            )
        else:
            ca_id = None
            new_cert_pem = self.__cert_tool.generate_certificate_pem(
                request_json=request_json,
                issuing_ca=None,
                certificate_key=certificate_key,
                validity_days=validity_days,
                enforce_template=True
            )
        
        if new_cert_pem:
            self.__db.connect_to_db()
            new_cert_id = self.__db.insert_certificate(new_cert_pem, ca_id, self.__cert_template_id, private_key_reference = None)
            self.__db.close_db()
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
            request_json: str = None,
            use_active_ca: bool = True,
            validity_days=PKITools.INFINITE_VALIDITY,
            enforce_template: bool = False,
            return_certificate = True
        ):

        if use_active_ca:
            ca_id = self.__ca_id
            new_cert = self.__cert_tool.generate_certificate_from_csr(
                csr_pem=csr_pem, 
                request_json=request_json,
                issuing_ca=self.__ca_active, 
                validity_days=validity_days,
                enforce_template=enforce_template)
        else:
            ca_id = None
            new_cert = self.__cert_tool.generate_certificate_from_csr(
                csr_pem=csr_pem, 
                request_json=request_json,
                issuing_ca=None, 
                validity_days=validity_days,
                enforce_template=enforce_template)
        
        if new_cert:
            new_cert_pem = new_cert.public_bytes(serialization.Encoding.PEM)
            self.__db.connect_to_db()
            new_cert_id = self.__db.insert_certificate(new_cert_pem, ca_id, self.__cert_template_id, private_key_reference = None)
            self.__db.close_db()
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
            request_json: str = None,
            use_active_ca: bool = True,
            validity_days=PKITools.INFINITE_VALIDITY,
            enforce_template: bool = False,
            return_certificate = True
        ):

        new_cert = self.generate_certificate_from_csr(
            csr_pem=csr_pem,
            request_json=request_json,
            use_active_ca=use_active_ca,
            validity_days=validity_days,
            enforce_template=enforce_template,
            return_certificate=return_certificate
        )

        return new_cert.public_bytes(serialization.Encoding.PEM)


    def get_ca_certificate(self):
        return self.__ca_active.get_certificate()


    def get_certificate_id(self, serial_number=None, fingerprint=None):
        self.__db.connect_to_db()
        id = self.__db.get_certificate_id(serial_number=serial_number, ca_id=self.__ca_id, fingerprint=fingerprint)
        self.__db.close_db()
        return id


    def get_certificate_details(self, certificate_id=None, serial_number=None, fingerprint=None):
        self.__db.connect_to_db()
        cert_details = self.__db.get_certificate_record(certificate_id=certificate_id, serial_number=serial_number, ca_id=self.__ca_id, fingerprint=fingerprint)
        self.__db.close_db()
        return cert_details

    def get_certificate_pem(self, certificate_id=None, serial_number=None, fingerprint=None):
        self.__db.connect_to_db()
        cert_details = self.__db.get_certificate_record(certificate_id=certificate_id, serial_number=serial_number, ca_id=self.__ca_id, fingerprint=fingerprint)
        self.__db.close_db()

        if cert_details:
            return cert_details["certificate_data"]
        else:
            return None

    def revoke_certificate(self, certificate_id, revocation_reason):
        self.__db.connect_to_db()
        status = self.__db.revoke_certificate(certificate_id, revocation_reason)
        self.__db.close_db()

        return status

    def generate_crl(self):
        """
        Generates a Certificate Revocation List (CRL) for a given CA, including revoked certificates.

        Parameters:
            ca_private_key: The private key of the Certificate Authority (CA).
            ca_certificate: The CA's certificate (used for signing the CRL).
            revoked_certificates: List of tuples [(serial_number, revocation_time, reason_code), ...]
            
        Returns:
            The signed CRL.
        """
        
        logger.info(f"Generating CRL for {self.__ca_active.get_config()['ca_name']}")

        if self.__ca_id == None:
            return None

        # Prepare the CRL builder
        crl_builder = CertificateRevocationListBuilder()

        # Set the issuer of the CRL (which is the CA's subject name)
        crl_builder = crl_builder.issuer_name(self.__ca_active.get_certificate().subject)

        # Set the last update time (current time)
        crl_builder = crl_builder.last_update(datetime.now(timezone.utc))

        # Set the next update time (set it as 1 month from now, for example)
#        crl_builder = crl_builder.next_update(datetime.now(timezone.utc).replace(year=datetime.now(timezone.utc).year + 1))
        crl_builder = crl_builder.next_update(datetime.now(timezone.utc) + timedelta(days=self.__ca_active.get_config()["crl_validity"]))

        # Revoked certificate information: (serial_number, revocation_time, reason_code)
        self.__db.connect_to_db()
        revoked_certificates = self.__db.get_revoked_certificates(self.__ca_id)
        self.__db.close_db()

        # Add revoked certificates to the CRL
        for serial_number, revocation_time, reason_code in revoked_certificates:
            try:
                reason_enum = PKITools.REVOCATION_REASON_MAPPING.get(reason_code, x509.ReasonFlags.unspecified) #x509.ReasonFlags(reason_code)  # ✅ Convert integer to ReasonFlags enum
            except ValueError:
                raise ValueError(f"Invalid revocation reason: {reason_code}")  # Handle invalid codes gracefully
            revoked_cert = RevokedCertificateBuilder().serial_number(serial_number).revocation_date(revocation_time)
            if reason_code != 0:
                revoked_cert = revoked_cert.add_extension(x509.CRLReason(x509.ReasonFlags(reason_enum)), critical=False)
            revoked_cert = revoked_cert.build()
            crl_builder = crl_builder.add_revoked_certificate(revoked_cert)

        # Sign the CRL with the CA's private key
        crl = crl_builder.sign(private_key=self.__ca_active.get_private_key(), algorithm=hashes.SHA256())

        return crl
