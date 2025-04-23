import json
from datetime import datetime, timedelta, timezone
from cryptography.hazmat.primitives import serialization
from cryptography.x509.ocsp import OCSPResponseBuilder, OCSPResponderEncoding
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization

class OCSPResponder:
    def __init__(self, name:str = "UNASIGNED", issuer_ski:str = "", issuer_certificate:str = "", response_validity:int = 1, certificate_pem:str = "", private_key_pem:str = ""):
        """Initialize the PKI Utilities class."""
        from .key_tools import KeyTools
        self.__config = {}
        self.__name = name
        self.__ca_id = None
        self.__issuer_ski = issuer_ski
        if issuer_certificate == "":
            self.__issuer_certificate: x509.Certificate = b""
        else:
            self.__issuer_certificate = x509.load_pem_x509_certificate(issuer_certificate.encode("utf-8"))
        self.__response_validity = response_validity
        self.__signing_key: KeyTools = KeyTools()
        if private_key_pem != "":
            self.__signing_key.set_private_key(serialization.load_pem_private_key(private_key_pem.encode("utf-8"), password=None))
        if certificate_pem == "":
            self.__certificate: x509.Certificate = b""
        else:
            self.__certificate = x509.load_pem_x509_certificate(certificate_pem.encode("utf-8"))


    def load_config_json(self, ocsp_config_json: str):
        from .key_tools import KeyTools

        self.__config = json.loads(ocsp_config_json)
        # Get general details
        self.__name  = self.__config["name"]
        self.__issuer_ski = self.__config["issuer_ski"]
        if self.__config["issuer_certificate"] is not "":
            self.__issuer_certificate = x509.load_pem_x509_certificate(self.__config["issuer_certificate"].encode("utf-8"))
        self.__response_validity = self.__config["response_validity"]
        # Get private key and certificate
        if self.__config["crypto"]["token_key_id"] == "":
            # key is software
            self.__signing_key.set_private_key(serialization.load_pem_private_key(self.__config["crypto"]["private_key"].encode("utf-8"), password=None))
        else:
            self.__signing_key = KeyTools(
                private_key =  None,
                key_id = self.__config["crypto"]["token_key_id"],
                slot_num = self.__config["crypto"]["token_slot"],
                token_password = self.__config["crypto"]["token_password"]
            )

        self.__certificate = x509.load_pem_x509_certificate(self.__config["crypto"]["certificate"].encode("utf-8"))
        pass


    def get_issuer_ski(self):
        """Returns the issuer in a controlled manner."""
        return self.__issuer_ski
    

    def get_signing_key(self):
        """Returns the private key in a controlled manner."""
        return self.__signing_key
    

    def get_private_key(self):
        """Returns the private key in a controlled manner."""
        return self.__signing_key.get_private_key()
    

    def export_private_key(self, password: bytes = None):
        """
        Securely exports the private key in PEM format.
        If a password is provided, the key is encrypted.
        """
        encryption_algorithm = (
            serialization.BestAvailableEncryption(password)
            if password else serialization.NoEncryption()
        )
        
        return self.__signing_key.get_private_key()(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=encryption_algorithm
        )
    
    def get_certificate(self) -> x509.Certificate:
        """Public method to retrieve the stored certificate."""
        return self.__certificate
    
    
    def get_config(self) -> dict:
        return self.__config
    

    def generate_response(self, cert_to_check, cert_status, revocation_time, revocation_reason):
                # Generate reply
        builder = OCSPResponseBuilder()
        
        builder = builder.add_response(
            cert=cert_to_check,
            issuer=self.__issuer_certificate,
            algorithm=hashes.SHA1(),  # match the hash algorithm used in request
            cert_status=cert_status,
            this_update=datetime.now(timezone.utc),
            next_update=datetime.now(timezone.utc) + timedelta(days=1),
            revocation_time=revocation_time,
            revocation_reason=revocation_reason,
        )

        builder = builder.responder_id(encoding=OCSPResponderEncoding.HASH, responder_cert=self.__certificate)
        
        return builder.sign(private_key=self.get_private_key(), algorithm=hashes.SHA256())


