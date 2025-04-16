from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric import rsa, ec, padding
from cryptography.hazmat.primitives.asymmetric.utils import Prehashed
import PyKCS11
from .pkcs11_helper import PKCS11Helper


#
# Key Tools Class
#
class KeyTools:
    def __init__(
        self,
        private_key: bytes = None,
        key_id: str = None,
        slot_num: int = None,
        token_password: str = ""
    ):
        self.__private_key: bytes = private_key
        self.__public_key: bytes = None
        if key_id is not None:
            self.__key_id: str = key_id
            self.__slot_num: int = slot_num
            self.__token_password: str = token_password
            self.__pkcs11 = PKCS11Helper()
            self.__pkcs11.open_session(token_password)
            self.__token_key = self.__pkcs11.get_key_by_id(key_id)
        else:
            self.__key_id = None
        pass

    def has_private_key(self):
        if self.private_key is None:
            return False
        else:
            return True

    def is_hsm(self):
        return self.__key_id is not None

    def generate_private_key(self, algorithm: str, key_type: str) -> bytes:
        """
        Generate a private key in PEM format.
        :param algorithm: "RSA" or "ECDSA"
        :param key_type: For RSA (2048, 3072, 4096), for ECDSA (P-256, P-384, P-521)
        :return: Private key in PEM format
        """
        if algorithm == "RSA":
            key_size = int(key_type)
            if key_size not in [2048, 3072, 4096]:
                raise ValueError("Invalid RSA key size")
            private_key: rsa.RSAPrivateKey = rsa.generate_private_key(
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
            private_key: ec.EllipticCurvePrivateKey = ec.generate_private_key(curve_mapping[key_type], backend=default_backend())

        else:
            raise ValueError("Unsupported algorithm")

        self.__private_key = private_key
        self.__public_key = self.__private_key.public_key()

        return self.__private_key


    def get_private_key(self):
        """Returns the private key in a controlled manner."""
        if self.__private_key:
            return self.__private_key
        else:
            return None
        

    def set_private_key(self, private_key: bytes):
        self.__private_key = private_key
        self.__public_key = self.__private_key.public_key()
        pass


    def set_public_key(self, public_key: bytes):
        """
            This is to support the special case were the object is only used to store a public key
        """
        self.__public_key = public_key
        pass


    def get_public_key(self):
        """Returns the public key in a controlled manner."""
        return self.__public_key
        

    def get_private_key_pem(self, password: bytes = None):
        """
        Securely exports the private key in PEM format.
        If a password is provided, the key is encrypted.
        """
        if self.__private_key:
            encryption_algorithm = (
                serialization.BestAvailableEncryption(password)
                if password else serialization.NoEncryption()
            )
            
            return self.__private_key.private_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PrivateFormat.PKCS8,
                encryption_algorithm=encryption_algorithm
            )
        else:
            return None


    def get_public_key_pem(self):
        """Returns the public key in a controlled manner."""
        if self.__private_key:
            return self.__private_key.public_key().public_bytes(encoding=serialization.Encoding.PEM, format=serialization.PublicFormat.SubjectPublicKeyInfo)
        else:
            return None


    def sign_digest(
        self, 
        tbs_digest: bytes
    ):
        
        #tbs_digest = b'\xcf\xcbS\xdb\x8a\xeeK\x8fP0\x96A^*9%\x93\xe6\x97\x83Q2\xd2\x95\x1cJ#\xf4\xa3k\xf0M'
        
        if not self.is_hsm():
            # Software key
            if isinstance(self.__private_key, rsa.RSAPrivateKey):
                # RSA: PKCS#1 v1.5 with SHA-256
                signature = self.__private_key.sign(
                    tbs_digest,
                    padding.PKCS1v15(),
                    Prehashed(hashes.SHA256())
                )
            elif isinstance(self.__private_key, ec.EllipticCurvePrivateKey):
                # ECC: ECDSA with SHA-256
                signature = self.__private_key.sign(
                    tbs_digest,
                    ec.ECDSA(Prehashed(hashes.SHA256()))
                )
            else:
                raise ValueError("Unsupported key type: {}".format(type(self.__private_key)))
        else:
            # Hardware key
            #mechanism = PyKCS11.Mechanism(PyKCS11.CKM_SHA256_RSA_PKCS, None)
            mechanism = PyKCS11.Mechanism(PyKCS11.CKM_RSA_PKCS, None)
            #mechanism = PyKCS11.Mechanism(PyKCS11.CKM_SHA256_RSA_PKCS_PSS, None)
            #mechanism = PyKCS11.Mechanism(PyKCS11.CKM_RSA_PKCS_OAEP, None)
            #mechanism = PyKCS11.Mechanism(PyKCS11.CKM_RSA_PKCS_PSS, None)
            signature = bytes(self.__pkcs11.get_session().sign(self.__token_key, tbs_digest, mechanism))

            #raw_signature = bytes(self.__pkcs11.get_session().sign(self.__token_key, tbs_digest, mechanism))
            #signature = OctetBitString(raw_signature).dump()

        if signature:
            #print(signature)
            return signature
        else:
            raise ValueError("Problem signing the digest")
            
