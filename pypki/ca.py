import json
import secrets
from cryptography import x509
from cryptography.hazmat.primitives import serialization

class CertificationAuthority:
    def __init__(self):
        """Initialize the PKI Utilities class."""
        self.__config = {}
        self.__private_key: bytes = b""
        self.__certificate: x509.Certificate = b""
        self.__issued_serials = set()

    def load_config_json(self, ca_config_json: str):
        self.__config = json.loads(ca_config_json)
        # Get private key and certificate
        self.__private_key = serialization.load_pem_private_key(self.__config["crypto"]["private_key"].encode("utf-8"), password=None)
        self.__certificate = x509.load_pem_x509_certificate(self.__config["crypto"]["certificate"].encode("utf-8"))
        pass


    def load_serials(self, initial_serials: set):
        """
        Load an initial set of issued serial numbers.

        Args:
            initial_serials (set): A set of serial numbers to initialize with.
        """
        if not isinstance(initial_serials, set):
            raise TypeError("initial_serials must be a set")
        else:
            # Count the number of items
            #serial_count = len(initial_serials)
            #print(f"Total issued serials for this CA: {serial_count}")
            pass

        self.__issued_serials.update(initial_serials)
        pass


    def generate_unique_serial(self):
        """
        Generate a unique serial number with a specified length in bytes.
        """
        while True:
            serial = int.from_bytes(secrets.token_bytes(self.__config["serial_number_length"]), "big")  # Convert bytes to integer
            if serial not in self.__issued_serials:
                self.__issued_serials.add(serial)
                return serial


    def get_private_key(self):
        """Returns the private key in a controlled manner."""
        return self.__private_key

    def export_private_key(self, password: bytes = None):
        """
        Securely exports the private key in PEM format.
        If a password is provided, the key is encrypted.
        """
        encryption_algorithm = (
            serialization.BestAvailableEncryption(password)
            if password else serialization.NoEncryption()
        )
        
        return self.__private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=encryption_algorithm
        )
    
    def get_certificate(self) -> x509.Certificate:
        """Public method to retrieve the stored certificate."""
        return self.__certificate
    
    def get_serial(self) -> bytes:
        return x509.random_serial_number()
    
    def get_config(self) -> dict:
        return self.__config
