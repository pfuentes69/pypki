import PyKCS11
import getpass
import os
from cryptography import x509
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import NameOID

PKCS11_LIB = "/usr/local/lib/pkcs11/libeTPkcs11.dylib"

class PKCS11Helper:
    def __init__(self, lib_path=PKCS11_LIB):
        self.__pkcs11 = PyKCS11.PyKCS11Lib()
        self.__pkcs11.load(lib_path)
        self.__session = None

    def get_token_info(self):
        slots = self.__pkcs11.getSlotList(tokenPresent=True)
        if not slots:
            raise RuntimeError("No PKCS#11 device found")
        
        token_info = self.__pkcs11.getTokenInfo(slots[0])
        return {
            "label": token_info.label.strip(),
            "manufacturer": token_info.manufacturerID.strip(),
            "model": token_info.model.strip(),
            "serial": token_info.serialNumber.strip()
        }
    
    def open_session(self, token_password: str) -> PyKCS11.Session: 
        slots = self.__pkcs11.getSlotList(tokenPresent=True)
        if not slots:
            raise RuntimeError("No PKCS#11 tokens found")

        #self.__session = self.__pkcs11.openSession(slots[0], PyKCS11.CKF_RW_SESSION)
        #self.__session.login(token_password)
        self.__session = self.__pkcs11.openSession(slots[0], PyKCS11.CKF_RW_SESSION | PyKCS11.CKF_SERIAL_SESSION)
        self.__session.login(str(token_password).encode("utf-8"), PyKCS11.CKU_USER)

        return self.__session
    
    def get_session(self) -> PyKCS11.Session: 
        return self.__session

    def close_session(self):
        if self.__session:
            self.__session.logout()
            self.__session.closeSession()
            self.__session = None


    def get_objects(self, obj_class):
        return self.__session.findObjects([{PyKCS11.CKA_CLASS: obj_class}])


    def get_certificates(self):
        try:
            # Attempt to retrieve certificates
            certs = self.__session.findObjects([(PyKCS11.CKA_CLASS, PyKCS11.CKO_CERTIFICATE)])
            return certs
        except PyKCS11.PyKCS11Error as e:
            print(f"❌ Error retrieving certificates: {e}")
            return []


    def get_ca_certificates(self):
        return [cert for cert in self.list_certificates() if "CA" in str(self.__session.getAttributeValue(cert, [PyKCS11.CKA_LABEL])[0])]


    def get_private_keys(self):
        try:
            # Attempt to retrieve private keys
            # print("🔎 Searching for private keys...")
            private_keys = self.__session.findObjects([(PyKCS11.CKA_CLASS, PyKCS11.CKO_PRIVATE_KEY)])
            return private_keys
        except PyKCS11.PyKCS11Error as e:
            print(f"❌ Error retrieving private keys: {e}")
            return []


    def generate_private_key(self, label, exportable=False, key_type="RSA2048"):
        if key_type not in ["RSA2048", "ECC256p"]:
            raise ValueError("Invalid key type. Choose 'RSA2048' or 'ECC256p'.")
        """
        # Generate CKA_ID based on label or random if label is empty
        if label:
            digest = hashes.Hash(hashes.SHA1())
            digest.update(label.encode())
            cka_id = digest.finalize()[:8]  # Use first 8 bytes
        else:
            cka_id = os.urandom(8)  # Generate random 8-byte ID
        """
        cka_id = os.urandom(8)  # Generate random 8-byte ID

        if key_type == "RSA2048":
            mechanism = PyKCS11.Mechanism(PyKCS11.CKM_RSA_PKCS_KEY_PAIR_GEN, None)
            pub_template = [
                (PyKCS11.CKA_LABEL, label),
                (PyKCS11.CKA_TOKEN, True),
                (PyKCS11.CKA_ENCRYPT, True),
                (PyKCS11.CKA_VERIFY, True),
                (PyKCS11.CKA_MODULUS_BITS, 2048),
                (PyKCS11.CKA_ID, cka_id)
            ]
        elif key_type == "ECC256p":
            mechanism = PyKCS11.Mechanism(PyKCS11.CKM_EC_KEY_PAIR_GEN, None)
            ec_params = bytes([0x06, 0x08, 0x2A, 0x86, 0x48, 0xCE, 0x3D, 0x03, 0x01, 0x07])  # OID for P-256
            pub_template = [
                (PyKCS11.CKA_LABEL, label),
                (PyKCS11.CKA_TOKEN, True),
                (PyKCS11.CKA_VERIFY, True),
                (PyKCS11.CKA_EC_PARAMS, ec_params),
                (PyKCS11.CKA_ID, cka_id)
            ]


        # ✅ Create an X.509 Distinguished Name (DN)
        subject_name = x509.Name([
            x509.NameAttribute(x509.oid.NameOID.COUNTRY_NAME, "ES"),
            x509.NameAttribute(x509.oid.NameOID.ORGANIZATION_NAME, "Test"),
            x509.NameAttribute(x509.oid.NameOID.COMMON_NAME, "Pedro Fuentes")
        ])
        
        # ✅ Encode subject name in DER format
        subject_der = subject_name.public_bytes(serialization.Encoding.DER)

        # Private key template
        priv_template = [
            (PyKCS11.CKA_LABEL, label),
            (PyKCS11.CKA_SUBJECT, subject_der),  # ✅ DER-encoded subject name
            (PyKCS11.CKA_TOKEN, True),
            (PyKCS11.CKA_SIGN, True),
            (PyKCS11.CKA_SENSITIVE, not exportable),
            (PyKCS11.CKA_EXTRACTABLE, exportable),
            (PyKCS11.CKA_ID, cka_id)  # Set CKA_ID (same as public key)
        ]

        # Handle the key generation
        try:
            if self.__session.generateKeyPair(pub_template, priv_template, mechanism):
                return cka_id
            else:
                return None
        except PyKCS11.PyKCS11Error as e:
            raise RuntimeError(f"Unexpected error: {str(e)}")


    def generate_csr(self, priv_key, subject_name):
        subject = x509.Name([
            x509.NameAttribute(NameOID.COMMON_NAME, subject_name)
        ])
        
        csr = x509.CertificateSigningRequestBuilder().subject_name(subject).sign(priv_key, hashes.SHA256())
        return csr.public_bytes(serialization.Encoding.PEM)

    def export_public_key(self, priv_key):
        pub_key = self.__session.findObjects([{PyKCS11.CKA_CLASS: PyKCS11.CKO_PUBLIC_KEY}])[0]
        return self.__session.getAttributeValue(pub_key, [PyKCS11.CKA_VALUE])[0]
    
    def insert_certificate(self, cert_pem, label):
        cert = x509.load_pem_x509_certificate(cert_pem)
        cert_der = cert.public_bytes(serialization.Encoding.DER)
        
        template = [
            (PyKCS11.CKA_CLASS, PyKCS11.CKO_CERTIFICATE),
            (PyKCS11.CKA_LABEL, label),
            (PyKCS11.CKA_VALUE, cert_der),
            (PyKCS11.CKA_TOKEN, True)
        ]
        self.__session.createObject(template)

    def export_certificate(self, cert):
        return self.__session.getAttributeValue(cert, [PyKCS11.CKA_VALUE])[0]
    

    def export_private_key(self, priv_key):
        return self.__session.getAttributeValue(priv_key, [PyKCS11.CKA_VALUE])[0]
    

    def get_key_by_id(self, key_id: str) -> PyKCS11.CK_OBJECT_HANDLE:
        # Find private key
        key_id = bytes.fromhex(key_id)
        priv_keys = self.__session.findObjects([
        (PyKCS11.CKA_CLASS, PyKCS11.CKO_PRIVATE_KEY),
        (PyKCS11.CKA_ID, key_id)
        ])

        if not priv_keys:
            raise RuntimeError("Private key not found")

        self.__selected_key = priv_keys[0]
        return self.__selected_key
    