import binascii
import PyKCS11
from cryptography import x509
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.asymmetric import rsa, padding
import datetime
from pypki.pkcs11_helper import PKCS11Helper

# Configuration
PKCS11_MODULE = "/usr/local/lib/pkcs11/libeTPkcs11.dylib"  # Replace with your PKCS#11 module path
TOKEN_PIN = "Wisekey1!"  # Replace with your token PIN
CKA_ID = "75B5FC23ACEE5CBF31245C4730F2F1F3C8E8B249"  # Replace with your key identifier (hex string)


def load_csr(csr_pem: str) -> x509.CertificateSigningRequest:
    """Loads a CSR from a PEM-encoded string."""
    return x509.load_pem_x509_csr(csr_pem.encode())


def sign_with_pkcs11(csr: x509.CertificateSigningRequest, key_id: str) -> x509.Certificate:
    """Signs a CSR using a private key stored in a PKCS#11 token."""

    # Find private key
    priv_key = pkcs11.get_key_by_id(key_id)

    # Extract public key from CSR
    public_key = csr.public_key()

    # Create the certificate builder
    subject = csr.subject
    issuer = csr.subject  # Self-signed for testing
    cert_builder = x509.CertificateBuilder() \
        .subject_name(subject) \
        .issuer_name(issuer) \
        .public_key(public_key) \
        .serial_number(x509.random_serial_number()) \
        .not_valid_before(datetime.datetime.utcnow()) \
        .not_valid_after(datetime.datetime.utcnow() + datetime.timedelta(days=365)) \
        .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)

    # Use a temporary key to generate the TBS certificate bytes
    dummy_private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048,
        backend=None
    )
    temp_cert = cert_builder.sign(
        private_key=dummy_private_key,
        algorithm=hashes.SHA256(),
        backend=None
    )
    tbs_cert_bytes = temp_cert.tbs_certificate_bytes

        # 🔹 Correct Signing: Hash the TBS certificate bytes
    digest = hashes.Hash(hashes.SHA256(), backend=None)
    digest.update(tbs_cert_bytes)
    tbs_digest = digest.finalize()  # This is what we actually sign

    # 🔹 Generate the actual signature using PKCS#11
    mechanism = PyKCS11.Mechanism(PyKCS11.CKM_SHA256_RSA_PKCS, None)  # Use hash-based signing
    signature = bytes(pkcs11.get_session().sign(priv_key, tbs_digest, mechanism))

    # 🔹 Manually re-create the certificate with the PKCS#11 signature
    final_cert = cert_builder.sign(
        private_key=dummy_private_key,  # Needed for compatibility, but ignored
        algorithm=hashes.SHA256(),
        backend=None
    )

    # 🔹 Replace the incorrect signature with the real PKCS#11 signature
    final_cert = x509.load_der_x509_certificate(
        final_cert.public_bytes(serialization.Encoding.DER), backend=None
    )

    # Replace the signature manually
    final_cert = x509.CertificateBuilder() \
        .subject_name(final_cert.subject) \
        .issuer_name(final_cert.issuer) \
        .public_key(final_cert.public_key()) \
        .serial_number(final_cert.serial_number) \
        .not_valid_before(final_cert.not_valid_before) \
        .not_valid_after(final_cert.not_valid_after) \
        .add_extension(final_cert.extensions.get_extension_for_class(x509.BasicConstraints).value, critical=True) \
        .sign(dummy_private_key, hashes.SHA256(), backend=None)

    # 🔹 Manually patch the signature
    final_cert_bytes = bytearray(final_cert.public_bytes(serialization.Encoding.DER))
    final_cert_bytes[-len(signature):] = signature  # Replace with real signature

    # Convert final cert to PEM format
    final_cert = x509.load_der_x509_certificate(bytes(final_cert_bytes), backend=None)

    cert_template = [
        (PyKCS11.CKA_CLASS, PyKCS11.CKO_CERTIFICATE),
        (PyKCS11.CKA_TOKEN, True),
        (PyKCS11.CKA_LABEL, "Test"),
        (PyKCS11.CKA_ID, key_id),
        (PyKCS11.CKA_SUBJECT, final_cert.subject.public_bytes()),
        (PyKCS11.CKA_VALUE, final_cert.public_bytes(encoding=serialization.Encoding.DER))
    ]

    # session.createObject(cert_template)

    return final_cert.public_bytes(serialization.Encoding.PEM)


def store_certificate_in_token(cert_pem: str, ck_id: str, label: str):
    """
    Stores an X.509 certificate in a PKCS#11 token.
    
    Args:
        cert_pem (str): Certificate in PEM format.
        ck_id (str): The CK_ID to set for the certificate (hex string).
        label (str): The label to assign to the certificate.
        session (PyKCS11.Session): The active PKCS#11 session.

    Raises:
        RuntimeError: If certificate storage fails.
    """

    # Convert PEM to DER format
    cert = x509.load_pem_x509_certificate(cert_pem) #.encode())
    cert_der = cert.public_bytes(encoding=serialization.Encoding.DER)

    # Convert CK_ID to bytes
    ck_id_bytes = bytes.fromhex(ck_id)

    # Define certificate attributes
    # Define the PKCS#11 template with more required attributes
    cert_template = [
        (PyKCS11.CKA_CLASS, PyKCS11.CKO_CERTIFICATE),       # Object type: Certificate
        (PyKCS11.CKA_CERTIFICATE_TYPE, PyKCS11.CKC_X_509),  # X.509 certificate
        (PyKCS11.CKA_TOKEN, True),                          # Store persistently
        (PyKCS11.CKA_PRIVATE, False),                       # Public certificate
        (PyKCS11.CKA_ID, ck_id_bytes),                      # Identifier for linking to key
        (PyKCS11.CKA_VALUE, cert_der),                      # Actual certificate data
        (PyKCS11.CKA_LABEL, label),                         # Friendly name
        (PyKCS11.CKA_SUBJECT, cert.subject.public_bytes(serialization.Encoding.DER)),  # DER-encoded Subject
        (PyKCS11.CKA_ISSUER, cert.issuer.public_bytes(serialization.Encoding.DER)),    # DER-encoded Issuer
    ]
    #         (PyKCS11.CKA_SERIAL_NUMBER, serial_number_bytes)    # Serial Number


    # Store certificate in token
    try:
        pkcs11.get_session().createObject(cert_template)
        print(f"Certificate stored successfully with CK_ID: {ck_id}, Label: {label}")
    except PyKCS11.PyKCS11Error as e:
        raise RuntimeError(f"Failed to store certificate: {e}")
    

# Example usage
csr_pem = """-----BEGIN CERTIFICATE REQUEST-----
MIICeTCCAWECAQAwNDELMAkGA1UEBhMCRVMxDTALBgNVBAoMBFRlc3QxFjAUBgNV
BAMMDVBlZHJvIEZ1ZW50ZXMwggEiMA0GCSqGSIb3DQEBAQUAA4IBDwAwggEKAoIB
AQDRdm8X/ctIV7LYzba3dxVcUG6lFNgAxLaVp0CMVrnVG5uFUDYfHLuVs11haaPK
fYFyhqjvHWoiHR3m4yhVIVFJ63UWuPwTYa+0RtD80RLvg44JMaAO7pM4VM47ZByy
T8xlou4XYQGfxhi/9SHvzuIiPhZPzCqZYyQmhgoy28oNA8zhWEB0jFc16pxcuUBb
WVN9Q47fplHn0Rj/qTbr0bCxEu1Z25TzsfU9oVGUoccTQuerYKAO6twOMUwSq5lp
TNgZEhEVwFrpDuS2P2OLs20mCxk9odj1vKOJH1jsJLvspKaXW5sVhLS0tcFDbaIM
iTzPUKzWsbHr7IHHSPLczMyJAgMBAAGgADANBgkqhkiG9w0BAQsFAAOCAQEAzBJi
GxLI2WCJN69Xu0QCAvRh3T820Hu00R2g3TTmmm/E+idG52uGUlSlIyWXjLOdl61b
wEMerOV0c3IIkRHG6hh+1MENmf82k6sIEy7qmYagg9htS0QyXIx0gnq5BvuFOZSI
hqmZRtAs1NZHdaAAhP3peH0N61fl0+gQPaEDjDm2MdSkSk2uK7NWKRRT8A2SurAV
+OfD9Nm2GUR2VKWPrngA6VzCMARJ4S53DW9veysL73VffbLJqjJHzxPzhriPMSdd
LHIFGpi34ASYLGA5Q0X/jz3ZiXdzDfqQ0KhA6l8qqZ7mthaWDNjflVoaBLpmzcCh
eAvn0y/XGL6IDeK1gQ==
-----END CERTIFICATE REQUEST-----"""


pkcs11 = PKCS11Helper()
# pin = getpass.getpass("Enter SafeNet Token PIN: ")
pin = "Wisekey1!"
pkcs11.open_session(pin)
csr = load_csr(csr_pem)
certificate_pem = sign_with_pkcs11(csr, CKA_ID)
print(certificate_pem.decode())
