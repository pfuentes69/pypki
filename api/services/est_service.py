import sys
import os

# Adds the parent directory of utils/ (i.e., the project root) to sys.path
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '../..')))

from cryptography.hazmat.primitives import serialization

from pypki import PKITools

from . import pki

def generate_certificate(csr_pem: bytes):

    pki.select_cert_template_by_name("IoT Device")

    # Generate a ca-signed certificate
    certificate_der = pki.generate_certificate_from_csr(
        csr_pem=csr_pem,
        request_json=None,
        use_active_ca=True,
        validity_days=PKITools.INFINITE_VALIDITY, 
        enforce_template=True
    )
    
    return certificate_der

def get_ca_certificate(data):
    
    ca_certificate = pki.get_ca_certificate()

    return ca_certificate.public_bytes(serialization.Encoding.PEM)
