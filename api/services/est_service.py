import sys
import os

# Adds the parent directory of utils/ (i.e., the project root) to sys.path
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '../..')))

from cryptography.hazmat.primitives import serialization

from pypki import CertificateTools, CertificationAuthority

from . import ca

def generate_certificate(csr_pem: bytes):

    certificate = CertificateTools()

    # Load template and request data
    with open("/Users/pedro/Development/Python/pypki/config/cert_templates/client_cert_template.json", "r") as template_file:
        template_json = template_file.read()

    certificate.load_certificate_template(template_json=template_json)

    request_json = '''{
        "subject_name": {
            "countryName": "ES",
            "organizationName": "Naviter",
            "commonName": "Test CA 2"
        }
    }
    '''

    # Generate a ca-signed certificate
    certificate_der = certificate.generate_certificate_from_csr(
        csr_pem=csr_pem,
        request_json=None,
        issuing_ca=ca,
        certificate_key=None,
        validity_days=365,
        enforce_template=True)

    return certificate_der

def get_ca_certificate(data):
    
    ca_certificate = ca.get_certificate()

    return ca_certificate.public_bytes(serialization.Encoding.PEM)
