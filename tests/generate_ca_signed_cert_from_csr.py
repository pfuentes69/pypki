import sys
import os

# Adds the parent directory of utils/ (i.e., the project root) to sys.path
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

import time
from pypki.key_tools import KeyTools
from pypki.certificate_tools import CertificateTools
from pypki.ca import CertificationAuthority

start_time = time.time()  # Record start time

print("Generate self-signed certificate from CSR")

ca = CertificationAuthority()
with open("config/ca_store/ca1_config.json", "rb") as config_file:
    ca_config_json = config_file.read()  # Read bytes from file
ca.load_config_json(ca_config_json)

certificate = CertificateTools()

# Load template and request data
with open("config/cert_templates/client_cert_template.json", "r") as template_file:
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

# Load the CSR from PEM format
with open("request_examples/example.csr", "rb") as csr_file:
    csr_pem = csr_file.read()

# Generate a self-signed certificate

certificate_pem = certificate.generate_certificate_pem_from_csr(
    csr_pem=csr_pem,
    request_json=request_json,
    issuing_ca=ca,
    certificate_key=None,
    validity_days=365,
    enforce_template=True)

with open("out/test_from_csr_certificate.pem", "wb") as cert_file:
    cert_file.write(certificate_pem)
    cert_file.close()

print("Private key, CSR, and certificate generated successfully.")

end_time = time.time()  # Record end time
elapsed_time = end_time - start_time  # Calculate elapsed time
print(f"Process completed in {elapsed_time:.6f} seconds")

print()
print("All done here... Bye!")
