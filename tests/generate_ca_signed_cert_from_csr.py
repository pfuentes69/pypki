DESCRIPTION = "Generate CA-Signed Certificate from CSR"

import sys
import os
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

import time
from pypki import CertificateTools, CertificationAuthority

start_time = time.time()

print("Generate CA-signed certificate from CSR")

ca = CertificationAuthority()
with open("config/ca_store/ca1_config.json", "rb") as config_file:
    ca_config_json = config_file.read()
ca.load_config_json(ca_config_json)

certificate = CertificateTools()
with open("config/cert_templates/client_cert_template.json", "r") as template_file:
    template_json = template_file.read()
certificate.load_certificate_template(template_json=template_json)

with open("doc/request_examples/example.csr", "rb") as csr_file:
    csr_pem = csr_file.read()

certificate_pem = certificate.generate_certificate_pem_from_csr(
    csr_pem=csr_pem,
    request_json=None,
    issuing_ca=ca,
    certificate_key=None,
    validity_days=365,
    enforce_template=True
)

with open("out/ca_signed_certificate_from_csr.pem", "wb") as cert_file:
    cert_file.write(certificate_pem)

print("Certificate generated successfully.")
print(f"Process completed in {time.time() - start_time:.6f} seconds")
print("\nAll done here... Bye!")
