DESCRIPTION = "Generate CA-Signed Certificate"

import sys
import os
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

import time
from pypki import CertificationAuthority, CertificateTools, KeyTools

start_time = time.time()

print("Generate CA-signed certificate")

ca = CertificationAuthority()
with open("config/ca_store/iot_rootca_config.json", "rb") as config_file:
    ca_config_json = config_file.read()
ca.load_config_json(ca_config_json)

certificate = CertificateTools()
with open("config/cert_templates/client_cert_template_v2.json", "r") as template_file:
    template_json = template_file.read()
certificate.load_certificate_template(template_json=template_json)

request_json = '''{
    "subject_name": {
        "countryName": "ES",
        "organizationName": "Naviter",
        "commonName": "Pedro Fuentes"
    }
}
'''

certificate_key = KeyTools()
certificate_key.generate_private_key("ECDSA", "P-256")
private_key_pem = certificate_key.get_private_key_pem()
with open("out/ecdsa_private_key.pem", "wb") as key_file:
    key_file.write(private_key_pem)

certificate_pem = certificate.generate_certificate_pem(
    request_json=request_json,
    issuing_ca=ca,
    certificate_key=certificate_key
)

with open("out/ca_signed_certificate.pem", "wb") as cert_file:
    cert_file.write(certificate_pem)

print("Private key and certificate generated successfully.")
print(f"Process completed in {time.time() - start_time:.6f} seconds")
print("\nAll done here... Bye!")
