DESCRIPTION = "Generate Self-Signed Certificate"

import sys
import os
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

import time
from pypki import KeyTools, CertificateTools

start_time = time.time()

print("Generate self-signed certificate")

certificate = CertificateTools()

with open("config/cert_templates/iot_rootca_cert_template.json", "r") as template_file:
    template_json = template_file.read()

certificate.load_certificate_template(template_json=template_json)

request_json = '''{
    "subject_name": {
        "countryName": "ES",
        "organizationName": "Naviter",
        "commonName": "IoT Root CA"
    }
}
'''

certificate_key = KeyTools()
certificate_key.generate_private_key("ECDSA", "P-256")
private_key_pem = certificate_key.get_private_key_pem()
with open("out/iot_rootca_private_key.pem", "wb") as key_file:
    key_file.write(private_key_pem)

certificate_pem = certificate.generate_certificate_pem(
    request_json=request_json,
    certificate_key=certificate_key
)

with open("out/iot_rootca_certificate.pem", "wb") as cert_file:
    cert_file.write(certificate_pem)

print("Private key and certificate generated successfully.")
print(f"Process completed in {time.time() - start_time:.6f} seconds")
print("\nAll done here... Bye!")
