DESCRIPTION = "Generate Self-Signed PKCS#12"

import sys
import os
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

import time
from pypki.certificate_tools import CertificateTools

start_time = time.time()

print("Generate self-signed PKCS#12")

certificate = CertificateTools()
with open("config/cert_templates/client_cert_template_v2.json", "r") as template_file:
    template_json = template_file.read()
certificate.load_certificate_template(template_json=template_json)

request_json = '''{
    "subject_name": {
        "countryName": "ES",
        "organizationName": "Naviter",
        "commonName": "Test CA 3"
    }
}
'''

certificate_p12 = certificate.generate_pkcs12(
    request_json=request_json,
    pfx_password=b"secret",
    friendly_name=b"TestP12",
    key_algorithm="RSA",
    key_type="2048"
)

with open("out/ss_certificate.p12", "wb") as cert_file:
    cert_file.write(certificate_p12)

print("P12 generated successfully.")
print(f"Process completed in {time.time() - start_time:.6f} seconds")
print("\nAll done here... Bye!")
