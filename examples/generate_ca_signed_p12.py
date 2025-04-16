import sys
import os

# Adds the parent directory of utils/ (i.e., the project root) to sys.path
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

import time
from pypki.ca import CertificationAuthority
from pypki.certificate_tools import CertificateTools


start_time = time.time()  # Record start time

print("Generate CA-signed PKCS#12")

ca = CertificationAuthority()
with open("config/ca_store/ca1_config.json", "rb") as config_file:
    ca_config_json = config_file.read()  # Read bytes from file
ca.load_config_json(ca_config_json)

certificate = CertificateTools()

# Load template and set request data
with open("config/cert_templates/client_cert_template.json", "r") as template_file:
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

# Generate a CA-signed certificate

certificate_p12 =  certificate.generate_pkcs12(
        request_json=request_json,
        issuing_ca=ca,  
        pfx_password = b"secret",
        friendly_name = b"TestP12",
        key_algorithm = "RSA",
        key_type = "2048")

with open("out/ca_signed_certificate.p12", "wb") as cert_file:
    cert_file.write(certificate_p12)
    cert_file.close()

print("P12 generated successfully.")

end_time = time.time()  # Record end time
elapsed_time = end_time - start_time  # Calculate elapsed time
print(f"Process completed in {elapsed_time:.6f} seconds")

print()
print("All done here... Bye!")
