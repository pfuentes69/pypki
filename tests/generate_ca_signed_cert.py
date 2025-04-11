import sys
import os

# Adds the parent directory of utils/ (i.e., the project root) to sys.path
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

import time
from pypki.ca import CertificationAuthority
from pypki.certificate_tools import CertificateTools
from pypki.key_tools import KeyTools


start_time = time.time()  # Record start time

print("Generate CA-signed certificate")

ca = CertificationAuthority()
#with open("config/ca_store/iot_rootca_config.json", "rb") as config_file:
with open("config/ca_store/ca1_config.json", "rb") as config_file:
#with open("config/ca_store/ca1_token_config.json", "rb") as config_file:
#with open("config/ca_store/ca2_config.json", "rb") as config_file:
#with open("config/ca_store/ca3_token_config.json", "rb") as config_file:
    ca_config_json = config_file.read()  # Read bytes from file
ca.load_config_json(ca_config_json)

certificate = CertificateTools()

# Load template and set request data
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

# Generate an RSA private key
certificate_key = KeyTools()
certificate_key.generate_private_key("ECDSA", "P-256")
private_key_pem = certificate_key.get_private_key_pem()
with open("out/ecdsa_private_key.pem", "wb") as key_file:
    key_file.write(private_key_pem)
    key_file.close()

# Load the private key from PEM format
#client_private_key = serialization.load_pem_private_key(
#    client_private_key_pem.encode() if isinstance(client_private_key_pem, str) else client_private_key_pem,
#    password=None  # Use password=b"yourpassword" if the key is encrypted
#)

# Generate a CA-signed certificate

certificate_pem = certificate.generate_certificate_pem(
    request_json=request_json, 
    issuing_ca=ca,  
    certificate_key=certificate_key
)

with open("out/client_certificate_v2.pem", "wb") as cert_file:
    cert_file.write(certificate_pem)
    cert_file.close()

print("Private key, CSR, and certificate generated successfully.")

end_time = time.time()  # Record end time
elapsed_time = end_time - start_time  # Calculate elapsed time
print(f"Process completed in {elapsed_time:.6f} seconds")

print()
print("All done here... Bye!")
