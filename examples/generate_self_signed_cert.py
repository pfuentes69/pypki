import sys
import os

# Adds the parent directory of utils/ (i.e., the project root) to sys.path
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

import time
from pypki import KeyTools, CertificateTools

start_time = time.time()  # Record start time

print("Generate self-signed certificate")

certificate = CertificateTools()

# Load template and request data
with open("config/cert_templates/iot_rootca_cert_template.json", "r") as template_file:
#with open("config/cert_templates/server_cert_template.json", "r") as template_file:
    template_json = template_file.read()

certificate.load_certificate_template(template_json=template_json)

"""
request_json = '''{
    "subject_name": {
        "countryName": "ES",
        "organizationName": "Naviter",
        "commonName": "IoT Root CA"
    }
}
'''
"""

request_json = '''{
    "subject_name": {
        "countryName": "ES",
        "organizationName": "Naviter",
        "commonName": "IoT Root CA"
    }
}
'''

# Load existing CA key and certificate from files.
#with open("ca_store/ca1_private_key.pem", "rb") as key_file:
#    ca_private_key_pem = key_file.read()  # Read bytes from file

#with open("ca_store/ca1_certificate.pem", "rb") as cert_file:
#    ca_cert_pem = cert_file.read()
    
# Generate an RSA private key
certificate_key = KeyTools()
#certificate_key.generate_private_key("RSA", "2048")
certificate_key.generate_private_key("ECDSA", "P-256")
private_key_pem = certificate_key.get_private_key_pem()
with open("out/iot_rootca_private_key.pem", "wb") as key_file:
    key_file.write(private_key_pem)
    key_file.close()

# Load the private key from PEM format
#client_private_key = serialization.load_pem_private_key(
#    client_private_key_pem.encode() if isinstance(client_private_key_pem, str) else client_private_key_pem,
#    password=None  # Use password=b"yourpassword" if the key is encrypted
#)

# Get the corresponding public key
#client_public_key = client_private_key.public_key()


# Generate a self-signed certificate

#certificate_pem = certificate.generate_certificate_from_template(issuing_ca=None, validity_days=3650)
#csr_pem = certificate.generate_csr_pem(signing_key)
#certificate_pem = certificate.generate_certificate_from_csr(csr_pem=csr_pem, signing_key=signing_key)

certificate_pem = certificate.generate_certificate_pem(request_json=request_json, certificate_key=certificate_key)

with open("out/iot_rootca_certificate.pem", "wb") as cert_file:
    cert_file.write(certificate_pem)
    cert_file.close()

print("Private key, CSR, and certificate generated successfully.")

end_time = time.time()  # Record end time
elapsed_time = end_time - start_time  # Calculate elapsed time
print(f"Process completed in {elapsed_time:.6f} seconds")

print()
print("All done here... Bye!")
