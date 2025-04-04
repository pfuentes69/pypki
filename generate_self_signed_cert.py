from cryptography import x509
from cryptography.hazmat.primitives import serialization
import time
import uuid
import json
from pypki.ca import CertificationAuthority
from pypki.pki_tools import PKITools, CertificateTools


start_time = time.time()  # Record start time

print("Generate self-signed certificate")

certificate = CertificateTools()

# Load template and request data
with open("config/cert_templates/ca_cert_template.json", "r") as template_file:
    template_json = template_file.read()

certificate.load_certificate_template(template_json=template_json)

with open("request_examples/ca_cert_request.json", "r") as request_file:
    request_json = request_file.read()

certificate.load_certificate_request(request_json=request_json)

# Load existing CA key and certificate from files.
#with open("ca_store/ca1_private_key.pem", "rb") as key_file:
#    ca_private_key_pem = key_file.read()  # Read bytes from file

#with open("ca_store/ca1_certificate.pem", "rb") as cert_file:
#    ca_cert_pem = cert_file.read()
    
# Generate an RSA private key
certificate.generate_private_key("RSA", "2048")
client_private_key_pem = certificate.export_private_key()
with open("out/sscert_private_key.pem", "wb") as key_file:
    key_file.write(client_private_key_pem)
    key_file.close()

# Load the private key from PEM format
#client_private_key = serialization.load_pem_private_key(
#    client_private_key_pem.encode() if isinstance(client_private_key_pem, str) else client_private_key_pem,
#    password=None  # Use password=b"yourpassword" if the key is encrypted
#)

# Get the corresponding public key
#client_public_key = client_private_key.public_key()


# Generate a self-signed certificate

certificate_pem = certificate.generate_certificate_from_template(issuing_ca=None, validity_days=3650)

with open("out/sscert_certificate.pem", "wb") as cert_file:
    cert_file.write(certificate_pem)
    cert_file.close()

print("Private key, CSR, and certificate generated successfully.")

end_time = time.time()  # Record end time
elapsed_time = end_time - start_time  # Calculate elapsed time
print(f"Process completed in {elapsed_time:.6f} seconds")

print()
print("All done here... Bye!")
