from cryptography import x509
from cryptography.hazmat.primitives import serialization
from pki_utils import PKIUtils

# Load template and request data
with open("cert_templates/server_cert_template.json", "r") as template_file:
    template_json = template_file.read()

with open("request_examples/server_cert_request.json", "r") as request_file:
    request_json = request_file.read()

pki_utils = PKIUtils()

# Load existing CA key and certificate from files.
with open("ca_store/ca1_private_key.pem", "rb") as key_file:
    ca_private_key_pem = key_file.read()  # Read bytes from file

with open("ca_store/ca1_certificate.pem", "rb") as cert_file:
    ca_cert_pem = cert_file.read()
    
# Generate an RSA private key
client_private_key_pem = pki_utils.generate_private_key("RSA", "2048")
with open("out/server_private_key.pem", "wb") as key_file:
    key_file.write(client_private_key_pem)
    key_file.close()

# Load the private key from PEM format
client_private_key = serialization.load_pem_private_key(
    client_private_key_pem.encode() if isinstance(client_private_key_pem, str) else client_private_key_pem,
    password=None  # Use password=b"yourpassword" if the key is encrypted
)

# Get the corresponding public key
client_public_key = client_private_key.public_key()

'''
# Generate a CSR
csr_pem = pki_utils.generate_csr(client_private_key_pem, template_json, request_json)
with open("out/certificate_request.csr", "wb") as csr_file:
    csr_file.write(csr_pem)
    csr_file.close()

# Generate a client certificate
certificate_pem = pki_utils.generate_certificate_from_csr(ca_private_key_pem, csr_pem, template_json, ca_cert_pem,, 100)
with open("out/client_certificate.pem", "wb") as cert_file:
    cert_file.write(certificate_pem)
    cert_file.close()
'''

certificate_pem = pki_utils.generate_certificate_from_template(client_public_key, ca_private_key_pem, request_json, template_json, ca_cert_pem, -1)
with open("out/server_certificate.pem", "wb") as cert_file:
    cert_file.write(certificate_pem)
    cert_file.close()

print("Private key, CSR, and certificate generated successfully.")
