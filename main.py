from cryptography import x509
from cryptography.hazmat.primitives import serialization
import time
import uuid
import json
from pypki.ca import CertificationAuthority
from pypki.pki_tools import PKITools, CertificateTools
from pypki.pypki import PyPKI

def generate_sample_certs():
    # Load request data

    pki.select_cert_template_by_name("IoT Device")

    # Load the JSON request template
    with open("tests/request_examples/iot_device_cert_request.json", "r") as request_file:
        request_json_template = json.load(request_file)  # Load JSON as a dictionary

    for i in range(300):
        # Create a copy of the template and modify the serialNumber
        request_json = request_json_template.copy()
        request_json["subject_name"]["serialNumber"] = str(uuid.uuid4())  # Generate random UUID

        # Convert modified request back to JSON string
        request_json_str = json.dumps(request_json)

        # Generate the certificate
        certificate_pem = pki.generate_certificate_from_template(
            request_json_str,
            private_key=None,
            use_active_ca=True,
            validity_days=PKITools.INFINITE_VALIDITY
        )

start_time = time.time()  # Record start time

pki = PyPKI("config/config.json")

"""
pki.reset_pki()
"""
pki.reset_pki()

ca = pki.select_ca_by_name("IoT Root CA 1")

"""
generate_sample_certs()
"""
generate_sample_certs()

# cert = pki.get_certificate_pem(serial_number="14106974174763673215")
id = pki.get_certificate_id(serial_number="14106974174763673215")

pki.revoke_certificate(13, PKITools.REVOCATION_REASONS["superseded"])
pki.revoke_certificate(134, PKITools.REVOCATION_REASONS["cACompromise"])
pki.revoke_certificate(34, PKITools.REVOCATION_REASONS["superseded"])

if pki.revoke_certificate(14, PKITools.REVOCATION_REASONS["superseded"]):
    print("Certificate revoked")
else:
    print("Certificate not found or already revoked")

# Generate the CRL
crl = pki.generate_crl()

# To save the CRL to a file
with open("out/crl.pem", "wb") as crl_file:
    crl_file.write(crl.public_bytes(serialization.Encoding.PEM))

end_time = time.time()  # Record end time
elapsed_time = end_time - start_time  # Calculate elapsed time
print(f"Process completed in {elapsed_time:.6f} seconds")

print()
print("All done here... Bye!")
