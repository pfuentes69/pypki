import sys
import os

# Adds the parent directory of utils/ (i.e., the project root) to sys.path
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

import time
import uuid
import json
from pypki.pki_tools import PKITools
from pypki.core import PyPKI

def generate_sample_certs():
    # Load request data

    # Load the JSON request template
    request_json_template_str = '''
        {
            "subject_name": {
                "serialNumber": "999000888",
                "commonName": "device_name 001"
            }
        }
    '''
    request_json_template = json.loads(request_json_template_str)

    for i in range(300):
        # Create a copy of the template and modify the serialNumber
        request_json = request_json_template.copy()
        request_json["subject_name"]["serialNumber"] = str(uuid.uuid4())  # Generate random UUID

        # Convert modified request back to JSON string
        request_json_str = json.dumps(request_json)

        # Generate the certificate
        certificate_pem = pki.generate_certificate_and_key(
            request_json_str,
            use_active_ca=True,
            validity_days=PKITools.INFINITE_VALIDITY,
            key_algorithm="ECDSA", 
            key_type="P-256"
        )

start_time = time.time()  # Record start time

print("Generate sample certificates")

pki = PyPKI("config/config.aws.json")
pki.load_template_collection()


ca = pki.select_ca_by_name("IoT Root CA 1")
pki.select_cert_template_by_name("IoT Device")

generate_sample_certs()

# Revoke some certificates 
pki.revoke_certificate(13, PKITools.REVOCATION_REASONS["superseded"])
pki.revoke_certificate(134, PKITools.REVOCATION_REASONS["cACompromise"])
pki.revoke_certificate(34, PKITools.REVOCATION_REASONS["superseded"])

if pki.revoke_certificate(14, PKITools.REVOCATION_REASONS["superseded"]):
    print("Certificate revoked")
else:
    print("Certificate not found or already revoked")

end_time = time.time()  # Record end time
elapsed_time = end_time - start_time  # Calculate elapsed time
print(f"Process completed in {elapsed_time:.6f} seconds")

print()
print("All done here... Bye!")
