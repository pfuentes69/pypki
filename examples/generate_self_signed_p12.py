import sys
import os

# Adds the parent directory of utils/ (i.e., the project root) to sys.path
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

import time
from pypki.certificate_tools import CertificateTools


start_time = time.time()  # Record start time

print("Generate self-signed PKCS#12")

certificate = CertificateTools()

# Load template and request data
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

certificate_p12 =  certificate.generate_pkcs12(
        request_json=request_json,
        pfx_password = b"secret",
        friendly_name = b"TestP12",
        key_algorithm = "RSA", #"ECDSA", #"RSA",
        key_type = "2048") #"P-256") #"2048")

with open("out/ss_certificate.p12", "wb") as cert_file:
    cert_file.write(certificate_p12)
    cert_file.close()

print("P12 generated successfully.")

end_time = time.time()  # Record end time
elapsed_time = end_time - start_time  # Calculate elapsed time
print(f"Process completed in {elapsed_time:.6f} seconds")

print()
print("All done here... Bye!")
