from cryptography import x509
from cryptography.hazmat.primitives import serialization
import time
import uuid
import json
from pypki.ca import CertificationAuthority
from pypki.pki_tools import PKITools, CertificateTools
from pypki.pypki import PyPKI

start_time = time.time()  # Record start time

print("Reset PKI Database")

pki = PyPKI("config/config.json")

pki.reset_pki()

end_time = time.time()  # Record end time
elapsed_time = end_time - start_time  # Calculate elapsed time
print(f"Process completed in {elapsed_time:.6f} seconds")

print()
print("All done here... Bye!")
