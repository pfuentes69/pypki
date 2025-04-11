import sys
import os

# Adds the parent directory of utils/ (i.e., the project root) to sys.path
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

import time
from cryptography.hazmat.primitives import serialization
from pypki.pypki import PyPKI


start_time = time.time()  # Record start time

print("Generate CRLs for all CAs")

pki = PyPKI("config/config.json")

ca_collection = pki.get_ca_collection()

for ca in ca_collection:
    print(f"Generating CRL for {ca['ca_name']}")
    pki.select_ca_by_id(ca["id"])
    # Generate the CRL
    crl = pki.generate_crl()
    # To save the CRL to a file
    ca_name = ca["ca_name"].replace(' ', '_')
    crl_name = f"out/{ca_name}.crl"
    with open(crl_name, "wb") as crl_file:
        crl_file.write(crl.public_bytes(serialization.Encoding.PEM))


end_time = time.time()  # Record end time
elapsed_time = end_time - start_time  # Calculate elapsed time
print(f"Process completed in {elapsed_time:.6f} seconds")

print()
print("All done here... Bye!")
