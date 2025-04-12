import sys
import os

# Adds the parent directory of utils/ (i.e., the project root) to sys.path
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '../..')))

from pypki import CertificationAuthority, PyPKI

"""
ca = CertificationAuthority()
with open("/Users/pedro/Development/Python/pypki/config/ca_store/ca1_config.json", "rb") as config_file:
    ca_config_json = config_file.read()  # Read bytes from file
ca.load_config_json(ca_config_json)
"""

pki = PyPKI("config/config.json")

ca: CertificationAuthority = pki.select_ca_by_name("IoT Root CA 1")
