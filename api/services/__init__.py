import sys
import os

# Adds the parent directory of utils/ (i.e., the project root) to sys.path
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '../..')))

import time
from pypki import CertificateTools, CertificationAuthority

start_time = time.time()  # Record start time

ca = CertificationAuthority()
with open("/Users/pedro/Development/Python/pypki/config/ca_store/ca1_config.json", "rb") as config_file:
    ca_config_json = config_file.read()  # Read bytes from file
ca.load_config_json(ca_config_json)
