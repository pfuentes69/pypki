import sys
import os
import atexit

# Adds the parent directory of utils/ (i.e., the project root) to sys.path
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '../..')))

from apscheduler.schedulers.background import BackgroundScheduler
from cryptography.hazmat.primitives import serialization
from pypki import CertificationAuthority, PyPKI, logger

CRL_PUBLICATION_FREQ = 10 * 60

crl_task_enabled = True

"""
ca = CertificationAuthority()
with open("/Users/pedro/Development/Python/pypki/config/ca_store/ca1_config.json", "rb") as config_file:
    ca_config_json = config_file.read()  # Read bytes from file
ca.load_config_json(ca_config_json)
"""

pki = PyPKI("config/config.json")

pki.load_ocsp_responders()

# Select default CA
#ca: CertificationAuthority = pki.select_ca_by_name("IoT Root CA 1")

def generate_crls():
    ca_collection = pki.get_ca_collection()

    for ca_item in ca_collection:
        pki.select_ca_by_id(ca_item["id"])
        # Generate the CRL
        crl = pki.generate_crl()
        # To save the CRL to a file
        ca_name = ca_item["name"].replace(' ', '_')
        crl_name = f"out/crl/{ca_name}.crl"
        with open(crl_name, "wb") as crl_file:
            crl_file.write(crl.public_bytes(serialization.Encoding.DER))
        crl_name = f"out/crl/{ca_name}.pem.crl"
        with open(crl_name, "wb") as crl_file:
            crl_file.write(crl.public_bytes(serialization.Encoding.PEM))

def services_task():
    logger.info("Services task")
    if crl_task_enabled:
        logger.info("Update CRLs")
        generate_crls()


# Run the Services task now
services_task()

scheduler = BackgroundScheduler()
scheduler.add_job(func=services_task, trigger="interval", seconds=CRL_PUBLICATION_FREQ)
scheduler.start()

# Shut down the scheduler when exiting the app
atexit.register(lambda: scheduler.shutdown())