import logging

from .ca import CertificationAuthority
from .db import PKIDataBase
from .pki_tools import PKITools
from .key_tools import KeyTools
from .certificate_tools import CertificateTools
from .pkcs11_helper import PKCS11Helper
from .log import logger
from .core import PyPKI

# Configure the logging
logging.basicConfig(
    level=logging.INFO,  # or DEBUG, WARNING, ERROR
    format='%(asctime)s [%(levelname)s] %(name)s: %(message)s',
    handlers=[
        logging.FileHandler("out/app.log"),        # logs to a file
        logging.StreamHandler()                # also logs to console
    ]
)
