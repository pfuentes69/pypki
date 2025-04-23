import base64
import datetime

from cryptography.hazmat.primitives import serialization

from pypki import PKITools, PKIDataBase

from . import pki

def convert_to_serializable(obj):
    if isinstance(obj, dict):
        return {k: convert_to_serializable(v) for k, v in obj.items()}
    elif isinstance(obj, list):
        return [convert_to_serializable(i) for i in obj]
    elif isinstance(obj, bytes):
        try:
            return obj.decode('utf-8')
        except UnicodeDecodeError:
            return base64.b64encode(obj).decode('utf-8')
    elif isinstance(obj, datetime.datetime):
        return obj.isoformat()
    else:
        return obj

def process_input(data):
    # Transform input if needed, pass to core logic
    result = "SOMETHING"
    return {"result": result}


def get_ca_collection_json():
    ca_list = pki.get_ca_collection()
    return ca_list


def get_ca_details_json(ca_id):
    ca_details = pki.get_ca_by_id(ca_id)
    return ca_details

def get_est_aliases():
    db:PKIDataBase = pki.get_db()
    db.connect_to_db()
    est_aliases = db.get_estaliases_collection()
    db.close_db()

    return est_aliases

def get_ca_name(ca_id):
    ca_details = pki.get_ca_by_id(ca_id)
    if ca_details:
        return ca_details["name"]
    else:
        return None


def get_certificate_details_json(cert_id):
    ca_details = pki.get_certificate_details(cert_id)
    return ca_details


def generate_certificate_from_csr(ca_template_config, csr_pem: bytes):
    pki.select_ca_by_id(ca_template_config["ca_id"])
    pki.select_cert_template_by_id(ca_template_config["template_id"])

    # Generate a ca-signed certificate
    certificate_der = pki.generate_certificate_from_csr(
        csr_pem=csr_pem,
        request_json=None,
        use_active_ca=True,
        validity_days=PKITools.INFINITE_VALIDITY, 
        enforce_template=True
    )
    
    return certificate_der

def get_ca_certificate(est_config, data):
    
    pki.select_ca_by_id(est_config["ca_id"])
    ca_certificate = pki.get_ca_certificate()

    return ca_certificate.public_bytes(serialization.Encoding.PEM)


def get_ca_and_template_id_by_alias_name(name):
    """
    Retrieve ca_id and template_id from ESTAliases by name.

    Args:
        db_config (dict): A dictionary containing database connection parameters.
        name (str): The name to look up in the ESTAliases table.

    Returns:
        tuple or None: A tuple (ca_id, template_id) if found, otherwise None.
    """
    db = pki.get_db()
    db.connect_to_db()
    result = db.get_ca_and_template_id_by_alias_name(name)
    db.close_db()

    return result if result else None


def get_certificate_status(cert_id:int = None, ca_id:int = None, ca_ski:str = None, serial_number:str = None):
    """
    Retrieve ca_id and template_id from ESTAliases by name.

    Args:
        db_config (dict): A dictionary containing database connection parameters.
        name (str): The name to look up in the ESTAliases table.

    Returns:
        tuple or None: A tuple (ca_id, template_id) if found, otherwise None.
    """
    db = pki.get_db()
    db.connect_to_db()
    if ca_ski is not None:
        ca_id = db.get_ca_id_by_ski(ca_ski=ca_ski)
        if ca_id is None:
            return None
    result = db.get_certificate_status(certificate_id=cert_id, ca_id=ca_id, serial_number=serial_number)
    db.close_db()

    return result if result else None

def get_ocsp_responder_by_issuer_ski(issuer_ski):
    return pki.get_ocsp_responder_by_issuer_ski(issuer_ski=issuer_ski)