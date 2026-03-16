import base64
import datetime
import json

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


def get_ca_collection():
    ca_list = pki.get_ca_collection()
    return ca_list


def get_ca_details(ca_id):
    ca_details = pki.get_ca_by_id(ca_id)
    return ca_details

def get_est_aliases():
    db: PKIDataBase = pki.get_db()
    with db.connection():
        est_aliases = db.get_estaliases_collection()
    return est_aliases

def get_ca_name(ca_id):
    ca_details = pki.get_ca_by_id(ca_id)
    if ca_details:
        return ca_details["name"]
    else:
        return None

def get_certificate_list(ca_id, template_id, page, per_page, offset):
    db: PKIDataBase = pki.get_db()
    with db.connection():
        total, results = db.get_certificate_list(ca_id, template_id, page, per_page, offset)
    return total, results


def get_certificate_details_json(cert_id):
    ca_details = pki.get_certificate_details(cert_id)
    return ca_details


def generate_certificate_from_csr(ca_template_config, csr_pem: bytes, return_certificate:bool = True):
    pki.select_ca_by_id(ca_template_config["ca_id"])
    pki.select_cert_template_by_id(ca_template_config["template_id"])

    # Generate a ca-signed certificate
    certificate_der = pki.generate_certificate_from_csr(
        csr_pem=csr_pem,
        request_json=None,
        use_active_ca=True,
        validity_days=PKITools.INFINITE_VALIDITY, 
        enforce_template=True,
        return_certificate=return_certificate
    )
    
    return certificate_der

def get_ca_certificate(est_config, data):
    
    pki.select_ca_by_id(est_config["ca_id"])
    ca_certificate = pki.get_ca_certificate()

    return ca_certificate.public_bytes(serialization.Encoding.PEM)


def get_ca_and_template_id_by_alias_name(name):
    db = pki.get_db()
    with db.connection():
        result = db.get_ca_and_template_id_by_alias_name(name)
    return result if result else None


def get_certificate_status(cert_id:int = None, ca_id:int = None, ca_ski:str = None, serial_number:str = None):
    db = pki.get_db()
    with db.connection():
        if ca_ski is not None:
            ca_id = db.get_ca_id_by_ski(ca_ski=ca_ski)
            if ca_id is None:
                return None
        result = db.get_certificate_status(certificate_id=cert_id, ca_id=ca_id, serial_number=serial_number)
    return result if result else None


def revoke_certificate(cert_id, revocation_reason):
    try:
        return pki.revoke_certificate(cert_id, revocation_reason)
    except Exception as e:
        return False


def get_ocsp_responder_by_issuer_ski(issuer_ski):
    return pki.get_ocsp_responder_by_issuer_ski(issuer_ski=issuer_ski)


def get_template_collection():
    template_list = pki.get_template_collection()
    return template_list


def get_template_details(template_id):
    db = pki.get_db()
    with db.connection():
        record = db.get_cert_template_record_by_id(template_id)
    if not record:
        return None
    definition = record.get("definition")
    if isinstance(definition, str):
        return json.loads(definition)
    return definition


def export_cert_template(template_id):
    db = pki.get_db()
    with db.connection():
        return db.export_cert_template(template_id)


def update_template(template_id, template_dict):
    db = pki.get_db()
    with db.connection():
        success = db.update_cert_template(template_id, template_dict)
    if success:
        pki.load_template_collection()
    return success


def create_template(template_dict):
    db = pki.get_db()
    with db.connection():
        template_id = db.insert_cert_template(template_dict)
    if template_id:
        pki.load_template_collection()
    return template_id
