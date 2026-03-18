import base64
import datetime
import json

from cryptography import x509
from cryptography.hazmat.primitives import serialization
from werkzeug.security import generate_password_hash

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


def get_dashboard_stats():
    db: PKIDataBase = pki.get_db()
    with db.connection():
        return db.get_dashboard_stats()


def get_ca_full_details(ca_id):
    """Returns CA record enriched with parsed certificate fields and latest CRL info."""
    ca_record = pki.get_ca_by_id(ca_id)
    if not ca_record:
        return None

    cert_pem = ca_record.get("certificate")
    if cert_pem:
        cert_bytes = cert_pem.encode("utf-8") if isinstance(cert_pem, str) else cert_pem
        try:
            cert = x509.load_pem_x509_certificate(cert_bytes)
            ca_record["subject_dn"] = cert.subject.rfc4514_string()
            ca_record["issuer_dn"] = cert.issuer.rfc4514_string()
            ca_record["not_before"] = cert.not_valid_before_utc
            ca_record["not_after"] = cert.not_valid_after_utc
            ca_record["cert_serial"] = format(cert.serial_number, "X")
        except Exception:
            ca_record["subject_dn"] = None
            ca_record["issuer_dn"] = None
            ca_record["not_before"] = None
            ca_record["not_after"] = None
            ca_record["cert_serial"] = None

    db: PKIDataBase = pki.get_db()
    with db.connection():
        crl_record = db.get_crl(ca_id)

    if crl_record:
        ca_record["crl_issue_date"] = crl_record.get("issue_date")
        ca_record["crl_next_update"] = crl_record.get("next_update")
    else:
        ca_record["crl_issue_date"] = None
        ca_record["crl_next_update"] = None

    return ca_record


def generate_crl(ca_id):
    """Generate a fresh CRL for the given CA. Returns issue/next-update dates or None."""
    crl = pki.generate_crl(ca_id)
    if crl is None:
        return None
    return {
        "issue_date": crl.last_update_utc,
        "next_update": crl.next_update_utc,
    }

def get_est_aliases():
    """Return all EST aliases without exposing password_hash to callers."""
    db: PKIDataBase = pki.get_db()
    with db.connection():
        rows = db.get_estaliases_collection()
    return [_strip_password(r) for r in rows]


def get_est_alias(alias_id: int):
    """Return a single EST alias by ID, without password_hash."""
    db: PKIDataBase = pki.get_db()
    with db.connection():
        row = db.get_est_alias(alias_id)
    return _strip_password(row) if row else None


def create_est_alias(data: dict):
    """
    Create a new EST alias.

    Required keys in data: name, ca_id, template_id, username, password.
    Optional: cert_fingerprint.

    Returns:
        dict with the new alias_id, or None on failure.
    """
    password_hash = generate_password_hash(data["password"])
    db: PKIDataBase = pki.get_db()
    with db.connection():
        new_id = db.create_est_alias(
            name=data["name"],
            ca_id=int(data["ca_id"]),
            template_id=int(data["template_id"]),
            username=data["username"],
            password_hash=password_hash,
            cert_fingerprint=data.get("cert_fingerprint"),
        )
    return {"alias_id": new_id} if new_id else None


def update_est_alias(alias_id: int, data: dict):
    """
    Update an existing EST alias.

    If 'password' key is present (and non-empty) the password is re-hashed;
    otherwise the stored hash is left unchanged.

    Returns:
        bool: True on success.
    """
    password = data.get("password") or ""
    password_hash = generate_password_hash(password) if password else None
    db: PKIDataBase = pki.get_db()
    with db.connection():
        return db.update_est_alias(
            alias_id=alias_id,
            name=data["name"],
            ca_id=int(data["ca_id"]),
            template_id=int(data["template_id"]),
            username=data["username"],
            password_hash=password_hash,
            cert_fingerprint=data.get("cert_fingerprint"),
        )


def delete_est_alias(alias_id: int):
    """Delete an EST alias. Returns True on success."""
    db: PKIDataBase = pki.get_db()
    with db.connection():
        return db.delete_est_alias(alias_id)


def set_default_est_alias(alias_id: int):
    """Set the given alias as the default. Returns True on success."""
    db: PKIDataBase = pki.get_db()
    with db.connection():
        return db.set_default_est_alias(alias_id)


def _strip_password(row: dict):
    """Remove password_hash from a row dict before sending to the web UI."""
    if row is None:
        return None
    return {k: v for k, v in row.items() if k != "password_hash"}

def get_ca_name(ca_id):
    ca_details = pki.get_ca_by_id(ca_id)
    if ca_details:
        return ca_details["name"]
    else:
        return None

def get_certificate_list(ca_id, template_id, page, per_page, offset,
                          status=None, expiring_soon=False):
    db: PKIDataBase = pki.get_db()
    with db.connection():
        total, results = db.get_certificate_list(
            ca_id, template_id, page, per_page, offset,
            status=status, expiring_soon=expiring_soon
        )
    return total, results


def get_certificate_details_json(cert_id):
    ca_details = pki.get_certificate_details(cert_id)
    return ca_details


def generate_certificate_from_csr(ca_template_config, csr_pem: bytes, return_certificate:bool = True):
    certificate_der = pki.generate_certificate_from_csr(
        csr_pem=csr_pem,
        ca_id=ca_template_config["ca_id"],
        template_id=ca_template_config["template_id"],
        request_json=None,
        validity_days=PKITools.INFINITE_VALIDITY,
        enforce_template=True,
        return_certificate=return_certificate
    )
    return certificate_der

def get_ca_certificate(est_config, data):
    ca_certificate = pki.get_ca_certificate(ca_id=est_config["ca_id"])
    if ca_certificate is None:
        return None
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


def kms_generate_key(algorithm: str, persist: bool, **kwargs):
    kms = pki.get_kms()
    return kms.generate_key(algorithm=algorithm, persist=persist, **kwargs)


def create_template(template_dict):
    db = pki.get_db()
    with db.connection():
        template_id = db.insert_cert_template(template_dict)
    if template_id:
        pki.load_template_collection()
    return template_id
