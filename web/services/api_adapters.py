import base64
import datetime
import json
import os

import jwt
from cryptography import x509
from cryptography.hazmat.primitives import serialization
from werkzeug.security import generate_password_hash, check_password_hash

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
        return obj.strftime('%Y-%m-%dT%H:%M:%SZ')
    else:
        return obj

# ── Audit Logs ────────────────────────────────────────────────────────────────

def write_audit_log(resource_type: str, resource_id, action: str, user_id: int = 0):
    db = pki.get_db()
    with db.connection():
        db.write_audit_log(resource_type, resource_id, action, user_id)


def get_audit_logs(page: int = 1, per_page: int = 25):
    db = pki.get_db()
    with db.connection():
        return db.get_audit_logs(page, per_page)


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


def update_ca(ca_id: int, data: dict, user_id: int = 0):
    """
    Update editable CA fields. Returns True on success.

    Accepted keys: name, max_validity, serial_number_length, crl_validity, extensions.
    `extensions` should be a dict; it is serialised to JSON here.
    """
    fields = {}
    if "name" in data and data["name"]:
        fields["name"] = data["name"].strip()
    for int_field in ("max_validity", "serial_number_length", "crl_validity"):
        if int_field in data and data[int_field] is not None:
            fields[int_field] = int(data[int_field])
    if "extensions" in data:
        ext = data["extensions"]
        fields["extensions"] = json.dumps(ext) if isinstance(ext, dict) else ext
    if not fields:
        return False
    db = pki.get_db()
    with db.connection():
        ok = db.update_ca(ca_id, fields)
    if ok:
        pki.load_ca_collection()
        write_audit_log("cas", ca_id, "UPDATE", user_id)
    return ok


def _verify_kms_key_for_ca(kms_key_id: int, cert_pem: str) -> None:
    """
    Validate that an existing KMS key is suitable for binding to a new CA.

    Raises ValueError if:
      - the key id does not exist in KeyStorage
      - the stored public key does not match the certificate's SPKI
      - the key is already referenced by another CA
    """
    db: PKIDataBase = pki.get_db()
    with db.connection():
        record = db.get_key_record(kms_key_id)
        existing_ca_id = db.get_ca_id_by_key_reference(kms_key_id)

    if not record:
        raise ValueError(f"kms_key_id {kms_key_id} not found in KeyStorage")
    if existing_ca_id is not None:
        raise ValueError(
            f"kms_key_id {kms_key_id} is already referenced by CA id {existing_ca_id}"
        )

    stored_pub_pem = record.get("public_key")
    if not stored_pub_pem:
        raise ValueError(
            f"kms_key_id {kms_key_id} has no public_key in KeyStorage; "
            "it cannot be bound to a CA"
        )

    try:
        cert = x509.load_pem_x509_certificate(cert_pem.encode("utf-8"))
    except Exception as e:
        raise ValueError(f"Invalid CA certificate PEM: {e}")

    cert_spki_der = cert.public_key().public_bytes(
        serialization.Encoding.DER,
        serialization.PublicFormat.SubjectPublicKeyInfo,
    )
    try:
        stored_pub = serialization.load_pem_public_key(stored_pub_pem.encode("utf-8"))
    except Exception as e:
        raise ValueError(f"Stored public key for kms_key_id {kms_key_id} is unreadable: {e}")
    stored_spki_der = stored_pub.public_bytes(
        serialization.Encoding.DER,
        serialization.PublicFormat.SubjectPublicKeyInfo,
    )
    if cert_spki_der != stored_spki_der:
        raise ValueError(
            "Certificate public key does not match the public key stored "
            f"for kms_key_id {kms_key_id}"
        )


def create_ca(data: dict, user_id: int = 0) -> int:
    """
    Create a new CA from a validated data dict.

    Required keys:
        name, certificate (PEM), and either private_key (PEM) or kms_key_id (int)
    Optional keys:
        certificate_chain (PEM), max_validity (int, default -1),
        serial_number_length (int, default 10), crl_validity (int, default 365),
        extensions (dict)

    Returns the new CA's database ID.
    """
    raw_kms_key_id = data.get("kms_key_id")
    kms_key_id = None
    if raw_kms_key_id is not None and raw_kms_key_id != "":
        try:
            kms_key_id = int(raw_kms_key_id)
        except (TypeError, ValueError):
            raise ValueError("kms_key_id must be an integer")
        _verify_kms_key_for_ca(kms_key_id, data["certificate"])

    config = {
        "ca_name": data["name"],
        "max_validity": int(data.get("max_validity", -1)),
        "serial_number_length": int(data.get("serial_number_length", 10)),
        "crl_validity": int(data.get("crl_validity", 365)),
        "extensions": data.get("extensions") or {},
        "crypto": {
            "certificate": data["certificate"],
            "private_key": data.get("private_key"),
            "kms_key_id": kms_key_id,
            "certificate_chain": data.get("certificate_chain") or "",
        },
    }
    new_id = pki.create_ca_from_config_json(json.dumps(config))
    write_audit_log("cas", new_id, "CREATE", user_id)
    return new_id


def delete_ca(ca_id: int, user_id: int = 0):
    """
    Delete a CA and all its dependent resources.
    Returns the stats dict from db.delete_ca(), or None if the CA was not found.
    Raises on database error.
    """
    stats = pki.delete_ca(ca_id)
    if stats is not None:
        write_audit_log("cas", ca_id, "DELETE", user_id)
    return stats


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


def create_est_alias(data: dict, user_id: int = 0):
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
    if new_id:
        write_audit_log("est_aliases", new_id, "CREATE", user_id)
    return {"alias_id": new_id} if new_id else None


def update_est_alias(alias_id: int, data: dict, user_id: int = 0):
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
        ok = db.update_est_alias(
            alias_id=alias_id,
            name=data["name"],
            ca_id=int(data["ca_id"]),
            template_id=int(data["template_id"]),
            username=data["username"],
            password_hash=password_hash,
            cert_fingerprint=data.get("cert_fingerprint"),
        )
    if ok:
        write_audit_log("est_aliases", alias_id, "UPDATE", user_id)
    return ok


def delete_est_alias(alias_id: int, user_id: int = 0):
    """Delete an EST alias. Returns True on success."""
    db: PKIDataBase = pki.get_db()
    with db.connection():
        ok = db.delete_est_alias(alias_id)
    if ok:
        write_audit_log("est_aliases", alias_id, "DELETE", user_id)
    return ok


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


def generate_certificate_from_csr(ca_template_config, csr_pem: bytes,
                                   return_certificate: bool = True,
                                   request_json: str = None,
                                   user_id: int = 0):
    certificate_der = pki.generate_certificate_from_csr(
        csr_pem=csr_pem,
        ca_id=ca_template_config["ca_id"],
        template_id=ca_template_config["template_id"],
        request_json=request_json,
        validity_days=PKITools.INFINITE_VALIDITY,
        enforce_template=True,
        return_certificate=return_certificate
    )
    # certificate_der is the cert_id when return_certificate=False
    cert_id = certificate_der if not return_certificate else None
    write_audit_log("certificates", cert_id, "CREATE", user_id)
    return certificate_der

def generate_pkcs12(ca_template_config, request_json: str,
                    key_algorithm: str = "RSA", key_type: str = "2048",
                    pfx_password: bytes = b"", friendly_name: bytes = b"MyCert",
                    store_key: bool = False, user_id: int = 0):
    p12_bytes, cert_id = pki.generate_pkcs12(
        request_json=request_json,
        ca_id=ca_template_config["ca_id"],
        template_id=ca_template_config["template_id"],
        key_algorithm=key_algorithm,
        key_type=key_type,
        pfx_password=pfx_password,
        friendly_name=friendly_name,
        validity_days=PKITools.INFINITE_VALIDITY,
        store_key=store_key,
    )
    write_audit_log("certificates", cert_id, "CREATE", user_id)
    return p12_bytes, cert_id


def get_certificate_private_key_pem(cert_id: int):
    """Returns (pem_str, storage_type) or (None, None)."""
    return pki.get_certificate_private_key_pem(cert_id)


def build_pkcs12_for_certificate(cert_id: int, pfx_password: bytes = b""):
    return pki.build_pkcs12_for_certificate(cert_id, pfx_password=pfx_password)


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


def parse_csr(csr_pem: str) -> dict:
    """Parse a PEM CSR and return subject fields and SAN values."""
    from cryptography import x509
    from cryptography.x509.oid import NameOID

    csr_bytes = csr_pem.encode() if isinstance(csr_pem, str) else csr_pem
    csr = x509.load_pem_x509_csr(csr_bytes)

    OID_MAP = {
        NameOID.COMMON_NAME:              "commonName",
        NameOID.COUNTRY_NAME:             "countryName",
        NameOID.STATE_OR_PROVINCE_NAME:   "stateOrProvinceName",
        NameOID.LOCALITY_NAME:            "localityName",
        NameOID.ORGANIZATION_NAME:        "organizationName",
        NameOID.ORGANIZATIONAL_UNIT_NAME: "organizationalUnitName",
        NameOID.SERIAL_NUMBER:            "serialNumber",
        NameOID.EMAIL_ADDRESS:            "emailAddress",
        NameOID.GIVEN_NAME:               "givenName",
        NameOID.SURNAME:                  "surname",
        NameOID.TITLE:                    "title",
        NameOID.STREET_ADDRESS:           "streetAddress",
        NameOID.POSTAL_CODE:              "postalCode",
        NameOID.PSEUDONYM:                "pseudonym",
        NameOID.DOMAIN_COMPONENT:         "domainComponent",
        NameOID.USER_ID:                  "userId",
    }

    subject = {}
    for attr in csr.subject:
        key = OID_MAP.get(attr.oid)
        if key:
            subject[key] = attr.value

    san = {}
    try:
        san_ext = csr.extensions.get_extension_for_oid(
            x509.ExtensionOID.SUBJECT_ALTERNATIVE_NAME
        )
        v = san_ext.value
        dns    = list(v.get_values_for_type(x509.DNSName))
        ips    = [str(ip) for ip in v.get_values_for_type(x509.IPAddress)]
        emails = list(v.get_values_for_type(x509.RFC822Name))
        uris   = list(v.get_values_for_type(x509.UniformResourceIdentifier))
        if dns:    san["dnsNames"] = dns
        if ips:    san["ipAddresses"] = ips
        if emails: san["emailAddresses"] = emails
        if uris:   san["uris"] = uris
    except x509.ExtensionNotFound:
        pass

    return {"subject": subject, "san": san}


def revoke_certificate(cert_id, revocation_reason, user_id: int = 0):
    try:
        ok = pki.revoke_certificate(cert_id, revocation_reason)
        if ok:
            write_audit_log("certificates", cert_id, "REVOKE", user_id)
        return ok
    except Exception:
        return False


def get_ocsp_responder_by_issuer_ski(issuer_ski):
    return pki.get_ocsp_responder_by_issuer_ski(issuer_ski=issuer_ski)

def get_ocsp_responders_list():
    return pki.get_ocsp_responders_list()

def get_ocsp_responder_by_id(responder_id):
    return pki.get_ocsp_responder_by_id(responder_id)

def update_ocsp_responder_settings(responder_id, settings):
    pki.update_ocsp_responder_settings(responder_id, settings)

def delete_ocsp_responder(responder_id):
    pki.delete_ocsp_responder(responder_id)

def create_ocsp_responder(data: dict) -> int:
    return pki.create_ocsp_responder(data)


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


def update_template(template_id, template_dict, user_id: int = 0):
    db = pki.get_db()
    with db.connection():
        success = db.update_cert_template(template_id, template_dict)
    if success:
        pki.load_template_collection()
        write_audit_log("templates", template_id, "UPDATE", user_id)
    return success


def kms_generate_key(algorithm: str, persist: bool, **kwargs):
    kms = pki.get_kms()
    return kms.generate_key(algorithm=algorithm, persist=persist, **kwargs)


# ── Crypto provider management (Phase 4: activation lifecycle) ───────────────
#
# Full CRUD lands in Phase 5; this is the read-only + activation surface.
# See doc/kms-strategy.md §9.1.

def _sanitise_provider(record: dict) -> dict:
    """Drop secret material before returning a provider record over the API."""
    if not record:
        return record
    safe = dict(record)
    safe.pop("auth_secret_blob", None)
    return safe


def list_crypto_providers():
    db: PKIDataBase = pki.get_db()
    with db.connection():
        rows = db.list_providers()
    return [_sanitise_provider(r) for r in rows]


def get_crypto_provider(provider_id: int):
    db: PKIDataBase = pki.get_db()
    with db.connection():
        row = db.get_provider_by_id(provider_id)
    return _sanitise_provider(row)


def get_crypto_provider_status(provider_id: int):
    return pki.get_kms().get_provider_status(provider_id)


def activate_crypto_provider(provider_id: int, pin: str = None, user_id: int = 0):
    """
    Activate a provider via the KMS. Records an audit-log entry on success;
    re-raises on failure so the route handler can map to an HTTP status.
    """
    pki.get_kms().activate_provider(provider_id, pin=pin)
    write_audit_log(
        "crypto_providers", provider_id,
        "ACTIVATE_OPERATOR" if pin else "ACTIVATE",
        user_id,
    )


def deactivate_crypto_provider(provider_id: int, user_id: int = 0):
    pki.get_kms().deactivate_provider(provider_id)
    write_audit_log("crypto_providers", provider_id, "DEACTIVATE", user_id)


# ── Provider CRUD (Phase 5a) ─────────────────────────────────────────────────

# Fields the API accepts on POST/PUT. `kind` and `is_default` are intentionally
# excluded from the update path; `is_default` only flips through reset_pki.
_CREATE_FIELDS = {
    "label", "kind", "module_path", "slot_label", "auth_kind",
    "auto_activate", "auth_secret_ref", "extra_json", "description",
}
_UPDATE_FIELDS = _CREATE_FIELDS - {"kind"}


def create_crypto_provider(payload: dict, user_id: int = 0) -> int:
    """
    Insert a new CryptoProviders row. Validates auth_secret_ref/auto_activate
    consistency and (when ``auth_secret_ref='db:encrypted'``) encrypts the
    operator-supplied PIN under the master KEK before storing.

    The payload may contain ``pin`` (plaintext) which is consumed and never
    persisted as plaintext: it is encrypted into ``auth_secret_blob`` for
    db:encrypted, and ignored otherwise.

    Returns the new provider id; raises ValueError on validation failure.
    """
    db: PKIDataBase = pki.get_db()
    record = {k: payload.get(k) for k in _CREATE_FIELDS if k in payload}
    record.setdefault("auth_kind", "pin")
    record.setdefault("auto_activate", False)
    record.setdefault("extra_json", "{}")

    if not record.get("label"):
        raise ValueError("label is required")
    if record.get("kind") not in ("software", "pkcs11"):
        raise ValueError("kind must be 'software' or 'pkcs11'")
    if record["kind"] == "pkcs11" and not record.get("module_path"):
        raise ValueError("module_path is required for kind='pkcs11'")

    pin = payload.get("pin")
    if record.get("auth_secret_ref") == "db:encrypted":
        if not pin:
            raise ValueError(
                "auth_secret_ref='db:encrypted' requires a 'pin' field in the payload"
            )
        from pypki.key_encryption import encrypt_provider_pin
        record["auth_secret_blob"] = encrypt_provider_pin(pin.encode("utf-8"))

    PKIDataBase.validate_provider_auth_config(record)

    with db.connection():
        new_id = db.insert_provider(
            label=record["label"],
            kind=record["kind"],
            auth_secret_ref=record.get("auth_secret_ref") or "operator:prompt",
            module_path=record.get("module_path"),
            slot_label=record.get("slot_label"),
            auth_kind=record.get("auth_kind", "pin"),
            auto_activate=bool(record.get("auto_activate")),
            auth_secret_blob=record.get("auth_secret_blob"),
            extra_json=record.get("extra_json") or "{}",
            description=record.get("description"),
            is_default=False,
        )
    if new_id is None:
        raise RuntimeError("Failed to create CryptoProviders row")
    write_audit_log("crypto_providers", new_id, "CREATE", user_id)
    return new_id


def update_crypto_provider(provider_id: int, payload: dict, user_id: int = 0) -> bool:
    """
    Update a provider. Validates the resulting record and re-encrypts the
    PIN if a new one is supplied for ``auth_secret_ref='db:encrypted'``.
    Returns True if anything changed.
    """
    db: PKIDataBase = pki.get_db()
    with db.connection():
        existing = db.get_provider_by_id(provider_id)
    if not existing:
        raise KeyError(f"crypto_provider id={provider_id} not found")

    fields = {k: payload[k] for k in _UPDATE_FIELDS if k in payload}

    # Re-encrypt the PIN on demand. If the operator changes auth_secret_ref
    # from db:encrypted to something else, drop the stored blob.
    new_ref = fields.get("auth_secret_ref", existing.get("auth_secret_ref"))
    pin = payload.get("pin")
    if new_ref == "db:encrypted" and pin:
        from pypki.key_encryption import encrypt_provider_pin
        fields["auth_secret_blob"] = encrypt_provider_pin(pin.encode("utf-8"))
    elif new_ref != "db:encrypted":
        fields["auth_secret_blob"] = None

    # Build the merged record for validation.
    merged = dict(existing)
    merged.update(fields)
    PKIDataBase.validate_provider_auth_config(merged)

    # Track the auto_activate flip separately so it's audit-loggable.
    auto_changed = (
        "auto_activate" in fields
        and bool(fields["auto_activate"]) != bool(existing.get("auto_activate"))
    )

    with db.connection():
        ok = db.update_provider(provider_id, fields)
    if ok:
        write_audit_log("crypto_providers", provider_id, "UPDATE", user_id)
        if auto_changed:
            write_audit_log(
                "crypto_providers", provider_id, "AUTO_ACTIVATE_TOGGLED", user_id
            )
    return ok


def delete_crypto_provider(provider_id: int, user_id: int = 0) -> dict | None:
    """Delete a provider. Maps to 200 / 404 / 409 in the route handler."""
    db: PKIDataBase = pki.get_db()
    # Make sure no backend session is left dangling for this provider.
    try:
        pki.get_kms().deactivate_provider(provider_id)
    except Exception:
        logger.warning(
            f"crypto_provider delete: deactivate failed for id={provider_id}; "
            f"proceeding with DB delete",
            exc_info=True,
        )
    with db.connection():
        result = db.delete_provider(provider_id)
    if result and result.get("deleted"):
        write_audit_log("crypto_providers", provider_id, "DELETE", user_id)
    return result


# ── Key management (Phase 5a) ────────────────────────────────────────────────

def list_kms_keys(provider_id: int = None, key_type: str = None):
    db: PKIDataBase = pki.get_db()
    with db.connection():
        rows = db.list_keys(provider_id=provider_id, key_type=key_type)
        # Annotate each row with a usage summary so the UI can show "in use".
        for r in rows:
            r["usage"] = db.count_key_usage(r["id"])
    return rows


def get_kms_key(key_id: int):
    db: PKIDataBase = pki.get_db()
    with db.connection():
        row = db.get_key_record(key_id)
        if not row:
            return None
        # Strip the encrypted/plain private material.
        row.pop("private_key", None)
        row.pop("token_password", None)
        row["usage"] = db.count_key_usage(key_id)
    return row


def generate_kms_key(provider_id: int, key_type: str, label: str = None,
                     user_id: int = 0) -> dict:
    result = pki.get_kms().generate_key_in_provider(
        provider_id, key_type=key_type, label=label,
    )
    write_audit_log("kms_keys", result["key_id"], "GENERATE", user_id)
    return result


def import_pkcs11_kms_key(provider_id: int, hsm_token_id: str,
                          label: str = None, user_id: int = 0) -> dict:
    result = pki.get_kms().import_pkcs11_key(
        provider_id, hsm_token_id, label=label,
    )
    write_audit_log("kms_keys", result["key_id"], "IMPORT", user_id)
    return result


def delete_kms_key(key_id: int, user_id: int = 0) -> dict | None:
    result = pki.get_kms().delete_key(key_id)
    if result and result.get("deleted"):
        write_audit_log("kms_keys", key_id, "DELETE", user_id)
    return result


def create_template(template_dict, user_id: int = 0):
    db = pki.get_db()
    with db.connection():
        template_id = db.insert_cert_template(template_dict)
    if template_id:
        pki.load_template_collection()
        write_audit_log("templates", template_id, "CREATE", user_id)
    return template_id


# ── User management ───────────────────────────────────────────────────────────

def get_users():
    db = pki.get_db()
    with db.connection():
        return db.get_users()


def get_user(user_id: int):
    db = pki.get_db()
    with db.connection():
        return db.get_user(user_id)


def create_user(data: dict, actor_id: int = 0):
    username = (data.get("username") or "").strip()
    password = data.get("password") or ""
    role     = data.get("role") or "user"
    if not username or not password:
        return None
    password_hash = generate_password_hash(password)
    db = pki.get_db()
    with db.connection():
        new_id = db.create_user(username, password_hash, role)
    if new_id:
        write_audit_log("users", new_id, "CREATE", actor_id)
    return new_id


def update_user(user_id: int, data: dict, actor_id: int = 0):
    fields = {}
    if "username" in data and data["username"]:
        fields["username"] = data["username"].strip()
    if "role" in data and data["role"]:
        fields["role"] = data["role"]
    if "is_active" in data:
        fields["is_active"] = bool(data["is_active"])
    if data.get("password"):
        fields["password_hash"] = generate_password_hash(data["password"])
    if not fields:
        return False
    db = pki.get_db()
    with db.connection():
        ok = db.update_user(user_id, fields)
    if ok:
        write_audit_log("users", user_id, "UPDATE", actor_id)
    return ok


def delete_user(user_id: int, actor_id: int = 0):
    db = pki.get_db()
    with db.connection():
        ok = db.delete_user(user_id)
    if ok:
        write_audit_log("users", user_id, "DELETE", actor_id)
    return ok


# ── Authentication ─────────────────────────────────────────────────────────────

def get_secret_key() -> str:
    return pki.get_config_value("secret_key", "change-me-in-production")


def authenticate_user(username: str, password: str):
    """Return user dict (without password_hash) if credentials are valid, else None."""
    db = pki.get_db()
    with db.connection():
        user = db.get_user_by_username(username)
    if not user:
        return None
    if not check_password_hash(user.get("password_hash", ""), password):
        return None
    user.pop("password_hash", None)
    return user


def record_login(user_id: int):
    db = pki.get_db()
    with db.connection():
        db.update_last_login(user_id)


_BACKUP_DIR = os.path.join("out", "backup")


def list_backups() -> list:
    """Return backup files sorted newest-first."""
    import glob
    files = sorted(glob.glob(os.path.join(_BACKUP_DIR, "*.bak")), reverse=True)
    result = []
    for path in files:
        name = os.path.basename(path)
        result.append({"filename": name, "size": os.path.getsize(path)})
    return result


def reset_pki_database() -> dict:
    """Drop and recreate all tables, then seed defaults from config files."""
    pki.reset_pki()
    # Reload in-memory state to reflect the fresh DB
    pki.load_template_collection()
    pki.load_ca_collection()
    pki.load_ocsp_responders()
    return {"reset": True}


def restore_database(filename: str) -> dict:
    """Restore the DB from a named backup file."""
    # Reject any path traversal attempts
    if os.sep in filename or "/" in filename or ".." in filename:
        raise ValueError("Invalid filename")
    backup_file = os.path.join(_BACKUP_DIR, filename)
    if not os.path.isfile(backup_file):
        raise FileNotFoundError(f"Backup not found: {filename}")
    pki.restore_backup(backup_file)
    return {"restored": filename}


def _sql_escape(v) -> str:
    """Return a properly escaped SQL literal for a Python value."""
    if v is None:
        return "NULL"
    if isinstance(v, bytes):
        # Use hex notation — no quoting issues whatsoever
        return "0x" + v.hex()
    if isinstance(v, bool):
        return "1" if v else "0"
    if isinstance(v, (int, float)):
        return str(v)
    # String (including datetime stringified below)
    s = str(v)
    # Escape in MySQL string-literal order (backslash first!)
    s = s.replace("\\", "\\\\")
    s = s.replace("'",  "\\'")
    s = s.replace("\n", "\\n")
    s = s.replace("\r", "\\r")
    s = s.replace("\0", "\\0")
    return f"'{s}'"


def backup_database() -> dict:
    """Dump the MySQL database to out/backup/YYYYmmddHHMM.bak using mysql.connector."""
    import mysql.connector

    db_cfg = pki.get_config_value("db_config", {})
    host     = db_cfg.get("host", "localhost")
    port     = int(db_cfg.get("port", 3306))
    user     = db_cfg.get("user", "root")
    password = db_cfg.get("password", "")
    database = db_cfg.get("database", "")

    backup_dir = os.path.join("out", "backup")
    os.makedirs(backup_dir, exist_ok=True)

    timestamp = datetime.datetime.now().strftime("%Y%m%d%H%M")
    backup_file = os.path.join(backup_dir, f"{timestamp}.bak")

    conn = mysql.connector.connect(
        host=host, port=port, user=user, password=password, database=database
    )
    try:
        cursor = conn.cursor()
        with open(backup_file, "w", encoding="utf-8") as f:
            f.write(f"-- PyPKI database backup\n")
            f.write(f"-- Created: {datetime.datetime.now().isoformat()}\n")
            f.write(f"-- Database: {database}\n\n")
            f.write("SET FOREIGN_KEY_CHECKS=0;\n\n")

            cursor.execute("SHOW TABLES")
            tables = [row[0] for row in cursor.fetchall()]

            for table in tables:
                # Table structure
                cursor.execute(f"SHOW CREATE TABLE `{table}`")
                create_stmt = cursor.fetchone()[1]
                f.write(f"DROP TABLE IF EXISTS `{table}`;\n")
                f.write(f"{create_stmt};\n\n")

                # Table data
                cursor.execute(f"SELECT * FROM `{table}`")
                rows = cursor.fetchall()
                if rows:
                    col_names = ", ".join(f"`{d[0]}`" for d in cursor.description)
                    for row in rows:
                        values = ", ".join(_sql_escape(v) for v in row)
                        f.write(f"INSERT INTO `{table}` ({col_names}) VALUES ({values});\n")
                    f.write("\n")

            f.write("SET FOREIGN_KEY_CHECKS=1;\n")
        cursor.close()
    finally:
        conn.close()

    size = os.path.getsize(backup_file)
    return {"filename": f"{timestamp}.bak", "path": backup_file, "size": size}


def validate_jwt_token(token: str):
    """Decode and validate a JWT. Returns user dict or None."""
    from pypki import logger
    secret_key = get_secret_key()
    try:
        payload = jwt.decode(token, secret_key, algorithms=["HS256"])
        return {
            "id": int(payload["sub"]),
            "username": payload["username"],
            "role": payload["role"],
        }
    except Exception as e:
        logger.warning(f"JWT validation failed: {type(e).__name__}: {e}")
        return None
