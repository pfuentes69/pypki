"""CA in-app issuance service (CR-0001).

Implements the two-axis matrix (issuance scenario × key source) defined
in doc/ca-management-specs.md §17.1: root, internal-subordinate, and
external-subordinate, each in generate-fresh or bind-existing variants.
The install-cert path completes the external-subordinate flow.
"""

import json
from datetime import datetime, timedelta, timezone

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa, ec
from cryptography.hazmat.primitives.asymmetric.utils import (
    decode_dss_signature, encode_dss_signature,
)
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat

from asn1crypto import x509 as asn1_x509
from asn1crypto.csr import CertificationRequest as asn1_csr
from asn1crypto.core import OctetBitString

from pypki import logger
from pypki.db import CAStateError
from . import pki
from .api_adapters import write_audit_log


# ── Helpers ──────────────────────────────────────────────────────────────────

def _parse_dn(subject_dn: str) -> x509.Name:
    return x509.Name.from_rfc4514_string(subject_dn)


def _spki_method1(public_key) -> bytes:
    """RFC 5280 §4.2.1.2 Method 1 SubjectKeyIdentifier bytes."""
    if isinstance(public_key, ec.EllipticCurvePublicKey):
        key_bytes = public_key.public_bytes(Encoding.X962, PublicFormat.UncompressedPoint)
    else:
        key_bytes = public_key.public_bytes(Encoding.DER, PublicFormat.PKCS1)
    digest = hashes.Hash(hashes.SHA1())
    digest.update(key_bytes)
    return digest.finalize()


def _ski_hex_from_cert(cert: x509.Certificate) -> str:
    try:
        ext = cert.extensions.get_extension_for_class(x509.SubjectKeyIdentifier)
        return ext.value.digest.hex()
    except x509.ExtensionNotFound:
        return _spki_method1(cert.public_key()).hex()


def _load_kms_pub_key(kms_key_id: int):
    """Return (cryptography public_key, KeyStorage record dict) for a KMS-bound key."""
    db = pki.get_db()
    with db.connection():
        record = db.get_key_record(kms_key_id)
    if not record:
        raise ValueError(f"kms_key_id {kms_key_id} not found in KeyStorage")
    if not record.get("public_key"):
        raise ValueError(
            f"kms_key_id {kms_key_id} has no public_key in KeyStorage; cannot be used"
        )
    pub_key = serialization.load_pem_public_key(record["public_key"].encode("utf-8"))
    return pub_key, record


def _dummy_key_matching(public_key):
    """Generate a throw-away key matching *public_key*'s algorithm.

    The `cryptography` library's `CertificateBuilder.sign` / CSR `.sign`
    require a real private key to produce a syntactically valid TBS; the
    real signature is patched in afterwards (see `_patch_*_signature`).
    Returns (private_key, is_ecdsa).
    """
    if isinstance(public_key, ec.EllipticCurvePublicKey):
        return ec.generate_private_key(public_key.curve), True
    return rsa.generate_private_key(public_exponent=65537, key_size=public_key.key_size), False


def _patch_cert_signature(pre_cert_der: bytes, real_signature: bytes, is_ecdsa: bool) -> bytes:
    cert = asn1_x509.Certificate.load(pre_cert_der)
    if is_ecdsa:
        r, s = decode_dss_signature(real_signature)
        cert["signature_value"] = OctetBitString(encode_dss_signature(r, s))
    else:
        cert["signature_value"] = OctetBitString(real_signature)
    return cert.dump()


def _patch_csr_signature(pre_csr_der: bytes, real_signature: bytes, is_ecdsa: bool) -> bytes:
    req = asn1_csr.load(pre_csr_der)
    if is_ecdsa:
        r, s = decode_dss_signature(real_signature)
        req["signature"] = OctetBitString(encode_dss_signature(r, s))
    else:
        req["signature"] = OctetBitString(real_signature)
    return req.dump()


def _ca_extensions(signing_pub_key, subject_pub_key):
    """Standard CA-cert extension block: BasicConstraints CA, KeyUsage, SKI, AKI."""
    return [
        (x509.BasicConstraints(ca=True, path_length=None), True),
        (x509.KeyUsage(
            digital_signature=False, content_commitment=False, key_encipherment=False,
            data_encipherment=False, key_agreement=False, key_cert_sign=True,
            crl_sign=True, encipher_only=False, decipher_only=False,
        ), True),
        (x509.SubjectKeyIdentifier(_spki_method1(subject_pub_key)), False),
        (x509.AuthorityKeyIdentifier(
            key_identifier=_spki_method1(signing_pub_key),
            authority_cert_issuer=None, authority_cert_serial_number=None,
        ), False),
    ]


def _resolve_key_source(data: dict):
    """Resolve the signing key. Returns (signing_key_id, key_owned, signing_pub_key).

    Honours decision 10 (XOR between generate-fresh and bind-existing). For the
    bind branch, verifies the key is unbound. For the generate branch, drives
    the KMS to create a new KeyStorage row. Raises ValueError on validation
    failure or after a failed KMS call.
    """
    has_generate = data.get("provider_id") is not None or data.get("key_type") is not None
    has_bind = data.get("kms_key_id") is not None
    if has_generate and has_bind:
        raise ValueError("Provide either (provider_id + key_type) or kms_key_id, not both")
    if not has_generate and not has_bind:
        raise ValueError("One of (provider_id + key_type) or kms_key_id is required")

    db = pki.get_db()
    if has_bind:
        kms_key_id = int(data["kms_key_id"])
        with db.connection():
            existing_ca = db.get_ca_id_by_key_reference(kms_key_id)
        if existing_ca is not None:
            raise ValueError(
                f"kms_key_id {kms_key_id} is already referenced by CA id {existing_ca}"
            )
        pub_key, _record = _load_kms_pub_key(kms_key_id)
        return kms_key_id, False, pub_key

    # generate-fresh
    if not data.get("provider_id"):
        raise ValueError("provider_id is required for key generation")
    if not data.get("key_type"):
        raise ValueError("key_type is required for key generation")
    provider_id = int(data["provider_id"])
    key_type = data["key_type"]
    key_label = data.get("key_label") or data.get("name")
    kms = pki.get_kms()
    try:
        result = kms.generate_key_in_provider(provider_id, key_type, label=key_label)
    except Exception as e:
        # Surface KMS errors as ValueError so the API layer can map to 400.
        raise ValueError(f"Key generation failed: {e}") from e
    new_id = result["key_id"]
    pub_key, _record = _load_kms_pub_key(new_id)
    return new_id, True, pub_key


# ── Phase 1 builders ─────────────────────────────────────────────────────────

def _build_root_cert(data, signing_key_id, signing_pub_key) -> str:
    """Build a self-signed root CA certificate signed via the KMS. Returns PEM."""
    subject = _parse_dn(data["subject_dn"])
    validity_days = int(data["validity_days"])
    not_valid_before = datetime.now(timezone.utc)
    not_valid_after = not_valid_before + timedelta(days=validity_days)

    builder = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(subject)
        .public_key(signing_pub_key)
        .serial_number(x509.random_serial_number())
        .not_valid_before(not_valid_before)
        .not_valid_after(not_valid_after)
    )
    for ext, critical in _ca_extensions(signing_pub_key, signing_pub_key):
        builder = builder.add_extension(ext, critical)

    dummy_key, is_ecdsa = _dummy_key_matching(signing_pub_key)
    pre_cert = builder.sign(private_key=dummy_key, algorithm=hashes.SHA256())

    digest = hashes.Hash(hashes.SHA256())
    digest.update(pre_cert.tbs_certificate_bytes)
    tbs_digest = digest.finalize()

    signature = pki.get_kms().sign_digest(signing_key_id, tbs_digest)
    final_der = _patch_cert_signature(
        pre_cert.public_bytes(Encoding.DER), signature, is_ecdsa
    )
    return x509.load_der_x509_certificate(final_der).public_bytes(Encoding.PEM).decode()


def _build_internal_sub_cert(data, signing_key_id, signing_pub_key, parent_record):
    """Build a sub-CA certificate signed by an internal parent CA.

    Returns (cert_pem, chain_pem). Honours decision 2 (chain derived from
    parent, operator override permitted) and decision 3 (validity capped
    by parent's notAfter).
    """
    parent_cert = x509.load_pem_x509_certificate(parent_record["certificate"].encode("utf-8"))
    parent_pub_key = parent_cert.public_key()

    subject = _parse_dn(data["subject_dn"])
    validity_days = int(data["validity_days"])
    not_valid_before = datetime.now(timezone.utc)
    not_valid_after = not_valid_before + timedelta(days=validity_days)

    parent_not_after = parent_cert.not_valid_after_utc
    if not_valid_after > parent_not_after:
        raise ValueError(
            f"validity_days={validity_days} would push notAfter past parent.notAfter "
            f"({parent_not_after.isoformat()})"
        )

    builder = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(parent_cert.subject)
        .public_key(signing_pub_key)
        .serial_number(x509.random_serial_number())
        .not_valid_before(not_valid_before)
        .not_valid_after(not_valid_after)
    )
    for ext, critical in _ca_extensions(parent_pub_key, signing_pub_key):
        builder = builder.add_extension(ext, critical)

    dummy_key, is_ecdsa = _dummy_key_matching(parent_pub_key)
    pre_cert = builder.sign(private_key=dummy_key, algorithm=hashes.SHA256())

    digest = hashes.Hash(hashes.SHA256())
    digest.update(pre_cert.tbs_certificate_bytes)
    tbs_digest = digest.finalize()

    parent_key_id = parent_record["private_key_reference"]
    signature = pki.get_kms().sign_digest(parent_key_id, tbs_digest)

    final_der = _patch_cert_signature(
        pre_cert.public_bytes(Encoding.DER), signature, is_ecdsa
    )
    cert_pem = x509.load_der_x509_certificate(final_der).public_bytes(Encoding.PEM).decode()

    if data.get("certificate_chain"):
        chain = data["certificate_chain"]
    else:
        chain = (parent_record.get("certificate") or "") + (parent_record.get("certificate_chain") or "")
    return cert_pem, chain


def _build_external_sub_csr(data, signing_key_id, signing_pub_key) -> str:
    """Build a CSR for external-subordinate phase 1. Returns PEM.

    Per resolved decision 6: the CSR has no requested-extensions attribute
    — its purpose is to convey the public key, subject DN, and proof of
    possession. The external issuer chooses the resulting cert's extensions.
    """
    subject = _parse_dn(data["subject_dn"])
    builder = x509.CertificateSigningRequestBuilder().subject_name(subject)

    dummy_key, is_ecdsa = _dummy_key_matching(signing_pub_key)
    pre_csr = builder.sign(private_key=dummy_key, algorithm=hashes.SHA256())

    digest = hashes.Hash(hashes.SHA256())
    digest.update(pre_csr.tbs_certrequest_bytes)
    tbs_digest = digest.finalize()

    signature = pki.get_kms().sign_digest(signing_key_id, tbs_digest)
    final_der = _patch_csr_signature(
        pre_csr.public_bytes(Encoding.DER), signature, is_ecdsa
    )
    return x509.load_der_x509_csr(final_der).public_bytes(Encoding.PEM).decode()


# ── Top-level orchestration ──────────────────────────────────────────────────

def generate_ca(data: dict, user_id: int = 0) -> dict:
    """Generate or issue a CA per CR-0001.

    Returns the new CA's full record for root / internal-subordinate (the
    row is `active`). For external-subordinate (phase 1) returns
    {ca_id, state="pending-issuance", csr_pem, key_label, subject_dn}.

    Raises `ValueError` on input validation failure (mapped to 400 by the
    route handler) and re-raises KMS / DB exceptions on transient failure
    (mapped to 503 / 500). Rolls back a freshly-generated KMS key if the
    flow fails between key generation and the CA insert.
    """
    mode = data.get("mode")
    if mode not in ("root", "internal-subordinate", "external-subordinate"):
        raise ValueError(
            f"Invalid mode: {mode!r}; must be one of "
            f"'root' | 'internal-subordinate' | 'external-subordinate'"
        )
    if not (data.get("name") or "").strip():
        raise ValueError("name is required")
    if not (data.get("subject_dn") or "").strip():
        raise ValueError("subject_dn is required")

    if mode == "external-subordinate":
        if data.get("parent_ca_id") is not None:
            raise ValueError("parent_ca_id must be absent for mode='external-subordinate'")
        if data.get("validity_days") is not None:
            raise ValueError(
                "validity_days must be absent for mode='external-subordinate' "
                "(the external issuer controls notBefore/notAfter)"
            )
    else:
        if data.get("validity_days") is None:
            raise ValueError(f"validity_days is required for mode={mode!r}")

    signing_key_id, key_owned, signing_pub_key = _resolve_key_source(data)

    db = pki.get_db()
    kms = pki.get_kms()

    def _rollback_key():
        if key_owned:
            try:
                kms.delete_key(signing_key_id)
                logger.info(f"Rolled back KMS key id={signing_key_id} after generate_ca failure")
            except Exception:
                logger.exception(
                    f"Rollback failed for KMS key id={signing_key_id} — manual cleanup may be needed"
                )

    try:
        if mode == "root":
            cert_pem = _build_root_cert(data, signing_key_id, signing_pub_key)
            chain_pem = ""
            gen_mode = "generate-root" if key_owned else "bind-root"
        elif mode == "internal-subordinate":
            parent_id = data.get("parent_ca_id")
            if parent_id is None:
                raise ValueError("parent_ca_id is required for mode='internal-subordinate'")
            with db.connection():
                parent = db.get_ca_record_by_id(int(parent_id))
            if not parent:
                raise ValueError(f"parent_ca_id={parent_id} not found")
            if parent.get("state", "active") != "active":
                raise ValueError(
                    f"parent CA id={parent_id} is in state '{parent.get('state')}' (must be 'active')"
                )
            cert_pem, chain_pem = _build_internal_sub_cert(
                data, signing_key_id, signing_pub_key, parent
            )
            gen_mode = "generate-internal-subordinate" if key_owned else "bind-internal-subordinate"
        else:  # external-subordinate
            csr_pem = _build_external_sub_csr(data, signing_key_id, signing_pub_key)
            with db.connection():
                new_id = db.insert_pending_ca(
                    name=data["name"],
                    private_key_reference=signing_key_id,
                    key_owned=key_owned,
                    pending_csr=csr_pem,
                    max_validity=int(data.get("max_validity", -1)),
                    serial_number_length=int(data.get("serial_number_length", 10)),
                    crl_validity=int(data.get("crl_validity", 365)),
                    extensions=data.get("extensions") or {},
                )
            gen_mode = "generate-external-subordinate" if key_owned else "bind-external-subordinate"
            write_audit_log("cas", new_id, "GENERATE_REQUEST", user_id,
                            metadata={"generation_mode": gen_mode})
            with db.connection():
                key_rec = db.get_key_record(signing_key_id) or {}
            return {
                "ca_id": new_id,
                "state": "pending-issuance",
                "csr_pem": csr_pem,
                "key_label": key_rec.get("label"),
                "subject_dn": data["subject_dn"],
            }

        # root / internal-sub: insert the active row through the existing path,
        # which encrypts the row consistently with every other CA-creation flow.
        config = {
            "ca_name": data["name"],
            "max_validity": int(data.get("max_validity", -1)),
            "serial_number_length": int(data.get("serial_number_length", 10)),
            "crl_validity": int(data.get("crl_validity", 365)),
            "extensions": data.get("extensions") or {},
            "crypto": {
                "certificate": cert_pem,
                "private_key": None,
                "kms_key_id": signing_key_id,
                "key_owned": key_owned,
                "certificate_chain": chain_pem,
            },
        }
        new_id = pki.create_ca_from_config_json(json.dumps(config))
        write_audit_log("cas", new_id, "CREATE", user_id,
                        metadata={"generation_mode": gen_mode})
        with db.connection():
            return db.get_ca_record_by_id(new_id)
    except Exception:
        _rollback_key()
        raise


# ── Phase 2: install issuer-signed certificate ───────────────────────────────

def install_ca_certificate(ca_id: int, data: dict, user_id: int = 0) -> dict:
    """Phase 2 of the external-subordinate flow (CR-0001).

    Validates the supplied certificate, transitions the row to active, and
    emits an INSTALL_CERT audit event. Per resolved decisions 6 + 7:
      - SPKI must match the bound KMS key (rejects an issuer-substituted key).
      - BasicConstraints cA=TRUE is required.
      - Subject DN is *not* compared against the CSR's DN — the issued cert's
        DN is authoritative.

    Returns the updated CA record.
    """
    if not (data.get("certificate") or "").strip():
        raise ValueError("certificate (PEM) is required")
    cert_pem = data["certificate"]
    chain_pem = data.get("certificate_chain") or ""

    try:
        cert = x509.load_pem_x509_certificate(cert_pem.encode("utf-8"))
    except Exception as e:
        raise ValueError(f"Invalid certificate PEM: {e}")

    db = pki.get_db()
    with db.connection():
        ca_row = db.get_ca_record_by_id(ca_id)
    if not ca_row:
        raise ValueError(f"CA id={ca_id} not found")
    if ca_row.get("state") != "pending-issuance":
        raise CAStateError(
            f"CA id={ca_id} state={ca_row.get('state')!r} — install-cert requires 'pending-issuance'"
        )

    bound_key_id = ca_row["private_key_reference"]
    bound_pub_key, _ = _load_kms_pub_key(bound_key_id)
    cert_spki = cert.public_key().public_bytes(
        Encoding.DER, PublicFormat.SubjectPublicKeyInfo
    )
    bound_spki = bound_pub_key.public_bytes(
        Encoding.DER, PublicFormat.SubjectPublicKeyInfo
    )
    if cert_spki != bound_spki:
        raise ValueError(
            "Certificate SPKI does not match the bound KMS key — the external "
            "issuer signed against a different key than the one in this CA's CSR"
        )

    try:
        bc = cert.extensions.get_extension_for_class(x509.BasicConstraints)
    except x509.ExtensionNotFound:
        raise ValueError("Installed certificate lacks the BasicConstraints extension")
    if not bc.value.ca:
        raise ValueError(
            "Installed certificate has BasicConstraints cA=FALSE — that is an "
            "end-entity certificate, not a CA certificate"
        )

    ski = _ski_hex_from_cert(cert)

    with db.connection():
        db.install_ca_certificate(
            ca_id=ca_id,
            certificate_pem=cert_pem,
            certificate_chain=chain_pem,
            ski=ski,
        )
    gen_mode = ("generate-external-subordinate" if ca_row.get("key_owned")
                else "bind-external-subordinate")
    write_audit_log("cas", ca_id, "INSTALL_CERT", user_id,
                    metadata={"generation_mode": gen_mode})
    with db.connection():
        return db.get_ca_record_by_id(ca_id)


# ── Unbound-key listing (CR-0001 backend addition, shared with CR-0002) ──────

def list_unbound_keys() -> list:
    """Return KeyStorage rows not yet bound to any CA, enriched with the
    8-char SPKI fingerprint (per CR-0002 decision 2).
    """
    db = pki.get_db()
    with db.connection():
        rows = db.get_unbound_keys()
    out = []
    for row in rows:
        spki_fp8 = None
        pub_pem = row.get("public_key")
        if pub_pem:
            try:
                pub_key = serialization.load_pem_public_key(pub_pem.encode("utf-8"))
                spki_der = pub_key.public_bytes(
                    Encoding.DER, PublicFormat.SubjectPublicKeyInfo
                )
                digest = hashes.Hash(hashes.SHA256())
                digest.update(spki_der)
                spki_fp8 = digest.finalize().hex()[:8]
            except Exception:
                spki_fp8 = None
        out.append({
            "id": row.get("id"),
            "provider_id": row.get("provider_id"),
            "key_type": row.get("key_type"),
            "label": row.get("label"),
            "storage_type": row.get("storage_type"),
            "hsm_token_id": row.get("hsm_token_id"),
            "key_owned": bool(row.get("key_owned")),
            "spki_fp8": spki_fp8,
        })
    return out
