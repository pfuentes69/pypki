import base64
import urllib.parse
from datetime import datetime, timedelta, timezone
from email.utils import formatdate

from cryptography.hazmat.primitives import serialization
from cryptography.x509.ocsp import load_der_ocsp_request, OCSPCertStatus
from cryptography.x509.oid import ObjectIdentifier
from cryptography import x509
from flask import Blueprint, request, Response

from web.services import api_adapters
from pypki import logger, PKITools, OCSPResponder

OCSP_NONCE_OID = ObjectIdentifier("1.3.6.1.5.5.7.48.1.2")

bp = Blueprint('ocsp', __name__)

@bp.route("", methods=["POST", "GET"])
def ocsp_responder():

    if request.method == "POST":
        logger.info("OCSP POST Request")
        ocsp_req_data = request.data
    else:
        logger.info("OCSP GET Request")
        # GET: base64-encoded DER appended to the URL path (RFC 2560 §A.1.1)
        # The path segment may be URL-encoded, so decode it first.
        encoded = request.path.split("/ocsp/")[-1]
        ocsp_req_data = base64.b64decode(urllib.parse.unquote(encoded))

    try:
        ocsp_request = load_der_ocsp_request(ocsp_req_data)
        cert_serial = format(ocsp_request.serial_number, 'x')
        issuer_ski = ocsp_request.issuer_key_hash.hex()
        logger.info(f"OCSP Request - Serial Number: {cert_serial}")
        logger.info(f"OCSP Request - Hash Algorithm: {ocsp_request.hash_algorithm.name}")
        logger.info(f"OCSP Request - Issuer Key Hash: {issuer_ski}")

        # Extract nonce if present
        nonce_ext = None
        for ext in ocsp_request.extensions:
            if ext.oid == OCSP_NONCE_OID:
                nonce_ext = ext.value
                break
        if nonce_ext:
            logger.info(f"OCSP Request - OCSP Nonce: {nonce_ext.nonce.hex()}")

        # Resolve the OCSP responder — fail early if none configured for this issuer
        ocsp_resp = api_adapters.get_ocsp_responder_by_issuer_ski(issuer_ski=issuer_ski)
        if ocsp_resp is None:
            logger.warning(f"OCSP Request - no responder configured for issuer_ski={issuer_ski}")
            return Response(status=400)

        # Apply nonce policy
        nonce_policy = ocsp_resp.get_nonce_policy()
        if nonce_policy == 'required' and nonce_ext is None:
            logger.warning("OCSP Request - nonce required but not present; rejecting")
            return Response(status=400)
        # Only reflect nonce when policy is not 'disabled'
        nonce_bytes = nonce_ext.nonce if (nonce_ext and nonce_policy != 'disabled') else None

        # Look up certificate status
        ca_id = ocsp_resp.get_ca_id()
        result = api_adapters.get_certificate_status(
            serial_number=cert_serial,
            ca_id=ca_id,
            ca_ski=issuer_ski if ca_id is None else None
        )

        if result:
            cert_to_check = x509.load_pem_x509_certificate(result[5].encode("utf-8"))
            if result[2] == "Active":
                cert_status = OCSPCertStatus.GOOD
                revocation_time = None
                revocation_reason = None
            else:
                cert_status = OCSPCertStatus.REVOKED
                revocation_time = result[3]
                revocation_reason = PKITools.REVOCATION_REASON_MAPPING[result[4]]
            logger.info(f"OCSP Request - Cert status: {cert_status}")
            response = ocsp_resp.generate_response(
                cert_to_check, cert_status, revocation_time, revocation_reason, nonce_bytes
            )
        else:
            # Certificate not found — return OCSP UNKNOWN (RFC 6960 §2.2)
            logger.warning(f"OCSP Request - unknown serial={cert_serial}; returning UNKNOWN status")
            response = ocsp_resp.generate_unknown_response(
                ocsp_request.serial_number, nonce_bytes
            )

        response_bytes = response.public_bytes(serialization.Encoding.DER)

        # RFC 5019 caching headers
        this_update = response.this_update_utc
        next_update = response.next_update_utc
        if this_update and next_update:
            max_age = max(0, int((next_update - this_update).total_seconds()))
            http_resp = Response(response_bytes, mimetype="application/ocsp-response")
            http_resp.headers['Cache-Control'] = f'max-age={max_age}, public, no-transform, must-revalidate'
            http_resp.headers['Last-Modified'] = formatdate(this_update.timestamp(), usegmt=True)
            http_resp.headers['Expires'] = formatdate(next_update.timestamp(), usegmt=True)
        else:
            http_resp = Response(response_bytes, mimetype="application/ocsp-response")

        return http_resp

    except Exception as e:
        logger.error(f"Error: {e}")
        return Response(status=400)
