import base64
from datetime import datetime, timedelta, timezone
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.serialization import pkcs7
from cryptography.x509.ocsp import load_der_ocsp_request, OCSPResponseBuilder, OCSPCertStatus, OCSPResponderEncoding
from cryptography.x509.oid import ObjectIdentifier
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from flask import Blueprint, request, Response, jsonify
from web.services import api_adapters

from pypki import logger, PKITools, OCSPResponder

OCSP_NONCE_OID = ObjectIdentifier("1.3.6.1.5.5.7.48.1.2")

bp = Blueprint('ocsp', __name__)

@bp.route("", methods=["POST", "GET"])
def ocsp_responder():

    if request.method == "POST":
        logger.info("OCSP POST Request")
        ocsp_req_data = request.data
    elif request.method == "GET":
        logger.info("OCSP GET Request")
        # GET uses base64-encoded DER in the URL
        encoded = request.path.split("/ocsp/")[-1]
        ocsp_req_data = base64.b64decode(encoded)

    try:
        ocsp_request = load_der_ocsp_request(ocsp_req_data)
        cert_serial = format(ocsp_request.serial_number, 'x')
        issuer_ski = ocsp_request.issuer_key_hash.hex()
        logger.info(f"OCSP Request - Serial Number: {cert_serial}")
        logger.info(f"OCSP Request - Hash Algorithm: {ocsp_request.hash_algorithm.name}")
        logger.info(f"OCSP Request - Issuer Key Hash: {issuer_ski}")
        nonce = None
        for ext in ocsp_request.extensions:
            if ext.oid == OCSP_NONCE_OID:
                nonce = ext.value
        if nonce:
            logger.info(f"OCSP Request - OCSP Nonce: {nonce.nonce.hex()}")

        # Resolve the OCSP responder first — fail early if none is configured for this CA
        ocsp_resp = api_adapters.get_ocsp_responder_by_issuer_ski(issuer_ski=issuer_ski)
        if ocsp_resp is None:
            logger.warning(f"OCSP Request - no responder configured for issuer_ski={issuer_ski}")
            return Response(status=400)

        # Use the responder's ca_id directly; fall back to SKI lookup if ca_id is not set
        # (legacy rows inserted before the ca_id backfill migration was run)
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
        else:
            logger.warning(f"OCSP Request - certificate status can't be determined for serial={cert_serial}")
            return Response("Certificate status unknown", status=400)

        response = ocsp_resp.generate_response(cert_to_check, cert_status, revocation_time, revocation_reason)
        return Response(response.public_bytes(serialization.Encoding.DER), mimetype="application/ocsp-response")

    except Exception as e:
        logger.error(f"Error: {e}")
        return Response(status=400)

    

