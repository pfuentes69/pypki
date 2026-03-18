import base64
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.serialization import pkcs7
from flask import Blueprint, request, Response, jsonify
from werkzeug.security import check_password_hash
from web.services import api_adapters

from pypki import logger

bp = Blueprint('est', __name__)


def _check_basic_auth(est_config) -> bool:
    """
    Validates HTTP Basic Auth credentials against the EST alias config.

    Returns True if:
    - No username is configured for the alias (auth not required), or
    - The provided credentials match the stored username and password hash.

    Returns False if credentials are missing or incorrect.
    """
    username = est_config.get("username") if est_config else None
    if not username:
        return True  # auth not required for this alias

    auth = request.authorization
    if not auth or auth.type != "basic":
        return False

    password_hash = est_config.get("password_hash") or ""
    return auth.username == username and check_password_hash(password_hash, auth.password)


def _unauthorized():
    """Returns a 401 response with WWW-Authenticate header (RFC 7235)."""
    return Response(
        "Unauthorized",
        status=401,
        headers={"WWW-Authenticate": 'Basic realm="EST"'},
    )

@bp.route('/est/<path:label>/cacerts', methods=['GET'])
@bp.route('/est/cacerts', methods=['GET'])
def get_ca_certs(label=None):
    """Returns the CA certificate in PKCS#7 format, based on the label."""
    logger.info("API - EST cacerts")

    est_config = api_adapters.get_ca_and_template_id_by_alias_name(label)
    if est_config:
        logger.info(f"Using EST config: {est_config}")
    else:
        logger.error(f"Label not valid")
        return Response(f"Invalid label {label}", status=404)

    ca_cert = api_adapters.get_ca_certificate(est_config, request.data)
    
    if not ca_cert:
        return Response("Problem retrieving CA certificate", status=404)
    
    # Prepare headers and send response
    response = Response(ca_cert, content_type='application/x-pem-file')
    response.headers['Content-Disposition'] = 'attachment; filename=certificate.pem'

    return response


@bp.route('/est/<path:label>/simpleenroll', methods=['POST'])
@bp.route('/est/simpleenroll', methods=['POST'])
def simple_enroll(label=None):
    """Processes a CSR and returns the issued certificate inside a PKCS#7 envelope."""
    logger.info("API - EST simpleenroll")

    est_config = api_adapters.get_ca_and_template_id_by_alias_name(label)
    if est_config:
        logger.info(f"Using EST config: {est_config}")
    else:
        if label is None:
            logger.info(f"Using EST default config")
        else:
            logger.error(f"Label not valid")
            return Response("Invalid label", status=404)

    if not _check_basic_auth(est_config):
        return _unauthorized()

    try:
        csr_pem = request.data
        #csr = x509.load_pem_x509_csr(csr_data)

        new_cert = api_adapters.generate_certificate_from_csr(est_config, csr_pem)

        # Create a PKCS#7 SignedData envelope
        pkcs7_cert = pkcs7.serialize_certificates([new_cert], encoding=serialization.Encoding.DER)

        # Base64 encode the PKCS#7 cert
        pkcs7_base64 = base64.b64encode(pkcs7_cert).decode('utf-8')

        # Prepare headers and send response
        response = Response(pkcs7_base64, content_type='application/pkcs7-mime; smime-type=certs-only')
        response.headers['Content-Transfer-Encoding'] = 'base64'
        return response


    except Exception as e:
        return Response(f"Error: {str(e)}", status=400)


"""
UTILITY ENDPOINTS, NOT EST STANDARD
"""

@bp.route('/est/<path:label>/simpleenrollpem', methods=['POST'])
@bp.route('/est/simpleenrollpem', methods=['POST'])
def simple_enroll_pem(label=None):
    """Processes a CSR and returns the issued certificate in PEM format."""
    logger.info("API - EST simpleenroll (PEM Version)")

    est_config = api_adapters.get_ca_and_template_id_by_alias_name(label)
    if est_config:
        logger.info(f"Using EST config: {est_config}")
    else:
        if label is None:
            logger.info(f"Using EST default config")
        else:
            logger.error(f"Label not valid")
            return Response("Invalid label", status=404)

    if not _check_basic_auth(est_config):
        return _unauthorized()

    try:
        csr_pem = request.data
        #csr = x509.load_pem_x509_csr(csr_data)

        new_cert = api_adapters.generate_certificate_from_csr(est_config, csr_pem)

        # Serialize the certificate to PEM format
        pem_cert = new_cert.public_bytes(encoding=serialization.Encoding.PEM)

        # Prepare headers and send response
        response = Response(pem_cert, content_type='application/x-pem-file')
        response.headers['Content-Disposition'] = 'attachment; filename=certificate.pem'
        return response

    except Exception as e:
        return Response(f"Error: {str(e)}", status=400)
    

