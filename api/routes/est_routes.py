from flask import Flask, Blueprint, jsonify, request, send_file, Response
from cryptography import x509
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.serialization import pkcs7
import datetime
import os
import base64

from api.services import est_service

bp = Blueprint('est', __name__)

# Default CA certificate and key paths (for the default label)
DEFAULT_CA_CERT_PATH = "/Users/pedro/Development/Python/pypki/config/ca_store/ca1_certificate.pem"
DEFAULT_CA_KEY_PATH = "/Users/pedro/Development/Python/pypki/config/ca_store/ca1_private_key.pem"

def load_ca_cert_and_key(label):
    """Loads the CA certificate and private key based on the label."""
    ca_cert_path = f"ca_{label}.pem" if label else DEFAULT_CA_CERT_PATH
    ca_key_path = f"ca_key_{label}.pem" if label else DEFAULT_CA_KEY_PATH

    if not os.path.exists(ca_cert_path) or not os.path.exists(ca_key_path):
        return None, None

    with open(ca_cert_path, "rb") as f:
        ca_cert = x509.load_pem_x509_certificate(f.read())

    with open(ca_key_path, "rb") as f:
        ca_private_key = serialization.load_pem_private_key(f.read(), password=None)

    return ca_cert, ca_private_key

@bp.route('/est/<path:label>/cacerts', methods=['GET'])
@bp.route('/est/cacerts', methods=['GET'])
def get_ca_certs(label=None):
    """Returns the CA certificate in PKCS#7 format, based on the label."""
    ca_cert, _ = load_ca_cert_and_key(label)
    
    if not ca_cert:
        return Response("Invalid label or CA not found", status=404)

    return send_file(f"ca_{label}.pem" if label else DEFAULT_CA_CERT_PATH, mimetype='application/pkcs7-mime')

@bp.route('/est/<path:label>/simpleenroll', methods=['POST'])
@bp.route('/est/simpleenroll', methods=['POST'])
def simple_enroll(label=None):
    """Processes a CSR and returns the issued certificate inside a PKCS#7 envelope."""
    ca_cert, ca_private_key = load_ca_cert_and_key(label)

    if not ca_cert or not ca_private_key:
        return Response("Invalid label or CA not found", status=404)

    try:
        csr_data = request.data
        csr = x509.load_pem_x509_csr(csr_data)

        # Issue a new certificate
        new_cert = (
            x509.CertificateBuilder()
            .subject_name(csr.subject)
            .issuer_name(ca_cert.subject)
            .public_key(csr.public_key())
            .serial_number(x509.random_serial_number())
            .not_valid_before(datetime.datetime.utcnow())
            .not_valid_after(datetime.datetime.utcnow() + datetime.timedelta(days=365))
            .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
            .sign(ca_private_key, hashes.SHA256())
        )

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
