from flask import Flask, Blueprint, jsonify, request, send_file, Response
from cryptography import x509
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.serialization import pkcs7
import datetime
import os
import base64

from api.services.est_service import generate_certificate, get_ca_certificate

bp = Blueprint('est', __name__)


@bp.route('/est/<path:label>/cacerts', methods=['GET'])
@bp.route('/est/cacerts', methods=['GET'])
def get_ca_certs(label=None):
    """Returns the CA certificate in PKCS#7 format, based on the label."""
    ca_cert = get_ca_certificate(request.data)
    
    if not ca_cert:
        return Response("Invalid label or CA not found", status=404)
    
    # Prepare headers and send response
    response = Response(ca_cert, content_type='application/x-pem-file')
    response.headers['Content-Disposition'] = 'attachment; filename=certificate.pem'

    return response


@bp.route('/est/<path:label>/simpleenroll', methods=['POST'])
@bp.route('/est/simpleenroll', methods=['POST'])
def simple_enroll(label=None):
    """Processes a CSR and returns the issued certificate inside a PKCS#7 envelope."""

    try:
        csr_pem = request.data
        #csr = x509.load_pem_x509_csr(csr_data)

        new_cert = generate_certificate(csr_pem)

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


@bp.route('/est/<path:label>/simpleenrollpem', methods=['POST'])
@bp.route('/est/simpleenrollpem', methods=['POST'])
def simple_enroll_pem(label=None):
    """Processes a CSR and returns the issued certificate in PEM format."""

    try:
        csr_pem = request.data
        #csr = x509.load_pem_x509_csr(csr_data)

        new_cert = generate_certificate(csr_pem)

        # Serialize the certificate to PEM format
        pem_cert = new_cert.public_bytes(encoding=serialization.Encoding.PEM)

        # Prepare headers and send response
        response = Response(pem_cert, content_type='application/x-pem-file')
        response.headers['Content-Disposition'] = 'attachment; filename=certificate.pem'
        return response

    except Exception as e:
        return Response(f"Error: {str(e)}", status=400)