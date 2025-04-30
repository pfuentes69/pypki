from flask import Blueprint, jsonify, request, abort, Response, send_from_directory
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.serialization import pkcs7
from api.services import api_adapters

from pypki import logger

# Serve CRL from this local folder
#CRL_FOLDER = "/Users/pedro/Development/Python/pypki/out/crl"
CRL_FOLDER = "../out/crl"

bp = Blueprint('main', __name__)

@bp.route("/status", methods=["GET"])
def status():
    return jsonify({"status": "API is up!"})

@bp.route("/process", methods=["POST"])
def process():
    data = request.json
    data = request.json
    result = api_adapters.process_input(data)
    return jsonify(result)

@bp.route('/ca', methods=['GET'])
def get_certification_authorities():
    logger.info("API - GET CA List")
    result = api_adapters.get_ca_collection()

    if not result:
        abort(404, description="Certification Authority not found")

    # Only include ID and NAME in the response
    filtered_result = [
        {
            "id": row["id"],
            "name": row["name"]
        }
        for row in result
    ]

    return jsonify(filtered_result), 200


@bp.route('/ca/<int:ca_id>', methods=['GET'])
def get_ca_details(ca_id):
    logger.info("API - GET CA Details")
    ca_details = api_adapters.get_ca_details(ca_id)
    if not ca_details:
        abort(404, description="Certification Authority not found")
    result = api_adapters.convert_to_serializable(ca_details)
    return jsonify(result)

@bp.route('/certificate/<int:cert_id>', methods=['GET'])
def get_certificate_details(cert_id):
    logger.info("API - GET Certificate Details")
    cert_details = api_adapters.get_certificate_details_json(cert_id)
    if not cert_details:
        abort(404, description="Certificate not found")
    result = api_adapters.convert_to_serializable(cert_details)
    return jsonify(result)


@bp.route('/certificate/pem/<int:cert_id>', methods=['GET'])
def get_certificate_pem(cert_id):
    logger.info("API - GET Certificate PEM")
    cert_details = api_adapters.get_certificate_details_json(cert_id)
    if not cert_details:
        abort(404, description="Certificate not found")
    # Serialize the certificate to PEM format
    pem_cert = cert_details["certificate_data"] #new_cert.public_bytes(encoding=serialization.Encoding.PEM)

    # Prepare headers and send response
    response = Response(pem_cert, content_type='application/x-pem-file')
    response.headers['Content-Disposition'] = 'attachment; filename=certificate.pem'
    return response


@bp.route('/certificate/status/<int:cert_id>', methods=['GET'])
def get_certificate_status(cert_id):
    logger.info("API - GET Certificate Revocation Status")
    cert_status = api_adapters.get_certificate_status(cert_id)
    if not cert_status:
        abort(404, description="Certificate not found")
#    result = api_adapters.convert_to_serializable(cert_details)
    return jsonify(cert_status)


@bp.route('/certificate/revoke/<int:cert_id>', methods=['POST'])
def revoke_certificate(cert_id):
    logger.info("API - POST Revoke Certificate")

    # Parse JSON body
    data = request.get_json()
    if not data or 'revocation_reason' not in data:
        abort(400, description="Missing 'revocation_reason' in request body")

    revocation_reason = data['revocation_reason']
    if not isinstance(revocation_reason, int):
        abort(400, description="'revocation_reason' must be an integer")

    # Call adapter function to perform revocation
    success = api_adapters.revoke_certificate(cert_id, revocation_reason)
    if not success:
        abort(404, description="Certificate not found or already revoked")

    return jsonify({"message": "Certificate revoked successfully", "cert_id": cert_id}), 200


@bp.route('/certificate/issue', methods=['POST'])
def issue_certificate_from_csr():
    logger.info("API - POST Issue Certificate from CSR")

    data = request.get_json()
    if not data:
        abort(400, description="Missing JSON body")

    # Required fields: ca_id, template_id, csr
    if 'ca_id' not in data or 'template_id' not in data or 'csr' not in data:
        abort(400, description="Missing 'ca_id', 'template_id', or 'csr' in request body")

    ca_id = data['ca_id']
    template_id = data['template_id']
    csr_pem = data['csr'].encode('utf-8')

    if not isinstance(ca_id, int) or not isinstance(template_id, int):
        abort(400, description="'ca_id' and 'template_id' must be integers")

    # Optional parameter: return_certificate, default is True
    return_certificate = data.get('return_certificate', True)


    request_config = {
        "ca_id": ca_id,
        "template_id": template_id
    }

    try:
        result = api_adapters.generate_certificate_from_csr(request_config, csr_pem, return_certificate)
        if result is None:
            abort(500, description="Certificate generation failed")

        if return_certificate:
            # Serialize the certificate to PEM format
            pem_cert = result.public_bytes(encoding=serialization.Encoding.PEM)
            return jsonify({
                "certificate_pem": pem_cert.decode('utf-8')
            }), 201
        else:
            return jsonify({
                "certificate_id": result  # assuming result is an ID (string or int)
            }), 201

    except Exception as e:
        logger.error(f"Error issuing certificate: {e}")
        abort(500, description="Internal Server Error")



@bp.route("/ca/crl/<int:ca_id>", methods=["GET"])
def download_crl(ca_id):
    ca_name:str = api_adapters.get_ca_name(ca_id)
    logger.info(f"API Get CRL for CA ID {ca_id}")
    if not ca_name:
        return Response("Invalid CA Identifier", status=404)
    
    ca_name = ca_name.replace(' ', '_') + ".crl"
    
    return send_from_directory(CRL_FOLDER, ca_name, mimetype="application/pkix-crl")

@bp.route('/getestaliases', methods=['GET'])
def get_est_aliases(label=None):
    """Returns the CA certificate in PKCS#7 format, based on the label."""
    logger.info("API - GET EST Aliases")
    est_aliases = api_adapters.get_est_aliases()
    
    if not est_aliases:
        return Response("No EST Aliases found", status=404)
    
    # Prepare headers and send response
    #response = Response(est_aliases, content_type='application/json')

    return jsonify(est_aliases)


@bp.route('/template', methods=['GET'])
def get_certificate_templates_list():
    logger.info("API - GET Certificate Templates List")
    result = api_adapters.get_template_collection()

    if not result:
        abort(404, description="Certificate Template list not found")

    # Only include ID and NAME in the response
    filtered_result = [
        {
            "id": row["id"],
            "name": row["name"]
        }
        for row in result
    ]

    return jsonify(filtered_result), 200
