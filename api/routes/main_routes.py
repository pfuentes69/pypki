from flask import Blueprint, jsonify, request, abort, Response, send_from_directory
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
    result = api_adapters.get_ca_collection_json()
    if not result:
        abort(404, description="Certification Authority not found")
    return jsonify(result)

@bp.route('/ca/<int:ca_id>', methods=['GET'])
def get_ca_details(ca_id):
    logger.info("API - GET CA Details")
    ca_details = api_adapters.get_ca_details_json(ca_id)
    if not ca_details:
        abort(404, description="Certification Authority not found")
    result = api_adapters.convert_to_serializable(ca_details)
    return jsonify(result)

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