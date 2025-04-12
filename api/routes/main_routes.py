from flask import Blueprint, jsonify, request, abort
from api.services import api_adapters

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

@bp.route('/cas', methods=['GET'])
def get_certification_authorities():
    result = api_adapters.get_ca_collection_json()
    if not result:
        abort(404, description="Certification Authority not found")
    return jsonify(result)

@bp.route('/cas/<int:ca_id>', methods=['GET'])
def get_ca_details(ca_id):
    result = api_adapters.get_ca_details_json(ca_id)
    if not result:
        abort(404, description="Certification Authority not found")
    return jsonify(result)