from flask import Blueprint, jsonify, request
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
