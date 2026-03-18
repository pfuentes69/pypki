import datetime

import jwt
from flask import Blueprint, jsonify, request

from web.services import api_adapters
from pypki import logger

bp = Blueprint('auth', __name__)


def _get_bearer_token():
    auth = request.headers.get('Authorization', '')
    if auth.startswith('Bearer '):
        return auth[7:]
    return None


@bp.route('/login', methods=['POST'])
def login():
    data = request.get_json()
    if not data or not data.get('username') or not data.get('password'):
        return jsonify({"error": "Missing credentials"}), 400

    user = api_adapters.authenticate_user(data['username'], data['password'])
    if not user:
        return jsonify({"error": "Invalid credentials"}), 401
    if not user.get('is_active'):
        return jsonify({"error": "Account disabled"}), 403

    secret_key = api_adapters.get_secret_key()
    now = datetime.datetime.now(datetime.timezone.utc)
    payload = {
        "sub": str(user["id"]),
        "username": user["username"],
        "role": user["role"],
        "iat": now,
        "exp": now + datetime.timedelta(hours=8),
    }
    token = jwt.encode(payload, secret_key, algorithm="HS256")
    api_adapters.record_login(user["id"])

    logger.info(f"Auth - Login: {user['username']} ({user['role']})")
    return jsonify({
        "token": token,
        "user": {"id": user["id"], "username": user["username"], "role": user["role"]},
    }), 200


@bp.route('/logout', methods=['POST'])
def logout():
    # JWT is stateless; the client discards the token
    return jsonify({"message": "Logged out"}), 200


@bp.route('/me', methods=['GET'])
def me():
    token = _get_bearer_token()
    if not token:
        return jsonify({"error": "Unauthorized"}), 401
    user = api_adapters.validate_jwt_token(token)
    if not user:
        return jsonify({"error": "Unauthorized"}), 401
    return jsonify(user), 200
