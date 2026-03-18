import json
import re

from flask import Blueprint, jsonify, request, abort, Response, send_from_directory, g
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.serialization import pkcs7
from web.services import api_adapters

from pypki import logger

# Serve CRL from this local folder
#CRL_FOLDER = "/Users/pedro/Development/Python/pypki/out/crl"
CRL_FOLDER = "../out/crl"

bp = Blueprint('main', __name__)


@bp.before_request
def require_auth():
    # Let CORS preflight pass through
    if request.method == 'OPTIONS':
        return None
    # Public endpoints that don't need a token.
    # CA certificates and CRLs are public PKI documents; any client must be
    # able to fetch them without authenticating to the management API.
    _PUBLIC = {
        'main.status',
        'main.download_ca_cert', 'main.download_ca_cert_der',
        'main.get_ca_crl', 'main.get_ca_crl_der',
        'main.download_crl',
    }
    if request.endpoint in _PUBLIC:
        return None
    auth = request.headers.get('Authorization', '')
    if not auth.startswith('Bearer '):
        return jsonify({"error": "Unauthorized"}), 401
    token = auth[7:]
    user = api_adapters.validate_jwt_token(token)
    if not user:
        return jsonify({"error": "Unauthorized"}), 401
    g.current_user = user


def _require_role(*roles):
    user = getattr(g, 'current_user', None)
    if not user or user.get('role') not in roles:
        return jsonify({"error": "Forbidden"}), 403
    return None


@bp.route("/status", methods=["GET"])
def status():
    return jsonify({"status": "API is up!"})

@bp.route("/process", methods=["POST"])
def process():
    err = _require_role('superadmin', 'admin')
    if err: return err
    data = request.json
    result = api_adapters.process_input(data)
    return jsonify(result)

@bp.route('/dashboard/stats', methods=['GET'])
def get_dashboard_stats():
    logger.info("API - GET Dashboard Stats")
    stats = api_adapters.get_dashboard_stats()
    return jsonify(stats), 200


@bp.route('/ca', methods=['GET'])
def get_certification_authorities():
    logger.info("API - GET CA List")
    result = api_adapters.get_ca_collection()

    if not result:
        abort(404, description="Certification Authority not found")

    filtered_result = [
        {
            "id": row["id"],
            "name": row["name"],
            "max_validity": row.get("max_validity"),
            "crl_validity": row.get("crl_validity"),
            "serial_number_length": row.get("serial_number_length"),
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


@bp.route('/ca/<int:ca_id>/full', methods=['GET'])
def get_ca_full_details(ca_id):
    logger.info("API - GET CA Full Details")
    ca_details = api_adapters.get_ca_full_details(ca_id)
    if not ca_details:
        abort(404, description="Certification Authority not found")
    result = api_adapters.convert_to_serializable(ca_details)
    return jsonify(result)


@bp.route('/ca/<int:ca_id>/cert', methods=['GET'])
def download_ca_cert(ca_id):
    logger.info(f"API - GET CA Certificate PEM for CA ID {ca_id}")
    ca_details = api_adapters.get_ca_details(ca_id)
    if not ca_details:
        abort(404, description="Certification Authority not found")
    cert_pem = ca_details.get("certificate")
    if not cert_pem:
        abort(404, description="Certificate not available")
    if isinstance(cert_pem, bytes):
        cert_pem = cert_pem.decode("utf-8")
    ca_name = ca_details.get("name", f"ca_{ca_id}").replace(" ", "_")
    response = Response(cert_pem, content_type="application/x-pem-file")
    response.headers["Content-Disposition"] = f'attachment; filename="{ca_name}.pem"'
    return response


@bp.route('/ca/<int:ca_id>/crl', methods=['GET'])
def get_ca_crl(ca_id):
    """Download the latest CRL for this CA in PEM format."""
    logger.info(f"API - GET CRL (PEM) for CA ID {ca_id}")
    ca_details = api_adapters.get_ca_details(ca_id)
    if not ca_details:
        abort(404, description="Certification Authority not found")
    db = api_adapters.pki.get_db()
    with db.connection():
        crl_record = db.get_crl(ca_id)
    if not crl_record or not crl_record.get("crl_data"):
        abort(404, description="No CRL found for this CA")
    ca_name = ca_details.get("name", f"ca_{ca_id}").replace(" ", "_")
    crl_pem = crl_record["crl_data"]
    if isinstance(crl_pem, bytes):
        crl_pem = crl_pem.decode("utf-8")
    response = Response(crl_pem, content_type="application/x-pem-file")
    response.headers["Content-Disposition"] = f'attachment; filename="{ca_name}.pem.crl"'
    return response


@bp.route('/ca/<int:ca_id>/crl/der', methods=['GET'])
def get_ca_crl_der(ca_id):
    """Download the latest CRL for this CA in DER format."""
    from cryptography import x509 as _x509
    from cryptography.hazmat.primitives import serialization as _ser
    logger.info(f"API - GET CRL (DER) for CA ID {ca_id}")
    ca_details = api_adapters.get_ca_details(ca_id)
    if not ca_details:
        abort(404, description="Certification Authority not found")
    db = api_adapters.pki.get_db()
    with db.connection():
        crl_record = db.get_crl(ca_id)
    if not crl_record or not crl_record.get("crl_data"):
        abort(404, description="No CRL found for this CA")
    ca_name = ca_details.get("name", f"ca_{ca_id}").replace(" ", "_")
    crl_pem = crl_record["crl_data"]
    if isinstance(crl_pem, str):
        crl_pem = crl_pem.encode("utf-8")
    crl_der = _x509.load_pem_x509_crl(crl_pem).public_bytes(_ser.Encoding.DER)
    response = Response(crl_der, content_type="application/pkix-crl")
    response.headers["Content-Disposition"] = f'attachment; filename="{ca_name}.crl"'
    return response


@bp.route('/ca/<int:ca_id>/cert/der', methods=['GET'])
def download_ca_cert_der(ca_id):
    """Download the CA certificate in DER format."""
    from cryptography import x509 as _x509
    from cryptography.hazmat.primitives import serialization as _ser
    logger.info(f"API - GET CA Certificate (DER) for CA ID {ca_id}")
    ca_details = api_adapters.get_ca_details(ca_id)
    if not ca_details:
        abort(404, description="Certification Authority not found")
    cert_pem = ca_details.get("certificate")
    if not cert_pem:
        abort(404, description="Certificate not available")
    if isinstance(cert_pem, str):
        cert_pem = cert_pem.encode("utf-8")
    ca_name = ca_details.get("name", f"ca_{ca_id}").replace(" ", "_")
    cert_der = _x509.load_pem_x509_certificate(cert_pem).public_bytes(_ser.Encoding.DER)
    response = Response(cert_der, content_type="application/pkix-cert")
    response.headers["Content-Disposition"] = f'attachment; filename="{ca_name}.der"'
    return response


@bp.route('/ca/<int:ca_id>/crl', methods=['POST'])
def issue_crl(ca_id):
    logger.info(f"API - POST Generate CRL for CA ID {ca_id}")
    err = _require_role('superadmin', 'admin')
    if err: return err
    ca_details = api_adapters.get_ca_details(ca_id)
    if not ca_details:
        abort(404, description="Certification Authority not found")
    result = api_adapters.generate_crl(ca_id)
    if not result:
        abort(500, description="CRL generation failed")
    return jsonify(api_adapters.convert_to_serializable({
        "message": "CRL generated successfully",
        "issue_date": result["issue_date"],
        "next_update": result["next_update"],
    })), 200


@bp.route('/certificate/parse-csr', methods=['POST'])
def parse_csr():
    logger.info("API - POST Parse CSR")
    data = request.get_json()
    if not data or not data.get('csr'):
        abort(400, description="Missing 'csr' field")
    try:
        result = api_adapters.parse_csr(data['csr'])
    except Exception as e:
        abort(400, description=f"Invalid CSR: {e}")
    return jsonify(result), 200


@bp.route('/certificate', methods=['GET'])
def list_certificates():
    try:
        # Get query parameters
        ca_id = request.args.get('ca_id', type=int)
        template_id = request.args.get('template_id', type=int)
        status = request.args.get('status', default=None)
        expiring_soon = request.args.get('expiring_soon', default='false').lower() == 'true'
        page = request.args.get('page', default=1, type=int)
        per_page = request.args.get('per_page', default=10, type=int)

        offset = (page - 1) * per_page

        total, results = api_adapters.get_certificate_list(
            ca_id, template_id, page, per_page, offset,
            status=status, expiring_soon=expiring_soon
        )

        return jsonify({
            "page": page,
            "per_page": per_page,
            "total": total,
            "certificates": results
        }), 200

    except Exception as e:
        return jsonify({"error": str(e)}), 500


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
    err = _require_role('superadmin', 'admin')
    if err: return err

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
    err = _require_role('superadmin', 'admin', 'user')
    if err: return err

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

    # Build request_json from form-supplied subject/SAN if present.
    # This lets the UI override or supplement what is in the CSR.
    subject_data = data.get('subject') or {}
    san_data     = data.get('san') or {}
    if subject_data or san_data:
        import json as _json
        request_json = _json.dumps({
            "subject_name": subject_data,
            "subjectAltName": san_data,
        })
    else:
        request_json = None

    request_config = {
        "ca_id": ca_id,
        "template_id": template_id
    }

    try:
        # Always get the cert_id so we can redirect the caller
        cert_id = api_adapters.generate_certificate_from_csr(
            request_config, csr_pem, return_certificate=False, request_json=request_json
        )
        if cert_id is None:
            abort(500, description="Certificate generation failed")

        response_body = {"certificate_id": cert_id}

        if return_certificate:
            cert_details = api_adapters.get_certificate_details_json(cert_id)
            if cert_details and cert_details.get("certificate_data"):
                pem = cert_details["certificate_data"]
                if isinstance(pem, bytes):
                    pem = pem.decode('utf-8')
                response_body["certificate_pem"] = pem

        return jsonify(response_body), 201

    except Exception as e:
        logger.error(f"Error issuing certificate: {e}")
        abort(500, description="Internal Server Error")



@bp.route('/certificate/issue-pkcs12', methods=['POST'])
def issue_certificate_pkcs12():
    logger.info("API - POST Issue Certificate (server-side key, PKCS12)")
    err = _require_role('superadmin', 'admin', 'user')
    if err: return err

    data = request.get_json()
    if not data:
        abort(400, description="Missing JSON body")
    if 'ca_id' not in data or 'template_id' not in data:
        abort(400, description="Missing 'ca_id' or 'template_id' in request body")

    ca_id       = data['ca_id']
    template_id = data['template_id']
    if not isinstance(ca_id, int) or not isinstance(template_id, int):
        abort(400, description="'ca_id' and 'template_id' must be integers")

    key_algorithm = data.get('key_algorithm', 'RSA')
    key_type      = data.get('key_type', '2048')
    passphrase    = data.get('passphrase', '')
    pfx_password  = passphrase.encode() if passphrase else b""
    friendly_name = data.get('friendly_name', 'Certificate').encode()
    store_key     = bool(data.get('store_key', False))

    subject_data = data.get('subject') or {}
    san_data     = data.get('san') or {}
    if subject_data or san_data:
        import json as _json
        request_json = _json.dumps({
            "subject_name": subject_data,
            "subjectAltName": san_data,
        })
    else:
        request_json = None

    request_config = {"ca_id": ca_id, "template_id": template_id}

    try:
        p12_bytes, cert_id = api_adapters.generate_pkcs12(
            request_config,
            request_json=request_json,
            key_algorithm=key_algorithm,
            key_type=key_type,
            pfx_password=pfx_password,
            friendly_name=friendly_name,
            store_key=store_key,
        )
    except (ValueError, TypeError) as e:
        logger.error(f"Error issuing PKCS12 (validation/build): {e}", exc_info=True)
        abort(400, description=str(e))
    except Exception as e:
        logger.error(f"Error issuing PKCS12: {e}", exc_info=True)
        abort(500, description="Certificate generation failed")

    resp = Response(p12_bytes, content_type='application/x-pkcs12')
    resp.headers['Content-Disposition'] = f'attachment; filename="certificate_{cert_id}.p12"'
    resp.headers['X-Certificate-Id'] = str(cert_id)
    return resp


@bp.route('/certificate/private-key/<int:cert_id>', methods=['GET'])
def get_certificate_private_key(cert_id):
    logger.info(f"API - GET Private Key for cert {cert_id}")
    err = _require_role('superadmin', 'admin')
    if err: return err

    pem, storage_type = api_adapters.get_certificate_private_key_pem(cert_id)
    if pem is None:
        abort(404, description="Private key not found for this certificate")
    if isinstance(pem, bytes):
        pem = pem.decode()
    return jsonify({"private_key_pem": pem, "storage_type": storage_type}), 200


@bp.route('/certificate/pkcs12/<int:cert_id>', methods=['POST'])
def download_certificate_pkcs12(cert_id):
    logger.info(f"API - POST Download PKCS12 for cert {cert_id}")
    err = _require_role('superadmin', 'admin')
    if err: return err

    data = request.get_json() or {}
    passphrase   = data.get('passphrase', '')
    pfx_password = passphrase.encode() if passphrase else b""

    try:
        p12_bytes = api_adapters.build_pkcs12_for_certificate(cert_id, pfx_password=pfx_password)
    except (ValueError, TypeError) as e:
        abort(400, description="Could not decrypt the private key — wrong passphrase.")
    except Exception as e:
        logger.error(f"Error building PKCS12: {e}")
        abort(500, description="Failed to build PKCS12")

    if p12_bytes is None:
        abort(404, description="Certificate not found or no private key stored")

    resp = Response(p12_bytes, content_type='application/x-pkcs12')
    resp.headers['Content-Disposition'] = f'attachment; filename="certificate_{cert_id}.p12"'
    return resp


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


# ── EST alias management (admin REST API) ──────────────────────────────────

@bp.route('/est', methods=['GET'])
def list_est_aliases():
    logger.info("API - GET EST Alias List")
    aliases = api_adapters.get_est_aliases()
    return jsonify(api_adapters.convert_to_serializable(aliases)), 200


@bp.route('/est', methods=['POST'])
def create_est_alias():
    logger.info("API - POST Create EST Alias")
    err = _require_role('superadmin', 'admin')
    if err: return err
    data = request.get_json()
    if not data:
        abort(400, description="Missing JSON body")
    for field in ("name", "ca_id", "template_id", "username", "password"):
        if not data.get(field):
            abort(400, description=f"Missing required field: {field}")

    result = api_adapters.create_est_alias(data)
    if not result:
        abort(500, description="Failed to create EST alias")
    return jsonify(result), 201


@bp.route('/est/<int:alias_id>', methods=['GET'])
def get_est_alias(alias_id):
    logger.info(f"API - GET EST Alias {alias_id}")
    alias = api_adapters.get_est_alias(alias_id)
    if not alias:
        abort(404, description="EST alias not found")
    return jsonify(api_adapters.convert_to_serializable(alias)), 200


@bp.route('/est/<int:alias_id>', methods=['PUT'])
def update_est_alias(alias_id):
    logger.info(f"API - PUT Update EST Alias {alias_id}")
    err = _require_role('superadmin', 'admin')
    if err: return err
    data = request.get_json()
    if not data:
        abort(400, description="Missing JSON body")
    for field in ("name", "ca_id", "template_id", "username"):
        if not data.get(field):
            abort(400, description=f"Missing required field: {field}")

    ok = api_adapters.update_est_alias(alias_id, data)
    if not ok:
        abort(404, description="EST alias not found or update failed")
    return jsonify({"message": "EST alias updated successfully"}), 200


@bp.route('/est/<int:alias_id>', methods=['DELETE'])
def delete_est_alias(alias_id):
    logger.info(f"API - DELETE EST Alias {alias_id}")
    err = _require_role('superadmin', 'admin')
    if err: return err
    ok = api_adapters.delete_est_alias(alias_id)
    if not ok:
        abort(404, description="EST alias not found")
    return jsonify({"message": "EST alias deleted successfully"}), 200


@bp.route('/est/<int:alias_id>/set-default', methods=['POST'])
def set_default_est_alias(alias_id):
    logger.info(f"API - POST Set Default EST Alias {alias_id}")
    err = _require_role('superadmin', 'admin')
    if err: return err
    ok = api_adapters.set_default_est_alias(alias_id)
    if not ok:
        abort(500, description="Failed to set default EST alias")
    return jsonify({"message": "Default EST alias updated"}), 200


@bp.route('/template', methods=['GET'])
def get_certificate_templates_list():
    logger.info("API - GET Certificate Templates List")
    result = api_adapters.get_template_collection()

    if not result:
        abort(404, description="Certificate Template list not found")

    filtered_result = [
        {
            "id": row["id"],
            "name": row["name"],
            "created_at": row.get("created_at"),
            "updated_at": row.get("updated_at")
        }
        for row in result
    ]

    return jsonify(api_adapters.convert_to_serializable(filtered_result)), 200


@bp.route('/template/<int:template_id>', methods=['GET'])
def get_template_details(template_id):
    logger.info(f"API - GET Template Details {template_id}")
    result = api_adapters.get_template_details(template_id)
    if not result:
        abort(404, description="Template not found")
    return jsonify(result), 200


@bp.route('/template/<int:template_id>/export', methods=['GET'])
def export_template(template_id):
    logger.info(f"API - GET Export Template {template_id}")
    definition = api_adapters.export_cert_template(template_id)
    if not definition:
        abort(404, description="Template not found")
    name = definition.get("template_name", f"template_{template_id}")
    filename = re.sub(r'[^a-zA-Z0-9_\-]', '_', name) + '.json'
    response = Response(
        json.dumps(definition, indent=2),
        content_type='application/json'
    )
    response.headers['Content-Disposition'] = f'attachment; filename="{filename}"'
    return response


@bp.route('/template/<int:template_id>', methods=['PUT'])
def update_template(template_id):
    logger.info(f"API - PUT Update Template {template_id}")
    err = _require_role('superadmin', 'admin')
    if err: return err
    data = request.get_json()
    if not data or 'template_name' not in data:
        abort(400, description="Missing 'template_name' in request body")
    success = api_adapters.update_template(template_id, data)
    if not success:
        abort(404, description="Template not found or update failed")
    return jsonify({"message": "Template updated successfully", "template_id": template_id}), 200


@bp.route('/kms/generate-key', methods=['POST'])
def kms_generate_key():
    logger.info("API - POST KMS Generate Key")
    err = _require_role('superadmin', 'admin', 'user')
    if err: return err
    data = request.get_json()
    if not data or 'algorithm' not in data:
        abort(400, description="Missing 'algorithm' in request body")
    algorithm = data.pop('algorithm')
    persist = data.pop('persist', True)
    try:
        result = api_adapters.kms_generate_key(algorithm=algorithm, persist=persist, **data)
    except ValueError as e:
        abort(400, description=str(e))
    return jsonify(result), 200


# ── User management ──────────────────────────────────────────────────────────

BUILTIN_SUPERADMIN = 'superadmin'


@bp.route('/users', methods=['GET'])
def list_users():
    logger.info("API - GET User List")
    err = _require_role('superadmin', 'admin')
    if err: return err
    users = api_adapters.get_users()
    return jsonify(api_adapters.convert_to_serializable(users)), 200


@bp.route('/users', methods=['POST'])
def create_user():
    logger.info("API - POST Create User")
    err = _require_role('superadmin', 'admin')
    if err: return err

    data = request.get_json()
    if not data:
        abort(400, description="Missing JSON body")
    if not data.get("username"):
        abort(400, description="Missing required field: username")
    if not data.get("password"):
        abort(400, description="Missing required field: password")

    requested_role = data.get("role", "user")
    current_role = g.current_user.get('role')
    if requested_role in ('superadmin', 'admin') and current_role != 'superadmin':
        return jsonify({"error": "Forbidden", "description": "Only superadmins can create admin or superadmin accounts"}), 403

    try:
        user_id = api_adapters.create_user(data)
    except ValueError as e:
        if str(e) == "username_taken":
            abort(409, description="Username already exists")
        raise
    if user_id is None:
        abort(500, description="Failed to create user")
    return jsonify({"message": "User created successfully", "user_id": user_id}), 201


@bp.route('/users/<int:user_id>', methods=['GET'])
def get_user(user_id):
    logger.info(f"API - GET User {user_id}")
    err = _require_role('superadmin', 'admin')
    if err: return err
    user = api_adapters.get_user(user_id)
    if not user:
        abort(404, description="User not found")
    return jsonify(api_adapters.convert_to_serializable(user)), 200


@bp.route('/users/<int:user_id>', methods=['PUT'])
def update_user(user_id):
    logger.info(f"API - PUT Update User {user_id}")
    err = _require_role('superadmin', 'admin')
    if err: return err

    data = request.get_json()
    if not data:
        abort(400, description="Missing JSON body")

    current_role     = g.current_user.get('role')
    current_username = g.current_user.get('username')

    target = api_adapters.get_user(user_id)
    if not target:
        abort(404, description="User not found")

    target_username = target.get('username')
    target_role     = target.get('role')

    if target_username == BUILTIN_SUPERADMIN:
        # Built-in superadmin can only be edited by themselves, password only
        if current_username != BUILTIN_SUPERADMIN:
            return jsonify({"error": "Forbidden", "description": "The built-in superadmin account can only be modified by the superadmin user themselves"}), 403
        allowed = {'password'}
        disallowed = [k for k in data if k not in allowed]
        if disallowed:
            return jsonify({"error": "Forbidden", "description": "Only the password can be changed for the built-in superadmin account"}), 403
    elif target_role in ('superadmin', 'admin'):
        if current_role != 'superadmin':
            return jsonify({"error": "Forbidden", "description": "Only superadmins can modify admin or superadmin accounts"}), 403
    # user/auditor targets: both admin and superadmin can modify

    try:
        ok = api_adapters.update_user(user_id, data)
    except ValueError as e:
        if str(e) == "username_taken":
            abort(409, description="Username already exists")
        raise
    if not ok:
        abort(404, description="User not found or nothing to update")
    return jsonify({"message": "User updated successfully"}), 200


@bp.route('/users/<int:user_id>', methods=['DELETE'])
def delete_user(user_id):
    logger.info(f"API - DELETE User {user_id}")
    err = _require_role('superadmin', 'admin')
    if err: return err

    target = api_adapters.get_user(user_id)
    if not target:
        abort(404, description="User not found")

    if target.get('username') == BUILTIN_SUPERADMIN:
        return jsonify({"error": "Forbidden", "description": "The built-in superadmin account cannot be deleted"}), 403

    if target.get('role') in ('superadmin', 'admin'):
        if g.current_user.get('role') != 'superadmin':
            return jsonify({"error": "Forbidden", "description": "Only superadmins can delete admin or superadmin accounts"}), 403

    ok = api_adapters.delete_user(user_id)
    if not ok:
        abort(404, description="User not found")
    return jsonify({"message": "User deleted successfully"}), 200


@bp.route('/template', methods=['POST'])
def create_template():
    logger.info("API - POST Create Template")
    err = _require_role('superadmin', 'admin')
    if err: return err
    data = request.get_json()
    if not data or 'template_name' not in data:
        abort(400, description="Missing 'template_name' in request body")
    template_id = api_adapters.create_template(data)
    if template_id is None:
        abort(500, description="Failed to create template")
    return jsonify({"message": "Template created successfully", "template_id": template_id}), 201


# ── Tools (superadmin only) ───────────────────────────────────────────────────

@bp.route('/tools/backup-db', methods=['POST'])
def backup_db():
    logger.info("API - POST Backup Database")
    err = _require_role('superadmin')
    if err: return err
    try:
        result = api_adapters.backup_database()
    except RuntimeError as e:
        abort(500, description=f"Backup failed: {e}")
    return jsonify(result), 200


@bp.route('/tools/reset-pki', methods=['POST'])
def reset_pki():
    logger.info("API - POST Reset PKI")
    err = _require_role('superadmin')
    if err: return err
    try:
        result = api_adapters.reset_pki_database()
    except Exception as e:
        logger.error(f"Reset PKI failed: {e}")
        abort(500, description=f"Reset failed: {e}")
    return jsonify(result), 200


@bp.route('/tools/backups', methods=['GET'])
def list_backups():
    logger.info("API - GET Backup List")
    err = _require_role('superadmin')
    if err: return err
    return jsonify(api_adapters.list_backups()), 200


@bp.route('/tools/restore-db', methods=['POST'])
def restore_db():
    logger.info("API - POST Restore Database")
    err = _require_role('superadmin')
    if err: return err
    data = request.get_json()
    if not data or not data.get('filename'):
        abort(400, description="Missing 'filename' in request body")
    try:
        result = api_adapters.restore_database(data['filename'])
    except FileNotFoundError as e:
        abort(404, description=str(e))
    except (ValueError, RuntimeError) as e:
        abort(400, description=str(e))
    except Exception as e:
        logger.error(f"Restore failed: {e}")
        abort(500, description=f"Restore failed: {e}")
    return jsonify(result), 200
