
from flask import Flask, render_template, request, jsonify
import requests

app = Flask(__name__)

EST_SERVER = 'http://127.0.0.1:5000/.well-known/est'

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/request-cert-form')
def generate_cert():
    return render_template('request_cert_form.html')

@app.route('/request-cert-csr')
def request_cert():
    return render_template('request_cert_csr.html')

@app.route('/get-ca-cert')
def get_ca_cert():
    return render_template('get_ca_cert.html')

@app.route('/select-value')
def select_value_page():
    return render_template('select_value.html')


@app.route('/api/submit-csr', methods=['POST'])
def submit_csr():
    csr = request.form.get('csr')
    try:
        headers = {'Content-Type': 'application/pkcs10'}
        response = requests.post(f"{EST_SERVER}/simpleenrollpem", data=csr.encode(), headers=headers, verify=False)
        return jsonify({'cert': response.text})
    except Exception as e:
        return jsonify({'error': str(e)})

@app.route('/api/fetch-ca-cert')
def fetch_ca_cert():
    try:
        response = requests.get(f"{EST_SERVER}/cacerts", verify=False)
        return jsonify({'pem': response.text})
    except Exception as e:
        return jsonify({'error': str(e)})
    
@app.route('/api/generate-cert', methods=['POST'])
def api_generate_cert():
    data = request.get_json()
    subject = data.get("subject_name", {})
    san = data.get("subjectAltName", {}).get("dnsNames", [])
    cert = f"""-----BEGIN CERTIFICATE-----
FAKE-CERTIFICATE-FOR {subject.get('commonName', 'Unknown')}
SAN: {", ".join(san)}
-----END CERTIFICATE-----"""
    return jsonify({'cert': cert})


@app.route('/api/get_values')
def api_get_values():
    return jsonify([
        {"label": "Option A", "value": "a"},
        {"label": "Option B", "value": "b"},
        {"label": "Option C", "value": "c"}
    ])

@app.route('/api/select_value', methods=['POST'])
def api_select_value():
    data = request.get_json()
    selected_value = data.get("value")
    if selected_value:
        return jsonify({"message": f"You selected: {selected_value}"})
    return jsonify({"error": "No value provided"}), 400


if __name__ == '__main__':
    app.run(debug=True, port=8080)
