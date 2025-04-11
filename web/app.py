
from flask import Flask, render_template, request, jsonify
import requests

app = Flask(__name__)

EST_SERVER = 'http://127.0.0.1:5000/.well-known/est'

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/request-cert')
def request_cert():
    return render_template('request_cert.html')

@app.route('/get-ca-cert')
def get_ca_cert():
    return render_template('get_ca_cert.html')

@app.route('/submit-csr', methods=['POST'])
def submit_csr():
    csr = request.form.get('csr')
    try:
        headers = {'Content-Type': 'application/pkcs10'}
        response = requests.post(f"{EST_SERVER}/simpleenrollpem", data=csr.encode(), headers=headers, verify=False)
        return jsonify({'cert': response.text})
    except Exception as e:
        return jsonify({'error': str(e)})

@app.route('/fetch-ca-cert')
def fetch_ca_cert():
    try:
        response = requests.get(f"{EST_SERVER}/cacerts", verify=False)
        return jsonify({'pem': response.text})
    except Exception as e:
        return jsonify({'error': str(e)})

if __name__ == '__main__':
    app.run(debug=True, port=8080)
