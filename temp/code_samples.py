with open("request_examples/iot_device_cert_request.json", "r") as request_file:
    request_json = request_file.read()

cert = Certificate()

cert.load_certificate_template(template_json)
cert.load_certificate_request(request_json)

# Generate an RSA private key
cert.generate_private_key("ECDSA", "P-256")

private_key_pem = cert.export_private_key()
with open("out/iot_rootca_private_key.pem", "wb") as key_file:
    key_file.write(private_key_pem)

certificate_pem = cert.generate_certificate_from_template(issuing_ca=ca, validity_days=PKITools.INFINITE_VALIDITY)
#certificate_pem = cert.generate_certificate_from_template(validity_days=PKITools.INFINITE_VALIDITY)
with open("out/iot_device_certificate.pem", "wb") as cert_file:
    cert_file.write(certificate_pem)

