# Request Examples

Sample files used to drive certificate issuance in tests and manual experiments.
All paths in the test scripts are relative to the project root, e.g. `doc/request_examples/example.csr`.

---

## Certificate Request JSONs

These files are passed as `request_json` to `CertificateTools.generate_certificate_pem()` and related methods. They supply the subject DN fields (and optional SAN entries) that are merged with the active certificate template at issuance time.

| File | Description |
|---|---|
| `ca_cert_request.json` | Root / intermediate CA certificate — `C=ES, O=Naviter, CN=Test CA 1` |
| `iot_rootca_cert_request.json` | IoT Root CA certificate — `C=ES, O=Naviter, CN=IoT Root CA 1` |
| `client_cert_request.json` | End-entity client certificate with a DNS SAN — `CN=device_name, SAN=clientname.naviter.es` |
| `server_cert_request.json` | TLS server certificate with two DNS SANs — `CN=www.naviter.es` |
| `iot_device_cert_request.json` | IoT device certificate identified by serial number — `serialNumber=999000888, CN=device_name 001` |

### Format

```json
{
    "subject_name": {
        "countryName": "ES",
        "organizationName": "Example Org",
        "commonName": "My Certificate"
    },
    "subjectAltName": {
        "dnsNames": ["example.com"]
    }
}
```

Fields that are not supplied here are taken from the template's `default` values. Mandatory template fields that are missing cause issuance to fail with a `ValueError`.

---

## OpenSSL CSR Files

These files are used by tests that issue certificates from an existing CSR rather than generating a new key pair inside PyPKI.

| File | Description |
|---|---|
| `csr.conf` | OpenSSL config used to generate `example.csr` and `example.key`. Contains a rich subject DN (C, ST, L, O, OU, CN, email, serialNumber, givenName, surname, title, businessCategory, postalCode, streetAddress) and multiple SAN types (DNS, IP, email, URI). |
| `example.csr` | PEM-encoded PKCS#10 CSR generated from `csr.conf`. Subject: `CN=device_name, O=Naviter`. SANs include DNS names, IP addresses, an email address, and a URI. RSA 2048-bit public key. |
| `example.key` | PEM-encoded RSA 2048-bit private key corresponding to `example.csr`. Used in local testing only — do not deploy. |

### Regenerating the CSR

```bash
openssl req -new -newkey rsa:2048 -nodes \
    -keyout doc/request_examples/example.key \
    -out    doc/request_examples/example.csr \
    -config doc/request_examples/csr.conf
```
