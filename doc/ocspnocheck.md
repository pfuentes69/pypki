The `OCSP No Check` extension (`id-pkix-ocsp-nocheck`) is a special X.509 extension used in OCSP responder certificates. It tells relying parties that they do not need to check the revocation status of this certificate (OCSP responder certs checking themselves would create a loop).

In Python, using the `cryptography` library, this extension can be added like this:

### ✅ Example: Add `OCSP No Check` Extension to a Certificate

```python
from cryptography import x509
from cryptography.x509.oid import ObjectIdentifier
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
import datetime

# Create private key
private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)

# Subject and issuer (self-signed example)
subject = issuer = x509.Name([
    x509.NameAttribute(x509.NameOID.COUNTRY_NAME, u"US"),
    x509.NameAttribute(x509.NameOID.ORGANIZATION_NAME, u"My Org"),
    x509.NameAttribute(x509.NameOID.COMMON_NAME, u"OCSP Responder"),
])

# OCSP No Check extension OID
OCSP_NO_CHECK_OID = ObjectIdentifier("1.3.6.1.5.5.7.48.1.5")

# Build certificate
builder = x509.CertificateBuilder().subject_name(subject).issuer_name(issuer)
builder = builder.public_key(private_key.public_key())
builder = builder.serial_number(x509.random_serial_number())
builder = builder.not_valid_before(datetime.datetime.utcnow())
builder = builder.not_valid_after(datetime.datetime.utcnow() + datetime.timedelta(days=365))

# Add the OCSP No Check extension (critical = False, and empty value)
builder = builder.add_extension(
    x509.UnrecognizedExtension(OCSP_NO_CHECK_OID, b''),
    critical=False
)

# Sign certificate
certificate = builder.sign(private_key=private_key, algorithm=hashes.SHA256())

# Output certificate (PEM)
cert_pem = certificate.public_bytes(serialization.Encoding.PEM)
print(cert_pem.decode())
```

---

### 📌 Key Notes:

- The OCSP No Check extension has an OID of `1.3.6.1.5.5.7.48.1.5`.
- It has **no value (empty DER)**, so we use `x509.UnrecognizedExtension` with empty bytes.
- It's typically **non-critical**.

---

Let me know if you need to embed it into a CA-signed certificate or add other extensions like `ExtendedKeyUsage` for OCSP.