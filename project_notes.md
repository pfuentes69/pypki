# Project Notes

## Certificate generation flow
1. Keys are generated:
   - By the customer
   - By the platform
2. A request is made:
   - A certificate template is selected, this will mandate everything except the subjectName and SAN
   - The CA is selected, or is set to be self-signed
   - The request is sent via a CSR. Two options:
      - The original request included a CSR
      - A CSR is generated using a JSON that contains subjectName and SAN, keys are generated as part of the request
3. The certificate is signed:
   - A TBS Certificate is generated using the template and request details.
   - The TBS Certificate is signed with a dummy key
   - The final certificate is generated signed with the appropriate key


   Awesome — here's a helper function that takes a DER-encoded X.509 certificate with a **dummy signature**, a **real signature (raw or DER)**, and safely replaces the `signatureValue` in the ASN.1 structure using `asn1crypto`:

---

### ✅ Requirements:

```bash
pip install asn1crypto
```

---

# 🧩 Helper Function to patch signature

```python
from asn1crypto import x509 as asn1_x509
from asn1crypto import pem
from cryptography.hazmat.primitives.asymmetric.utils import encode_dss_signature
import math

def patch_certificate_signature(pre_cert_der: bytes, real_signature: bytes, is_ecdsa: bool = False) -> bytes:
    """
    Replace the dummy signature in a DER-encoded cert with the actual one.
    
    Args:
        pre_cert_der: DER-encoded certificate with dummy signature.
        real_signature: The correct signature (raw r||s for ECDSA, or raw bytes for RSA).
        is_ecdsa: Whether the signature is ECDSA (if True, it will be DER-encoded).

    Returns:
        The final DER-encoded certificate with the real signature.
    """
    cert = asn1_x509.Certificate.load(pre_cert_der)

    # ECDSA: encode raw r||s into ASN.1 DER
    if is_ecdsa:
        # Split r and s
        half = len(real_signature) // 2
        r = int.from_bytes(real_signature[:half], byteorder='big')
        s = int.from_bytes(real_signature[half:], byteorder='big')
        der_sig = encode_dss_signature(r, s)
    else:
        der_sig = real_signature

    # Set the new signature
    cert['signature_value'] = asn1_x509.Certificate._fields[2][1].type(der_sig)

    # Return new DER
    return cert.dump()
```

---

### 💡 Usage Example:

```python
final_der = patch_certificate_signature(
    pre_cert_der=pre_cert.public_bytes(serialization.Encoding.DER),
    real_signature=signature,          # raw signature (r||s for ECDSA, or RSA sig)
    is_ecdsa=True                      # set False if RSA
)
```

Then load it back with `cryptography`:

```python
from cryptography import x509

final_cert = x509.load_der_x509_certificate(final_der)
```

---

Let me know if you want a version that also outputs PEM, or handles `Ed25519`, or extracts `r` and `s` automatically based on curve size.