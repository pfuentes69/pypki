# Certificate Template Definitions

Certificate templates are JSON policy documents that control how certificates are issued. They define subject name constraints, X.509 extensions, validity limits, and allowed cryptographic algorithms. Only the subject name and SAN values come from the certificate request — everything else is governed by the template.

Templates are stored in `config/cert_templates/` and can be managed through the web UI template editor or the REST API.

---

## Top-Level Structure

```json
{
  "template_name": "Server Authentication",
  "max_validity": 398,
  "subject_name": { ... },
  "extensions": { ... },
  "allowed_cryptography": { ... }
}
```

| Field | Type | Required | Description |
|---|---|---|---|
| `template_name` | string | yes | Display name of the template |
| `max_validity` | integer | yes | Maximum certificate validity in days. Use `-1` for unlimited |
| `subject_name` | object | yes | Subject name field configuration |
| `extensions` | object | yes | X.509 extension configuration |
| `allowed_cryptography` | object | no | Allowed key algorithms and sizes |

---

## Subject Name

The `subject_name` section defines which Distinguished Name (DN) attributes are allowed and whether they are required.

```json
"subject_name": {
  "fields": {
    "countryName":            { "mandatory": true,  "default": "US" },
    "stateOrProvinceName":    { "mandatory": false, "default": "" },
    "localityName":           { "mandatory": false, "default": "" },
    "organizationName":       { "mandatory": true,  "default": "" },
    "organizationalUnitName": { "mandatory": false, "default": "" },
    "commonName":             { "mandatory": true,  "default": "" },
    "serialNumber":           { "mandatory": false, "default": "" },
    "emailAddress":           { "mandatory": false, "default": "" }
  }
}
```

### Available Fields

| Field | OID | Notes |
|---|---|---|
| `countryName` | 2.5.4.6 | ISO 3166-1 alpha-2 code (e.g. `"US"`, `"DE"`) |
| `stateOrProvinceName` | 2.5.4.8 | State or province |
| `localityName` | 2.5.4.7 | City or locality |
| `organizationName` | 2.5.4.10 | Organization |
| `organizationalUnitName` | 2.5.4.11 | Organizational unit |
| `commonName` | 2.5.4.3 | Common name (FQDN for server certs, identity for others) |
| `serialNumber` | 2.5.4.5 | Serial number — used for device identity (IoT) |
| `emailAddress` | 1.2.840.113549.1.9.1 | Email address in subject |

### Field Options

| Option | Type | Description |
|---|---|---|
| `mandatory` | boolean | Whether the field must be present in the certificate request |
| `default` | string | Value to use if the field is not provided in the request. Empty string means the field is omitted |

---

## Extensions

### basicConstraints

Controls whether the certificate is a CA certificate.

```json
"basicConstraints": {
  "critical": true,
  "ca": false,
  "pathLen": null
}
```

| Option | Type | Description |
|---|---|---|
| `critical` | boolean | Whether the extension is marked critical |
| `ca` | boolean | `true` for CA certificates, `false` for end-entity certificates |
| `pathLen` | integer \| null | Maximum CA path length. `null` means unlimited. Only meaningful when `ca` is `true` |

---

### keyUsage

Defines the cryptographic operations the certificate key may be used for.

```json
"keyUsage": {
  "critical": true,
  "values": ["digitalSignature", "keyEncipherment"]
}
```

| Value | Description |
|---|---|
| `digitalSignature` | Signing data, messages, or TLS handshakes |
| `nonRepudiation` | Non-repudiation (content commitment) |
| `keyEncipherment` | Encrypting symmetric keys (RSA key exchange in TLS) |
| `dataEncipherment` | Directly encrypting data (uncommon) |
| `keyAgreement` | Key agreement protocols (ECDH) |
| `keyCertSign` | Signing certificates — required for CA certificates |
| `cRLSign` | Signing Certificate Revocation Lists — required for CA certificates |

---

### extendedKeyUsage

Specifies application-level purposes for the certificate key.

```json
"extendedKeyUsage": {
  "critical": false,
  "allowed": ["serverAuth", "clientAuth"]
}
```

| Value | OID | Description |
|---|---|---|
| `serverAuth` | 1.3.6.1.5.5.7.3.1 | TLS server authentication |
| `clientAuth` | 1.3.6.1.5.5.7.3.2 | TLS client authentication |
| `emailProtection` | 1.3.6.1.5.5.7.3.4 | S/MIME email signing and encryption |
| `codeSigning` | 1.3.6.1.5.5.7.3.3 | Code signing |
| `timeStamping` | 1.3.6.1.5.5.7.3.8 | Trusted timestamping authority |
| `ocspSigning` | 1.3.6.1.5.5.7.3.9 | OCSP response signing |
| `smartCardLogon` | 1.3.6.1.4.1.311.20.2.2 | Smart card logon |
| `documentSigning` | 1.3.6.1.4.1.311.10.3.12 | Document signing |
| `anyExtendedKeyUsage` | 2.5.29.37.0 | Any extended key usage (unrestricted) |

---

### subjectAltName

Controls which Subject Alternative Name (SAN) types are permitted and their cardinality.

```json
"subjectAltName": {
  "critical": false,
  "allowed_types": {
    "dnsNames": {
      "allowed": true,
      "mandatory": false,
      "min": 1,
      "max": 5
    },
    "ipAddresses": {
      "allowed": true,
      "mandatory": false,
      "min": 0,
      "max": 3
    },
    "emailAddresses": {
      "allowed": false,
      "mandatory": false
    }
  }
}
```

| SAN Type | Description |
|---|---|
| `dnsNames` | DNS domain names (e.g. `www.example.com`) |
| `ipAddresses` | IPv4 or IPv6 addresses |
| `emailAddresses` | RFC 822 email addresses |

Options per SAN type:

| Option | Type | Description |
|---|---|---|
| `allowed` | boolean | Whether this SAN type may be included |
| `mandatory` | boolean | Whether at least one value of this type is required |
| `min` | integer | Minimum number of values (optional) |
| `max` | integer | Maximum number of values (optional) |

---

### subjectKeyIdentifier

Includes the Subject Key Identifier extension, which contains a hash of the public key.

```json
"subjectKeyIdentifier": {
  "include": true
}
```

---

### authorityKeyIdentifier

Includes the Authority Key Identifier extension, linking the certificate to the issuing CA's key.

```json
"authorityKeyIdentifier": {
  "include": true,
  "critical": false
}
```

---

### OCSPNoCheck

Includes the `id-pkix-ocsp-nocheck` extension. Used exclusively on OCSP responder certificates to indicate that the OCSP responder certificate itself should not be checked for revocation.

```json
"OCSPNoCheck": {
  "include": true
}
```

---

### policyIdentifiers

Includes the Certificate Policies extension with one or more policy OIDs.

```json
"policyIdentifiers": {
  "critical": false,
  "values": ["2.23.140.1.2.2", "1.3.6.1.4.1.11129.2.5.1"]
}
```

Common policy OIDs:

| OID | Description |
|---|---|
| `2.23.140.1.2.2` | CA/Browser Forum OV (Organization Validated) |
| `2.23.140.1.2.1` | CA/Browser Forum DV (Domain Validated) |
| `2.23.140.1.2.3` | CA/Browser Forum IV (Individual Validated) |
| `2.5.29.32.0` | anyPolicy |

---

### cdp

Includes a CRL Distribution Point extension pointing to the location where the CRL can be fetched.

```json
"cdp": {
  "url": "http://crl.example.com/root.crl",
  "critical": false
}
```

---

### aia

Includes the Authority Information Access extension with OCSP and/or CA Issuers URLs.

```json
"aia": {
  "critical": false,
  "authorityInfoAccess": {
    "OCSP": {
      "url": "http://ocsp.example.com"
    },
    "caIssuers": {
      "url": "http://ca.example.com/ca.crt"
    }
  }
}
```

| Field | Description |
|---|---|
| `OCSP.url` | URL of the OCSP responder for this certificate's CA |
| `caIssuers.url` | URL where the issuing CA certificate can be downloaded |

Either or both entries may be omitted.

---

## Allowed Cryptography

Specifies which key algorithms are accepted in certificate requests for this template. If this section is omitted, all algorithms supported by the CA are allowed.

```json
"allowed_cryptography": {
  "keyAlgorithms": [
    { "name": "RSA", "min_size": 2048, "default_size": 3072, "max_size": 8192 },
    { "name": "ECDSA", "curves": ["P-256", "P-384", "P-521"] },
    { "name": "Ed25519" }
  ]
}
```

### RSA

| Option | Type | Description |
|---|---|---|
| `name` | string | Must be `"RSA"` |
| `min_size` | integer | Minimum key size in bits |
| `default_size` | integer | Suggested default key size |
| `max_size` | integer | Maximum key size in bits |

### ECDSA

| Option | Type | Description |
|---|---|---|
| `name` | string | Must be `"ECDSA"` |
| `curves` | array | Allowed elliptic curves: `"P-256"`, `"P-384"`, `"P-521"` |

### Ed25519

```json
{ "name": "Ed25519" }
```

No additional options — Ed25519 has a fixed key size.

---

## Complete Examples

### Server Authentication

```json
{
  "template_name": "Server Authentication",
  "max_validity": 398,
  "subject_name": {
    "fields": {
      "countryName":         { "mandatory": true,  "default": "US" },
      "organizationName":    { "mandatory": true,  "default": "" },
      "commonName":          { "mandatory": true,  "default": "" }
    }
  },
  "extensions": {
    "basicConstraints":       { "critical": true,  "ca": false, "pathLen": null },
    "keyUsage":               { "critical": true,  "values": ["digitalSignature", "keyEncipherment"] },
    "extendedKeyUsage":       { "critical": false, "allowed": ["serverAuth", "clientAuth"] },
    "subjectAltName": {
      "critical": false,
      "allowed_types": {
        "dnsNames":           { "allowed": true, "mandatory": true, "min": 1, "max": 5 },
        "ipAddresses":        { "allowed": true, "mandatory": false, "min": 0, "max": 3 }
      }
    },
    "subjectKeyIdentifier":   { "include": true },
    "authorityKeyIdentifier": { "include": true, "critical": false },
    "policyIdentifiers":      { "critical": false, "values": ["2.23.140.1.2.2"] },
    "cdp":                    { "url": "http://crl.example.com/root.crl", "critical": false },
    "aia": {
      "critical": false,
      "authorityInfoAccess": {
        "OCSP":      { "url": "http://ocsp.example.com" },
        "caIssuers": { "url": "http://ca.example.com/ca.crt" }
      }
    }
  },
  "allowed_cryptography": {
    "keyAlgorithms": [
      { "name": "RSA",    "min_size": 2048, "default_size": 3072, "max_size": 8192 },
      { "name": "ECDSA",  "curves": ["P-256", "P-384", "P-521"] },
      { "name": "Ed25519" }
    ]
  }
}
```

### CA Certificate

```json
{
  "template_name": "Intermediate CA",
  "max_validity": -1,
  "subject_name": {
    "fields": {
      "countryName":      { "mandatory": true, "default": "US" },
      "organizationName": { "mandatory": true, "default": "" },
      "commonName":       { "mandatory": true, "default": "" }
    }
  },
  "extensions": {
    "basicConstraints":       { "critical": true, "ca": true, "pathLen": 0 },
    "keyUsage":               { "critical": true, "values": ["keyCertSign", "cRLSign"] },
    "subjectKeyIdentifier":   { "include": true },
    "authorityKeyIdentifier": { "include": true, "critical": false }
  },
  "allowed_cryptography": {
    "keyAlgorithms": [
      { "name": "RSA",   "min_size": 4096, "default_size": 4096, "max_size": 8192 },
      { "name": "ECDSA", "curves": ["P-384", "P-521"] }
    ]
  }
}
```

### S/MIME (Email Protection)

```json
{
  "template_name": "S/MIME",
  "max_validity": 825,
  "subject_name": {
    "fields": {
      "countryName":      { "mandatory": true, "default": "US" },
      "organizationName": { "mandatory": true, "default": "" },
      "commonName":       { "mandatory": true, "default": "" }
    }
  },
  "extensions": {
    "basicConstraints":       { "critical": true, "ca": false, "pathLen": null },
    "keyUsage":               { "critical": true, "values": ["digitalSignature", "keyEncipherment"] },
    "extendedKeyUsage":       { "critical": false, "allowed": ["emailProtection", "clientAuth"] },
    "subjectAltName": {
      "critical": false,
      "allowed_types": {
        "emailAddresses": { "allowed": true, "mandatory": true }
      }
    },
    "subjectKeyIdentifier":   { "include": true },
    "authorityKeyIdentifier": { "include": true, "critical": false },
    "cdp":                    { "url": "http://crl.example.com/root.crl", "critical": false }
  }
}
```

### OCSP Responder

```json
{
  "template_name": "OCSP Responder",
  "max_validity": -1,
  "subject_name": {
    "fields": {
      "commonName": { "mandatory": true, "default": "" }
    }
  },
  "extensions": {
    "basicConstraints":       { "critical": true,  "ca": false, "pathLen": null },
    "keyUsage":               { "critical": true,  "values": ["digitalSignature"] },
    "extendedKeyUsage":       { "critical": false, "allowed": ["ocspSigning"] },
    "OCSPNoCheck":            { "include": true },
    "subjectKeyIdentifier":   { "include": true },
    "authorityKeyIdentifier": { "include": true, "critical": false }
  }
}
```

### IoT Device

```json
{
  "template_name": "IoT Device",
  "max_validity": -1,
  "subject_name": {
    "fields": {
      "organizationName": { "mandatory": false, "default": "" },
      "serialNumber":     { "mandatory": false, "default": "" },
      "commonName":       { "mandatory": true,  "default": "" }
    }
  },
  "extensions": {
    "basicConstraints":       { "critical": true,  "ca": false, "pathLen": null },
    "keyUsage":               { "critical": true,  "values": ["digitalSignature", "keyEncipherment"] },
    "extendedKeyUsage":       { "critical": false, "allowed": ["clientAuth"] },
    "authorityKeyIdentifier": { "include": true, "critical": false }
  },
  "allowed_cryptography": {
    "keyAlgorithms": [
      { "name": "ECDSA", "curves": ["P-256", "P-384"] },
      { "name": "Ed25519" }
    ]
  }
}
```

---

## Template Files

Built-in templates are located in `config/cert_templates/`:

| File | Purpose |
|---|---|
| `template_base.json` | Generic template showing all available options |
| `ca_cert_template.json` | CA certificate (keyCertSign, cRLSign) |
| `client_cert_template.json` | TLS client authentication |
| `client_cert_template_v2.json` | Minimal client template |
| `server_cert_template.json` | TLS server (398-day max, serverAuth) |
| `smime_cert_template.json` | S/MIME email protection (825-day max) |
| `ocsp_responder_cert_template.json` | OCSP responder (ocspSigning + OCSPNoCheck) |
| `iot_device_cert_template.json` | IoT device client certificates |
| `iot_rootca_cert_template.json` | IoT root CA (ECDSA only) |
