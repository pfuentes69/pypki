# REST API

All authenticated endpoints require `Authorization: Bearer <token>` obtained from `POST /api/auth/login`.

## Authentication

| Method | Path | Description |
|---|---|---|
| POST | `/api/auth/login` | Log in, returns JWT |
| POST | `/api/auth/logout` | Invalidate token |
| GET | `/api/auth/me` | Current user info |

## Certification Authorities

| Method | Path | Description |
|---|---|---|
| GET | `/api/ca` | List all CAs |
| POST | `/api/ca` | Add a CA (PEM or PKCS#12) |
| GET | `/api/ca/<id>` | CA summary |
| PUT | `/api/ca/<id>` | Update CA settings |
| DELETE | `/api/ca/<id>` | Delete a CA |
| GET | `/api/ca/<id>/full` | CA details with parsed certificate fields |
| GET | `/api/ca/<id>/cert` | CA certificate PEM — public, no auth |
| GET | `/api/ca/<id>/cert/der` | CA certificate DER — public, no auth |
| GET | `/api/ca/<id>/crl` | Current CRL PEM — public, no auth |
| GET | `/api/ca/<id>/crl/der` | Current CRL DER — public, no auth |
| POST | `/api/ca/<id>/crl` | Issue a new CRL |

## Certificates

| Method | Path | Description |
|---|---|---|
| GET | `/api/certificate` | List certificates (paginated, filterable) |
| GET | `/api/certificate/<id>` | Certificate details |
| GET | `/api/certificate/pem/<id>` | Download certificate PEM — public, no auth |
| GET | `/api/certificate/status/<id>` | Revocation status |
| POST | `/api/certificate/issue` | Issue certificate from JSON request |
| POST | `/api/certificate/issue-pkcs12` | Issue certificate + key as PKCS#12 |
| POST | `/api/certificate/revoke/<id>` | Revoke a certificate |
| POST | `/api/certificate/pkcs12/<id>` | Download existing certificate + key as PKCS#12 |
| GET | `/api/certificate/private-key/<id>` | Get private key PEM (admin only) |
| POST | `/api/certificate/parse-csr` | Parse a CSR and return JSON fields |

## Certificate Templates

| Method | Path | Description |
|---|---|---|
| GET | `/api/template` | List templates |
| POST | `/api/template` | Create a template |
| GET | `/api/template/<id>` | Template details |
| PUT | `/api/template/<id>` | Update a template |
| GET | `/api/template/<id>/export` | Export template as JSON |

## OCSP Responders

| Method | Path | Description |
|---|---|---|
| GET | `/api/ocsp` | List OCSP responders |
| POST | `/api/ocsp` | Add a responder (PEM or PKCS#12) |
| GET | `/api/ocsp/<id>` | Responder details |
| PUT | `/api/ocsp/<id>` | Update responder settings |
| DELETE | `/api/ocsp/<id>` | Delete a responder |

OCSP protocol requests are handled at `POST /ocsp` (DER body, RFC 6960 §4.1) or `GET /ocsp/<base64-encoded-request>` (URL-safe base64, RFC 6960 §4.1.1). The responder is resolved from the issuer key hash inside the request — there is no issuer SKI in the URL.

## EST Service

| Method | Path | Description |
|---|---|---|
| GET | `/api/est` | List EST aliases |
| POST | `/api/est` | Create an alias |
| GET | `/api/est/<id>` | Alias details |
| PUT | `/api/est/<id>` | Update an alias |
| DELETE | `/api/est/<id>` | Delete an alias |
| POST | `/api/est/<id>/set-default` | Set as default alias |
| GET | `/.well-known/est[/<label>]/cacerts` | CA certificate (public) |
| POST | `/.well-known/est[/<label>]/simpleenroll` | Enroll via CSR → PKCS#7 |
| POST | `/.well-known/est[/<label>]/simpleenrollpem` | Enroll via CSR → PEM |

## Users

| Method | Path | Description |
|---|---|---|
| GET | `/api/users` | List users |
| POST | `/api/users` | Create user |
| GET | `/api/users/<id>` | User details |
| PUT | `/api/users/<id>` | Update user |
| DELETE | `/api/users/<id>` | Delete user |

## KMS and Tools

| Method | Path | Description |
|---|---|---|
| POST | `/api/kms/generate-key` | Generate a key |
| GET | `/api/audit-logs` | Query audit log (paginated) |
| POST | `/api/audit-logs/clear` | Clear audit log |
| GET | `/api/tools/app-log` | Application log tail |
| POST | `/api/tools/clear-app-log` | Clear application log |
| POST | `/api/tools/backup-db` | Create a database backup |
| GET | `/api/tools/backups` | List available backups |
| POST | `/api/tools/restore-db` | Restore from a backup |
| POST | `/api/tools/reset-pki` | Full database reset (destructive) |
