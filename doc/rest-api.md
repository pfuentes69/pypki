# REST API

All authenticated endpoints require `Authorization: Bearer <token>`
obtained from `POST /api/auth/login`. Routes that do not require auth
are marked **(public)**. Routes that require a specific role are
marked with the role name.

## Authentication

| Method | Path | Description |
|---|---|---|
| POST | `/api/auth/login` | Log in, returns JWT |
| POST | `/api/auth/logout` | Invalidate token |
| GET | `/api/auth/me` | Current user info |

## Dashboard

| Method | Path | Description |
|---|---|---|
| GET | `/api/dashboard/stats` | Aggregate counters (CAs, certs, OCSP responders, …) |

## Certification Authorities

Authoritative spec: [ca-management-specs.md](ca-management-specs.md).

| Method | Path | Description |
|---|---|---|
| GET | `/api/ca` | List all CAs |
| POST | `/api/ca` | Add a CA (PEM, PKCS#12, or bind existing KMS key) — admin |
| POST | `/api/ca/generate` | Generate a new CA in-app (root / internal-sub / external-sub CSR phase 1) — admin (CR-0001) |
| POST | `/api/ca/<id>/install-cert` | Install signed certificate into a pending-issuance CA (CR-0001) — admin |
| GET | `/api/ca/<id>` | CA summary |
| PUT | `/api/ca/<id>` | Update CA settings — admin |
| DELETE | `/api/ca/<id>` | Delete a CA (cascade per spec) — admin |
| GET | `/api/ca/<id>/full` | CA details with parsed certificate fields |
| GET | `/api/ca/<id>/cert` | CA certificate PEM **(public)** |
| GET | `/api/ca/<id>/cert/der` | CA certificate DER **(public)** |
| GET | `/api/ca/<id>/crl` | Current CRL PEM **(public)** |
| GET | `/api/ca/<id>/crl/der` | Current CRL DER **(public)** |
| POST | `/api/ca/<id>/crl` | Issue a new CRL — admin |
| GET | `/ca/crl/<ca_id>` | Unauthenticated CRL distribution endpoint **(public)** |

## Certificates

Authoritative spec: [certificate-management-specs.md](certificate-management-specs.md).

| Method | Path | Description |
|---|---|---|
| GET | `/api/certificate` | List certificates (paginated, filterable) |
| GET | `/api/certificate/<id>` | Certificate details |
| GET | `/api/certificate/pem/<id>` | Download certificate PEM **(public)** |
| GET | `/api/certificate/status/<id>` | Revocation status |
| POST | `/api/certificate/issue` | Issue certificate from JSON request (CSR upload path) |
| POST | `/api/certificate/issue-pkcs12` | Issue certificate + key as PKCS#12 (server-side keygen) |
| POST | `/api/certificate/revoke/<id>` | Revoke a certificate — admin |
| POST | `/api/certificate/pkcs12/<id>` | Download existing certificate + key as PKCS#12 |
| GET | `/api/certificate/private-key/<id>` | Get private key PEM — admin only |
| POST | `/api/certificate/parse-csr` | Parse a CSR and return JSON fields |

## Certificate Templates

Authoritative spec: [certificate-template-specs.md](certificate-template-specs.md).

| Method | Path | Description |
|---|---|---|
| GET | `/api/template` | List templates |
| POST | `/api/template` | Create a template — admin |
| GET | `/api/template/<id>` | Template details |
| PUT | `/api/template/<id>` | Update a template — admin |
| GET | `/api/template/<id>/export` | Export template as JSON |

`DELETE /api/template/<id>` is intentionally not implemented today; see
[certificate-template-specs.md §6.4](certificate-template-specs.md).

## OCSP Responders

| Method | Path | Description |
|---|---|---|
| GET | `/api/ocsp` | List OCSP responders |
| POST | `/api/ocsp` | Add a responder (PEM or PKCS#12) — admin |
| GET | `/api/ocsp/<id>` | Responder details |
| PUT | `/api/ocsp/<id>` | Update responder settings — admin |
| DELETE | `/api/ocsp/<id>` | Delete a responder — admin |

OCSP protocol requests are handled at `POST /ocsp` (DER body,
RFC 6960 §4.1) and `GET /ocsp/<base64-encoded-request>` (URL-safe
base64, RFC 6960 §4.1.1). The responder is resolved from the issuer
key hash inside the request — there is no issuer SKI in the URL.

## EST Service

Authoritative spec: [est-specs.md](est-specs.md).

| Method | Path | Description |
|---|---|---|
| GET | `/api/est` | List EST aliases |
| POST | `/api/est` | Create an alias — admin |
| GET | `/api/est/<id>` | Alias details |
| PUT | `/api/est/<id>` | Update an alias — admin |
| DELETE | `/api/est/<id>` | Delete an alias — admin |
| POST | `/api/est/<id>/set-default` | Set as default alias — admin |
| GET | `/api/getestaliases` | Legacy list endpoint (kept for backwards compat) |
| GET | `/.well-known/est[/<label>]/cacerts` | CA certificate **(public)** |
| POST | `/.well-known/est[/<label>]/simpleenroll` | Enroll via CSR → PKCS#7 (per-alias Basic Auth; mTLS planned — CR-0001 in est-specs.md §14.1) |
| POST | `/.well-known/est[/<label>]/simpleenrollpem` | Enroll via CSR → PEM (non-standard) |

## Users

| Method | Path | Description |
|---|---|---|
| GET | `/api/users` | List users — admin |
| POST | `/api/users` | Create user — admin |
| GET | `/api/users/<id>` | User details — admin |
| PUT | `/api/users/<id>` | Update user — admin |
| DELETE | `/api/users/<id>` | Delete user — admin |

## Crypto Providers

Authoritative spec: [kms-specs.md §9.1](kms-specs.md).

| Method | Path | Description |
|---|---|---|
| GET | `/api/crypto-providers` | List providers |
| POST | `/api/crypto-providers` | Create provider — superadmin |
| GET | `/api/crypto-providers/<id>` | Provider details |
| PUT | `/api/crypto-providers/<id>` | Update provider — superadmin |
| DELETE | `/api/crypto-providers/<id>` | Delete provider (refused if keys reference it) — superadmin |
| GET | `/api/crypto-providers/<id>/status` | Activation state |
| POST | `/api/crypto-providers/<id>/activate` | Activate provider (resolve auth secret) — admin |
| POST | `/api/crypto-providers/<id>/deactivate` | Deactivate provider — admin |

## KMS Keys

Authoritative spec: [kms-specs.md §9.2](kms-specs.md).

| Method | Path | Description |
|---|---|---|
| GET | `/api/kms/keys` | List keys (with `?unbound=true` filter; `?provider_id=…`, `?key_type=…`) |
| POST | `/api/kms/keys` | Generate a key in the named provider — admin |
| GET | `/api/kms/keys/<id>` | Key details — usage, public key |
| POST | `/api/kms/keys/import` | Import an on-token key (pkcs11 providers) — admin |
| POST | `/api/kms/keys/<id>/export` | Export the public key only |
| DELETE | `/api/kms/keys/<id>` | Delete a key (refused when in use) — admin |
| POST | `/api/kms/generate-key` | Legacy single-shot keygen endpoint (kept for backwards compat) |

## Audit Logs

| Method | Path | Description |
|---|---|---|
| GET | `/api/audit-logs` | Query audit log (paginated) |
| POST | `/api/audit-logs/clear` | Clear audit log — superadmin |

## Tools

| Method | Path | Description |
|---|---|---|
| GET | `/api/tools/app-log` | Application log tail |
| POST | `/api/tools/clear-app-log` | Clear application log — superadmin |
| GET | `/api/tools/backups` | List available backups |
| POST | `/api/tools/backup-db` | Create a database backup — superadmin |
| POST | `/api/tools/restore-db` | Restore from a backup — superadmin |
| POST | `/api/tools/reset-pki` | Full database reset (destructive) — superadmin |

## Status

| Method | Path | Description |
|---|---|---|
| GET | `/api/status` | Liveness probe **(public)** |
