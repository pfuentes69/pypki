# Roadmap

This document captures medium-term improvements that are valuable, but
not required for the current release.

For the **current execution status** of every item below — what's done,
what's in flight, what's pending, what's deferred — see
[PROGRESS.md](PROGRESS.md). Both files are kept in sync as new
requirements arrive: this one is the strategic view, that one is the
tactical status board.

Cross-references to the authoritative per-area specs:

| Area | Spec |
|---|---|
| CA management | [ca-management-specs.md](ca-management-specs.md) |
| End-entity certificates | [certificate-management-specs.md](certificate-management-specs.md) |
| Certificate templates | [certificate-template-specs.md](certificate-template-specs.md) |
| EST service | [est-specs.md](est-specs.md) |
| KMS | [kms-specs.md](kms-specs.md) |
| HSM contracts | [hsm-support-specs.md](hsm-support-specs.md) |
| Database schema | [database-specs.md](database-specs.md) |

In-flight design proposals (`CR-NNNN`) live in §17 of the
corresponding spec.

## 1. Reliability And Testing

- Introduce automated tests for the core issuance, revocation, CRL,
  OCSP, EST, and user-management flows. KMS-layer pytest coverage
  exists (Phases 0–6, 54 tests); the app-level surfaces are still on
  script-based smoke tests.
- Add CI checks for linting, import/syntax validation, and a minimal
  integration run against a disposable MariaDB instance. No
  `.github/workflows/` exists yet.
- Replace ad-hoc script-only verification with repeatable test
  fixtures and sample data builders.

## 2. Security Hardening

- ~~Encryption-at-rest for software keys and HSM PINs.~~ **Done** —
  per-provider KEK derived via HKDF-SHA256 from `HSM_PIN_KEK`; provider
  auth secrets KEK-wrapped under `auth_secret_ref='db:encrypted'`. See
  [kms-specs.md §6–7](kms-specs.md).
- ~~Reconcile the end-entity key-escrow path with the per-provider KEK
  encryption regime.~~ **Done** — `generate_pkcs12(store_key=True)`
  KEK-wraps in both paths; the passphrase variant carries
  `storage_type='PassphraseEncrypted'`. See PROGRESS §2.
- Add first-class secret management for admin/bootstrap credentials
  instead of relying only on generated local files. Currently shipped
  via `setup.sh` → `.env` + `.setup_credentials`.
- Support stronger auth options for the management API and UI,
  including MFA and shorter-lived/rotatable JWTs. Today
  `auth_routes.py` issues plain non-rotatable tokens.
- Expand EST authentication beyond Basic Auth to include
  client-certificate (mTLS) authentication. Specified as **CR-0001**
  in [est-specs.md §14.1](est-specs.md); schema column
  (`ESTAliases.cert_fingerprint`) and UI placeholder already in place.

## 3. HSM / PKCS#11 Support

A first-class HSM/PKCS#11 backend coexisting with software keys, with
data-driven provider configuration, encrypted-at-rest secret handling,
and a portable PKCS#11 subset that works against SoftHSM2, YubiHSM 2,
and Thales Luna without code changes.

The full design lives in [kms-specs.md](kms-specs.md); the HSM-specific
contracts (signing mechanisms, slot addressing, session lifecycle,
storage-type semantics) live in
[hsm-support-specs.md](hsm-support-specs.md); SoftHSM2 dev-environment
operations live in [softhsm2-manual.md](softhsm2-manual.md).
Implementation status per phase is in [PROGRESS.md §3](PROGRESS.md).

The remaining initiative is the **vendor-fidelity validation pass**
against real-vendor PKCS#11 implementations (YubiHSM 2 simulator,
Thales DPoD, AWS CloudHSM as a Luna fallback), held back until the
hardware / SDK becomes available. SoftHSM2 remains the canonical
regression target until then. See
[kms-specs.md §13 Phase 7](kms-specs.md).

## 4. PKI And Protocol Maturity

CA management is specified in
[ca-management-specs.md](ca-management-specs.md); end-entity
certificate flows in
[certificate-management-specs.md](certificate-management-specs.md);
templates in
[certificate-template-specs.md](certificate-template-specs.md); EST in
[est-specs.md](est-specs.md). Each spec carries its own §13 / §12
weaknesses-and-risks catalogue, its phased order of work, and the
in-flight design proposals (`CR-NNNN`) currently in §17 / §14 of the
matching spec.

- Add richer OCSP and CRL interoperability tests against common
  clients and relying-party stacks (openssl ocsp, certutil, Windows
  CryptoAPI).
- Improve CA/template validation before persistence so configuration
  errors are caught earlier. CA-side risks catalogued in
  [ca-management-specs.md §13](ca-management-specs.md); template-side
  JSON-schema validation is the highest-leverage gap in
  [certificate-template-specs.md §12.1](certificate-template-specs.md).
- Add certificate renewal workflows, key rollover flows, and safer
  decommissioning for CAs and OCSP responders
  ([ca-management-specs.md §14 Phase 3 + Phase 5](ca-management-specs.md)).
- Implement the RFC 7030 endpoints not yet exposed by EST:
  `simplereenroll`, `csrattrs`, `serverkeygen` — see
  [est-specs.md §10.5](est-specs.md) and the Phase C ordering in
  [est-specs.md §11](est-specs.md).
- Consider publishing OpenAPI-style API documentation for the
  management endpoints.

## 5. Deployment And Operations

- Provide a production-focused deployment guide covering TLS
  termination, reverse proxies, backups, upgrades, and restore drills.
  TLS termination is also a prerequisite for EST CR-0001 (mTLS).
- Replace the stub `/api/status` (currently always `{"status": "API is
  up!"}`) with a real readiness check (DB connectivity, default
  provider activation state, required env vars present).
- Improve uninstall/reset tooling so operators can choose between
  preserving or purging data explicitly. `utils/reset_pki.py` is
  destructive today with no preserve flag.
- Support alternative runtime configuration layouts more consistently
  across utilities and background jobs (all currently assume
  `config/config.json`).

## 6. Usability And Admin Experience

- Expand the UI with safer destructive-action workflows. KMS pages
  have rich confirmation modals (Phase 5b); CA / OCSP / template /
  user deletes are still on the original simpler shape.
- Improve audit-log search / filter / export capabilities and add
  retention controls
  ([database-specs.md §8.4](database-specs.md)).
- Surface more certificate lifecycle information in the dashboard,
  including expiring certs and OCSP/CRL freshness.
- Add guided import flows for CAs, OCSP responders, and EST aliases —
  matching the Phase 5b KMS / Crypto Providers experience.
- First-run guidance (onboarding wizard) for fresh installs.
- Inline form validation on CA / template / OCSP / EST forms.

## 7. Documentation And Lifecycle Management

- Keep operational docs aligned with the Docker-first deployment path
  and current utility scripts.
- Separate historical design notes from current operator
  documentation more clearly. The `doc/learning/` and the original
  flat `project-notes.md` were not audited recently; their relevance
  to current operators is unclear.
- Add upgrade notes for schema-changing releases so operators know
  when `reset_pki.py` is sufficient and when an in-place migration is
  needed. `migrate_schema()` is idempotent at boot but the per-release
  scope is not documented.
- Per-release "what changed" notes — no CHANGELOG.md exists today.

## 8. Functional Improvements

This section is the home for change requests that add new product
capabilities, distinct from the reliability / security / polish
improvements above. New requirements coming in from operators or
testing land here first; once accepted they get a corresponding
`[pending]` entry in [PROGRESS.md](PROGRESS.md), and (when the work
warrants it) a `CR-NNNN` design proposal in §17 / §14 of the
appropriate spec.

- ~~**Self-signed certificate option in the request flow.**~~
  **Done** — `ca_id ∈ {null, 0}` on `/api/certificate/issue-pkcs12`
  produces a server-keygen self-signed certificate recorded with
  `is_self_signed=TRUE`. See
  [certificate-management-specs.md §6.3](certificate-management-specs.md).
- **Generic signing services on top of the KMS.** A configurable
  external sign surface for non-PKI use cases (raw hash signing
  initially, richer formats later such as RFC 3161, CMS, JOSE, and
  code-signing wrappers). Built as a sibling consumer of the KMS
  alongside CAs / OCSP / EST, not as new KMS internals. Spec:
  [kms-specs.md §17](kms-specs.md).
- **EST mTLS client-cert authentication.** Promoted from §2 because
  it adds product capability (devices can enroll with cert-based
  identity) on top of the security hardening rationale. CR-0001 in
  [est-specs.md §14.1](est-specs.md).
