# Roadmap

This document captures medium-term improvements that are valuable, but not required for the current release.

For the **current execution status** of every item below — what's done, what's
in flight, what's pending, what's deferred — see
[PROGRESS.md](PROGRESS.md). Both files are kept in sync as new requirements
arrive: this one is the strategic view, that one is the tactical status board.

## 1. Reliability And Testing

- Introduce automated tests for the core issuance, revocation, CRL, OCSP, EST, and user-management flows.
- Add CI checks for linting, import/syntax validation, and a minimal integration run against a disposable MariaDB instance.
- Replace ad-hoc script-only verification with repeatable test fixtures and sample data builders.

## 2. Security Hardening

- Encryption-at-rest for software keys and HSM PINs, behind a per-provider secret reference with an explicit auto-activation toggle. Specified in [kms-specs.md §6–7](kms-specs.md); tracked under HSM / PKCS#11 Support below to keep the work consolidated.
- ~~Reconcile the end-entity key-escrow path with the per-provider KEK encryption regime.~~ **Done.** `generate_pkcs12(store_key=True)` now KEK-wraps in both passphrase and no-passphrase paths; the passphrase variant carries `storage_type='PassphraseEncrypted'` (a new enum value) so the regimes don't share a label. `build_pkcs12_for_certificate` KEK-unwraps and dispatches on storage type. `SoftwareBackend.load_key` refuses `'PassphraseEncrypted'` cleanly with a pointer to the re-download flow. See PROGRESS §2 for the implementation breakdown.
- Add first-class secret management for admin/bootstrap credentials instead of relying only on generated local files.
- Support stronger auth options for the management API and UI, including MFA and shorter-lived/rotatable tokens.
- Expand EST authentication beyond Basic Auth to include client-certificate authentication where appropriate.

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

CA-management lifecycle, signing pipeline, issuance policy, CRL
distribution, and the operator-visible weaknesses + security risks are
specified in [ca-management-specs.md](ca-management-specs.md). Phased
work plan and acceptance criteria for declaring CA management
feature-complete live in §14–15 of that doc; in-flight design
proposals (`CR-NNNN`) are tracked in §17 of the same doc.

- Add richer OCSP and CRL interoperability tests against common clients and relying-party stacks.
- Improve CA/template validation before persistence so configuration errors are caught earlier (CA-side risks catalogued in [ca-management-specs.md §13](ca-management-specs.md)).
- Add certificate renewal workflows, key rollover flows, and safer decommissioning for CAs and OCSP responders ([ca-management-specs.md §14 Phase 3 + Phase 5](ca-management-specs.md)).
- Consider publishing OpenAPI-style API documentation for the management endpoints.

## 5. Deployment And Operations

- Provide a production-focused deployment guide covering TLS termination, reverse proxies, backups, upgrades, and restore drills.
- Add health/readiness endpoints suitable for orchestration and monitoring.
- Improve uninstall/reset tooling so operators can choose between preserving or purging data explicitly.
- Support alternative runtime configuration layouts more consistently across utilities and background jobs.

## 6. Usability And Admin Experience

- Expand the UI with safer destructive-action workflows, clearer first-run guidance, and better inline validation.
- Improve audit-log search/filter/export capabilities and add retention controls.
- Surface more certificate lifecycle information in the dashboard, including expiring certs and OCSP/CRL freshness.
- Add guided import flows for CAs, OCSP responders, and EST aliases.

## 7. Documentation And Lifecycle Management

- Keep operational docs aligned with the Docker-first deployment path and current utility scripts.
- Separate historical design notes from current operator documentation more clearly.
- Add upgrade notes for schema-changing releases so operators know when `reset_pki.py` is sufficient and when a migration script is needed.

## 8. Functional Improvements

This section is the home for change requests that add new product
capabilities, distinct from the reliability / security / polish
improvements above. New requirements coming in from operators or
testing land here first; once accepted they get a corresponding
`[pending]` entry in [PROGRESS.md](PROGRESS.md).

- **Self-signed certificate option in the request flow.** Today the
  certificate-request page requires picking both a CA and a template.
  Add a "Self-signed" option — most likely a sentinel entry at the top
  of the CA dropdown — so an operator can generate a one-off self-signed
  certificate without involving any managed CA.
  Behaviour:
  - The selected template still drives subject DN, validity, and
    extensions.
  - The freshly-generated private key signs the certificate as its own
    issuer (subject == issuer).
  - The KMS path is unchanged: the new key goes through the default
    software provider exactly as in the current key-generation flow.
  - The result is recorded in the `Certificates` table with `ca_id`
    NULL (already nullable in the schema) plus an explicit
    `is_self_signed` marker so the certificate list can show the
    distinction without a JOIN gymnastic.

- **Generic signing services on top of the KMS.** A configurable
  external sign surface for non-PKI use cases (raw hash signing
  initially, richer formats later such as RFC 3161, CMS, JOSE, and
  code-signing wrappers). Built as a sibling consumer of the KMS
  alongside CAs / OCSP / EST, not as new KMS internals. Spec:
  [kms-specs.md §17](kms-specs.md).
