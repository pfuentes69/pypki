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

- Encryption-at-rest for software keys and HSM PINs, behind a per-provider secret reference with an explicit auto-activation toggle. Specified in [kms-strategy.md §6–7](kms-strategy.md); tracked under HSM / PKCS#11 Support below to keep the work consolidated.
- Add first-class secret management for admin/bootstrap credentials instead of relying only on generated local files.
- Support stronger auth options for the management API and UI, including MFA and shorter-lived/rotatable tokens.
- Expand EST authentication beyond Basic Auth to include client-certificate authentication where appropriate.

## 3. HSM / PKCS#11 Support

The full specification — architecture, data model, REST API, management UI,
PKCS#11 conformance, dev environment, and phased order of work — lives in
[kms-strategy.md](kms-strategy.md). The remaining concrete defects (with
file/line pointers) are catalogued as a punch-list in
[hsm-gap-analysis.md](hsm-gap-analysis.md). Current HSM support exists end-to-end
on paper but has correctness, portability, and operator-experience gaps that
block production use.

- **Provider model.** Introduce `CryptoProviders` (kinds `software` and `pkcs11`) so each provider — software cryptotoken, SoftHSM dev, YubiHSM, Luna, … — is configured once with module path (when applicable), slot, and auth, and `KeyStorage` rows reference it by FK. Replaces the hard-coded macOS SafeNet path, the inline per-key connection columns, and the flat plaintext-PEM software bucket (kms-strategy.md §3–4; closes Gap 4).
- **Correctness (blockers).** Fix the RSA-on-HSM mechanism so signatures verify against `sha256WithRSAEncryption` (Gap 1), and add the missing ECDSA branch in `KeyTools.sign_digest` (Gap 2).
- **Slot addressing.** Thread the provider's `slot_label` through `open_session()` so multi-slot tokens and reinitialised SoftHSM2 tokens work (Gap 3).
- **Stability.** Add per-key locking around `KMS.load_key` to prevent duplicate sessions under concurrent first-use (Gap 7); share one PKCS#11 session per provider, opened on activation and closed on deactivation/shutdown (Gap 6).
- **Secret handling.** Move HSM PINs and software-key PEMs out of the plaintext database under a per-provider secret reference (`db:encrypted` / `env:` / `vault:` / `operator:prompt`) with an explicit auto-activation toggle per provider (kms-strategy.md §6–7; closes Gap 5).
- **Operator UX.** Provider management API + UI (CRUD, activate/deactivate); per-provider key management API + UI (list, generate RSA/ECDSA, import on-token keys, delete) — kms-strategy.md §9–10, closes Gap 8.
- **Hardening.** Validate `hsm_token_id` at insert/load (Gap 9); give symmetric keys their own storage taxonomy (Gap 11); update the stale `migrate_keys_to_kms.py` OCSP error reference (Gap 12).
- **Dev environment.** SoftHSM2-based dev/CI environment first (already wired into the Docker setup; see kms-strategy.md §12 and [softhsm2-manual.md](softhsm2-manual.md)). Gaps 1, 2, 6, 7 are not safely fixable without it.
- **Fidelity pass.** *Pending hardware/SDK availability.* Run the full HSM test suite against the YubiHSM 2 simulator and / or a Thales DPoD trial (or AWS CloudHSM as a Luna-equivalent fallback) before declaring HSM support release-ready against those vendors. SoftHSM2 remains the canonical regression target until then. See [kms-strategy.md §13 Phase 7](kms-strategy.md).
- **Testing.** Parameterise the signing suite over the two backends so every test runs once against `software-default` and once against `softhsm-dev` in CI — recovers the test-parity benefit of unified PKCS#11 without making SoftHSM the production path.

## 4. PKI And Protocol Maturity

- Add richer OCSP and CRL interoperability tests against common clients and relying-party stacks.
- Improve CA/template validation before persistence so configuration errors are caught earlier.
- Add certificate renewal workflows, key rollover flows, and safer decommissioning for CAs and OCSP responders.
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
