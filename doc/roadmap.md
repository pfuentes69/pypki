# Roadmap

This document captures medium-term improvements that are valuable, but not required for the current release.

## 1. Reliability And Testing

- Introduce automated tests for the core issuance, revocation, CRL, OCSP, EST, and user-management flows.
- Add CI checks for linting, import/syntax validation, and a minimal integration run against a disposable MariaDB instance.
- Replace ad-hoc script-only verification with repeatable test fixtures and sample data builders.

## 2. Security Hardening

- Eliminate clear-text private-key storage for software keys by adding encryption-at-rest for `KeyStorage`.
- Add first-class secret management for admin/bootstrap credentials instead of relying only on generated local files.
- Support stronger auth options for the management API and UI, including MFA and shorter-lived/rotatable tokens.
- Expand EST authentication beyond Basic Auth to include client-certificate authentication where appropriate.
- Move HSM token PINs out of `KeyStorage.token_password` to a per-provider secret reference resolved via env-var / vault / operator-supplied (see [hsm-gap-analysis.md](hsm-gap-analysis.md) Gap 5 and the "HSM provider model" section).
- Either implement the `storage_type='Encrypted'` decrypt path or drop the enum value to remove the foot-gun (Gap 10).

## 3. HSM / PKCS#11 Support

Tracked in detail in [hsm-gap-analysis.md](hsm-gap-analysis.md). Current HSM
support exists end-to-end on paper but has correctness, portability, and
operator-experience gaps that block production use.

- **Correctness (blockers).** Fix the RSA-on-HSM mechanism so signatures verify against `sha256WithRSAEncryption` (Gap 1), and add the missing ECDSA branch in `KeyTools.sign_digest` (Gap 2).
- **Portability.** Introduce an `HSMProviders` record so each HSM (SoftHSM dev, YubiHSM, Luna, …) is configured once with module path, slot, and auth, and `KeyStorage` rows reference it by FK — replacing the hard-coded macOS SafeNet path and the inline per-key connection columns (Gap 4 + "HSM provider model" section). Thread `hsm_slot` through `open_session()` so multi-slot tokens work (Gap 3).
- **Stability.** Add per-key locking in `KMS.load_key` to prevent duplicate sessions under concurrent first-use (Gap 7); share PKCS#11 sessions and close them on `unload_key` / process shutdown (Gap 6).
- **Operator UX.** Extend `kms.generate_key` and the `/kms/generate-key` endpoint with an HSM option, and add an `import_hsm_key()` API for registering pre-existing on-token keys (Gap 8).
- **Hardening.** Validate the `hsm_token_id` format at insert/load time (Gap 9), give symmetric keys their own storage taxonomy so they can be loaded without crashing the PEM parser (Gap 11), and update the stale `migrate_keys_to_kms.py` reference in the OCSP responder error path (Gap 12).
- **Dev environment.** Stand up a SoftHSM2-based dev/CI environment first (see the "Development environment — SoftHSM2 first" section in [hsm-gap-analysis.md](hsm-gap-analysis.md)) — Gaps 1, 2, 6, 7 are not safely fixable without it. Validate against the YubiHSM 2 simulator and a Thales DPoD trial before declaring HSM support release-ready.
- **Testing.** Add SoftHSM2-based integration tests in CI so regressions in mechanism selection, slot handling, or session lifecycle fail fast.

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
