# pyPKI — Progress Tracker

This document is the operational status board for everything tracked
in [roadmap.md](roadmap.md). Each roadmap item is broken down into
concrete tasks with one of four status markers:

- **[done]** — implemented, tested, and merged.
- **[partial]** — some sub-tasks complete, others outstanding.
- **[pending]** — not started.
- **[deferred]** — blocked on an external dependency (hardware, SDK,
  …).

When new requirements arrive, both [roadmap.md](roadmap.md) (the
strategic view) and this document (the tactical status board) are
updated together.

### Working rule

Each entry in this file is a **single line**: state, title, link to
the authoritative description.

The authoritative description lives elsewhere — in the matching
module spec (e.g. [kms-specs.md](kms-specs.md),
[est-specs.md](est-specs.md)) for spec-backed work, or in the
matching [roadmap.md](roadmap.md) bullet for smaller features that do
not warrant their own spec doc. If you find yourself adding a
paragraph of context here, the detail belongs upstream and this entry
should shrink to a pointer.

The "at a glance" table below is the only place where this rule is
relaxed — it summarises counts.

---

## At a glance

| Area | done | partial | pending | deferred | total |
|---|---:|---:|---:|---:|---:|
| §1 Reliability And Testing | 2 | 0 | 11 | 0 | 13 |
| §2 Security Hardening | 5 | 0 | 4 | 0 | 9 |
| §3 HSM / PKCS#11 Support | 1 | 1 | 0 | 3 | 5 |
| §4 PKI And Protocol Maturity | 1 | 2 | 8 | 0 | 11 |
| §5 Deployment And Operations | 0 | 2 | 7 | 0 | 9 |
| §6 Usability And Admin Experience | 5 | 3 | 14 | 0 | 22 |
| §7 Documentation And Lifecycle Management | 2 | 1 | 2 | 0 | 5 |
| §8 Functional Improvements | 1 | 0 | 2 | 0 | 3 |
| **Total** | **17** | **9** | **48** | **3** | **77** |

Counts reflect entries in this doc after the rule above is applied —
broad initiatives may be a single rolled-up line that points at a
spec. Granular work breakdowns live in the spec they reference.

Headline: HSM / PKCS#11 work (§3) is feature-complete; the only open
items are vendor-fidelity validation passes deferred to hardware /
SDK availability. App-level testing (§1), deployment operations (§5),
and non-KMS UX polish (§6) are the largest remaining blocks of work.
EST mTLS authentication (§2 / §8, CR-0001 in
[est-specs.md §14.1](est-specs.md)) is the next-up security item.

---

## §1 — Reliability And Testing

### [done]
- **KMS-layer pytest coverage.** 54 tests across
  `test_kms_software_backend.py`, `test_kms_pkcs11_backend.py`,
  `test_kms_phase4_secrets.py`, `test_kms_phase5_keymgmt.py`,
  `test_kms_phase6_hardening.py`, plus 8 in
  `test_pkcs12_storage_regime.py`. Includes a multi-threaded SoftHSM2
  stress test and end-to-end generate / import / delete round-trips.
  — Phases 0–6 ([kms-specs.md §13](kms-specs.md)).
- **Pytest fixture infrastructure for KMS tests.** `tests/conftest.py`
  provides `FakeDB`, `kms`, `hsm_pin_kek`, `softhsm_module`,
  `softhsm_pkcs11_tool`, `softhsm_token`, `softhsm_rsa_key`,
  `softhsm_ecdsa_key`. Skips gracefully when SoftHSM2 / pkcs11-tool
  are not installed.

### [pending]
- **App-level pytest coverage — certificate issuance.** No tests
  exercise the issuance flow end-to-end (CSR → template → CA → cert).
- **App-level pytest coverage — revocation.** Revoke / un-revoke,
  CRL re-generation triggers, audit-log entries.
- **App-level pytest coverage — CRL.** CRL signing, CDP fields,
  scheduled refresh.
- **App-level pytest coverage — OCSP responder.** Request parsing,
  response signing, nonce policy, hash-algorithm options, responder-id
  encoding.
- **App-level pytest coverage — EST.** `cacerts`, `simpleenroll`,
  alias resolution, Basic-Auth gate (and mTLS gate once CR-0001
  lands).
- **App-level pytest coverage — user management.** Create / update /
  delete, role gating, password change.
- **Replace ad-hoc smoke scripts with fixtures.** The
  `tests/generate_*.py` scripts in the interactive menu
  (`python -m tests`) overlap with what pytest fixtures should
  provide; consolidate.
- **CI workflow file.** No `.github/workflows/` directory exists.
- **CI: lint check.** No linter wired up (ruff / flake8 / pylint).
- **CI: syntax / import validation.** Currently done ad-hoc via
  `python -c "import ast; ast.parse(...)"`; needs a proper job.
- **CI: pytest run.** Should run the existing test suite on every PR.
- **CI: integration MariaDB.** Spin up a disposable MariaDB service
  container and exercise the migration + `reset_pki` path end-to-end.

---

## §2 — Security Hardening

### [done]
- **Software-key encryption-at-rest.** `KeyStorage.private_key` for
  asymmetric software keys is AES-256-GCM ciphertext under a
  per-provider KEK derived via HKDF-SHA256 from `HSM_PIN_KEK`. —
  Phase 0.2.
- **HSM PIN encryption-at-rest.** Provider auth secrets via
  `auth_secret_ref='db:encrypted'` are wrapped under the master KEK
  and stored in `CryptoProviders.auth_secret_blob`. — Phase 4.
- **Per-provider secret reference + auto-activation toggle.** Resolvers
  `db:encrypted` / `env:` / `vault:` / `operator:prompt`;
  `auto_activate` validated against the resolver kind. — Phase 4
  ([kms-specs.md §6–7](kms-specs.md)).
- **`HSM_PIN_KEK` plumbing.** Generated by `setup.sh`, written to
  `.env`, passed to the Docker container via `docker-compose.yml`,
  auto-loaded from `.env` in local-dev mode by
  `web/services/__init__.py`.
- **End-entity key-escrow regime aligned with the per-provider KEK.**
  `generate_pkcs12(store_key=True)` KEK-wraps in both branches;
  `storage_type='PassphraseEncrypted'` (new enum value) distinguishes
  the passphrase-encrypted regime so the
  `'Encrypted'` label keeps single meaning. Refusal-with-clear-message
  in `SoftwareBackend.load_key`. Regression coverage in
  `tests/test_pkcs12_storage_regime.py`.

### [pending]
- **First-class secret management for admin/bootstrap credentials.**
  Currently generated by `setup.sh` and stored in `.env` /
  `.setup_credentials`; no integration with Vault / k8s secrets / etc.
- **MFA for the management UI.** `auth_routes.py` issues plain JWTs.
- **Shorter-lived / rotatable JWT tokens.** Token TTL and rotation
  policy not configurable; refresh-token flow not implemented.
- **EST client-certificate authentication (CR-0001).** Schema column
  (`ESTAliases.cert_fingerprint`) and UI placeholder exist; route-layer
  enforcement not wired. Full design in
  [est-specs.md §14.1](est-specs.md).

---

## §3 — HSM / PKCS#11 Support

Cross-reference: [kms-specs.md](kms-specs.md) for the KMS design,
[hsm-support-specs.md](hsm-support-specs.md) for the HSM-specific
contracts.

### [done]
- Phases 0–6 — provider model, sibling backends, SoftHSM2 dev env,
  RSA + ECDSA HSM signing, slot-by-label, encrypted-at-rest software
  keys, `auth_secret_ref` resolvers, provider-scoped session lifecycle,
  thread-safe `load_key`, provider/key API+UI, hex `hsm_token_id`
  validation, `Symmetric` storage type, `pkcs11_helper`/`KeyTools`
  slim-down. Per-phase breakdown:
  [kms-specs.md §2](kms-specs.md).

### [partial]
- Test parametrisation across backends — software and PKCS#11 suites
  exist separately; matrix consolidation pending.

### [deferred]
- YubiHSM 2 simulator fidelity pass — pending Yubico SDK availability
  ([kms-specs.md §13 Phase 7](kms-specs.md)).
- Thales DPoD fidelity pass — pending trial registration.
- AWS CloudHSM (Luna fallback) fidelity pass — pending account
  access.

---

## §4 — PKI And Protocol Maturity

Cross-reference: [ca-management-specs.md](ca-management-specs.md),
[certificate-management-specs.md](certificate-management-specs.md),
[certificate-template-specs.md](certificate-template-specs.md),
[est-specs.md](est-specs.md). In-flight design proposals (`CR-NNNN`)
live in §17 / §14 of the matching spec.

### [done]
- **In-app CA generation (CR-0001).** Root, internal-subordinate, and
  external-subordinate (CSR phase 1 + install-cert phase 2) all wired;
  `pending-issuance` state surfaced in the UI.
  [ca-management-specs.md §17.1](ca-management-specs.md).

### [partial]
- **CA / template validation before persistence.** `kms_key_id` ↔
  certificate public-key match check on CA creation,
  `CryptoProviders.validate_provider_auth_config` cross-field rules
  landed. Comprehensive JSON-schema validation of template
  `definition` still missing
  ([certificate-template-specs.md §12.1](certificate-template-specs.md));
  CA / OCSP / EST payload-level validation still missing.
- **CA renewal workflow (partial).** The current path requires
  deleting and re-creating the CA. Renewal that preserves CA identity
  / SKI is not implemented.

### [pending]
- **OCSP / CRL interop tests.** Run signed responses through
  `openssl ocsp` / `certutil` / Windows CryptoAPI to confirm RP-side
  acceptance.
- **Key rollover workflow.** Generate new key for an existing CA,
  re-sign chain, mark old key for retirement.
- **CA decommissioning workflow.** Safe shutdown ordering: revoke
  issued certs, generate final CRL, archive, delete.
- **OCSP responder decommissioning workflow.** Same shape, OCSP-side.
- **EST `simplereenroll`.** Not implemented; pairs with EST CR-0001
  mTLS work ([est-specs.md §10.5](est-specs.md)).
- **EST `csrattrs`.** Not implemented; clients cannot query the server
  for required CSR attributes
  ([est-specs.md §10.5](est-specs.md)).
- **EST `serverkeygen`.** Not implemented; would reuse the management
  UI's PKCS#12 keygen path
  ([est-specs.md §10.5](est-specs.md)).
- **OpenAPI / Swagger documentation for the management API.**
  Discussed earlier in conversation; `flasgger` (lightest touch) or
  `APIFlask` (cleaner, more invasive) — not implemented.

---

## §5 — Deployment And Operations

### [partial]
- **Health endpoint.** `GET /api/status` exists at
  [main_routes.py:55](../web/routes/main_routes.py#L55) but only
  returns `{"status": "API is up!"}` — does not check DB connectivity
  or KMS provider readiness.
- **Uninstall / reset tooling.** `utils/reset_pki.py` resets the
  database; `uninstall.sh` removes the Docker stack. The explicit
  preserve-vs-purge distinction is documented in README but not
  exposed as a flag.

### [pending]
- **Production deployment guide.** README covers Docker basics; no
  TLS-termination guide, reverse-proxy guide, or backup/restore drill
  documentation. The TLS guide is a prerequisite for EST CR-0001
  (mTLS).
- **TLS termination guidance.** No nginx / Caddy / Traefik example.
- **Reverse-proxy guidance.** No reference config for putting pyPKI
  behind a corporate proxy.
- **Backup / restore drill documentation.** `utils/restore_backup.py`
  exists but isn't paired with a "test your backups" runbook.
- **Real readiness endpoint.** Replace the stub `/api/status` with a
  check that verifies DB connectivity, KMS default provider activated,
  and any required env vars are set. Should distinguish liveness from
  readiness for orchestration.
- **Explicit preserve-vs-purge flag for reset_pki.** Currently
  `reset_pki` always drops the database; no opt-in to preserve audit
  logs / users / certificates.
- **Alternative runtime configuration layouts.** Utilities and the
  background scheduler all assume `config/config.json`. No explicit
  support for split / per-environment config layouts.

---

## §6 — Usability And Admin Experience

### [done]
- **Crypto Provider management UI.** Full CRUD via modals, activate /
  deactivate flows, default-provider protection, in-use key counts. —
  Phase 5b.
- **Keys management UI.** Provider-aware generate, import, delete,
  with usage warnings and owned-vs-imported confirmation messaging. —
  Phase 5b.
- **CA `key_owned` semantics.** Distinguishes CAs that own their key
  (delete cascades) from CAs bound to a pre-existing KMS key (delete
  preserves the key). — recent work.
- **`KeyStorage.key_owned` semantics.** Distinguishes generated keys
  (delete cascades to on-token objects) from imported keys (delete
  preserves them). — Phase 6.
- **Crypto Provider form cross-field validation.** Auto-activate ↔
  `auth_secret_ref` consistency enforced both client-side and
  server-side. — Phase 5b.

### [partial]
- **Destructive-action confirmations.** KMS pages have rich
  confirmations with usage/ownership context; CA / OCSP / template /
  user delete dialogs use the original simpler shape.
- **Inline form validation.** Cross-field validation done for Crypto
  Providers; CA / template / OCSP / EST forms not audited.
- **Guided import flows.** Crypto Providers and Keys have guided
  modals (Phase 5b). CA / OCSP / EST imports still use the original
  flat forms.

### [pending]
- **Destructive-action confirmation: CA delete.** Should warn about
  certs that become orphaned, CRL impact, OCSP responder
  dependencies.
- **Destructive-action confirmation: OCSP responder delete.**
- **Destructive-action confirmation: certificate template delete.**
  Should refuse / warn when EST aliases or CAs reference the template
  ([certificate-template-specs.md §12.3](certificate-template-specs.md)).
- **Destructive-action confirmation: user delete.**
- **First-run guidance.** No onboarding wizard; operator lands on the
  dashboard with the seeded `software-default` provider but no
  guidance on next steps.
- **Inline validation: CA form.**
- **Inline validation: certificate template form.**
- **Inline validation: OCSP responder form.**
- **Inline validation: EST alias form.**
- **Audit-log search.** Current `audit_logs.html` is a flat paginated
  view.
- **Audit-log filter.** No filter by resource type / action / user.
- **Audit-log export.** No CSV / JSON export.
- **Audit-log retention controls.** No configurable retention or
  archival ([database-specs.md §8.4](database-specs.md)).
- **Dashboard certificate lifecycle widgets.** Expiring certs list,
  OCSP/CRL freshness, issuance trend.
- **Guided import flow: CA from PEM / PKCS#12.** Currently a single
  form; could be a multi-step wizard with validation per step.
- **Guided import flow: OCSP responder.**
- **Guided import flow: EST alias.**

---

## §7 — Documentation And Lifecycle Management

### [done]
- **HSM strategy + gap-analysis docs separation.** `kms-specs.md` is
  the forward-looking spec; `hsm-support-specs.md` is the closed-bug
  catalogue with all 12 gaps marked CLOSED. Cross-references
  consistent.
- **Per-area spec consolidation.** Each subsystem now has its own
  long-form spec aligned to the same template (Goals / Status /
  Architecture / Data model / Lifecycle / Weaknesses / Order of work /
  Acceptance / Cross-references):
  [database-specs.md](database-specs.md),
  [ca-management-specs.md](ca-management-specs.md),
  [certificate-management-specs.md](certificate-management-specs.md),
  [certificate-template-specs.md](certificate-template-specs.md),
  [est-specs.md](est-specs.md),
  [kms-specs.md](kms-specs.md),
  [hsm-support-specs.md](hsm-support-specs.md).

### [partial]
- **Operational docs aligned with the Docker-first deployment path.**
  README is current for Docker + SoftHSM2 + `HSM_PIN_KEK` + manual
  setup. `structure.md`, `project-notes.md`, `rest-api.md`,
  `roadmap.md`, and `PROGRESS.md` were realigned against the current
  code state in this round. Historical-vs-current separation for
  `doc/learning/` was not re-audited.

### [pending]
- **Schema migration upgrade notes per release.** No release-notes
  document explaining when `reset_pki.py` is sufficient vs when an
  in-place migration is required. `migrate_schema()` runs idempotently
  at boot but its scope per release isn't documented.
- **Per-release "what changed" notes.** No CHANGELOG.md.

---

## §8 — Functional Improvements

Cross-reference: [roadmap.md §8](roadmap.md).

### [done]
- **Self-signed certificate option in the request flow.** `ca_id ∈
  {null, 0}` on `/api/certificate/issue-pkcs12` produces a
  server-keygen self-signed cert recorded with `is_self_signed=TRUE`.
  See [certificate-management-specs.md §6.3](certificate-management-specs.md).

### [pending]
- **Generic signing services on top of the KMS** —
  [kms-specs.md §17](kms-specs.md).
- **EST mTLS client-cert authentication (CR-0001)** —
  [est-specs.md §14.1](est-specs.md).

---

## How to use this document

- **Triaging new work:** before starting, find the matching
  `[pending]` task here (or add one). When complete, flip to `[done]`
  with a one-line note about which phase / commit / PR landed it.
- **Reviewing the project state:** the at-a-glance table is a
  reasonable executive summary. The per-section breakdown is the
  honest operator-facing read.
- **Adding new requirements:** add the task here as `[pending]` and
  link it from the matching roadmap.md bullet. Don't update only
  one of the two — they drift apart fast otherwise.

When in doubt about whether something is `[done]` or `[partial]`,
prefer `[partial]` and spell out the gap. Honest tracking beats green
checkmarks.
