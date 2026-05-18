# PyPKI — Methodology Audit Report

**Skill:** `methodology-audit` v0.1 ([SKILL.md](methodology/skills/methodology-audit/SKILL.md)).
**Audited against:** WiseKey AI-Assisted Development Methodology — `methodology/` submodule, pinned at submodule HEAD.
  - [`best-practices.md`](methodology/best-practices.md) — v1.5 (implemented; awaiting re-validation).
  - [`ai-coding-security-policy.md`](methodology/ai-coding-security-policy.md) — v1.4 (validated).
  - [`workflow-integration.md`](methodology/workflow-integration.md) — v1.4 (implemented; awaiting re-validation).
**Repository:** `/Users/pedro/Development/Python/pypki` — branch `main` (per `git status` at session start).
**Audit date:** 2026-05-14.
**Auditor:** Claude Code (advisory; read-only; no file in the audited repo modified except for the creation of this report).
**Companion:** [`methodology-gap-analysis.md`](methodology-gap-analysis.md) at the repo root — earlier informal gap analysis from the same session, kept for context. This report is the formal skill output and is self-contained; it does not require the gap analysis as prerequisite reading.

> **Special focus this run.** Per the kickoff prompt, this audit pays particular attention to the **system / feature split** — flagging any place where the existing artifact structure does not naturally fit the four-layer hierarchy from [best-practices.md](methodology/best-practices.md) §5.1. That analysis is concentrated in §6.

---

## 1. Scope and method

The audit covers the seven dimensions named in the skill's §4 (operational layer, tracking layer, spec layer, tier annotations, aggregate state, sign-off coverage, open questions) plus the four sections requested by [`06-how-to-onboard-an-existing-project-with-an-agent.md`](methodology/training/how-to/06-how-to-onboard-an-existing-project-with-an-agent.md) §4 (what's there, what's missing, what's misaligned, recommended cutover sequence, candidate feature/system split).

The audit is **read-only**. No file in the repository was modified except for the creation of this report. Heuristic Tier C detection is enabled (path patterns `*/crypto/`, `*/pki/`, `*/auth/`, `*/audit/`, `*/signing/`, `*/hsm/`, `*/key-*/`). Severity tags: **HIGH** = actual rule violation; **MEDIUM** = misalignment that blocks the onboarding path; **LOW** = cosmetic drift or deferred refinement.

Citations point at the methodology section that authorises each rule. Recommended actions are mapped to the eight-step existing-repo path in [workflow-integration.md](methodology/workflow-integration.md) §6.

---

## 2. What's there

Existing artifacts the methodology cares about, walked dimension by dimension.

### 2.1 Operational layer

| Artifact | Present | Shape |
|---|---|---|
| [`CLAUDE.md`](CLAUDE.md) at repo root | yes | From the methodology template; partially filled (project context, code style, data class, channel) on 2026-05-14; *Repository layout* placeholders and *Build/test/lint* commands still unfilled; *Security do-not-touch zones* declared `NONE` for both Tier C and §11. See §5.4 below. |
| `.gitmodules` | yes | Pins `methodology/` submodule to `wisekeylab/wisekey-ai-coding-methodology` per the how-to Phase 0 Option 2 (submodule). |
| `methodology/` submodule | yes | Methodology v1.4/v1.5 documents accessible to the agent. |
| `.github/` directory | **no** | — |
| `.github/CODEOWNERS` | no | — |
| `.github/pull_request_template.md` | no | — |
| `.github/workflows/progress-update-check.yml` | no | — |
| `.github/workflows/ai-disclosure-check.yml` | no | — |
| `.github/workflows/lint-and-test.yml` (or equivalent) | no | No CI at all per `doc/PROGRESS.md` §1. |
| Branch protection on `main` | not introspectable from local clone | — |
| Pre-commit hooks / secret-scan | not configured | — |
| [`methodology-gap-analysis.md`](methodology-gap-analysis.md) | yes | Informal precursor to this report — not a methodology artifact, but at the repo root. |

### 2.2 Tracking layer

| Artifact | Present | Shape |
|---|---|---|
| `PROJECT-STATUS.md` at repo root | **no** | — |
| `platform-overview.md` at repo root | n/a | Platform layer not warranted (single product). |
| `progress.md` per feature | **no** | No `features/` directory exists. |
| [`doc/PROGRESS.md`](doc/PROGRESS.md) | yes | Substantial, curated, 77 deliverables across 8 areas — but uses **non-methodology state vocabulary** (`[done]`/`[partial]`/`[pending]`/`[deferred]`) and lacks stable deliverable IDs / FR linkage. Methodology cannot map it to `proposed/specified/in-progress/implemented/validated/released/blocked/dropped` without translation. |
| [`doc/roadmap.md`](doc/roadmap.md) | yes | Strategic intent across all areas; cross-referenced by `doc/PROGRESS.md`. |

### 2.3 Spec layer

All specs follow a near-identical section template (Goals / Status / Architecture / Data model / Lifecycle / REST API / Management UI / Audit logging / Weaknesses / Order of work / Acceptance / Cross-references) — meaning they were authored as members of a single coherent system. This is the most important signal for the §6 system/feature analysis.

| Spec | Lines | Section count | Methodology mapping |
|---|---:|---:|---|
| [`doc/ca-management-specs.md`](doc/ca-management-specs.md) | 1658 | 18 | Feature candidate `ca-management`. |
| [`doc/certificate-management-specs.md`](doc/certificate-management-specs.md) | 1071 | 18 | Feature candidate `end-entity-certificates`. |
| [`doc/certificate-template-specs.md`](doc/certificate-template-specs.md) | 1019 | 16 | Feature candidate `certificate-templates`. |
| [`doc/est-specs.md`](doc/est-specs.md) | 875 | 15 | Feature candidate `est-service`. |
| [`doc/kms-specs.md`](doc/kms-specs.md) | 1231 | 18 | Feature candidate `kms` (Tier C heavy). |
| [`doc/hsm-support-specs.md`](doc/hsm-support-specs.md) | 274 | 10 | Closed-bug catalogue per `doc/PROGRESS.md` §3 (all 12 gaps CLOSED) — candidate to **merge** into `features/kms/` or to remain as a history-block artifact. |
| [`doc/database-specs.md`](doc/database-specs.md) | 779 | 12 | **Not feature-shaped.** Describes the shared data model (`pypki/db.py`, 3544 LOC) cross-referenced by every other spec. Best fit: **system technical design** content, not a feature. See §6.3 below. |
| [`doc/structure.md`](doc/structure.md) | 147 | 2 | Architecture/layout overview — system technical design content. |
| [`doc/project-notes.md`](doc/project-notes.md) | — | — | Operator-facing notes — fits as a runbook or system-level annex. |
| [`doc/rest-api.md`](doc/rest-api.md) | — | — | API reference — cross-cutting, system-level content. |
| [`doc/learning/`](doc/learning/) | 14 files | — | Reference notes (architecture, patterns) — historical-vs-current separation not re-audited per `doc/PROGRESS.md` §7. |
| `ADRs` under `docs/adr/` | **no** | — | — |

### 2.4 Code modules referenced by the audit

Walked for tier and sign-off analysis. LOCs from `wc -l`:

| Module | LOC | Likely role |
|---|---:|---|
| `pypki/db.py` | 3544 | Shared persistence (foundation of every spec's *Data model* section). |
| `pypki/kms.py` | 945 | KMS orchestrator; holds key handles. |
| `pypki/backends/pkcs11.py` | 1069 | PKCS#11 / HSM backend; key custody. |
| `pypki/backends/software.py` | 308 | Software-key backend; KEK-wrapped at rest. |
| `pypki/backends/base.py` | 186 | Backend protocol + typed errors. |
| `pypki/pkcs11_helper.py` | 117 | Low-level PKCS#11 helpers. |
| `pypki/key_encryption.py` | 265 | AES-256-GCM KEK wrapping (HKDF-SHA256). |
| `pypki/key_tools.py` | 160 | Key generation / management. |
| `pypki/ca.py` | 129 | `CertificationAuthority` class. |
| `pypki/certificate_tools.py` | 769 | End-entity certificate generation. |
| `pypki/ocsp_responder.py` | 287 | OCSP response signing. |
| `pypki/signing_algorithm.py` | 483 | Signing-algorithm token catalogue. |
| `pypki/core.py` | 899 | `PyPKI` orchestrator. |
| `web/routes/main_routes.py` | 1640 | Monolithic REST surface for CAs, certs, CRLs, templates, users, tools. |
| `web/routes/auth_routes.py` | 64 | JWT auth (login/logout). |
| `web/routes/est_routes.py` | 169 | RFC 7030 EST endpoints. |
| `web/routes/ocsp_routes.py` | 131 | RFC 6960 OCSP endpoints. |
| `web/services/api_adapters.py` | 1260 | Shared adapter layer between routes and core. |
| `web/services/ca_generate.py` | 577 | In-app CA generation (CR-0001). |
| `web/services/__init__.py` | 136 | Shared PyPKI instance + background scheduler. |
| `utils/migrate_ocsp_settings.py`, `migrate_template_cdp_aia.py` | 84 + 135 | DB schema migrations. |
| `utils/reset_pki.py`, `restore_backup.py`, `generate_*.py` | small | Operational tooling. |

`tests/` carries a comprehensive pytest suite for the KMS layer (54 tests across six files per `doc/PROGRESS.md` §1) plus interactive smoke scripts in `tests/__main__.py`.

---

## 3. What's missing

Listed in onboarding-priority order. Severity per §1.

### 3.1 Operational layer

- **(HIGH) `.github/` directory absent.** Missing every operational artifact: `pull_request_template.md`, `CODEOWNERS`, `progress-update-check.yml`, `ai-disclosure-check.yml`, language-appropriate `lint-and-test.yml` / `dependency-review.yml` / `secret-scan.yml`. Citation: [workflow-integration.md](methodology/workflow-integration.md) §2.1, §2.4, §2.5; [legacy-onboarding-checklist.md](methodology/templates/operational/legacy-onboarding-checklist.md) Phase 2.
- **(HIGH) PR-template-driven AI disclosure cannot be required.** Citation: [ai-coding-security-policy.md](methodology/ai-coding-security-policy.md) §9.1.
- **(HIGH) Atomic-update CI gate not enforced.** Citation: [best-practices.md](methodology/best-practices.md) §5.5; [`progress-update-check.yml`](methodology/templates/operational/progress-update-check.yml).
- **(HIGH) AI-disclosure CI gate not enforced.** Citation: [`ai-disclosure-check.yml`](methodology/templates/operational/ai-disclosure-check.yml).
- **(MEDIUM) [`CLAUDE.md`](CLAUDE.md) partially unfilled.** *Repository layout* placeholders `[flat / system / platform]` and `[features/ | systems/<system>/features/]` still in square brackets; example dirs `lib/`, `services/`, `api/` listed under *Repository layout* don't exist in this repo and will mislead any agent reading the file for orientation. *Build / test / lint* commands all `[command]` — `pytest` works today and should be named.

### 3.2 Tracking layer

- **(HIGH) `PROJECT-STATUS.md` at repo root missing.** Citation: [best-practices.md](methodology/best-practices.md) §5.3; template [`project-status-template.md`](methodology/templates/project-status-template.md).
- **(HIGH) No `features/` directory and no per-feature `progress.md`.** Citation: [best-practices.md](methodology/best-practices.md) §5.1, §5.3.
- **(HIGH) State vocabulary mismatch.** [`doc/PROGRESS.md`](doc/PROGRESS.md) uses `[done]`/`[partial]`/`[pending]`/`[deferred]` — the methodology requires `proposed/specified/in-progress/implemented/validated/released/blocked/dropped`. The agent contract distinction (§5.4: AI may move to `implemented` but never to `validated`) cannot be expressed in the current vocabulary. Citation: [best-practices.md](methodology/best-practices.md) §5.2, §5.4.
- **(MEDIUM) Stable deliverable IDs and FR linkage absent.** `doc/PROGRESS.md` rows are not numbered (`D-1`, `D-2`, …) and do not cite functional-requirement IDs (`FR-N`). Citation: [best-practices.md](methodology/best-practices.md) §5.6.
- **(MEDIUM) Validation log / active-blockers tables absent per progress template.** Citation: [`progress-template.md`](methodology/templates/progress-template.md) §3, §4.

### 3.3 Spec layer

- **(MEDIUM) No spec for the OCSP responder.** OCSP behaviour is currently inlined in `ca-management-specs.md` §9 and lives in `pypki/ocsp_responder.py` + `web/routes/ocsp_routes.py`. A dedicated `ocsp-responder` feature is the natural shape (Tier C — criteria 5 and 6).
- **(MEDIUM) No spec for authentication.** `web/routes/auth_routes.py` (JWT issuance) has no spec — it is an §11 sign-off category in its own right.
- **(MEDIUM) No spec for audit logging.** Every other spec has a §12 *Audit logging* section; audit-log is structurally cross-cutting. Candidate for either its own feature or a system-level concern documented in the system technical design.
- **(MEDIUM) No functional vs technical split.** Each `doc/*-specs.md` mixes intent and implementation. Citation: [best-practices.md](methodology/best-practices.md) §4.2.
- **(MEDIUM) FR-N / AC-N IDs not used.** Change requests `CR-NNNN` exist (a different concept) but functional requirements are unnumbered.
- **(LOW) No `docs/adr/`.** Significant decisions (per-provider KEK regime, KEY-OWNED semantics, `auth_secret_ref` resolvers) sit in prose paragraphs of the specs but not as discrete ADRs. Citation: [best-practices.md](methodology/best-practices.md) §4.1.

### 3.4 Tier annotations

- **(HIGH) No *AI Tier* column anywhere.** Neither in any spec's *Module catalogue* nor in `CODEOWNERS`. Citation: [ai-coding-security-policy.md](methodology/ai-coding-security-policy.md) §6.3, §6.4. Heuristic candidates: §5.4 below.
- **(HIGH) Sub-tier (`controlled` vs `strict`) undetermined.** Methodology v1.4 requires both tier and sub-tier in the Module catalogue. Citation: [ai-coding-security-policy.md](methodology/ai-coding-security-policy.md) §6.3.3.
- **(HIGH) [`CLAUDE.md`](CLAUDE.md) declares `Tier C: NONE` and `Tier B by default` simultaneously.** Internally inconsistent with §6.2 criterion 3 (Tier B is partly defined as adjacent to a Tier C boundary) and with §6.4 (default is Tier A; elevation needs criteria). See §5.4 finding TC-4 below.

### 3.5 Sign-off coverage

- **(HIGH) `CODEOWNERS` absent; no §11 category mechanised.** [`CLAUDE.md`](CLAUDE.md) declares `§11 sign-off: NONE` but `web/routes/auth_routes.py` (authentication), audit-log tables (audit), the EST/OCSP/main routes (public API), and the schema migration scripts (migrations) are named §11 categories regardless of Tier. Citation: [ai-coding-security-policy.md](methodology/ai-coding-security-policy.md) §11.

### 3.6 Aggregate state

- **(MEDIUM) No `PROJECT-STATUS.md`, so the aggregate-state rule cannot be evaluated.** Once `PROJECT-STATUS.md` exists and per-feature `progress.md` files exist, lowest-state-wins per [best-practices.md](methodology/best-practices.md) §5.3 will apply.

### 3.7 OSS-release artifacts (triggered by 2026-05-14 declaration)

[`CLAUDE.md`](CLAUDE.md) declares PyPKI is *"developed as base for other projects. The main intent is to release it as Open Source code."* This activates [ai-coding-security-policy.md](methodology/ai-coding-security-policy.md) §6.5.

- **(HIGH, contingent on Q-2) `MAINTAINERS.md` missing.** §6.5(3) requires it for Tier C OSS code authoring rules. Collapses if owner's "Tier C: NONE" stance is upheld and defended.
- **(MEDIUM) `CONTRIBUTING.md` missing.** §6.5(5) requires it to carry an AI-disclosure block matching the internal PR template.
- **(LOW) Upstream / downstream compliance-scope separation not documented.** §6.5(4). Deferrable until first OSS release.

---

## 4. What's misaligned

Distinct from §3 *missing* — these are artifacts that exist but do not fit the methodology's shape. They need translation, not creation.

| # | Misalignment | Severity | Methodology reference |
|---|---|---|---|
| M-1 | **State vocabulary.** `doc/PROGRESS.md` uses `[done]`/`[partial]`/`[pending]`/`[deferred]`. Translation table needed: `[done]` → `released` (or `validated` if independent test/reviewer evidence exists; default `released` for shipped work); `[partial]` → `in-progress` with notes; `[pending]` → `proposed`; `[deferred]` → `blocked` with the blocker captured per template §4. Citation: [best-practices.md](methodology/best-practices.md) §5.2. | HIGH | §5.2 |
| M-2 | **Spec template ≠ methodology template.** All seven legacy specs share a custom 12-to-18-section template that does not map 1:1 to the functional-spec / technical-design split. The mapping is *non-trivial*: §1 Goals + §16 Out of scope + §15 Acceptance criteria are functional content; §3 Architecture + §4 Data model + §7 Signing pipeline + §10 REST API are technical content. A bulk migration would be expensive and is forbidden by [workflow-integration.md](methodology/workflow-integration.md) §6.1 step 4. **Action: linkage pattern for all stable specs; migration only when a substantive change is queued.** | HIGH | [workflow-integration.md](methodology/workflow-integration.md) §6.4 |
| M-3 | **OCSP responder code without spec, OCSP design inside `ca-management-specs.md` §9.** OCSP currently sits across `pypki/ocsp_responder.py`, `web/routes/ocsp_routes.py`, and §9 of `ca-management-specs.md`. As a methodology feature, OCSP belongs in `features/ocsp-responder/` — but the existing spec is *one section of a different spec*, not a standalone file. | MEDIUM | [best-practices.md](methodology/best-practices.md) §5.1 |
| M-4 | **Database spec is structurally a system technical design fragment.** [`doc/database-specs.md`](doc/database-specs.md) describes the shared data model (`pypki/db.py`) that **every** other spec's *Data model* section cross-references. Treating it as a feature would invert the dependency — every other feature would depend on it. Best fit: **content for the system technical design** at the repo root, with each feature's `technical-design.md` citing specific tables it owns. | MEDIUM | [best-practices.md](methodology/best-practices.md) §5.1 (system technical design); §6.3 of this report. |
| M-5 | **KMS / HSM-support overlap.** [`doc/kms-specs.md`](doc/kms-specs.md) and [`doc/hsm-support-specs.md`](doc/hsm-support-specs.md) overlap heavily; the latter is a closed-bug catalogue with all 12 gaps marked CLOSED per `doc/PROGRESS.md` §3. Two reasonable resolutions: **(a)** merge into one `features/kms/` and absorb `hsm-support-specs.md` content as a *History* annex; **(b)** keep them as two features for tracker purposes. Recommendation: (a) — see §6 below. | MEDIUM | [best-practices.md](methodology/best-practices.md) §5.1 (feature boundary discipline) |
| M-6 | **Shared REST surface, per-feature spec sections.** Every legacy spec has a §10 *REST API specification* and §11 *Management UI* section. In the code these are **one** monolithic surface — `web/routes/main_routes.py` (1640 LOC) + `web/services/api_adapters.py` (1260 LOC) + the Jinja2 template set under `web/templates/`. The methodology's per-feature `technical-design.md` carries the feature's own contract; a cross-cutting REST API description belongs in the system technical design, with per-feature specs citing the relevant endpoint subset. | MEDIUM | [technical-design-template.md](methodology/templates/technical-design-template.md) §7 |
| M-7 | **Shared audit-log schema, per-feature spec sections.** Every legacy spec has a §12 *Audit logging* section. The audit log is structurally cross-cutting; per the methodology this is a system-level concern. Options: a separate `features/audit-log/` feature, or system-level content with each feature citing its emitted events. | MEDIUM | [technical-design-template.md](methodology/templates/technical-design-template.md) §9 |
| M-8 | **[`doc/PROGRESS.md`](doc/PROGRESS.md) is a single rolled-up tracker; the methodology distributes tracking per feature.** This is the same as M-1 plus the *granularity* question: the methodology wants per-feature `progress.md` with stable D-IDs, not one repo-wide tracker. Translation requires splitting the existing 77 deliverables across features (per §6 split below). | MEDIUM | [best-practices.md](methodology/best-practices.md) §5.3 |
| M-9 | **Example `Repository layout` paths in [`CLAUDE.md`](CLAUDE.md) reference directories that do not exist** (`lib/`, `services/`, `api/`). These are template artifacts the owner did not edit; AI agents reading them for orientation will be misled. | MEDIUM | [`CLAUDE.md.example`](methodology/templates/operational/CLAUDE.md.example) |

---

## 5. Detailed findings by audit dimension

Numbered per the audit skill's §4 dimensions. Severity-tagged, with methodology citations.

### 5.1 Operational layer

Captured in §3.1 above. Net: every artifact except `CLAUDE.md` (partially) is missing. Highest-leverage day-1 work per [workflow-integration.md](methodology/workflow-integration.md) §6.3.

### 5.2 Tracking layer

Captured in §3.2 above. Distinctive feature of this repo: a substantial legacy tracker (`doc/PROGRESS.md`) exists with the right *content* but the wrong *shape* — translation, not creation, is the work.

### 5.3 Spec layer

Captured in §3.3 above plus M-2 through M-7. Distinctive feature: a uniform 12-to-18-section template across seven specs, which makes the boundary work in §6 unusually clean — the legacy authors clearly thought of these as one coherent system.

### 5.4 Tier annotations

**Findings:**

- **TC-1 (HIGH).** No *AI Tier* annotation anywhere. Path-pattern heuristic flags the following as **Tier C candidates** for tech-lead confirmation:

| Path | Triggering criterion (§6.3) | Notes |
|---|---|---|
| [`pypki/key_encryption.py`](pypki/key_encryption.py) | 1 (cryptographic primitive: AES-256-GCM KEK wrapping via HKDF-SHA256) | Plus criterion 2 because the wrapped material is key custody. |
| [`pypki/key_tools.py`](pypki/key_tools.py) | 2 (key generation / management) | — |
| [`pypki/pkcs11_helper.py`](pypki/pkcs11_helper.py) | 2 (PKCS#11 / HSM low-level helpers) | — |
| [`pypki/backends/pkcs11.py`](pypki/backends/pkcs11.py) | 2 (HSM backend; key handles) | — |
| [`pypki/backends/software.py`](pypki/backends/software.py) | 2 (software backend; KEK-wrapped keys) | — |
| [`pypki/backends/base.py`](pypki/backends/base.py) | 2 (key-custody contract / errors) | Adjacent; possible Tier B under §6.2 crit. 3. |
| [`pypki/kms.py`](pypki/kms.py) | 2 + 5 (KMS orchestrator; root of trust) | — |
| [`pypki/ca.py`](pypki/ca.py) | 2 + 5 (CA signing; root of trust); possibly 4 (CP/CPS) | — |
| [`pypki/certificate_tools.py`](pypki/certificate_tools.py) | 2 + 5 (end-entity signing; chains back to CA) | — |
| [`pypki/ocsp_responder.py`](pypki/ocsp_responder.py) | 5 + 6 (OCSP response signing; non-repudiation) | — |
| [`pypki/signing_algorithm.py`](pypki/signing_algorithm.py) | 1-adjacent (algorithm catalogue) | Per §8.6, algorithm choice is a human decision regardless of tier. |
| [`web/routes/ocsp_routes.py`](web/routes/ocsp_routes.py) | Tier B under §6.2 crit. 3 (adjacent, shared process) | — |
| [`web/routes/est_routes.py`](web/routes/est_routes.py) | Tier B under §6.2 crit. 3 | — |
| [`web/services/ca_generate.py`](web/services/ca_generate.py) | 2 + 5 (CA generation pipeline) | — |

- **TC-2 (HIGH).** Sub-tier (`controlled` vs `strict`) undetermined for every candidate above. The question per §6.3.3: does any planned deployment of PyPKI sit inside a WebTrust audit, FIPS evaluation, eIDAS QSEAL scope, or a published CP/CPS, **without** documented evaluator acceptance of AI-assisted authorship? If yes: those paths are **Tier C — strict**. If no: candidates for **Tier C — controlled** under the §6.3.1 controls package.
- **TC-3 (HIGH).** [`CLAUDE.md`](CLAUDE.md) declares `Tier C: NONE`, `§11 sign-off: NONE`, and `Tier B by default` simultaneously. Per [ai-coding-security-policy.md](methodology/ai-coding-security-policy.md) §6.2 criterion 3, Tier B applies in part to code *adjacent to a Tier C boundary sharing memory/process address space*. If there is no Tier C, there is no boundary to be adjacent to. The methodology default is Tier A ([§6.4](methodology/ai-coding-security-policy.md)). "Tier B by default" inverts that. The owner's call must be one of: **(A)** methodology default — explicit Tier C list under §6.3 criteria 2/5/6 (the heuristic above); **(B)** argued override — keep `Tier C: NONE` *and* drop "Tier B by default" (codebase is Tier A under methodology default), with the override argued in the system technical design per [§6.4](methodology/ai-coding-security-policy.md); **(C)** pick a minimum Tier C set for "Tier B by default" to rest on — typically `pypki/key_encryption.py`, the PKCS#11 backend, and the CA/OCSP signers. Recommended: **(A)** with sub-tier `strict` as safe default until evaluator acceptance is documented.
- **TC-4 (HIGH, contingent on Q-2).** Once Tier C is established, per [§6.5(1)](methodology/ai-coding-security-policy.md) open-sourcing does **not** collapse Tier C. The maintainer-roster rules of §6.5(3) apply.

### 5.5 Aggregate state

Not applicable until §3.2 *PROJECT-STATUS.md* and per-feature `progress.md` exist. Once they do, the lowest-state-wins rule from [best-practices.md](methodology/best-practices.md) §5.3 applies automatically; no separate enforcement gate is needed because aggregate state is computed on read.

### 5.6 Sign-off coverage

Captured in §3.5. Categories applicable to PyPKI per [§11](methodology/ai-coding-security-policy.md):

| §11 category | Triggering paths in this repo |
|---|---|
| §11 cryptographic / key-custody | The Tier C candidates in §5.4 TC-1. |
| §11 authentication | [`web/routes/auth_routes.py`](web/routes/auth_routes.py) — JWT issuance/refresh. |
| §11 audit | The audit-log tables per [`doc/database-specs.md`](doc/database-specs.md) and the `audit_logs.html` admin UI. |
| §11 public API | EST endpoints under [`web/routes/est_routes.py`](web/routes/est_routes.py); OCSP under [`web/routes/ocsp_routes.py`](web/routes/ocsp_routes.py); management API under [`web/routes/main_routes.py`](web/routes/main_routes.py). |
| §11 migrations | [`utils/migrate_*.py`](utils/) plus the `migrate_schema()` boot path inside `pypki/db.py`. |

These are §11 categories independent of the AI Tier. The owner's `§11 sign-off: NONE` declaration in [`CLAUDE.md`](CLAUDE.md) needs revisiting alongside TC-3.

### 5.7 Open questions

Carried forward into §8.

---

## 6. Candidate system / feature split for review

**The user's special focus.** Mapped to [best-practices.md](methodology/best-practices.md) §5.1.

### 6.1 Layer decision — single-system or flat?

**Recommendation: single-system layout** (`systems/<system>/` wrapper *elided* to the repo root per [best-practices.md](methodology/best-practices.md) §5.1 — *"For a single-system project the `systems/<system>/` wrapper can be elided and the system specifications sit at the repository root."*).

**Evidence that the system layer is warranted** (per the §5.1 heuristic *"more than ~5 features that share user model, error model, or contracts; multiple features that depend on each other's contracts and not just their existence"*):

1. **Seven specs, one template.** All seven `doc/*-specs.md` files share a near-identical 12-to-18-section template. This is the strongest possible signal that the legacy authors thought of these as members of one system.
2. **Shared error model.** Every spec's §10 *REST API specification* uses the same HTTP error vocabulary (`401`, `404`, `409`, …); the implementation lives in one place (`web/services/api_adapters.py`).
3. **Shared user model.** One user table (`Users`), one auth surface (`web/routes/auth_routes.py`), one JWT regime, one role gating mechanism across **all** features.
4. **Shared data model.** [`doc/database-specs.md`](doc/database-specs.md) describes the data model that every other spec cross-references. `pypki/db.py` (3544 LOC) is the single shared persistence module.
5. **Shared signing substrate.** CA signing, end-entity signing, CRL signing, and OCSP response signing **all** go through the KMS backend (`pypki/kms.py` + `pypki/backends/`). The signing pipeline §7 in `ca-management-specs.md` and `certificate-management-specs.md` is the same pipeline.
6. **Shared audit log.** Every spec's §12 *Audit logging* targets the same `AuditLog` table.

**Evidence that the *platform* layer is NOT warranted:** PyPKI is one deployable artifact. No second product/system shares its kernel. Per §5.1 the platform layer is for *"two or more systems share a stable kernel of concepts"* — not the case here.

**Alternative considered and rejected:** flat layout (features at the repo root, no system wrapper). Would require restating shared content — data model, error model, signing pipeline, audit log — in every feature spec, or in a hidden-but-shared CLAUDE.md annex. Either choice fights the methodology.

### 6.2 Candidate feature list

Eight features proposed. Slugs are kebab-case capability names per [best-practices.md](methodology/best-practices.md) §5.1.

| Slug | Source | Notes |
|---|---|---|
| `features/ca-management/` | [`doc/ca-management-specs.md`](doc/ca-management-specs.md) | Move OCSP content out (§9 → `ocsp-responder`). CA generation, lifecycle, CRL retain. |
| `features/end-entity-certificates/` | [`doc/certificate-management-specs.md`](doc/certificate-management-specs.md) | — |
| `features/certificate-templates/` | [`doc/certificate-template-specs.md`](doc/certificate-template-specs.md) | — |
| `features/est-service/` | [`doc/est-specs.md`](doc/est-specs.md) | Likely pilot feature (CR-0001 mTLS is a clean methodology deliverable). |
| `features/ocsp-responder/` | **new feature; no legacy spec.** Inherits §9 of `ca-management-specs.md` plus implementation in `pypki/ocsp_responder.py` + `web/routes/ocsp_routes.py`. | Tier C heavy (criteria 5, 6). Resolves M-3. |
| `features/kms/` | [`doc/kms-specs.md`](doc/kms-specs.md) **merged with** [`doc/hsm-support-specs.md`](doc/hsm-support-specs.md) | Resolves M-5. HSM content becomes a closed-history annex. Tier C heavy. |
| `features/auth/` | **new feature; no legacy spec.** Inherits `web/routes/auth_routes.py` + JWT design notes scattered across other specs. | §11 sign-off category. Owner can defer if the §11 lifecycle remains coarse-grained for now. |
| `features/audit-log/` | **new feature; no legacy spec.** Inherits every other spec's §12 *Audit logging* content. | Resolves M-7. §11 sign-off category. Alternative: keep as system-level technical-design content without a feature folder — see §6.4. |
| `features/oss-release/` | **new feature; no legacy spec.** OSS prep work: `MAINTAINERS`, `CONTRIBUTING`, upstream/downstream separation. | Per §3.7. Defer until OSS-release work begins. |

### 6.3 What stays at system level (NOT features)

| Source | System destination | Why |
|---|---|---|
| [`doc/database-specs.md`](doc/database-specs.md) | System `technical-design.md` § *Data model* | Shared data model is the dependency every feature inherits — putting it in a feature inverts the dependency (resolves M-4). |
| [`doc/structure.md`](doc/structure.md) | System `technical-design.md` § *Architecture* + § *Component breakdown* | System-level architecture. |
| [`doc/rest-api.md`](doc/rest-api.md) | System `technical-design.md` § *API contracts* (or a linked OpenAPI document) | Cross-cutting API reference. Features cite the relevant endpoint subset. (Resolves M-6.) |
| Audit-log schema | System `technical-design.md` § *Error handling and observability* OR `features/audit-log/` | Owner's call — see §6.4. (Resolves M-7.) |
| JWT auth conventions, role gating | System `technical-design.md` § *Security considerations* | Cross-cutting. (Or move to `features/auth/` if the owner picks that route.) |
| [`doc/roadmap.md`](doc/roadmap.md) | Cross-feature; cited from `PROJECT-STATUS.md` § *Cross-feature blockers and risks* | Strategic intent across features. |
| [`doc/project-notes.md`](doc/project-notes.md) | System annex / operator runbook | Operator-facing, not a methodology artifact. |
| [`doc/learning/`](doc/learning/) | Unchanged; reference material | Historical-vs-current separation per `doc/PROGRESS.md` §7 not re-audited. |

### 6.4 Places where the existing structure does NOT cleanly fit the four-layer hierarchy — explicit list

Per the user's special focus. Listed with the boundary call required.

- **B-1. OCSP across two specs.** OCSP design lives in `ca-management-specs.md` §9 (~6% of that file) and in `pypki/ocsp_responder.py` + `web/routes/ocsp_routes.py`. **Boundary call:** extract to `features/ocsp-responder/` and trim the section in `ca-management-specs.md` to a cross-reference. Cleanest at linkage-shell time; full migration of the section happens only when next substantive OCSP change is queued.
- **B-2. KMS vs HSM-support — one feature or two?** `kms-specs.md` is the forward-looking spec; `hsm-support-specs.md` is a closure record. Two reasonable resolutions; **recommended:** merge into `features/kms/`, absorb HSM content as a closed-history annex (matches §5.4 of [`progress-template.md`](methodology/templates/progress-template.md) *History* block). Alternative: keep separate if owner wants HSM-bug tracking discrete.
- **B-3. Database — feature or system content?** Listed in §6.3 as **system technical-design content**, not a feature. Owner override possible if `features/database-schema/` is desired for §11 *migrations* sign-off scoping. **Recommended:** system-level, with §11 migrations sign-off attached via `CODEOWNERS` to `pypki/db.py` + `utils/migrate_*.py` paths rather than a feature folder.
- **B-4. Auth — feature or system-level concern?** Single 64-LOC route module. Two options: **(a)** standalone `features/auth/` for clarity around §11 authentication sign-off; **(b)** system-level *Security considerations* content with `CODEOWNERS` on `web/routes/auth_routes.py`. **Recommended:** (b) until JWT/MFA/refresh-token work begins (per `doc/PROGRESS.md` §2 these are `[pending]`); promote to (a) at that point.
- **B-5. Audit log — feature or system-level cross-cutting concern?** Every other spec touches it; it has no spec of its own; the codebase touches it from everywhere. **Recommended:** system-level technical-design content + a §11 audit `CODEOWNERS` rule on the audit-log code paths. Promote to `features/audit-log/` when audit-log work itself becomes a focus (per `doc/PROGRESS.md` §6 *Audit-log search / filter / export / retention* are `[pending]`).
- **B-6. REST API and Management UI — per-feature or system-level?** Each legacy spec has §10/§11 inline; the code has one monolithic surface. **Recommended:** the *contract* (HTTP error model, auth pattern, response shape conventions) is system-level; per-feature `technical-design.md` cites the specific endpoints the feature owns. The Jinja2 UI shell follows the same pattern.
- **B-7. CA generation — `web/services/ca_generate.py` (577 LOC) sits outside the system code in `pypki/`.** It's the in-app CA generation pipeline (CR-0001). Tier C heavy (criteria 2, 5). **Boundary call:** part of `features/ca-management/`; the path location in `web/services/` is implementation choice, not a feature boundary.
- **B-8. `pypki/core.py` (899 LOC) — the `PyPKI` orchestrator — touches every feature.** Not a feature itself; should be named in the system technical design as the central orchestrator with a documented contract.

### 6.5 Aggregate state map (once features exist)

For visualisation only; not actionable in this read-only audit. Mapping `doc/PROGRESS.md` §-headings to candidate features:

| `doc/PROGRESS.md` section | Candidate feature | Likely aggregate state |
|---|---|---|
| §1 Reliability And Testing | Crosses features; testing infra lives at system level | `in-progress` |
| §2 Security Hardening | Crosses features | `in-progress` |
| §3 HSM / PKCS#11 Support | `features/kms/` | `released` (HSM gaps CLOSED) + `in-progress` (vendor fidelity passes deferred) |
| §4 PKI And Protocol Maturity | Distributes across `ca-management`, `end-entity-certificates`, `est-service`, `ocsp-responder` | `in-progress` |
| §5 Deployment And Operations | System-level / operational | `in-progress` |
| §6 Usability And Admin Experience | Distributes across features (each feature's UI section) | `in-progress` |
| §7 Documentation And Lifecycle Management | System-level | `in-progress` |
| §8 Functional Improvements | Distributes | `in-progress` |

System aggregate per §5.3 lowest-state-wins: **`in-progress`** across the board until features lock down.

---

## 7. Recommended cutover sequence

Mapped to the eight steps in [workflow-integration.md](methodology/workflow-integration.md) §6 and the phase structure of [`legacy-onboarding-checklist.md`](methodology/templates/operational/legacy-onboarding-checklist.md). The order is *days*, not *weeks*, for the high-leverage steps.

### Step 1 — Inventory and shape (this report)
**Status:** DONE in this run. Tier C candidates listed in §5.4 TC-1; system/feature split in §6; §11 categories in §5.6.

### Step 2 — Install the operational layer (highest leverage; day-1)
**Status:** PENDING.

1. Resolve **Q-2** (Tier C — Option A / B / C per §5.4 TC-3) — this is the gate on everything else.
2. Resolve **Q-1** (single-system vs flat — §6.1 recommends single-system).
3. Finish [`CLAUDE.md`](CLAUDE.md): fill *Repository layout* per Q-1; name `pytest` and the dev-install command in *Build/test/lint*; fix the misleading `lib/`/`services/`/`api/` example paths; update *Security do-not-touch zones* per Q-2; update *Project-specific notes* to match.
4. Invoke `methodology-bootstrap` skill (or do manually) to create `.github/CODEOWNERS`, `.github/pull_request_template.md`, `.github/workflows/progress-update-check.yml`, `.github/workflows/ai-disclosure-check.yml`, skeleton `lint-and-test.yml` / `dependency-review.yml` / `secret-scan.yml`.
5. Configure branch protection on `main` per [workflow-integration.md](methodology/workflow-integration.md) §2.2: block direct pushes, require one human reviewer + status checks + CODEOWNERS review for §11 paths.
6. Configure AI-agent access scope per [workflow-integration.md](methodology/workflow-integration.md) §2.7.

**Exit criterion:** any PR from this point forward triggers the methodology CI gates and PR-template AI disclosure.

### Step 3 — Tracking layer (week 1)
**Status:** PENDING.

1. Create `PROJECT-STATUS.md` at the repo root from [`project-status-template.md`](methodology/templates/project-status-template.md). One row per feature from §6.2 (eight features).
2. Create one `features/<slug>/progress.md` per feature from [`progress-template.md`](methodology/templates/progress-template.md).
3. Translate `doc/PROGRESS.md` rows into deliverables per the M-1 translation table. Assign stable IDs (`D-1`, `D-2`, …) per feature. **History blocks start at the onboarding date; do NOT backfill prior history** ([workflow-integration.md](methodology/workflow-integration.md) §6.1 step 3).

### Step 4 — Spec linkage (week 1–2; per feature)
**Status:** PENDING.

For each feature in §6.2, choose linkage or migration per [workflow-integration.md](methodology/workflow-integration.md) §6.1 step 4 and §6.4:

- **Default (linkage).** Invoke `legacy-spec-linkage` in linkage mode. Generates a thin `functional-spec.md` whose *Related artifacts* line points at the corresponding `doc/*-specs.md`. Cost: ~1 hr per feature.
- **Migration only for substantive change.** Use migration mode only for features queued for a substantive change in the next ~4 weeks. Otherwise: linkage and defer.
- **Tier C subsection of each spec MAY require migration sooner** because the system technical design needs the *Module catalogue* with the *AI Tier* column (Step 5).
- **OCSP feature gets a fresh shell** (no legacy spec; lift §9 of `ca-management-specs.md` as a starting point or link to it).

### Step 5 — Tier annotation (week 2; concurrent with Step 4 for migrated specs)
**Status:** PENDING.

1. Resolve Q-2 (Tier C — controlled/strict per §5.4 TC-2).
2. Add the *AI Tier* column to the *Module catalogue* of the system technical design at the repo root, populated from §5.4 TC-1 plus the heuristic candidates the owner confirms or downgrades. Default Tier A; elevate only against §6.3 criteria.
3. Verify Tier C paths are covered by the `CODEOWNERS` from Step 2.
4. Capture the Q-2 decision as `docs/adr/0001-tier-c-paths.md` for audit trail.

### Step 6 — Cutover (week 2; 1–2 weeks after Step 2)
**Status:** PENDING.

Communicate the cutover date to the team in writing. From the cutover, **all** new PRs follow methodology rules (PR template, AI disclosure, atomic update, §11 trigger checkboxes).

### Step 7 — Pilot feature (week 2–4)
**Status:** PENDING.

Recommendation per §3.3: `features/est-service/`. CR-0001 (mTLS authentication) in `doc/est-specs.md` §14.1 is a natural in-flight methodology deliverable, and it touches §11 *authentication* sign-off — a useful test of the operational layer end-to-end. Capture frictions in the pilot's `progress.md` *History*.

### Step 8 — Selective backfill (continuous; indefinite)
**Status:** PENDING.

- Spec migration (linkage → full schema) happens incrementally as features are touched. **Never as a project of its own** ([workflow-integration.md](methodology/workflow-integration.md) §6.1 step 8).
- ADRs backfilled opportunistically.
- Wire up ruff (or chosen lint stack — Q-8 in §8) and graduate `lint-and-test.yml` from soft to hard gate.
- OSS-release work begins when ready (`features/oss-release/`).

### What is explicitly NOT in the cutover sequence

Per [workflow-integration.md](methodology/workflow-integration.md) §6.2 *Anti-patterns to avoid*:

- No retroactive migration of working spec content.
- No backfilled fictional `progress.md` history before the onboarding date.
- No reorganisation of the existing `pypki/` / `web/` / `config/` directory layout.
- No bulk tier elevation "to be safe".

---

## 8. Open questions

The audit cannot answer these — they require project-owner decisions. Listed in execution-blocking order. The two gating questions are **Q-2** (Tier model) and **Q-1** (layout) — answering them unblocks everything else.

- **Q-1. Layout — single-system (recommended in §6.1) or flat?** Single-system aligns with the seven specs' shared template, shared data model, shared signing substrate, shared audit log. The `systems/<system>/` wrapper is *elided* to the repo root for single-system projects.
- **Q-2. Tier model — pick one of A / B / C from §5.4 TC-3.** This is the most consequential decision and the gate on Step 2. Recommended: **A** with Tier C — *strict* as safe default until evaluator acceptance is documented.
- **Q-3. Tier C sub-tier specifically: is any planned PyPKI deployment inside a WebTrust / FIPS / eIDAS QSEAL / CP/CPS scope?** Determines `strict` vs `controlled` per §6.3.3.
- **Q-4. Feature slug confirmation — eight features from §6.2.** Confirm names, merges (especially `kms` + `hsm-support`), and whether `auth` / `audit-log` start as features (option a) or as system-level content with CODEOWNERS (option b — recommended in §6.4 B-4 and B-5).
- **Q-5. Pilot feature.** Recommendation: `features/est-service/` (per §3.3 of the recommended sequence). Confirm.
- **Q-6. Build/test/lint commands to name in [`CLAUDE.md`](CLAUDE.md).** Proposed: `Test (unit): pytest`; `Test (smoke menu): python -m tests`; `Install dev deps: pip install -r requirements-dev.txt`; `Build / Lint / Type-check / Format` deferred to Q-7 / Q-8.
- **Q-7. Lint tool choice.** `doc/PROGRESS.md` §1 lists "CI: lint check" as `[pending]`. Options: ruff (recommended, lowest friction) vs black + isort + mypy. Affects Step 8.
- **Q-8. AI channel breadth.** [`CLAUDE.md`](CLAUDE.md) lists Claude Code only. Methodology §5.1 also enumerates Microsoft Copilot and OpenAI Team. Are those *forbidden* or simply *unused*?
- **Q-9. Owner per feature.** [`progress-template.md`](methodology/templates/progress-template.md), [`functional-spec-template.md`](methodology/templates/functional-spec-template.md), [`technical-design-template.md`](methodology/templates/technical-design-template.md) all require an *Owner*. One-engineer project → owner is the project owner; team project → owner per feature.
- **Q-10. Where does this report live after Step 2 lands?** Repo root (default) or moved under `docs/adr/0000-methodology-adoption.md`. The audit report is not a methodology artifact in its own right; it documents a moment in time.

---

## 9. Methodology references

- [`methodology/methodology-brief.md`](methodology/methodology-brief.md) — agent-loadable summary, agent contract.
- [`methodology/best-practices.md`](methodology/best-practices.md) §4.2 (three-layer specs), §5.1 (four-layer hierarchy + system layer heuristics), §5.2 (state vocabulary), §5.3 (where state lives, aggregate rule), §5.4 (agent contract), §5.5 (atomic updates), §5.6 (granularity / traceability), §5.7 (spec/code/release linkage).
- [`methodology/ai-coding-security-policy.md`](methodology/ai-coding-security-policy.md) §4 (data classification), §5 (tool/channel eligibility), §6.2 (Tier B), §6.3.1 (Tier C — controlled), §6.3.2 (Tier C — strict), §6.3.3 (sub-tier determination), §6.4 (decision procedure), §6.5 (open-source platforms), §9.1 (PR disclosure), §11 (sign-off categories).
- [`methodology/workflow-integration.md`](methodology/workflow-integration.md) §2 (GitHub config), §6 (existing-repo onboarding eight steps), §6.1 (the steps), §6.2 (anti-patterns), §6.3 (cheapest first step), §6.4 (linkage pattern shape), §6.5 (agent-driven workflow).
- [`methodology/skills/methodology-audit/SKILL.md`](methodology/skills/methodology-audit/SKILL.md) — this skill, shaping the report.
- [`methodology/templates/operational/legacy-onboarding-checklist.md`](methodology/templates/operational/legacy-onboarding-checklist.md) — single-page Phase-1-to-7 checklist matching Step 1–Step 8 above.
- [`methodology/templates/operational/CLAUDE.md.example`](methodology/templates/operational/CLAUDE.md.example) — `CLAUDE.md` template currently partially-filled at the repo root.
- [`methodology/training/how-to/06-how-to-onboard-an-existing-project-with-an-agent.md`](methodology/training/how-to/06-how-to-onboard-an-existing-project-with-an-agent.md) — the how-to driving this run.
