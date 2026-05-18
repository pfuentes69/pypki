# PyPKI — Methodology Gap Analysis

**Audited against:** WiseKey AI-Assisted Development Methodology — `methodology/` submodule (best-practices v1.5, security-policy v1.4, workflow-integration v1.4).
**Audit date:** 2026-05-14 (revised after CLAUDE.md edits the same day).
**Auditor:** Claude Code (advisory, read-only against the methodology submodule).
**Reference skill:** [`methodology/skills/methodology-audit/SKILL.md`](methodology/skills/methodology-audit/SKILL.md).
**Reference checklist:** [`methodology/templates/operational/legacy-onboarding-checklist.md`](methodology/templates/operational/legacy-onboarding-checklist.md).

> **Reading order.** §1 summary → §1.1 review-pass delta after CLAUDE.md edit → §2 dimension-by-dimension findings (severity-tagged, resolved items marked) → §3 prioritised action plan (mapped to the eight-step existing-repo path in [workflow-integration.md](methodology/workflow-integration.md) §6) → §4 open questions for the project owner.

---

## 1. Executive summary

PyPKI is a **PKI / KMS / OCSP / EST application** — a domain that the methodology singles out as Tier-C-heavy by default ([ai-coding-security-policy.md](methodology/ai-coding-security-policy.md) §6.3). Bringing it under the methodology is therefore high-value: the rules that govern *which* code AI may touch, and *what* must be attested at every PR, are exactly the rules a PKI codebase needs.

Current state:

- **Operational layer:** absent. `CLAUDE.md` exists at the repo root but is the **unfilled template** copied verbatim from [`methodology/templates/operational/CLAUDE.md.example`](methodology/templates/operational/CLAUDE.md.example) — every placeholder still in square brackets, every `path/to/methodology/...` link still unresolved. There is no `.github/` directory: no `CODEOWNERS`, no PR template, no methodology CI workflows.
- **Tracking layer:** absent in methodology terms. [`doc/PROGRESS.md`](doc/PROGRESS.md) is a substantial and well-curated status board, but uses a non-methodology state vocabulary (`[done]` / `[partial]` / `[pending]` / `[deferred]`) and does not decompose work into stable-ID deliverables linked to functional requirements. No `PROJECT-STATUS.md` at the repo root. No per-feature `progress.md`.
- **Spec layer:** present in legacy form. `doc/*-specs.md` (CA, certificate management, template, EST, KMS, HSM, database) are domain specs aligned to a **single** template (Goals / Status / Architecture / Data model / Lifecycle / Weaknesses / Order of work / Acceptance / Cross-references) — internally consistent but not split into the methodology's *functional-spec* + *technical-design* pair, and not located under `features/` or `systems/`.
- **Tier annotations:** absent. No *AI Tier* column anywhere. Modules that clearly fit Tier C criteria 1, 2, 4, 5, 6 (cryptographic primitives, key custody, CP/CPS-bound signing, root-of-trust, non-repudiation) live in `pypki/` with no annotation that signals AI restrictions.
- **Data class & AI channel:** not declared. The methodology cannot answer "which AI tools is this repository approved for?" without a Class declaration.

**Headline.** The cheapest, highest-leverage day-1 action is **Phase 2** of the legacy-onboarding checklist: populate `CLAUDE.md`, install `.github/` operational artifacts, and stand up Tier C `CODEOWNERS` enforcement. That alone makes every subsequent PR methodology-compliant for everything the operational layer covers, even before tracking and spec migration begin.

## 1.1 Review-pass delta (2026-05-14, post-CLAUDE.md edit)

The project owner edited `CLAUDE.md` between the first draft of this audit and this revision. Net effect:

**Resolved or partially resolved:**

- **Methodology link paths fixed** (was O-1's link sub-finding) — `path/to/methodology/...` placeholders are now `methodology/...`.
- **Project context filled** — declares PyPKI as a general-purpose PKI platform intended for **open-source release**. This is a material disclosure that activates [ai-coding-security-policy.md](methodology/ai-coding-security-policy.md) **§6.5 — Open-source WiseKey platforms** (see new §2.8 below).
- **Data classification declared** — Class 2 (resolves Q-3).
- **Approved AI tool channel declared** — Claude Code (partially resolves Q-4; remaining gap: the methodology channel list in §5.1 also enumerates Microsoft Copilot and OpenAI Team — the project owner should confirm whether these are *forbidden* for this repo or simply *not currently used*).
- **Code-style pointer present** ("Use best practices for Python coding") — minimal but no longer blank.

**Still open in `CLAUDE.md`:**

- *Repository layout* still carries `[flat / system / platform]` and `[features/ | systems/<system>/features/]` placeholders (Q-1 unresolved), and the example dirs `lib/`, `services/`, `api/` listed in the template **do not exist** in this repo — they will mislead an AI agent reading `CLAUDE.md` for orientation.
- *Build, test, lint* — every command is still `[command]`. The wording was softened to "Once available, the AI agent will use…" but `pytest` clearly works today and should be named.

**New contradiction surfaced by the edit (HIGH):**

The owner wrote `Security do-not-touch zones (Tier C)`: **NONE**, `§11 sign-off paths`: **NONE**, and `Project-specific notes`: *"This project is a special case, so even if the focus is PKI, it is in general considered as **Tier B** in terms of permissibility for use of AI agents."* These three statements are not jointly consistent with the methodology, and the contradiction is the single most important thing for the project owner to resolve before Phase 1 lands. New finding TC-4 in §2.4 captures the detail; new finding OSS-1 in §2.8 covers the open-source dimension. Recast Q-2 in §4 reflects the revised question.

---

## 2. Findings by dimension

Severity: **HIGH** — actual rule violation or missing-day-1 artifact; **MEDIUM** — misalignment that blocks the onboarding path; **LOW** — cosmetic drift or deferred refinement.

### 2.1 Operational layer

| # | Finding | Severity | Methodology reference |
|---|---|---|---|
| O-1 | ~~`CLAUDE.md` is the unfilled template.~~ **Partially resolved (2026-05-14):** link paths fixed, project context and code-style filled, data class and channel declared. **Still open:** *Repository layout* section still carries `[flat / system / platform]` and `[features/ | systems/<system>/features/]` placeholders, and the example dirs `lib/`, `services/`, `api/` listed under it **do not exist in this repo** — leaving them in place will mislead any AI agent reading `CLAUDE.md` for orientation. | MEDIUM (was HIGH) | [workflow-integration.md](methodology/workflow-integration.md) §5 step 1; [`CLAUDE.md.example`](methodology/templates/operational/CLAUDE.md.example) |
| O-2 | No `.github/` directory at all. Missing: `pull_request_template.md`, `CODEOWNERS`, `workflows/progress-update-check.yml`, `workflows/ai-disclosure-check.yml`, language-appropriate `lint-and-test.yml` / `dependency-review.yml` / `secret-scan.yml`. | HIGH | [workflow-integration.md](methodology/workflow-integration.md) §2.1, §2.4, §2.5 |
| O-3 | No branch protection / `CODEOWNERS` enforcement for Tier C paths. AI agents are currently free to author PRs touching `pypki/key_encryption.py`, `pypki/pkcs11_helper.py`, etc., with no mechanical gate. (Owner has declared *Tier C: NONE* in `CLAUDE.md` — see TC-4 below; if that declaration stands, this finding collapses, but the `CODEOWNERS` for the §11 sign-off categories remains required.) | HIGH | [ai-coding-security-policy.md](methodology/ai-coding-security-policy.md) §6.3, §11 |
| O-4 | The `Build, test, lint` block in `CLAUDE.md` still carries `[command]` placeholders for every command. Project uses `pytest` (see `tests/conftest.py`) and ships `requirements-dev.txt`; the canonical commands exist and should be named. The wording was softened to "Once available, the AI agent will use…" but **`pytest` works today**. No lint tool is wired up (`doc/PROGRESS.md` §1 lists this as `[pending]`). | HIGH | [best-practices.md](methodology/best-practices.md) §7.1; [`CLAUDE.md.example`](methodology/templates/operational/CLAUDE.md.example) lines 41–52 |
| O-5 | ~~`AI tool channels for this project` section unfilled.~~ **Resolved (2026-05-14):** Class 2 declared; Claude Code listed as approved channel. **Minor residual:** the §5.1 methodology channel list also enumerates Microsoft Copilot and OpenAI Team — the owner should confirm whether these are *forbidden* for this repo or simply *not currently used*. | LOW (was MEDIUM) | [ai-coding-security-policy.md](methodology/ai-coding-security-policy.md) §4, §5 |

### 2.2 Tracking layer

| # | Finding | Severity | Methodology reference |
|---|---|---|---|
| T-1 | No `PROJECT-STATUS.md` at repo root. | HIGH | [best-practices.md](methodology/best-practices.md) §5.3; [`project-status-template.md`](methodology/templates/project-status-template.md) |
| T-2 | No per-feature `progress.md`. Work is not organised under `features/` or `systems/<system>/features/`. | HIGH | [best-practices.md](methodology/best-practices.md) §5.1, §5.3 |
| T-3 | [`doc/PROGRESS.md`](doc/PROGRESS.md) uses a **non-methodology state vocabulary** (`[done]`, `[partial]`, `[pending]`, `[deferred]`) rather than the eight-state methodology lifecycle (`proposed → specified → in-progress → implemented → validated → released`, plus `blocked` / `dropped`). The two most important distinctions for AI-assisted work — `implemented` vs `validated`, and the agent contract that bars an AI from moving deliverables into `validated` — cannot currently be expressed. | HIGH | [best-practices.md](methodology/best-practices.md) §5.2, §5.4 (agent contract) |
| T-4 | `doc/PROGRESS.md` rows do not carry stable deliverable IDs (`D-1`, `D-2`, …) and do not link explicitly to functional-requirement IDs (`FR-N`) — so spec → code traceability is implicit and cannot be machine-checked. | MEDIUM | [best-practices.md](methodology/best-practices.md) §5.6 |
| T-5 | No *Active deliverables — notes* section, *Validation log*, or *Active blockers* table per the progress template. Inline `[partial]` items in `doc/PROGRESS.md` describe gaps in prose but not in a queryable form. | MEDIUM | [`progress-template.md`](methodology/templates/progress-template.md) §2–§5 |
| T-6 | No *History* block per feature. Decisions and transitions live in commit messages and prose paragraphs of `doc/PROGRESS.md` § headers. | LOW | [`progress-template.md`](methodology/templates/progress-template.md) §5 |

### 2.3 Spec layer

| # | Finding | Severity | Methodology reference |
|---|---|---|---|
| S-1 | Specs are domain-grouped in `doc/*-specs.md`, not feature-grouped under `features/<feature>/`. Existing files: `ca-management-specs.md`, `certificate-management-specs.md`, `certificate-template-specs.md`, `est-specs.md`, `kms-specs.md`, `hsm-support-specs.md`, `database-specs.md`. | MEDIUM | [best-practices.md](methodology/best-practices.md) §4.2, §5.1; [workflow-integration.md](methodology/workflow-integration.md) §6.1 step 4 |
| S-2 | No split between *functional* (what + why) and *technical* (how) — each spec mixes the two. AI agents reading them will struggle to separate stable intent from evolving implementation. | MEDIUM | [best-practices.md](methodology/best-practices.md) §4.2 |
| S-3 | Numbered, testable functional-requirement IDs (`FR-1`, `FR-2`) and acceptance-criteria IDs (`AC-1`, `AC-2`) are not used systematically — change-requests are coded `CR-NNNN` (a different concept) and live in §17/§14 of each spec. | MEDIUM | [`functional-spec-template.md`](methodology/templates/functional-spec-template.md) §8, §9 |
| S-4 | No `docs/adr/` directory. Architecturally significant decisions (e.g., per-provider KEK regime, KEY-OWNED semantics, `auth_secret_ref` resolver design) live as prose in the specs but not as discrete ADRs. | LOW | [best-practices.md](methodology/best-practices.md) §4.1 |

### 2.4 Tier annotations and security do-not-touch zones

This is the **highest-risk dimension** for PyPKI: it is a PKI / KMS codebase, and the methodology's Tier C rules are explicitly built to keep AI agents out of code where they would invalidate evaluations or compromise the root of trust.

| # | Finding | Severity | Methodology reference |
|---|---|---|---|
| TC-1 | No *AI Tier* annotation exists anywhere in the codebase or specs — neither a column in a module catalogue nor a CODEOWNERS rule. Heuristic-tier detection per the audit skill (path patterns `*/crypto/`, `*/pki/`, `*/auth/`, `*/audit/`, `*/signing/`, `*/hsm/`, `*/key-*/`) flags the following as **Tier C candidates** that the project owner must confirm or downgrade: | HIGH | [ai-coding-security-policy.md](methodology/ai-coding-security-policy.md) §6.3, §6.4 |
| | • `pypki/key_encryption.py` — AES-256-GCM KEK wrapping. **Criterion 1** (cryptographic primitive: key wrap derived via HKDF-SHA256). | | §6.3 criterion 1 |
| | • `pypki/key_tools.py` — key generation & management. **Criterion 2** (key custody). | | §6.3 criterion 2 |
| | • `pypki/pkcs11_helper.py` and `pypki/backends/pkcs11.py` — PKCS#11 / HSM low-level helpers. **Criterion 2** (key custody at HSM boundary). | | §6.3 criterion 2 |
| | • `pypki/kms.py` and `pypki/backends/` (incl. `base.py`, `software.py`) — KMS signing call sites holding key handles. **Criterion 2** (key-custody call site) + **criterion 5** (root of trust). | | §6.3 criteria 2, 5 |
| | • `pypki/ca.py` — CertificationAuthority operations (CA cert / CRL signing). **Criterion 2** + **criterion 5** + likely **criterion 4** (CP/CPS-bound if deployed under one). | | §6.3 criteria 2, 4, 5 |
| | • `pypki/certificate_tools.py` — end-entity certificate generation / signing. **Criterion 2** + **criterion 5**. | | §6.3 criteria 2, 5 |
| | • `pypki/ocsp_responder.py` — OCSP response signing. **Criterion 5** + **criterion 6** (non-repudiation of revocation answers). | | §6.3 criteria 5, 6 |
| | • `pypki/signing_algorithm.py` — signing-algorithm token catalogue. **Criterion 1**-adjacent (governs algorithm selection); per [ai-coding-security-policy.md](methodology/ai-coding-security-policy.md) §8.6, algorithm choices are human decisions regardless of tier. | | §6.3 criterion 1; §8.6 |
| | • `web/routes/ocsp_routes.py` and `web/routes/est_routes.py` — protocol surfaces that invoke the Tier C signers. Likely **Tier B** (Tier-C-adjacent) under §6.2 criterion 3 (shared address space). | | §6.2 criterion 3 |
| TC-2 | Sub-tier (`controlled` vs `strict`) is therefore also undetermined for every Tier C candidate above. Methodology v1.4 requires both tier *and* sub-tier in the Module catalogue. The relevant question per [ai-coding-security-policy.md](methodology/ai-coding-security-policy.md) §6.3.3: does any deployed instance of PyPKI sit inside a WebTrust audit, FIPS evaluation, eIDAS QSEAL scope, or a published CP/CPS? If yes (and the evaluator has not documented acceptance of AI authorship), those paths are **Tier C — strict**; otherwise they are candidates for **Tier C — controlled**. | HIGH | §6.3.1, §6.3.2, §6.3.3 |
| TC-3 | ~~`CLAUDE.md` § *Security do-not-touch zones* still lists the template's example paths…~~ **Superseded (2026-05-14):** the owner replaced the example paths with `NONE` for both Tier C and §11 sign-off. The directional finding (template example paths misleading the agent) is closed; the substantive question moves to TC-4. | — (superseded) | — |
| TC-4 | **(NEW, post-CLAUDE.md edit.)** The owner has declared `Tier C: NONE` and `§11 sign-off: NONE`, while simultaneously stating in *Project-specific notes* that "*the project is in general considered as Tier B in terms of permissibility for use of AI agents*". This combination is not jointly consistent with the methodology in three ways: **(i)** Per [ai-coding-security-policy.md](methodology/ai-coding-security-policy.md) §6.2 criterion 3, Tier B is in part defined as *"adjacent to a Tier C boundary and shares its memory or process address space"*. If there is no Tier C in the project, criterion 3 cannot supply a default Tier B. The other Tier B triggers — §6.2 criteria 1 (Class 3 data processed at build/test time) and 2 (source bound by customer/contractual confidentiality) — do **not** apply to this codebase (Class 2, open source per project context). So the *default* Tier B stance has no §6.2 trigger to rest on. **(ii)** Per §6.4 *Decision procedure*, the methodology's default tier is **Tier A**; elevation to Tier B or Tier C requires meeting a specific §6.2 / §6.3 criterion. A blanket "Tier B by default" inverts that. **(iii)** Per §6.3 criteria 2, 5, and 6, a PKI codebase deployed as a CA has key-custody call sites ([`pypki/kms.py`](pypki/kms.py), [`pypki/backends/`](pypki/backends/), [`pypki/pkcs11_helper.py`](pypki/pkcs11_helper.py)), root-of-trust signing operations ([`pypki/ca.py`](pypki/ca.py), [`pypki/certificate_tools.py`](pypki/certificate_tools.py)), and non-repudiation outputs ([`pypki/ocsp_responder.py`](pypki/ocsp_responder.py)) — these are independent triggers; any one of them makes the call site Tier C. Declaring "Tier C: NONE" is the project owner's call to make under §6.4, but the methodology asks for that override to be **argued in the technical design**, not asserted in `CLAUDE.md`. Recommended resolution path: see Q-2 (revised) in §4 — the owner picks one of three consistent positions. | **HIGH** | [ai-coding-security-policy.md](methodology/ai-coding-security-policy.md) §6.2, §6.3, §6.4 |

### 2.5 Sign-off coverage (Security Policy §11)

| # | Finding | Severity | Methodology reference |
|---|---|---|---|
| SO-1 | No `CODEOWNERS` exists, so no §11 sign-off category is currently mechanised. Categories likely applicable to PyPKI based on observed code: §11 *cryptographic / key-custody* (the Tier C candidates above), *authentication* ([`web/routes/auth_routes.py`](web/routes/auth_routes.py) — JWT issuance), *audit* (`audit_logs.html` + the audit table per `database-specs.md`), *public API* (any externally-reachable endpoint under [`web/routes/main_routes.py`](web/routes/main_routes.py) + EST + OCSP), and *migrations* (DB schema migrations under `utils/migrate_*.py` and the `migrate_schema()` boot path). The owner's `§11 sign-off: NONE` declaration in `CLAUDE.md` (2026-05-14) is at odds with the existence of `auth_routes.py` (authentication is a named §11 category regardless of tier) and the migration scripts — recommend revisiting alongside Q-2. | HIGH | [ai-coding-security-policy.md](methodology/ai-coding-security-policy.md) §11 |

### 2.6 AI-disclosure and atomic-update enforcement

| # | Finding | Severity | Methodology reference |
|---|---|---|---|
| AD-1 | No PR template with AI-disclosure block. Compliant disclosure (tool / model / role / data class / component tier / attestation) cannot currently be required at PR time. | HIGH | [ai-coding-security-policy.md](methodology/ai-coding-security-policy.md) §9.1; [workflow-integration.md](methodology/workflow-integration.md) §2.4 |
| AD-2 | No CI gate enforcing the atomic-update rule (code change + `progress.md` update in the same PR). Without it, [best-practices.md](methodology/best-practices.md) §5.5 stays aspirational. | HIGH | [`progress-update-check.yml`](methodology/templates/operational/progress-update-check.yml); [best-practices.md](methodology/best-practices.md) §5.5 |
| AD-3 | No CI gate enforcing AI-disclosure presence. | HIGH | [`ai-disclosure-check.yml`](methodology/templates/operational/ai-disclosure-check.yml) |

### 2.7 Repository-shape decision (flat / system / platform)

This is a one-time decision the project owner must make before Phase 3 of the legacy-onboarding path; it shapes where `progress.md` files live.

Observations:

- PyPKI is a single deployable product (a Flask + Docker stack with one core library `pypki/`, one web surface `web/`, one set of operational scripts).
- The legacy specs already group work into ~7 coherent areas (CA, certificates, templates, EST, KMS, HSM, OCSP, database) that share a kernel — common DB schema, common KMS substrate, common audit log, common error model.
- Per [best-practices.md](methodology/best-practices.md) §5.1 *When to introduce the system layer*: more than ~5 features sharing user model / error model / contracts; multiple features depending on each other's contracts. **PyPKI clearly meets this bar.**

**Recommendation:** adopt a single-system layout (`systems/pypki/` elided to the repo root, i.e. system-level `functional-spec.md` / `technical-design.md` / `progress.md` at the root, plus `features/<feature>/` for each of the seven legacy spec areas). This is what [best-practices.md](methodology/best-practices.md) §5.1 calls "a single-system project". The platform layer is **not** warranted (no second system in scope).

This needs confirmation by the project owner (see §4 Q-1).

### 2.8 Open-source dimension (NEW, post-CLAUDE.md edit)

The 2026-05-14 edit to `CLAUDE.md` declares that PyPKI is "*developed as base for other projects. The main intent is to release it as Open Source code.*" This activates [ai-coding-security-policy.md](methodology/ai-coding-security-policy.md) **§6.5 — Open-source WiseKey platforms**, which has specific consequences the methodology spells out.

| # | Finding | Severity | Methodology reference |
|---|---|---|---|
| OSS-1 | §6.5(1) is explicit: *"Open-sourcing does not collapse Tier C."* The compliance-validated-boundary (§6.3 criterion 4), root-of-trust (criterion 5), and regulatory-non-repudiation (criterion 6) triggers are properties of the **operating deployment**, not of the source's confidentiality state. If any downstream deployment of PyPKI sits inside a WebTrust / FIPS / eIDAS / CP/CPS scope, the corresponding code paths remain Tier C *in the upstream open-source repo* — even though the source is public. This reinforces TC-4: the owner's "Tier C: NONE" position needs an argued justification, especially given that PyPKI is explicitly being prepared as a base for downstream deployments. | HIGH | §6.5(1) |
| OSS-2 | §6.5(3) requires a `MAINTAINERS` file listing the named, identity-verified maintainers who may author Tier C code. For Tier C — *strict* sub-tier, the maintainer-only authoring rule applies and **no AI assistance** is permitted at any step. For Tier C — *controlled*, the §6.3.1 controls package applies (on-premises AI only, dual review, full session logging, security-team sign-off per change). Neither file nor process exists in the repo today. This finding is contingent on resolving TC-4 / Q-2 — if the owner's "Tier C: NONE" stands and is defensible, this finding collapses. | HIGH (contingent on Q-2) | §6.5(3) |
| OSS-3 | §6.5(4) requires the project's `CONTRIBUTING` file to require an AI-disclosure block on community pull requests, matching the WiseKey-internal PR template ([workflow-integration.md](methodology/workflow-integration.md) §2.4). No `CONTRIBUTING` file exists. Action: add `CONTRIBUTING.md` at the repo root at the point PyPKI accepts community PRs (deferrable until first OSS release). | MEDIUM | §6.5(5) |
| OSS-4 | §6.5(4) — *Upstream / downstream separation*. The repo is currently a single thing; once PyPKI is released as open source, WiseKey-operated downstream deployments (if any) become a distinct compliance scope: the upstream project is then treated as a §10 vendor-managed dependency, with WiseKey-as-maintainer in the vendor role. This shapes the long-term release / signing / build-attestation pipeline. Not actionable today, but should be captured as a deliverable in the OSS-release feature when it is created (proposed slug: `features/oss-release/`). | LOW | §6.5(4) |

---

## 3. Action plan

Aligned to the eight-step existing-repo onboarding path in [workflow-integration.md](methodology/workflow-integration.md) §6 and the single-page checklist at [`methodology/templates/operational/legacy-onboarding-checklist.md`](methodology/templates/operational/legacy-onboarding-checklist.md). Steps are **forward-looking**: no retroactive migration of working content.

The plan is split into phases. Within each phase, items are listed in execution order. Severity-HIGH findings from §2 are addressed by Phase 1; severity-MEDIUM by Phase 2; severity-LOW are deferred to Phase 3 (selective backfill, indefinite).

### Phase 1 — Operational layer + Tier C identification (highest leverage; days, not weeks)

> Maps to legacy-onboarding-checklist Phase 1 + Phase 2. Resolves O-1, O-2, O-3, O-4, O-5, TC-1, TC-3, AD-1, AD-2, AD-3, SO-1.

1. **P1.1 — Identify Tier C paths and sub-tiers.** Project owner confirms the Tier C candidate list in §2.4 (TC-1) and decides sub-tier per §2.4 TC-2 (depends on whether any deployment is bound by WebTrust / FIPS / eIDAS / CP/CPS — see open question Q-2). Record the decision as an ADR under `docs/adr/0001-tier-c-paths.md` (creating the directory).
2. **P1.2 — Populate `CLAUDE.md`.** Replace every placeholder:
   - All `path/to/methodology/...` links → `methodology/...` (the actual submodule path).
   - *Project context*: one paragraph describing PyPKI (PKI / KMS / OCSP / EST application, owner, integrations).
   - *Repository layout*: declare the single-system layout (per §2.7 recommendation, subject to Q-1) and list `pypki/`, `web/`, `config/`, `utils/`, `tests/`, `doc/` (legacy), `features/` (to be created), `docs/adr/`.
   - *Build, test, lint*: `pytest` (unit); integration tests run via `python -m tests`; no linter currently — record `[pending: ruff]` per `doc/PROGRESS.md` §1; `setup_venv.sh` for environment setup.
   - *Code style*: short pointer to the project's existing conventions (Python 3, type hints where present, `from pypki.log import logger`, etc.).
   - *Security do-not-touch zones*: replace the template's `lib/crypto/**` examples with the **actual** Tier C paths from P1.1 (`pypki/key_encryption.py`, `pypki/pkcs11_helper.py`, `pypki/backends/pkcs11.py`, `pypki/kms.py`, `pypki/key_tools.py`, `pypki/ca.py`, `pypki/certificate_tools.py`, `pypki/ocsp_responder.py`).
   - *§11 sign-off paths*: `web/routes/auth_routes.py` (auth), audit-log tables (audit), `web/routes/*_routes.py` (public API), `utils/migrate_*.py` + `utils/reset_pki.py` (migrations).
   - *AI tool channels*: declare data class (open question Q-3) and the approved channel list.
3. **P1.3 — Install `.github/` operational artifacts.** Copy from `methodology/templates/operational/`:
   - `.github/pull_request_template.md` ← `pull-request-template.md`.
   - `.github/CODEOWNERS` ← `CODEOWNERS.example`, populated with the Tier C paths from P1.1 and the §11 paths from P1.2.
   - `.github/workflows/progress-update-check.yml` ← `progress-update-check.yml`.
   - `.github/workflows/ai-disclosure-check.yml` ← `ai-disclosure-check.yml`.
   - Add language-appropriate `lint-and-test.yml` (skeleton that runs `pytest`; lint job marked `continue-on-error: true` until ruff is wired up — see `doc/PROGRESS.md` §1 *CI: lint check*), `dependency-review.yml`, `secret-scan.yml` (gitleaks or equivalent).
4. **P1.4 — Configure branch protection.** Per [workflow-integration.md](methodology/workflow-integration.md) §2.2: block direct pushes to `main`, require one human reviewer, require the CI gates from P1.3 as status checks, enforce `CODEOWNERS` review for Tier C paths.
5. **P1.5 — Configure agent access.** Per [workflow-integration.md](methodology/workflow-integration.md) §2.7: fine-grained app or PAT scoped to the repo; AI agents operate on feature branches only.

### Phase 2 — Tracking layer + spec linkage (weeks)

> Maps to legacy-onboarding-checklist Phase 3 + Phase 4 (linkage pattern by default). Resolves T-1, T-2, T-3, T-4, T-5, S-1.

1. **P2.1 — Confirm repository shape.** Resolve Q-1 (single-system vs flat). Assuming single-system: features live at `features/<feature>/`.
2. **P2.2 — Create `PROJECT-STATUS.md`** at the repo root from [`project-status-template.md`](methodology/templates/project-status-template.md). One row per feature listed below.
3. **P2.3 — Create one `features/<feature>/` per legacy spec area.** Proposed slug list (kebab-case capability names per [best-practices.md](methodology/best-practices.md) §5.1):
   - `features/ca-management/` — legacy `doc/ca-management-specs.md`.
   - `features/end-entity-certificates/` — legacy `doc/certificate-management-specs.md`.
   - `features/certificate-templates/` — legacy `doc/certificate-template-specs.md`.
   - `features/est-service/` — legacy `doc/est-specs.md`.
   - `features/kms/` — legacy `doc/kms-specs.md` (Tier C heavy).
   - `features/hsm-support/` — legacy `doc/hsm-support-specs.md` (Tier C heavy).
   - `features/ocsp-responder/` — currently covered inline in `pypki/ocsp_responder.py` and `web/routes/ocsp_routes.py`; new shell needed (Tier C — criterion 5/6).
   - `features/database-schema/` — legacy `doc/database-specs.md` (likely §11 *migrations* sign-off).
4. **P2.4 — For each feature, install the linkage pattern shell.** Per [workflow-integration.md](methodology/workflow-integration.md) §6.4: a thin `functional-spec.md` whose *Related artifacts* line points at the legacy `doc/*-specs.md` file; a thin `technical-design.md` likewise; a `progress.md` from [`progress-template.md`](methodology/templates/progress-template.md). The legacy specs continue to be authoritative — **do not migrate stable content** ([workflow-integration.md](methodology/workflow-integration.md) §6.1 step 4).
5. **P2.5 — Migrate `doc/PROGRESS.md` rows into per-feature `progress.md` deliverables tables.** Translate the legacy state vocabulary into the methodology vocabulary:
   - `[done]` → `released` (or `validated` where there is independent test/reviewer evidence; default to `released` for shipped work).
   - `[partial]` → `in-progress` with notes in *Active deliverables — notes* section.
   - `[pending]` → `proposed`.
   - `[deferred]` → `blocked`, with the blocker reason captured in §4 of the progress template.
   - Assign stable IDs (`D-1`, `D-2`, …) per feature.
   - **History blocks start at the onboarding date** ([workflow-integration.md](methodology/workflow-integration.md) §6.1 step 3); do **not** backfill prior history.
6. **P2.6 — Pick a pilot feature and run it through the methodology end-to-end.** Recommendation: `features/est-service/` — there is a live in-flight design proposal (CR-0001, EST mTLS authentication) in `doc/est-specs.md` §14.1 that maps cleanly to a methodology deliverable, and it touches §11 *authentication* sign-off. Capture frictions in the pilot's `progress.md` *History*.
7. **P2.7 — Pick the cutover date.** One to two weeks after P1 lands. From the cutover, **all** new PRs follow methodology rules (AI disclosure, atomic update, §11 trigger checkboxes).

### Phase 3 — Tier annotation + selective backfill (continuous; indefinite duration)

> Maps to legacy-onboarding-checklist Phase 5 + Phase 7. Resolves TC-2, T-6, S-2, S-3, S-4.

1. **P3.1 — Add the *AI Tier* column** to each feature's `technical-design.md` *Module catalogue* as that design is fleshed out (during migration, not in bulk). For each module: Tier (A / B / C) + sub-tier where C + the triggering criterion. Default Tier A; elevate only against the §6.3 criteria.
2. **P3.2 — Migrate spec content** (linkage → full functional + technical split) only when the next substantive change to that area would touch it anyway. **Never as a project of its own** ([workflow-integration.md](methodology/workflow-integration.md) §6.1 step 4 + step 8).
3. **P3.3 — Promote significant decisions to ADRs.** Backfill `docs/adr/` opportunistically when a new architectural decision is made; do not retroactively author ADRs for stable decisions already documented in the legacy specs.
4. **P3.4 — Wire up a linter** (ruff is the lowest-friction choice for Python; `doc/PROGRESS.md` §1 lists this as `[pending]`) and graduate the `lint-and-test.yml` lint job from `continue-on-error: true` to a hard gate.

### What is explicitly **not** in the action plan

Per [workflow-integration.md](methodology/workflow-integration.md) §6.2 *Anti-patterns to avoid*:

- **No retroactive migration of working spec content.** `doc/*-specs.md` files keep doing their job until a substantive change touches them.
- **No backfill of fictional history** in `progress.md` files. Per-feature `History` blocks start at the cutover date.
- **No reorganisation of the codebase folder structure** (`pypki/`, `web/`, `config/`, etc.) just to match the methodology — current layout is methodology-compatible.
- **No bulk tier elevation "to be safe".** Default Tier A; elevate where §6.3 criteria clearly apply.

---

## 4. Open questions for the project owner

The following decisions cannot be inferred from the codebase and must be made by the project owner before Phase 1 can complete. Listed in execution-blocking order.

- **Q-1. Repository shape — flat / single-system / platform?** §2.7 recommends single-system based on the seven coherent areas already in `doc/*-specs.md`. Alternative: keep flat (no system wrapper) and let features sit directly under `features/`. Platform layer is not warranted. Confirm or override. `CLAUDE.md` § *Repository layout* still carries the placeholder `[flat / system / platform]` — this answer fills it in.

- **Q-2. (REVISED, post-CLAUDE.md edit.) Reconcile Tier C / Tier B / §11 sign-off declarations.** The owner has declared `Tier C: NONE`, `§11 sign-off: NONE`, and `Tier B in general` simultaneously. Per finding TC-4 these are not jointly consistent with the methodology. The owner must pick one of the three positions below — each is internally consistent; the choice depends on the project's real compliance posture:

  - **Option A — methodology default (recommended starting point for an open-source PKI base).** Default is Tier A; specific paths are Tier C under §6.3 criteria 2, 5, 6 (see §2.4 TC-1 list); some surrounding paths are Tier B under §6.2 criterion 3 (adjacency). Then decide Tier C — *controlled* vs *strict* sub-tier per §6.3.3 based on whether **any** WiseKey-operated downstream deployment of PyPKI will sit inside a WebTrust / FIPS / eIDAS / CP/CPS scope **without** documented evaluator acceptance of AI-assisted authorship (default *strict* if uncertain). `§11 sign-off` populated with `auth`, `audit`, public-API, and `migrations` paths.

  - **Option B — owner override, argued.** Keep `Tier C: NONE` but **drop the "Tier B in general" stance** (because §6.2 criterion 3 cannot supply it once Tier C is empty). The codebase is then **Tier A** by methodology default, with the argument captured in the technical design as required by §6.4. This is defensible if and only if: (i) the upstream OSS repo is never itself the compliance-validated artifact; (ii) WiseKey commits to evaluating downstream-deployment tier separately when those exist (per §6.5(4) upstream/downstream separation); (iii) `§11 sign-off` is still populated for `auth`, `audit`, public-API, `migrations` — these are §11 categories regardless of Tier.

  - **Option C — "Tier B by default" interpretation.** If the owner's intent is *"treat the whole codebase conservatively because it's PKI-adjacent"*, then **something** must be Tier C for §6.2 criterion 3 to apply. Pick the minimum Tier C set (typically [`pypki/key_encryption.py`](pypki/key_encryption.py), the PKCS#11 backend, and the CA / OCSP signers) and inherit Tier B on the rest of `pypki/` and `web/routes/`. This collapses to a special case of Option A.

  Recommended: **Option A**, with Tier C — *strict* as the safe default until evaluator acceptance is documented. Whichever option the owner picks, `CLAUDE.md` § *Security do-not-touch zones* and § *Project-specific notes* are updated together so the agent-facing statement is consistent.

- ~~**Q-3. Data classification.**~~ **Resolved (2026-05-14): Class 2.**

- **Q-4. Approved AI tool channels — minor residual.** `CLAUDE.md` lists Claude Code only. The methodology §5.1 channel list also enumerates Microsoft Copilot and OpenAI Team. Confirm whether these are *forbidden* for this repo (then say so in `CLAUDE.md`) or simply *not currently used* (then no change). Class 2 permits all three under §5.

- **Q-5. Feature slug list confirmation.** §3 P2.3 proposes eight feature slugs. Confirm the names and whether any should be merged (e.g., `kms` + `hsm-support`?) or split further (e.g., separate `auth` and `audit` features for the §11-sign-off paths in [`web/routes/auth_routes.py`](web/routes/auth_routes.py) and the audit log). Consider adding `features/oss-release/` per OSS-4.

- **Q-6. Pilot feature selection.** §3 P2.6 recommends `features/est-service/` because CR-0001 is a natural in-flight deliverable. Confirm, or pick a different feature whose next change is imminent.

- **Q-7. Ownership.** Each `progress.md`, functional spec, and technical design names an *Owner*. For a one-engineer project, this is the project owner; for a team project, name an owner per feature.

- **Q-8. Lint tool choice.** `doc/PROGRESS.md` §1 lists "CI: lint check" as `[pending]`. Ruff is the lowest-friction Python option; black + isort + mypy is the more traditional stack. Confirm before P3.4.

- **Q-9. Where should this gap analysis live after Phase 1 lands?** Two natural homes: keep it at the repo root as the cutover-time audit record; or move it under `docs/adr/0000-methodology-adoption.md` once Phase 1 is complete. The methodology has no opinion; the audit report itself is not a methodology artifact.

- **Q-10. (NEW) Build/test commands in `CLAUDE.md`.** `pytest` works today and should be named in `CLAUDE.md` § *Build, test, lint* — the "Once available" softening reads as understating what the repo can already run. Confirm the commands to name now (proposed: `Test (unit): pytest`; `Test (smoke menu): python -m tests`; `Install dev deps: pip install -r requirements-dev.txt`; leave `Build`/`Lint`/`Type-check`/`Format` as `[pending: ruff/mypy]` referencing `doc/PROGRESS.md` §1).

---

## 5. Citations

- [`methodology/methodology-brief.md`](methodology/methodology-brief.md) — 2-page overview, agent contract, four-layer hierarchy.
- [`methodology/best-practices.md`](methodology/best-practices.md) §4.2 (three-layer spec model), §5 (execution tracking), §5.2 (state vocabulary), §5.4 (agent contract), §5.5 (atomic updates).
- [`methodology/ai-coding-security-policy.md`](methodology/ai-coding-security-policy.md) §4 (data classification), §5 (tool/channel eligibility), §6 (tier criteria), §6.3.1 / §6.3.2 (sub-tiers), §9.1 (PR disclosure), §11 (sign-off categories).
- [`methodology/workflow-integration.md`](methodology/workflow-integration.md) §2 (GitHub config), §6 (existing-repo onboarding path, eight steps), §6.4 (linkage pattern shape).
- [`methodology/templates/operational/legacy-onboarding-checklist.md`](methodology/templates/operational/legacy-onboarding-checklist.md) — single-page checklist matching this action plan.
- [`methodology/templates/operational/CLAUDE.md.example`](methodology/templates/operational/CLAUDE.md.example) — source of the unfilled template currently at the repo root.
- [`methodology/skills/methodology-audit/SKILL.md`](methodology/skills/methodology-audit/SKILL.md) — audit-skill definition; this report is shaped to its §4 dimensions.
