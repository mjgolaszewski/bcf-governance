# Governance Playbook

## Purpose

Use governed files as executable project state: product scope, delivery sequence, active work, evidence, and release readiness must be inspectable without operator memory.

Repo evidence: `template-repo/AGENTS.yml`, `scripts/validate_governance_yaml.py`, `template-repo/schemas/*.json`.

## Authority Order

When artifacts disagree, use this order:

1. user or owner instructions
2. `AGENTS.yml`
3. `plans/product-spec.yml`
4. `plans/build-plan.yml`
5. `plans/phase-ledger.yml`
6. `governance-profile.yml` and `architecture-boundaries.yml`
7. `MEMORY.yml`
8. `phases/*.yml`

`AGENTS.yml` is instruction-only. Execution evidence belongs in phase logs.

Repo evidence: `template-repo/AGENTS.yml` authorities and regression shield.

## Canonical Artifacts

Canonical owner details live in `governance/ARTIFACT_OWNERSHIP.md`. The validator enforces schema shape, repo-relative `document.path`, active-phase alignment, phase/workitem/log consistency, phase-history retention, release-gate wiring, hotfix alignment, observability contract shape, artifact-root ownership, audit placement, nested-governance declarations, vendored artifact hashes, line and KiB context budgets, and declared test roots.

Fresh installs omit existing-repo adoption playbooks; installs with `--adoption-mode existing` keep `governance/EXISTING_REPO_ADOPTION.md` and `governance/existing-repo-adoption.yml`. `bcf install --upgrade` refreshes pack-owned support files while preserving every existing repository-owned governance state file byte for byte. Newly introduced state artifacts may be created only when absent; `--reset-options` is the explicit opt-in for regenerating option surfaces.

Repo evidence: `scripts/install_governance_pack.py`, `scripts/validate_governance_yaml.py`, `template-repo/governance-profile.yml`.

## Cleanup And Compaction

Use `bcf cleanup` before rescaffolding or hand-editing a drifted repo. It is dry-run by default and reports safe actions separately from semantic/manual actions.

Safe cleanup actions are deterministic: create `audits/README.md`, move audit/review evidence from legacy roots into `audits/`, rewrite exact path references, and, when `--phase-retention-mode` is passed, remove or archive verified/closed historical phase artifacts outside the retained active window after updating compact `plans/phase-history.yml` entries with summaries, hashes, and the declared retention source. Phase-scoped hotfix logs and matching hotfix lane records leave active governance with their related phase. `--phase-retention-mode` without a value uses `git-history`; `--phase-retention-mode archive` uses ignored local archive storage; `--archive-closed-phases` remains an archive alias. Phase-history entries must point to retained artifacts or git-history refs. Semantic compaction remains manual or LLM-assisted: product specs, architecture docs, security docs, runbooks, and nested vendored governance need owner judgment before removal or rewriting.

Installed repos include `governance/repo-cleanup-contract.yml` for the machine cleanup contract and `governance/REPO_CLEANUP.md` for the human sequence. Documentation currency is a required semantic review item: compare each section to repo files, commands, tests, and canonical governance before closeout.

Repo evidence: `scripts/cleanup_governance_pack.py`, `scripts/validate_governance_yaml.py`, `template-repo/governance/artifact-manifest.yml`, `template-repo/governance/repo-cleanup-contract.yml`.

## Change Rules

- Default to the smallest valid vertical slice.
- Preserve public contracts unless explicitly authorized.
- Update canonical governed artifacts together when behavior, environment, release gates, or governance changes.
- Keep append-heavy entries terse, but include full intent, action/evidence, and consequence.
- Split governance scripts or package modules above 800 LOC only around stable concepts; characterize behavior before changing it.
- Run semantic governance validation when governed artifacts change.
- Run the exposure scan before release evidence is trusted; governed artifacts must not carry local workspace paths or private infrastructure markers unless explicitly allowed.
- Keep release gates fail-closed until repo-specific commands are wired.

Repo evidence: `template-repo/AGENTS.yml`, `template-repo/Makefile.fragment`, `scripts/doctor_governance_pack.py`.

## Lifecycle

Use phase status values from `plans/phase-ledger.yml`: `planned`, `active`, `blocked`, `paused`, `completed`, `verified`, `closed`, `abandoned`.

Phase logs use the closeout status values validated by schema and semantic checks: `planned`, `completed`, `verified`, `closed`. Verified or closed logs need closeout fields for tickets, suites, architecture gates, health checks, warnings, and constraints.

Repo evidence: `template-repo/schemas/phase-ledger.schema.json`, `template-repo/schemas/phase-log.schema.json`, `scripts/validate_governance_yaml.py`.

## Operating Rhythm

1. Install with `bcf install` or migrate pack-owned support files with `bcf install --upgrade`.
2. For existing drifted repos, run `bcf cleanup` and address manual actions before claiming compaction.
3. Open phases and hotfix logs with `bcf scaffold` or `scripts/scaffold_governance_artifacts.py`.
4. Execute scoped workitems only.
5. Record terse evidence in phase logs or audits.
6. Run `bcf validate` and `bcf exposure-scan`; run `bcf doctor` after release gates are wired.

Repo evidence: `bcf_governance/cli.py`, `scripts/cleanup_governance_pack.py`, `scripts/scaffold_governance_artifacts.py`, `scripts/doctor_governance_pack.py`.
