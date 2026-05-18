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

Canonical owner details live in `governance/ARTIFACT_OWNERSHIP.md`. The validator enforces schema shape, repo-relative `document.path`, active-phase alignment, phase/workitem/log consistency, release-gate wiring, hotfix alignment, and observability contract shape.

Fresh installs omit existing-repo adoption playbooks; installs with `--adoption-mode existing` keep `governance/EXISTING_REPO_ADOPTION.md` and `governance/existing-repo-adoption.yml`.

Repo evidence: `scripts/install_governance_pack.py`, `scripts/validate_governance_yaml.py`, `template-repo/governance-profile.yml`.

## Change Rules

- Default to the smallest valid vertical slice.
- Preserve public contracts unless explicitly authorized.
- Update canonical governed artifacts together when behavior, environment, release gates, or governance changes.
- Keep append-heavy entries terse, but include full intent, action/evidence, and consequence.
- Run semantic governance validation when governed artifacts change.
- Keep release gates fail-closed until repo-specific commands are wired.

Repo evidence: `template-repo/AGENTS.yml`, `template-repo/Makefile.fragment`, `scripts/doctor_governance_pack.py`.

## Lifecycle

Use phase status values from `plans/phase-ledger.yml`: `planned`, `active`, `blocked`, `paused`, `completed`, `verified`, `closed`, `abandoned`.

Phase logs use the closeout status values validated by schema and semantic checks: `planned`, `completed`, `verified`, `closed`. Verified or closed logs need closeout fields for tickets, suites, architecture gates, health checks, warnings, and constraints.

Repo evidence: `template-repo/schemas/phase-ledger.schema.json`, `template-repo/schemas/phase-log.schema.json`, `scripts/validate_governance_yaml.py`.

## Operating Rhythm

1. Install with `bcf install` or `scripts/install_governance_pack.py`.
2. Open phases and hotfix logs with `bcf scaffold` or `scripts/scaffold_governance_artifacts.py`.
3. Execute scoped workitems only.
4. Record terse evidence in phase logs.
5. Run `bcf validate`; run `bcf doctor` after release gates are wired.

Repo evidence: `bcf_governance/cli.py`, `scripts/scaffold_governance_artifacts.py`, `scripts/doctor_governance_pack.py`.
