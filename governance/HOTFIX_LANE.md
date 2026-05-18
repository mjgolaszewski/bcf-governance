# Hotfix Lane

## Purpose

Use the hotfix lane for urgent repair when the normal phase process is too heavy but machine-readable evidence is still required.

Repo evidence: `template-repo/AGENTS.yml` hotfix lane contract, `scripts/scaffold_governance_artifacts.py`.

## Eligibility

Eligible triggers: default-branch red CI, release-blocking regression, security breakage, or expiring external dependency breakage. Do not use the lane for ordinary feature work.

## Modes

`full` is required for default-branch red CI, release-blocking regressions, security breakage, and expiring external breakage. `lite` is allowed only for single-commit repair with no public-contract or security-scope change.

Repo evidence: `scripts/validate_governance_yaml.py`, `tests/fixtures/bad_hotfix_mode`.

## Required Artifacts

Record the hotfix in `plans/phase-ledger.yml`, create a log named `phases/phase-NN-hotfix##.yml`, capture validation evidence, and reconcile canonical artifacts before closeout when behavior or environment contracts changed.

Repo evidence: `template-repo/phases/phase-NN-hotfixNN.yml`, `template-repo/schemas/hotfix-log.schema.json`.
