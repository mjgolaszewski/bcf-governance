# Hotfix Lane

## Purpose

Use a hotfix lane when the normal phase process is too heavy for urgent repair but the repo still needs machine-readable evidence.

## Eligibility

Use the lane for:

- default branch red CI
- release-blocking regression
- security breakage
- expiring external dependency breakage

Do not use it to bypass normal planning for ordinary feature work.

## Required Artifacts

- hotfix record in `plans/phase-ledger.yml`
- hotfix execution log in `phases/`
- validation command evidence
- reconciliation note explaining whether canonical phase artifacts changed

## Modes

- `full`: default mode for default-branch red CI, release-blocking regressions, and security or expiring-external breakage.
- `lite`: allowed only for a single-commit repair with no public-contract change and no security-scope change.

Hotfix execution logs should be named from the last landed phase plus the hotfix number:

- `phases/phase-NN-hotfix##.yml`
- the phase portion comes from `hotfix.related_phase_id`

## Required Hotfix Record Fields

- `id`
- `mode`
- `status`
- `triggered_by_commits`
- `failing_workflows`
- `root_cause`
- `remediated_in_phase`
- `hotfix_log`
- `canonical_artifacts`

## Required Remediation History Fields

- `id`
- `mode`
- `recorded_at_utc`
- `action`
- `remediated_in_phase`
- `hotfix_log`
- `canonical_artifacts`
- `local_validation`

Optional when remote CI confirmation exists:

- `remote_validation_completed.commit`
- `remote_validation_completed.workflows`

## Closeout Rules

- Narrow scope is allowed.
- Machine-readable evidence is not optional.
- Lite mode still records machine-readable evidence; it only narrows when the hotfix lane is appropriate, not whether the lane is governed.
- Temporary paths must merge back into canonical phase artifacts before closeout if they alter behavior or environment contracts.
