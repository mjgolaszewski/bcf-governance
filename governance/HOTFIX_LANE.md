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

Hotfix execution logs should be named from the last landed phase plus the hotfix number:

- `phases/phase-NN-hotfix##.yml`
- the phase portion comes from `hotfix.related_phase_id`

## Required Hotfix Record Fields

- `id`
- `status`
- `triggered_by_commits`
- `failing_workflows`
- `root_cause`
- `remediated_in_phase`
- `hotfix_log`
- `canonical_artifacts`

## Required Remediation History Fields

- `id`
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
- Temporary paths must merge back into canonical phase artifacts before closeout if they alter behavior or environment contracts.
