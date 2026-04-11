# Model Risk And Provenance

## Applicability

Use this playbook for repos that produce forecasts, scoring, financial outputs, medical outputs, compliance outputs, AI outputs, or any high-impact decision support.

## Core Rules

- Published outputs should identify active rule or model versions.
- Inputs, assumptions, and policy packs should be explicit.
- Historical reruns should remain reproducible after assumptions change.
- Source freshness should be visible to operators.
- User-facing language should not overstate certainty.
- External truth-set certification should be recorded separately from implementation completeness.

## Recommended Artifacts

- versioned rule packs or policy packs
- source provenance fields
- effective-date selection
- reproducibility notes
- model-risk dashboard or audit artifact
- known constraints in release readiness

## Review Questions

- Can an operator explain why an output changed?
- Can a historical run identify the assumptions it used?
- Is stale source data visible?
- Does the UI avoid turning modeled tradeoffs into unqualified advice?
- Are owner-supplied or third-party certification dependencies explicit?
