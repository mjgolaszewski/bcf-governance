# AI Drift Review

## Purpose

When AI-assisted implementation is used, schedule recurring reviews for common drift patterns.

## Cadence

The source repo records reviews every other sprint. Adapt the cadence to the target repo, but make it explicit in `AGENTS.yml` or the build plan.

## Review Scope

Check for:

- fabricated precision in product claims
- generic UI copy that implies unavailable behavior
- hidden recommendation or advice framing
- inert controls or placeholder flows presented as live
- mock-heavy tests that bypass runtime behavior
- duplicated orchestration that weakens architecture boundaries
- undocumented environment assumptions
- generated artifacts that drift from source contracts

## Evidence

Record the review in the relevant phase log:

- reviewed surfaces
- findings
- remediations
- known residual risks
- validation commands
