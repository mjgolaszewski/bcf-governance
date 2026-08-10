# Quality And Release Gates

## Baseline Gates

The template declares these required standard-profile gates: governance validation, architecture test, module size, layer membership, bounded-context membership, import boundaries, CQRS side rules, router thinness, duplication/shared-abstraction checks, lint, typecheck, tests, contract tests, secret scan, dependency audit, SBOM, vulnerability scan, and runtime smoke.

Repo evidence: `template-repo/governance-profile.yml`, `template-repo/Makefile.fragment`.

## Gate Policy

- `required` gates must be invoked by `make release-check`.
- `optional` gates may be omitted, but if invoked must be real evidence commands.
- `deferred` and `not_applicable` gates must not be invoked by `make release-check`.
- Placeholder, echo-only, no-op, and version-probe commands are not release evidence.
- CI lanes should be self-seeding and aligned with required push jobs when a runner is available.

Repo evidence: `scripts/validate_governance_yaml.py`, `scripts/doctor_governance_pack.py`, `template-repo/.github/workflows/governance.yml`.

## Evidence Policy

Record terse evidence in `phases/phase-NN-log.yml`: command, result, warnings, constraints, and follow-up work. Keep full intent visible; do not turn phase logs into transcripts.

Repo evidence: `template-repo/AGENTS.yml`, `template-repo/phases/phase-NN-log.yml`, `template-repo/schemas/phase-log.schema.json`.

## CI Resource Ownership

Docker-based release gates must mark disposable resources with the exact label
`io.bcf-governance.ci-run=<run-id>`. Use run-scoped Compose projects and image
tags. `bcf ci-cleanup` is dry-run by default and may remove only exact-label
matches; global Docker and build-cache pruning are forbidden. Runner labels
remain repository-owned and are not embedded in installed templates.

Full-history publication review is deliberately separate from normal commit
CI. Before making a repository public, use `bcf publish-audit --history` from a
complete, non-shallow clone and remediate every redacted finding.
