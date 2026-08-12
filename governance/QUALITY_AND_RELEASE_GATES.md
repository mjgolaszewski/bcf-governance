# Quality And Release Gates

## Baseline Gates

The template declares these required standard-profile gates: governance validation, architecture test, module size, layer membership, bounded-context membership, import boundaries, CQRS side rules, router thinness, duplication/shared-abstraction checks, lint, typecheck, tests, contract tests, secret scan, dependency audit, SBOM, vulnerability scan, security review, and runtime smoke.

Repo evidence: `template-repo/governance-profile.yml`, `template-repo/Makefile.fragment`.

## Structural Gate Policy

- `bcf validate` checks artifact structure, cross-file consistency, required target declarations, and unresolved bootstrap placeholders.
- Make targets are aliases. Their names and command text never prove execution or promote lifecycle state.
- Required CI jobs invoke `bcf evidence run` (or the copied script), upload content-addressed per-gate bundles, and finish with `bcf truth`.
- Mandatory gates need a passing normal execution and a failing behavioral control in an isolated worktree. Dynamic or unresolved workflow paths fail closed.

Repo evidence: `scripts/validate_governance_yaml.py`, `scripts/doctor_governance_pack.py`, `template-repo/.github/workflows/governance.yml`.

## Evidence Integrity

Phase logs author `planned` or `completed` plus requirement declarations. They never author `verified`, `closed`, suite/health/security booleans, zero-findings, or release readiness.

`bcf truth` recomputes every receipt from exact-tree identity, tracked cleanliness, raw artifact hashes, process exit, test counts/node IDs, environment assertions, behavioral controls, finding accounting, and provenance. Valid direct evidence computes `verified`; current reconciliation and no profile-blocking findings compute `closed`. A relevant mutation returns the effective state to `completed` without an authored reopening edit.

Required test lanes default to one collected and executed test and zero skips. Critical/High remediation binds to an executed node and a control that makes it fail. A review that discovers and fixes nineteen findings reports total nineteen and open zero.

Semantic mutants run on pull requests, high-value implementation and semantic mutants nightly, and the full profiles weekly.

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
