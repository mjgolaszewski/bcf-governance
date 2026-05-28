# Operations Runbook

## Purpose

This runbook describes how to validate and run `{{PROJECT_NAME}}`.

## Release Validation

Run the full release gate from the repo root:

```bash
python3 -m pip install -r requirements-governance.txt
make release-check
```

That command should cover:

- governance YAML validation
- granular architecture gates for module size, layer membership, bounded-context membership, import boundaries, CQRS side rules, router thinness, and bounded-context duplication
- lint
- typecheck
- unit tests
- integration or contract tests
- frontend tests when applicable
- secret scanning, dependency audit, SBOM generation, and vulnerability scans
- Docker or runtime smoke checks

`Makefile.fragment` starts with fail-closed placeholder targets. Replace required gates with repo-specific commands and keep `governance-profile.yml` aligned with any gate marked `required`, `optional`, `deferred`, or `not_applicable`. Optional gates may be omitted from `release-check`; if invoked, they must still be real evidence commands.

If the repo layout differs from the starter backend shape, update `architecture-boundaries.yml` before relying on `make architecture-test`.

For existing repositories, install with `--adoption-mode existing` to include conversion playbooks; keep the first adoption commit focused on governance artifacts, inventory, and gate wiring.

## Governance Helpers

```bash
python3 scripts/validate_governance_yaml.py
python3 scripts/scaffold_governance_artifacts.py phase --help
python3 scripts/scaffold_governance_artifacts.py hotfix --help
```

Generate real hotfix logs with the scaffold helper rather than copying the template example file; the governed filename convention is `phases/phase-NN-hotfix##.yml`.
Governance validation should cover structural schema checks from `schemas/`, repo-relative `document.path` checks, configured release-gate checks, and semantic cross-artifact consistency checks.

The installed validator is split into `scripts/governance_validation/` support
modules. Keep those files below 800 LOC and split future growth by stable
validation surface, not by incidental helper sharing.

## Cleanup Helpers

Use `bcf cleanup` from an installed BCF CLI when this repo accumulates audit or governance drift:

```bash
bcf cleanup --repo-root .
bcf cleanup --repo-root . --format json --compact
```

The command is dry-run by default. Safe apply mode moves legacy audit/review evidence into `audits/` and rewrites exact path references:

```bash
bcf cleanup --repo-root . --apply
```

Do not use cleanup as a substitute for semantic review. Product specs, phase history, architecture docs, security docs, runbooks, and vendored governance require owner judgment before rewriting or removal. Phase-history entries must stay compact and point to retained artifacts or git-history refs with hashes.
Use `governance/repo-cleanup-contract.yml` for machine-readable cleanup rules and `governance/REPO_CLEANUP.md` for the human sequence.

To opt into strict historical phase retention, run one of the retention modes:

```bash
bcf cleanup --repo-root . --phase-retention-mode --apply
bcf cleanup --repo-root . --phase-retention-mode archive --apply
```

The first command uses `git-history` retention and removes stale closed triplets
after recording hashes and git refs. The archive mode moves stale closed
triplets into ignored `governance/archive/phase-artifacts/` storage. With no
phase-retention switch, cleanup keeps existing historical triplet behavior.

## Runtime Diagnostics

Document service health, release metadata, metrics, traces, logs, and operator-safe diagnostic endpoints here.

## Secrets Policy

- Do not store live secrets in governance files.
- Use environment variables or the approved secrets manager.
- Keep `.env.example` files free of real credentials.

## Evidence Policy

Record validation evidence in the active `phases/phase-*.yml` log.
