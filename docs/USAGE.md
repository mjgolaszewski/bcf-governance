# Using BCF Governance

This is the canonical operator guide for installing and running BCF. The root
README is an overview; the governed repository's own operational commands
belong in its installed `docs/OPERATIONS.md` and gate contract.

## Profiles

- `lite` bootstraps a repository with `governance-validate` and
  `governance-exposure-scan`. It is the only profile allowed before the full
  application gate surface is known.
- `standard` requires complete executable contracts for architecture, lint,
  type, test, contract, security, SBOM, scan, review, and runtime gates.
- `regulated` adds trusted verifier keys, independent Critical/High review,
  permitted risk authorities, model-risk policy, and hotfix governance.

Standard and regulated profiles cannot represent a partially wired target.
Their complete profile configuration is validated before BCF mutates the
repository.

## Required root artifacts

`governance/artifact-manifest.yml` declares `README.md`, `LICENSE`, and
`CHANGELOG.md` as standard required artifacts. They must be regular UTF-8 files:

- README begins with a non-empty H1 project heading.
- LICENSE contains substantive license or copyright text.
- CHANGELOG begins with `# Changelog`, contains exactly one
  `## [Unreleased]`, and uses `## [X.Y.Z] - YYYY-MM-DD` release headings.

Every pull request changes `CHANGELOG.md`. Generated CI checks the diff from
the exact pull-request base SHA. It uses a full checkout and fails if the base
commit cannot be resolved, preventing a shallow clone from silently bypassing
the policy.

Installation treats these artifacts as application-owned. Missing files are
scaffolded; existing files are never placeholder-rewritten or overwritten. An
existing incompatible artifact makes validated installation fail and the
transaction leaves the repository byte-identical.

## Fresh installation

Initialize Git at the target root and install dependencies:

```bash
git init /path/to/repo
python3 -m pip install bcf-governance
```

Bootstrap lite:

```bash
bcf install \
  --target /path/to/repo \
  --profile lite \
  --project-id example \
  --project-name "Example" \
  --product-name "Example" \
  --require-strict-validation
```

Install standard or regulated only with a complete config:

```bash
bcf install \
  --target /path/to/repo \
  --profile standard \
  --profile-config /path/to/standard-gates.yml \
  --project-id example \
  --project-name "Example" \
  --require-strict-validation
```

Installation uses a checksummed path manifest and a shadow transaction. It
rejects absolute or parent-traversing destinations, duplicate destinations,
symlink destinations and parents, and conflicts with pack-owned paths.
Placeholders are applied only to manifested files being installed. Existing
`.gitignore` bytes are preserved and an idempotent marked BCF block is merged.
Validation failure or interrupted transfer rolls back touched files and modes.

## Existing repository adoption

Use conversion mode for an established application:

```bash
bcf install \
  --target /path/to/repo \
  --adoption-mode existing \
  --profile lite \
  --project-id example \
  --project-name "Example" \
  --require-strict-validation
```

The first phase inventories source roots, architecture, tests, workflows,
runtime, secrets, and release requirements. Keep that first change focused on
governance and gate wiring. Lite remains lite until every standard gate has a
real executable contract and behavioral control; unavailable gates are work
to complete, not standard-profile exceptions.

Preview and apply monotonic promotion:

```bash
bcf profile promote --repo-root . --to standard --config standard-gates.yml --check
bcf profile promote --repo-root . --to standard --config standard-gates.yml --apply
```

Promotion changes profile-derived policy, Make aliases, and the static CI
matrix transactionally. It never regenerates phase artifacts and cannot move
to a weaker profile.

## Upgrade and rescaffold

Normal upgrade refreshes pack-owned runtime and schemas, creates newly required
artifacts only when absent, and runs the idempotent evidence migration:

```bash
bcf install --target . --upgrade --profile lite
```

For standard or regulated, provide the complete profile config. Use
`--reset-options` only when intentionally regenerating profile-derived option
surfaces. Migration may normalize legacy authored terminal state and booleans;
the original values and hashes remain in a non-authoritative migration report.

`--force-rescaffold` is destructive and confirmation-gated. Use it only after
reviewing cleanup and history retention. BCF has no `--force` escape hatch.

## Gate contracts and CI

`governance/gate-contracts.yml` is canonical. Each required gate declares:

- argv only, a repo-relative cwd, non-secret environment, and required
  environment/secret names;
- evidence kind, thresholds, outputs, and environment assertions;
- one or more contained negative mutations and typed failure oracles.

Tracked scripts express complex commands. Make targets are developer aliases,
not evidence. Generated CI contains a static matrix with exactly the profile's
required gates, captures one bundle per gate, and passes those bundles to the
final truthfulness job. Dynamic or unresolvable mandatory execution fails
closed.

Required test lanes default to at least one collected and executed test and no
skips. Security-critical finding proofs bind to executable node IDs and
negative controls that make those nodes fail. A file path alone is not
regression evidence.

## Lifecycle and evidence

Phase logs author work completion and requirement declarations. They never
author terminal truth:

1. `completed` means implementation is reported ready for verification.
2. `verified` is computed from all current direct evidence, including balanced
   finding resolution.
3. `closed` is computed from verification, current reconciliation, and no
   profile-blocking finding on the same tree.

Capture and evaluate locally:

```bash
bcf evidence run --gate test --output .artifacts/bcf/test
bcf truth --evidence-dir .artifacts/bcf --format json
# Local outputs are non-authoritative; retain them by SHA-256 as CI artifacts.
```

Positive and negative runs occur in separate pristine detached worktrees. BCF
rejects dirty callers, non-ignored untracked influence, unsafe tracked
symlinks, out-of-tree paths, tracked-file mutation, and undeclared outputs.
Receipts contain raw stdout/stderr and declared outputs with hashes; their
reported result is not trusted. Truth recomputes observations, test counts,
node IDs, environment assertions, artifact hashes, and behavioral oracles.

Evidence is exact-tree by default. A different commit, tree, or tracked working
tree makes it stale. Security-impacting changes always require a new security
review. Evidence and truth schema 2.0 is required; 0.5 bundles are invalid.

## Findings and provenance

The canonical finding registry accounts for every discovered issue, including
issues fixed during the review that found them. Finding totals and disposition
counts are derived; nineteen found and remediated means total nineteen, open
zero—not zero findings.

Actors are typed as human, model, service, or workflow. Producer, reviewer,
remediator, and verifier roles remain visible. Standard warns on same-actor
verification. Regulated requires detached DSSE/Ed25519 attestation and an
independent verifier for Critical/High findings.

## Cleanup

Cleanup is a dry run unless `--apply` is supplied:

```bash
bcf cleanup --repo-root .
bcf cleanup --repo-root . --apply
```

It can move audit evidence into `audits/`, rewrite exact references, and retain
closed phase history only with a valid truth report bound to the governed tree
and a durable CI/release reference. Product intent, architecture/security docs,
runbooks, and semantic compaction remain owner-reviewed work. Non-interactive
apply requires `--yes`.

Use `--remove-governance-pack` only to decommission BCF. Dedicated BCF files and
CI can be removed; mixed workflows are reported for manual editing.

## Supporting commands

- `bcf validate`: schema and cross-file semantics.
- `bcf semantic-ownership`: source-first Python SOIP evaluation against the
  repository's canonical representation registry.
- `bcf truth`: evidence-derived lifecycle and release state.
- `bcf doctor`: configuration and wiring diagnostics.
- `bcf exposure-scan`: local-path and private-infrastructure scanning.
- `bcf scaffold`: phase and hotfix artifact generation.
- `bcf migrate-evidence`: preview/apply 0.5 state migration.
- `bcf ci-cleanup`: dry-run cleanup of exact-label CI resources only.
- `bcf publish-audit --history`: opt-in redacted scan of reachable Git history.

Standard-v2 repositories use `declared_families_blocking`: every declared
representation must name one discovered owner and causal construction path.
Regulated repositories may select `repository_wide_blocking`, which additionally
requires every discovered type in the authoritative Python roots to be
registered. The report is structural evidence about representation ownership;
it does not prove arbitrary business correctness.

CI-owned Docker resources use the exact
`io.bcf-governance.ci-run=<run-id>` label. BCF never infers ownership from names
or performs global Docker/build-cache pruning; it revalidates the exact ID and
label immediately before deletion and removes container anonymous volumes.
