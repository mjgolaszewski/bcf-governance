#!/usr/bin/env markdown
# -*- coding: utf-8 -*-

<p align="center">
  <img src="docs/assets/bcf-governance-pack-hero.jpg" alt="BCF AI Governance Pack" width="760">
</p>

# BCF Governance

**A reusable governance pack for agent-led software delivery where product
scope, delivery plans, active work, release gates, and audit evidence stay
machine-readable, validated, and small enough for agents to follow.**

BCF Governance gives a repository an executable operating model for AI-assisted
engineering. It installs canonical agent instructions, phase plans, active
ledgers, schemas, architecture boundary gates, release-gate profiles,
observability contracts, and helper commands that keep agents from treating
docs, plans, and tests as disconnected prose.

Current release: `v0.4.6`.

## Why It Matters

AI agents drift when the repository lets them. They add evidence in arbitrary
folders, grow memory files into transcripts, close phases while work remains
open, invent new governance lanes, or run tests that are not declared anywhere.
BCF turns those failure modes into executable contracts:

- one canonical authority file for agent instructions
- one product spec and build plan for declared scope
- one active phase ledger and durable memory pointer set
- one artifact manifest for audits, vendored packs, line and KiB context budgets,
  phase-artifact retention, and nested-governance boundaries
- one cleanup contract for deterministic moves, semantic review, documentation
  currency, and cleanup closeout evidence
- one release-gate profile that classifies required, optional, deferred, and
  not-applicable checks
- one validator that catches schema drift, path drift, phase drift, stale
  active pointers, unwired release gates, oversized context files, undeclared
  test roots, misplaced audit evidence, and retained phase-history drift

The result is not more ceremony for its own sake. It is a smaller, stricter
surface that agents can actually read and obey.

## Who Benefits

**Repository owners** get a repeatable way to bootstrap or repair governance
without relying on tribal memory. They can compare repositories against the
same artifact map, gate taxonomy, and cleanup expectations instead of
debugging a different governance style in every repo.

**Engineering teams** get a local CLI for installing the pack, scaffolding
phases and hotfixes, validating governed artifacts, diagnosing release-gate
wiring, and cleaning up drifted audit paths. They can make repo-specific gate
commands explicit while keeping the governance shape consistent.

**Reviewers and release owners** get a compact set of files that define what is
in scope, what phase is active, which checks are required, and where evidence
belongs. Release readiness becomes a set of inspectable files and commands, not
a reconstruction exercise from chat history.

**Security, compliance, and platform teams** get declared audit roots,
vendored-artifact provenance, secret-scan and vulnerability-scan gate slots,
and explicit ownership for runtime, observability, and evidence contracts.

**AI agents** get explicit instructions, machine-readable schemas, small-context
budgets, and fail-closed commands that make the expected behavior hard to miss.
The pack is intentionally biased toward small required files and deterministic
checks because agents follow executable rails better than long prose.

## What It Installs

The pack is intentionally split into installable templates, playbooks, and CLI
helpers:

- `template-repo/` contains files copied into governed repositories.
- `governance/` contains human playbooks for the operating model.
- `bcf` is the installable CLI.
- `scripts/` contains source-compatible helper scripts copied into template
  installs where appropriate.
- `template-repo/schemas/` contains JSON schemas for governed YAML artifacts.

The main installed artifacts are:

- `AGENTS.yml`, `AGENTS.md`, and `CLAUDE.md` for agent instruction routing
- `MEMORY.yml` for durable project memory, not transcripts
- `governance-profile.yml` for profile and release-gate classification
- `governance/artifact-manifest.yml` for artifact roots, `audits/`, vendored
  packs, line and KiB context budgets, phase-retention policy, and
  nested-governance policy
- `governance/repo-cleanup-contract.yml` and `governance/REPO_CLEANUP.md` for
  drift cleanup, documentation currency, and cleanup closeout rules
- `architecture-boundaries.yml` for source roots, layers, bounded contexts, and
  AST architecture gates
- `plans/product-spec.yml`, `plans/build-plan.yml`, and
  `plans/phase-ledger.yml` for scope, sequencing, and active state
- `plans/phase-history.yml` for compact machine-readable history of removed or
  archived closed phase and phase-scoped hotfix artifacts
- `plans/phase-NN-plan.yml`, `plans/phase-NN-workitems.yml`, and
  `phases/phase-NN-log.yml` for scoped execution evidence
- `contracts/observability/v1/` for telemetry and logging contract baselines
- `audits/` as the canonical root for human-requested audits, sprint reports,
  code reviews, parity reviews, and test-audit evidence
- `Makefile.fragment` with fail-closed release-gate targets

## Local Setup

Install the CLI from this repo or from the public release wheel without GitHub
authentication:

```bash
python3 -m pip install https://github.com/mjgolaszewski/bcf-governance/releases/download/v0.4.6/bcf_governance-0.4.6-py3-none-any.whl
```

For a source checkout:

```bash
python3 -m pip install .
bcf --version
```

For pack development in this repo:

```bash
python3 -m pip install -e ".[dev]"
pytest tests
```

Target repositories should install their copied governance requirements before
running local validation:

```bash
python3 -m pip install -r requirements-governance.txt
```

## Command Surface

The CLI exposes eight workflows:

- `bcf install` installs, upgrades, or updates the governance pack.
- `bcf validate` validates governed YAML, semantic alignment, release-gate
  wiring, artifact ownership, line and KiB context budgets, vendored hashes,
  and test roots.
- `bcf exposure-scan` checks governed artifacts for local paths and private
  infrastructure markers before CI or release evidence is trusted.
- `bcf scaffold` creates phase and hotfix artifacts with the expected names.
- `bcf doctor` reports placeholder, release-gate, inactive-gate, and
  non-evidence command gaps plus the running package version, source, and public
  installation path.
- `bcf cleanup` plans or applies conservative audit-root cleanup for drifted
  repos.
- `bcf ci-cleanup` plans or removes Docker resources bearing one exact BCF CI
  run-ownership label.
- `bcf publish-audit --history` performs an opt-in, redacted scan of every
  unique blob reachable from local Git refs before publication.

## Bootstrap A New Repo

For a standard new repo:

```bash
bcf install \
  --target /path/to/target-repo \
  --profile standard \
  --project-id your-project \
  --project-name "Your Project" \
  --product-name "Your Product" \
  --date "$(date -u +%F)"
```

The installer copies `template-repo/`, removes template-only phase examples,
replaces placeholders, applies the selected profile, opens the first phase, and
runs validation. It refuses to overwrite existing governance files unless
`--force` is passed.

For a minimal install that can pass strict validation before repo-specific
release gates are wired:

```bash
bcf install \
  --target /path/to/target-repo \
  --profile lite \
  --project-id your-project \
  --project-name "Your Project" \
  --require-strict-validation
```

## Upgrade A Governed Repo

Use upgrade mode when a repo already has BCF governance and should receive the
latest pack-owned scripts, validator support modules, schemas, cleanup docs,
and architecture gate test without resetting
product or phase state. Existing governance state files are preserved byte for
byte; upgrade never parses and re-emits them or merges template assumptions
into repository-owned policy:

```bash
bcf install --target /path/to/target-repo --upgrade
```

To also reset generated option surfaces such as `Makefile.fragment`,
`governance-profile.yml`, and `architecture-boundaries.yml`, add
`--reset-options` and pass the intended profile and gate commands:

```bash
bcf install \
  --target /path/to/target-repo \
  --upgrade \
  --reset-options \
  --profile standard
```

Use `--force-rescaffold` only when you intend to replace active BCF-owned
state, not for normal upgrades.

Upgrade preserves `AGENTS.yml`, `MEMORY.yml`, `governance-profile.yml`,
`governance/artifact-manifest.yml`, `Makefile.fragment`,
`requirements-governance.txt`, the governance CI workflow, product/build/phase
plans, active phase logs, and existing phase history entries byte for byte. It
creates `plans/phase-history.yml` only when missing and does not enable strict
historical triplet cleanup unless the repo opts in through
`bcf cleanup --phase-retention-mode`. `--reset-options` is the explicit opt-in
for regenerating option surfaces.

## Existing Repo Adoption

Use adoption mode when converting a non-empty repository:

```bash
bcf install \
  --target /path/to/existing-repo \
  --adoption-mode existing \
  --profile lite \
  --project-id your-project \
  --project-name "Your Project" \
  --require-strict-validation
```

Existing adoption keeps `governance/EXISTING_REPO_ADOPTION.md` and
`governance/existing-repo-adoption.yml` in the target repo. Start with `lite`
when the repo has not yet mapped architecture, CI, and release gates. Promote
to `standard` after mandatory gates are executable or explicitly classified.

## Release Gates

Standard and regulated profiles expect real release-gate commands. You can wire
them during install:

```bash
bcf install \
  --target /path/to/target-repo \
  --profile standard \
  --project-id your-project \
  --date "$(date -u +%F)" \
  --gate-command "architecture-test=python3 -m pytest backend/tests/architecture" \
  --gate-command "architecture-module-size=python3 -m pytest backend/tests/architecture -k production_modules_respect_loc_cap" \
  --gate-command "architecture-layer-membership=python3 -m pytest backend/tests/architecture -k production_modules_map_to_exactly_one_layer" \
  --gate-command "architecture-context-membership=python3 -m pytest backend/tests/architecture -k production_modules_map_to_exactly_one_bounded_context" \
  --gate-command "architecture-import-boundaries=python3 -m pytest backend/tests/architecture -k do_not_import" \
  --gate-command "architecture-cqrs-side=python3 -m pytest backend/tests/architecture -k cqrs" \
  --gate-command "architecture-router-thinness=python3 -m pytest backend/tests/architecture -k routers_remain_thin" \
  --gate-command "architecture-duplication=python3 -m pytest backend/tests/architecture -k 'duplication or shared_abstraction'" \
  --gate-command "lint=ruff check ." \
  --gate-command "typecheck=mypy ." \
  --gate-command "test=pytest backend/tests" \
  --gate-command "contract-test=pytest backend/tests/contracts" \
  --gate-command "security-secret-scan=gitleaks detect --source ." \
  --gate-command "security-dependency-audit=pip-audit" \
  --gate-command "security-sbom=syft dir:." \
  --gate-command "security-vulnerability-scan=trivy fs ." \
  --gate-command "runtime-smoke=docker compose config" \
  --require-strict-validation
```

After install, merge `Makefile.fragment` into the repo Makefile or include it
from the repo Makefile.

## Governance Cleanup

Use cleanup when an existing repo has accumulated governance drift. The command
is dry-run by default:

```bash
bcf cleanup --repo-root /path/to/target-repo
bcf cleanup --repo-root /path/to/target-repo --format json --compact
```

Safe apply mode asks for confirmation:

```bash
bcf cleanup --repo-root /path/to/target-repo --apply
```

For noninteractive automation, express approval explicitly:

```bash
bcf cleanup --repo-root /path/to/target-repo --apply --yes
```

To intentionally remove BCF governance from a repo, dry-run first:

```bash
bcf cleanup --repo-root /path/to/target-repo --remove-governance-pack
bcf cleanup --repo-root /path/to/target-repo --remove-governance-pack --apply
```

Add `--yes` only after reviewing the dry-run when this command executes without
a TTY.

Deterministic cleanup can:

- create `audits/README.md`
- move `docs/audits/` files to `audits/`
- move `governance/parity-reviews/`, `governance/test-audits/`, and
  `governance/code-reviews/` into `audits/`
- rewrite exact path references in text files
- with `--phase-retention-mode` and no value, use `git-history`: verify closed
  historical phase artifacts are present at `HEAD`, record compact
  `plans/phase-history.yml` entries with hashes and git refs, and remove old
  active triplet and phase-scoped hotfix files
- with `--phase-retention-mode archive`, move closed historical phase artifacts
  into ignored `governance/archive/phase-artifacts/` storage and record compact
  `plans/phase-history.yml` entries with artifact hashes
- prune phase-scoped hotfix lane records from `plans/phase-ledger.yml` when
  their related phase leaves active governance
- with `--archive-closed-phases`, use the backward-compatible alias for
  `--phase-retention-mode archive`
- with `--remove-governance-pack`, delete known pack-owned files, directories,
  dedicated governance workflow, and BCF architecture gate test files

Cleanup deliberately does not rewrite product specs, architecture docs,
security docs, runbooks, or vendored governance. Those are reported as manual
actions because they require semantic review and often benefit from LLM
support. With no phase-retention switch, cleanup preserves existing historical
triplet and hotfix behavior. After a repo opts into a retention mode,
validation enforces that historical phase triplets and phase-scoped hotfix logs
outside the retained active window are no longer active, while current phase
artifacts, already scaffolded future phase artifacts, and future artifacts in
the current train remain retained. Phase artifact cleanup is deterministic only
when the log status and
`governance/artifact-manifest.yml` retention policy make it unambiguous.
Phase-history entries must retain artifact hashes and a declared retention
source; empty history entries do not satisfy validation. CI should use a full
checkout for `git-history` mode so recorded refs can be verified.
Mixed CI workflows that contain BCF steps are reported for manual editing
instead of deleting unrelated jobs.

Cleanup applies changes in a temporary shadow worktree, validates the proposed
governance state, and transfers files atomically with rollback. In unattended
environments, `--apply` requires `--yes`; it fails before mutation instead of
attempting to read interactive input.

New installs also include `governance/repo-cleanup-contract.yml`. The contract
standardizes cleanup intent, canonical roots, drift patterns, deterministic
commands, LLM-required review, validation, evidence, and closeout rules. Use
`governance/REPO_CLEANUP.md` as the human summary. Keep documentation currency
terse but complete: update sections against repo evidence, remove stale claims,
and record validation outcomes.

## Rescaffolding

Use destructive rescaffold mode only when you intentionally want a fresh BCF
governance layer:

```bash
bcf install --target /path/to/target-repo --force-rescaffold --profile standard
```

The command warns for confirmation and removes known BCF governance-owned paths
before reinstalling the pack. It does not try to preserve or summarize old
phase history; run `bcf cleanup` and create any needed historical index first.

## Phase And Hotfix Work

Generate governed hotfix logs with the scaffold helper:

```bash
bcf scaffold hotfix \
  --project-id your-project \
  --hotfix-id HF-001 \
  --mode full \
  --hotfix-number 1 \
  --summary "release-blocking fix" \
  --related-phase-id P01 \
  --date "$(date -u +%F)" \
  --validation-command "make governance-validate" \
  --validation-command "make release-check"
```

Use scaffold helpers for real `plans/phase-*.yml` and `phases/phase-*.yml`
artifacts. The `phase-NN` files in the pack are templates, not long-term
working files.

## Validation

Install governance dependencies and validate before the first governed commit:

```bash
python3 -m pip install -r requirements-governance.txt
bcf validate
bcf exposure-scan
bcf validate --format json --compact
bcf doctor --repo-root /path/to/target-repo
```

`bcf validate` checks structural schemas before semantic alignment. It fails on
unresolved placeholders, non-portable `document.path` values, phase catalog
gaps, stale active-phase pointers, hotfix drift, release-gate placeholders,
audit files outside `audits/`, undeclared nested governance, stale vendored
artifact hashes, opted-in phase and hotfix retention drift, context-budget
overruns, and invoked test roots missing from `AGENTS.yml`. Context budgets
accept legacy integer line caps, but new pack output uses explicit
`line_hard_cap` and `kib_hard_cap` values for each agent-required file. The
validator treats both dimensions as hard per-file gates and reports aggregate
agent-required context size as an advisory in JSON output when it exceeds the
manifest recommendation.

`bcf exposure-scan` is a separate CI-friendly gate for governed text artifacts.
It flags common local workspace paths and private infrastructure markers, with
inline allow markers reserved for intentional examples.

Before publishing a repository, opt into a complete-history audit from a
non-shallow clone:

```bash
bcf publish-audit --repo-root . --history
```

The audit deduplicates reachable blobs, includes deleted historical files, and
reports only rule IDs, object/provenance identifiers, and remediation guidance.
It never prints matched secret values. Reserved `.invalid` and `.test` examples
are accepted. This command is intentionally not added to generated per-commit
CI.

Docker CI cleanup follows exact ownership labels and is dry-run by default:

```bash
bcf ci-cleanup --run-id "$BCF_CI_RUN_ID"
bcf ci-cleanup --run-id "$BCF_CI_RUN_ID" --apply --yes
```

Label owned resources with `io.bcf-governance.ci-run=<run-id>` and use
run-scoped Compose projects and image tags. The helper never performs global
Docker or build-cache pruning.

## Agent Deconstruction

BCF governance scripts and installed validator modules must stay below 800 LOC.
When a file approaches that cap, split around stable concepts only, add or keep
characterization coverage before behavior changes, and avoid vague shared
helpers for security-sensitive semantics. Current split points are installer
argument/reporting/upgrade migration, cleanup models/phase retention, and
validator common/release-gate/phase/artifact/catalog/runner surfaces.

## Profiles

Choose the smallest profile that proves the current risk:

- `lite`: core governance files, product/build/ledger state, scaffolding, and
  validation.
- `standard`: lite plus phase plans, workitems, logs, architecture gates, and
  configured release gates.
- `regulated`: standard plus provenance, hotfix formalism, security/SBOM
  evidence, and full release-gate closeout.

Gate statuses in `governance-profile.yml` mean:

- `required`: `release-check` must invoke the gate and the target must satisfy
  its declared command policy.
- `optional`: `release-check` may omit the gate, but if invoked the target must
  satisfy its declared command policy.
- `deferred`: known future gate; do not invoke it from `release-check` yet.
- `not_applicable`: intentionally absent; do not invoke it from
  `release-check`.

## Repository Boundaries

This repo owns the governance pack and its tests. Target repositories own their
product scope, architecture mapping, release commands, docs, runbooks, and
audit evidence. BCF can scaffold and validate structure, but it cannot know
whether a product decision, security claim, or runbook statement is true
without repo evidence.

Semantic consolidation remains a human or LLM-assisted task. Deterministic
helpers should move files, detect drift, enforce schemas, and report gaps; they
should not invent product intent.

## Maintainer Checks

For pack maintenance in this repo:

```bash
pytest tests
python3 .github/scripts/run_validator_mutants.py --profile high-value
python3 .github/scripts/run_validator_mutants.py --profile full
```

To sanity-check the uninstantiated template pack:

```bash
bcf validate --repo-root template-repo --allow-placeholders --allow-release-gate-placeholders
```

## Release Process

Release changes are merged through a reviewed pull request. After every version
surface agrees and CI passes, push an immutable `vX.Y.Z` tag at the merge
commit. The tag workflow verifies the package version, runs the full test and
template-validation suite, builds and checks the wheel and sdist, emits
`SHA256SUMS`, creates GitHub build-provenance attestations, and publishes all
three files on the GitHub Release. Release actions are pinned to commit SHAs and
receive only contents, identity-token, and attestation write permissions.

PyPI is not used. Consumers can install the public wheel URL shown in Local
Setup without repository authentication.
