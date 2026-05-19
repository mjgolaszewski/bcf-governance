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

Current release: `v0.3.3`.

## Why It Matters

AI agents drift when the repository lets them. They add evidence in arbitrary
folders, grow memory files into transcripts, close phases while work remains
open, invent new governance lanes, or run tests that are not declared anywhere.
BCF turns those failure modes into executable contracts:

- one canonical authority file for agent instructions
- one product spec and build plan for declared scope
- one active phase ledger and durable memory pointer set
- one artifact manifest for audits, vendored packs, context budgets, and
  nested-governance boundaries
- one release-gate profile that classifies required, optional, deferred, and
  not-applicable checks
- one validator that catches schema drift, path drift, phase drift, stale
  active pointers, unwired release gates, oversized context files, undeclared
  test roots, and misplaced audit evidence

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
  packs, context budgets, and nested-governance policy
- `architecture-boundaries.yml` for source roots, layers, bounded contexts, and
  AST architecture gates
- `plans/product-spec.yml`, `plans/build-plan.yml`, and
  `plans/phase-ledger.yml` for scope, sequencing, and active state
- `plans/phase-NN-plan.yml`, `plans/phase-NN-workitems.yml`, and
  `phases/phase-NN-log.yml` for scoped execution evidence
- `contracts/observability/v1/` for telemetry and logging contract baselines
- `audits/` as the canonical root for human-requested audits, sprint reports,
  code reviews, parity reviews, and test-audit evidence
- `Makefile.fragment` with fail-closed release-gate targets

## Local Setup

Install the CLI from this repo or a released package:

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

The CLI exposes five workflows:

- `bcf install` installs or updates the governance pack.
- `bcf validate` validates governed YAML, semantic alignment, release-gate
  wiring, artifact ownership, context budgets, vendored hashes, and test roots.
- `bcf scaffold` creates phase and hotfix artifacts with the expected names.
- `bcf doctor` reports placeholder, release-gate, inactive-gate, and
  non-evidence command gaps.
- `bcf cleanup` plans or applies conservative audit-root cleanup for drifted
  repos.

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

Deterministic cleanup can:

- create `audits/README.md`
- move `docs/audits/` files to `audits/`
- move `governance/parity-reviews/`, `governance/test-audits/`, and
  `governance/code-reviews/` into `audits/`
- rewrite exact path references in text files

Cleanup deliberately does not rewrite product specs, phase history,
architecture docs, security docs, runbooks, or vendored governance. Those are
reported as manual actions because they require semantic review and often
benefit from LLM support.

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
bcf validate --format json --compact
bcf doctor --repo-root /path/to/target-repo
```

`bcf validate` checks structural schemas before semantic alignment. It fails on
unresolved placeholders, non-portable `document.path` values, phase catalog
gaps, stale active-phase pointers, hotfix drift, release-gate placeholders,
audit files outside `audits/`, undeclared nested governance, stale vendored
artifact hashes, context-budget overruns, and invoked test roots missing from
`AGENTS.yml`.

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
