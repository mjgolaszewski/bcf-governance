# Operations Runbook

## Purpose

This runbook describes how to validate and run `{{PROJECT_NAME}}`.

BCF uses deterministic programs—not an implementing agent's judgment—to
compute verification, closure, and release readiness. The project retains its
own architecture and CI topology; profile and gate contracts declare which BCF
capabilities apply.

## Release Validation

Run the configured release gate from the repo root:

```bash
python3 -m pip install -r requirements-governance.txt
make release-check
```

Lite runs only governance validation and exposure scanning. Standard and
regulated contracts must cover:

- governance YAML validation
- granular architecture gates for module size, layer membership, bounded-context membership, import boundaries, CQRS side rules, router thinness, and bounded-context duplication
- lint
- typecheck
- unit tests
- integration or contract tests
- frontend tests when applicable
- secret scanning, dependency audit, SBOM generation, and vulnerability scans
- Docker or runtime smoke checks

`Makefile.fragment`, gate applicability, evidence behavior, and closeout
requirements are generated from `governance/gate-contracts.yml`. CI
orchestration is generated from `governance/ci-graph.yml` and its explicitly
registered `governance/ci-extensions/*.yml` files. Do not hand-author
applicability or generated workflow YAML. Use `bcf profile promote` with either `--check` or
`--apply` and a complete profile contract to change profiles. Make targets remain developer aliases;
their command text is not verification.

An absent `profile_contract_version` means v1. Fresh Standard and Regulated
installs default to v2; Lite defaults to v1. Promote explicitly with
`bcf profile promote --repo-root . --to standard --contract-version 2.0`
and either `--check` or `--apply`. Promotion and normal upgrades preserve
workflow bytes. Promotion validation also preserves local Git custody so
retained phase-history hashes remain mechanically verifiable. Fresh Standard-v2
installs require explicit candidate and trusted runner mappings and render the
reference graph. Thereafter edit the graph contract and use
`bcf ci graph lock --apply`, `bcf ci graph validate`, and
`bcf ci graph render --check|--apply`. `bcf ci adopt github --check|--apply`
uses that graph while preserving unrelated workflows. Legacy label and producer
arguments apply only to profile-v1 adoption.

Required CI jobs invoke the evidence wrapper for their gate IDs, upload the
content-addressed bundles, and feed them to the final truthfulness job. The
wrapper rejects dirty or untracked influence, then runs the positive gate and
each configured negative behavioral control in separate pristine detached
worktrees. A control must satisfy its typed failure oracle; command-not-found,
timeout, signal, or an arbitrary crash is never proof. Dynamic or unresolved
mandatory workflow paths fail closed.

In profile v2, preflight allocates one private immutable evidence session for
the exact commit, tree, profile, producer, run, attempt, and gate inventory.
Every positive gate executes once and writes inside that session. Truth rejects
mixed sessions or attempts. CI artifact names include the exact provider run
and attempt, and the reference workflow never polls or occupies a runner while
waiting for another job. Nested local automation running inside a provider
process must pass `--local-producer-id`; this prevents ambient provider
variables from changing the immutable session and receipt identity.

`README.md`, `LICENSE`, and `CHANGELOG.md` are standard required root
artifacts. Preserve their application-specific content. Every pull request must
update `CHANGELOG.md`; governance CI verifies the exact base-to-HEAD diff and
requires a full Git checkout.

Automation PRs remain subject to the same rule. A repository may explicitly
adopt a trusted producer with `bcf ci automation adopt github --producer
dependabot --check|--apply` after provisioning the bounded contents-write App
and protected environment. Adoption derives exact allowed paths from the
Dependabot configuration and eligible Git-tracked dependency files. Files with
the exact BCF generated-workflow provenance header are excluded because action
pins must be changed in their canonical source and rendered mechanically. An
Actions update with no project-owned surface fails adoption. Fresh installs do
not activate write automation. The reconciler uses authenticated numeric identity
and dependency paths to write fixed text; it does not use PR prose and cannot
approve or merge.

Before opening a pull request, reproduce its exact remote context:

```bash
bcf ci local-pr --repo-root . --remote origin
```

The helper fetches the remote default branch, checks ancestry, and supplies the
actual base SHA and pull-request event context to preflight.

If the repo layout differs from the starter backend shape, update `architecture-boundaries.yml` before relying on `make architecture-test`.

For existing repositories, install with `--adoption-mode existing` to include conversion playbooks; keep the first adoption commit focused on governance artifacts, inventory, and gate wiring.

## Governance Helpers

```bash
python3 scripts/validate_governance_yaml.py
python3 scripts/governance_evidence.py run --gate test --output .artifacts/bcf/test # non-authoritative local bundle; retain by sha256 as a CI artifact
python3 scripts/governance_truth.py --evidence-dir .artifacts/bcf # non-authoritative local report; retain by sha256 as a CI artifact
python3 scripts/scaffold_governance_artifacts.py phase --help
python3 scripts/scaffold_governance_artifacts.py hotfix --help
```

Generate real hotfix logs with the scaffold helper rather than copying the template example file; the governed filename convention is `phases/phase-NN-hotfix##.yml`.
Governance validation should cover structural schema checks from `schemas/`, repo-relative `document.path` checks, configured release-gate checks, and semantic cross-artifact consistency checks.

Structural validation never promotes lifecycle state. Phase logs may author
`completed`; `verified`, `closed`, and release readiness are computed by the
truth engine from current-tree evidence and canonical finding accounting.
Receipt and truth schemas are `2.0`; 0.5 bundles fail as
`unsupported_schema_version` and must be recaptured.

Standalone tooling is exported under the private `scripts/_bcf_runtime/`
namespace; public scripts are thin wrappers. Keep runtime modules below 800 LOC
and split future growth by stable validation surface, not incidental helper
sharing.

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

Interactive apply asks for confirmation. In non-TTY automation, append `--yes`
only after the dry-run has been reviewed; otherwise cleanup refuses before any
mutation.

Do not use cleanup as a substitute for semantic review. Product specs, phase history, architecture docs, security docs, runbooks, and vendored governance require owner judgment before rewriting or removal. Phase-history entries must stay compact and point to retained artifacts or git-history refs with hashes.
Use `governance/repo-cleanup-contract.yml` for machine-readable cleanup rules and `governance/REPO_CLEANUP.md` for the human sequence.

To opt into strict historical phase retention, run one of the retention modes:

```bash
bcf cleanup --repo-root . --phase-retention-mode --apply
bcf cleanup --repo-root . --phase-retention-mode archive --truth-report .artifacts/bcf/truth.json --apply # non-authoritative path; verify sha256 against its CI artifact
```

Append `--yes` to either retention command in noninteractive automation.

The first command uses `git-history` retention and removes stale completed phase
artifacts after recording hashes and Git refs. Add a current `--truth-report`
only to preserve a mechanically derived closeout snapshot; without one, the
compact row records authored completion only. Archive mode requires a passing
closed report and moves stale artifacts into ignored
`governance/archive/phase-artifacts/` storage. Phase-scoped hotfix logs and
matching hotfix lane records leave active governance with their related phase.
With no phase-retention switch, cleanup keeps existing historical triplet and
hotfix behavior.

## Runtime Diagnostics

Document service health, release metadata, metrics, traces, logs, and operator-safe diagnostic endpoints here.

## CI Resource Ownership

When CI-backed evidence supports a release claim, workflow display names are
operator presentation only. Authority binds numeric repository and workflow
identity, active path and trusted bytes, event, run and attempt, and the exact
candidate commit and tree. Candidate code belongs on fresh disposable workers;
persistent trusted jobs do not check out or execute it. Use `bcf ci adopt
github` only as an explicit transaction after reviewing the generated topology
and supplying the required routing and producer arguments.

Give every CI run a unique identifier and label every Docker resource it owns
with `io.bcf-governance.ci-run=<run-id>`. Use a run-scoped Compose project such
as `bcf-ci-<run-id>`, run-scoped image tags, and the same label on containers,
networks, volumes, and images created outside Compose. Build labels should use
the same key and value where the builder supports OCI labels.

Preview cleanup first, then apply it explicitly in automation:

```bash
bcf ci-cleanup --run-id "$BCF_CI_RUN_ID"
bcf ci-cleanup --run-id "$BCF_CI_RUN_ID" --apply --yes
```

The helper selects only resources with that exact label, then re-inspects the
exact ID and label immediately before each deletion. Container deletion also
removes attached anonymous volumes. It never infers ownership from names,
accepts caller globs, or performs global Docker or build-cache pruning.
Do not hard-code runner labels into the governance pack; runner selection is a
repository-owned CI decision.

Prune expired local evidence sessions separately:

```bash
bcf ci-cleanup --repo-root . --prune-evidence-sessions
bcf ci-cleanup --repo-root . --prune-evidence-sessions --apply --yes
```

Retention comes from `governance/artifact-manifest.yml`. Cleanup considers only
valid non-authoritative local entries under `.artifacts/bcf/sessions` and revalidates exact manifest
identity and filesystem ownership before deletion.

## Secrets Policy

- Do not store live secrets in governance files.
- Use environment variables or the approved secrets manager.
- Keep `.env.example` files free of real credentials.

## Evidence Policy

Keep narrative execution notes in the active phase log. Store measurable
evidence bundles and truth reports outside the tracked tree, normally under
ignored `.artifacts/bcf/`, and retain them in CI artifact or release storage by sha256.
Receipt result fields are descriptive only: BCF recomputes results from process
outcomes, raw artifact hashes, test reports, declared expectations, and probes.
