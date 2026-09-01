# Using BCF Governance

This is the canonical operator guide for installing and running BCF. The root
[README](../README.md) is an overview, [Architecture](ARCHITECTURE.md) explains
the design positions, and [CI authority](CI_AUTHORITY.md) owns provider-backed
certification. A governed repository's own commands belong in its installed
`docs/OPERATIONS.md` and gate contract.

## Profiles

- `lite` defaults to profile contract v1 and bootstraps a repository with `governance-validate` and
  `governance-exposure-scan`. It is the only profile allowed before the full
  application gate surface is known.
- Fresh `standard` installations default to profile contract v2 and require complete executable contracts for architecture, lint,
  type, test, contract, security, SBOM, scan, review, and runtime gates.
- Fresh `regulated` installations also use v2 and add trusted verifier keys, independent Critical/High review,
  permitted risk authorities, model-risk policy, and hotfix governance.

Standard and regulated profiles cannot represent a partially wired target.
Their complete profile configuration is validated before BCF mutates the
repository.

## CI graph ownership

Fresh Standard-v2 installations create `governance/ci-graph.yml` and require
explicit candidate and trusted runner mappings. The graph is the operator
interface for orchestration. Generated `.github/workflows/*.yml` files are
deterministic projections and must not be edited directly.

Use these commands after changing the graph or a registered extension:

```bash
bcf ci graph lock --repo-root . --apply
bcf ci graph validate --repo-root .
bcf ci graph explain --repo-root . --format json
bcf ci graph diff --repo-root .
bcf ci graph render --repo-root . --check
bcf ci graph render --repo-root . --apply
```

`lock --apply` updates only digests for registered extensions and declared
value sources. `render --apply` changes only graph-generated workflow paths;
unrelated workflows remain byte-identical. `bcf ci adopt github --check|--apply`
uses the graph when present. The older label and producer arguments remain only
for profile-v1 adoption.

Before translating an established workflow set, capture a non-authoritative
exact inventory:

```bash
bcf ci graph import github \
  --repo-root . \
  --output governance/ci-workflow-inventory.yml \
  --write
```

The inventory retains normalized job definitions plus triggers, edges, runners,
permissions, matrices, artifacts, cleanup markers, concurrency, and authority
markers. Import does not authorize a migration or silently convert unsupported
behavior. Every existing job must map once to a core role or a registered
project extension before rendered workflows may replace existing bytes.

Standard's reference graph has one main-push authority; the ordinary governance
workflow remains directly callable for pull requests and exact-main reuse but
does not independently run on push. Scheduled controls remain scheduled
evidence and are not pull-request prerequisites. Hosted jobs are rejected when
their governed command contains polling, sleeping, leasing, or runner-wait
operations.

Contract version is distinct from profile strictness. An absent
`profile_contract_version` means `1.0`, so installing newer BCF tooling does not
silently promote an existing consumer. Contract v2 adds declared SOIP,
immutable evidence sessions, typed N/A records, and optional project-selected
CI-authority and runtime contracts. A configured v2 capability is validated
fail-closed; an absent optional capability is reported by `bcf doctor`.

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
  --candidate-runner-label ubuntu-24.04 \
  --candidate-runner-kind hosted \
  --trusted-runner-label self-hosted \
  --trusted-runner-label example-trusted-control \
  --trusted-runner-kind self-hosted \
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
bcf profile promote --repo-root . --to standard --contract-version 2.0 --check
bcf profile promote --repo-root . --to standard --contract-version 2.0 --apply
```

`--config standard-gates.yml` is optional when the canonical gate contracts
already describe the desired profile. Promotion changes profile-derived
policy and local Make aliases transactionally. It preserves installed workflow
bytes, never regenerates phase artifacts, and cannot move to a weaker profile
or contract version. Its validation shadow preserves local Git custody, so
compacted phase-history hashes remain verifiable during `--check` and `--apply`.
Adopt a GitHub topology separately and explicitly with
`bcf ci adopt github`, supplying the reviewed candidate labels, trusted labels,
producer argv, and either `--check` or `--apply`.

The 0.7.1 controller treats command-line workflow values only as compatibility
pins. It reconstructs numeric repository and workflow IDs, the active path,
trusted workflow bytes, event, run attempt, commit, and tree through the
provider API. A v1 CI-authority document may omit `admission_workflow`; an
activated Standard-v2 topology records it as the canonical admission owner.
Authority v1.1 replaces inline privileged workflow copies with one closed
workflow registry and role references. Its reusable producers are members of
one admission run and exact attempt; a same-SHA success from another run is not
eligible evidence. Existing v1.0 consumers remain readable, but new exact-main
and release commands require v1.1.
The finalizer authenticates its own workflow run before creating a session,
and publication requires that exact successful run and attempt to match the
immutable session and closed bundle inventory. Generated workflows supply the
required controller arguments; operators should not copy run IDs from check
names, display titles, or earlier attempts.

The controller-owned interfaces are `bcf ci-github exact-main
admit|finalize|publish` and `bcf ci-github release
resolve|resolve-publication|authorize|build|verify|collect|inspect|publish`. Before release
authorization, `resolve` selects current exact main, its highest admitted
attempt, the newest finalizer attempt, and both provider artifacts through
authenticated APIs. It emits one immutable input document and only the scalar
coordinates needed to download those exact artifacts. `authorize --inputs`
re-authenticates the document and downloaded bytes. Compatibility callers may
still supply the complete legacy field set, but BCF's own v1.1 workflow does
not. Workflow YAML supplies environment and paths; it does not select provider
state with `jq`, `max_by`, ad hoc API queries, or operator-copied IDs.
After collection, `resolve-publication` selects the newest authenticated
exact-main collector attempt, its exact provider artifact, the current commit
and tree, and the tag derived from BCF's version owner. The publisher accepts
that projection and a controller-owned release-asset directory; operators do
not supply run, attempt, artifact, digest, subject, tag, or asset-list custody.
BCF's own publisher additionally requires a short-lived `BCF_RELEASE_ADMIN_TOKEN`
secret because GitHub's workflow token cannot read repository immutable-release
settings. Provision it only on the trusted no-checkout path with Administration read,
Attestations read, and Contents write, then remove it after publication.

Workflow custody is compiled, not transcribed. After committing final workflow
bytes, derive the complete registry in one operation:

```bash
bcf ci pin-authority \
  --repo-root . \
  --definition-commit "$(git rev-parse HEAD)" \
  --apply
```

The command reads every registered workflow from that exact Git commit, derives
blob OIDs and SHA-256 digests, expands literal matrices, and compiles admission,
producer, and privileged provider job names plus the admission workflow's source-role
map. Partial registry pinning is rejected.
`bcf preflight` recomputes the same model before evidence allocation, so edited
workflow bytes or copied job labels cannot defer a deterministic failure to remote
CI. When an interpreter contract declares `requirements_projection`, the project,
optional, build-system, and gate-specific dependency union has one compiled bootstrap
view. Regenerate it after changing an owner and check it without mutation:

```bash
bcf environment apply --repo-root .
bcf environment check --repo-root .
```

Preflight requires exact projection bytes and then verifies the selected executable,
Python constraint, virtual-environment identity, and installed distribution versions.
Evidence, mutants, package tests, and release verification are downstream of this
boundary.

The same front door derives required interpreter distributions and version constraints
from the project's declared dependencies, configured optional groups, and explicit
gate-tool additions in `governance/gate-contracts.yml`. It also proves that the selected
executable retains its lexical identity and that a selected virtual environment has a
consistent prefix, `pyvenv.cfg`, and no system-site-package exposure. Missing or wrong
versions of `pytest`, `pip`, or application dependencies are infrastructure failures
before evidence capture; they cannot become successful controls or consume a remote
evidence lane.

For test-suite controls, evidence capture runs the full positive selection once, then
runs only each control's declared pytest oracle nodes in its detached mutant worktree.
The positive baseline must contain those nodes, and the isolated JUnit must show those
same nodes failing. Diagnostic controls continue to execute the canonical gate command.

BCF self-controller rotation has a separate mechanical path. Trusted control runs
`bcf ci-github controller-pin resolve` to select the newest exact-main package
producer and exact artifact without caller-supplied run IDs. After the provider
artifact is downloaded, `controller-pin compile` verifies its checksum inventory,
metadata, and wheel bytes and emits a pin record. A maintainer projects that record
with `bcf ci sync-self-controller --pin PIN.json --apply`. The target pin and the
last provider-proven installation are distinct: active control jobs stay on the
installed commit while that commit installs the new target. After exact-main
bootstrap and probe runs pass on every declared trusted runner,
`bcf ci-github controller-pin confirm --repository OWNER/REPO --output PROOF.json`
compiles their identities from provider state. Passing that proof through
`bcf ci sync-self-controller --pin PIN.json --confirmation PROOF.json --apply`
promotes the target and projects policy, topology, bootstrap, probe, finalizer,
admission, and status workflows together. A second target is rejected while one
rotation remains unconfirmed. AI and humans review policy and decide whether to
rotate; they do not author custody values or declare installation success.

The isolated authority canary uses `bcf ci-github canary admit|observe`. Its observer
authenticates one exact run attempt and complete job inventory, then publishes through
the separate `bcf/authority-canary` context. It never borrows a producer from another
same-SHA run. The owner dispatches the workflow on `main` with the closed `scenario`
choice: `success` makes both hosted producers pass, while `producer-b-failure` gives
producer B a deterministic nonzero exit. Rerunning the latter retains the scenario and
therefore proves that attempt 2 fails with higher authority than attempt 1. The observer
uses `always()` and starts only after both hosted producers terminate; it does not occupy
a trusted runner while candidate work is running.

Privileged release artifacts have one decoder. It authenticates the owning role and
workflow attempt first, then requires an exact numeric artifact ID, safe name, provider
SHA-256, repository identity, default branch, and current-main commit. Authorization
accepts only the newest exact-main certification artifact. The builder shares the
authorizer's release run and attempt; the verifier and collector independently recheck
the build artifact; publication accepts only the provider-authenticated collector
receipt whose asset digests match the bytes being published. Caller-supplied IDs and
digests are lookup keys, not authority.
The authorizer also hashes the downloaded controller wheel and requires it to match the
controller identity used by the release receipt.
For cross-workflow handoffs, YAML supplies the authenticated run, attempt, and exact
artifact name; the controller requires one matching provider artifact and records its
numeric ID and provider digest.

The release-byte inventory is closed: one wheel, one source archive, and one
`SHA256SUMS`. The verifier parses the checksum file and independently recomputes both
archive digests; hashing the checksum file alone is insufficient.
Authorization also reads the dependency lock and wheelhouse manifest through the
authenticated exact-main Git API and records each blob OID and SHA-256. The builder and
verifier reject local copies whose bytes differ. `release runtime` owns the disposable
offline environments without a provider token, installs the hash-closed dependency set
with `--no-index` and `--require-hashes`, tests the wheel and extracted sdist, runs strict
Twine validation, and binds every raw stdout, stderr, and JUnit file. A separate
`release verify-evidence` command authenticates provider state without executing package
code. `--release-artifact-dir` and `--runtime-evidence-dir` make the controller derive
both exact inventories; workflow shell does not maintain parallel file lists. The
compatibility `release verify` command remains available, but BCF's governed topology
requires the split operations. The trusted collector recomputes the bindings; a
candidate-authored pass label is not authority.

BCF 0.7 retains the additive `finalize-callback` and `publish-callback` controller
operations for event-driven fan-in. The finalizer always emits one immutable
callback envelope: a pending envelope contains no candidate artifact, while a
terminal envelope binds the closed bundle-manifest digest. The publisher
authenticates the exact triggering finalizer run and treats pending as a clean
no-op; only a verified terminal envelope reaches status publication. Existing
`finalize` and `publish` callers remain supported. Human-readable workflow and
job names are presentation only and never participate in authority decisions.

The self-adoption reference topology is generated as three short workflows:
exact-main admission, authenticated producer reconstruction, and verified
status publication. Each has a purpose-oriented job display name, a five-minute
ceiling, no checkout, and no polling or sleeping. Installation leaves every job
guarded by the repository variable `BCF_CI_AUTHORITY_ENABLED`; an absent or
non-`true` value skips the job before runner allocation. Activation is a later
transaction because numeric workflow IDs and trusted default-main workflow
bytes cannot be pinned before the structural workflows merge. Existing
producer workflows remain the code-execution owners and continue on fresh
hosted VMs; the trusted callbacks execute only the preinstalled exact-main
controller on the persistent control-plane runners.

All GitHub-owned actions emitted by BCF are resolved through one immutable pin
registry. Generated workflows therefore use exact commit identities rather
than moving major tags. Consumer-owned workflows are preserved until explicit
adoption, and action release updates remain reviewed governance changes.

Standard-v2 N/A records live under `governance/capability-na/`. Each record
names the exact capability, gate, or semantic family; repository scope;
rationale and supporting evidence; approving role; subject commit; review
time; and either an expiry or deterministic re-review trigger. The subject
commit must be an ancestor of the current committed tree. An active trigger or
expired record blocks readiness. Regulated requirements cannot be bypassed by
N/A, and CI authority cannot be marked N/A when CI evidence supports a release
claim.

## Upgrade and rescaffold

Normal upgrade refreshes pack-owned runtime and schemas, creates newly required
artifacts only when absent, and runs the idempotent evidence migration:

```bash
bcf install --target . --upgrade
```

Upgrade preserves the repository's selected profile, contract version, and
workflow bytes. A conflicting `--profile` or `--profile-contract-version`
fails with direction to use explicit promotion. Use `--reset-options` only
when intentionally rebuilding profile-derived non-workflow surfaces; it still
does not change the contract version. Migration may normalize legacy authored terminal state and booleans;
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

Before opening a pull request, reproduce its exact base and event context:

```bash
bcf ci local-pr --repo-root . --remote origin
```

The helper resolves and fetches the remote default branch, validates ancestry,
and mechanically runs the canonical preflight with its own selected interpreter
and the real base SHA. No extra command is required. Advanced callers may append
an exact argv after `--`; that explicit command receives the same authenticated
PR environment. This makes PR-only changelog and base-diff behavior fail locally
instead of first appearing in remote CI.

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

Truth defaults to closure evaluation: an incomplete phase or hotfix fails and
cannot produce a release receipt. Protected pull-request CI may use
`--evaluation-mode pr` to compute merge eligibility from exact-tree gates while
the phase train remains in progress. That mode preserves the lifecycle as
planned or completed rather than closed, and release-receipt output is
mechanically prohibited.

Positive and negative runs occur in separate pristine detached worktrees. BCF
rejects dirty callers, non-ignored untracked influence, unsafe tracked
symlinks, out-of-tree paths, tracked-file mutation, and undeclared outputs.
Receipts contain raw stdout/stderr and declared outputs with hashes; their
reported result is not trusted. Truth recomputes observations, test counts,
node IDs, environment assertions, artifact hashes, and behavioral oracles.

Evidence is exact-tree by default. A different commit, tree, or tracked working
tree makes it stale. Security-impacting changes always require a new security
review. Evidence and truth schema 2.0 is required; 0.5 bundles are invalid.

Profile-v2 `release-check` first runs the cheap preflight and allocates one
private immutable evidence session. All positive gates bind receipts to that
same manifest and execute once. Generated CI transports that manifest and
names lane and terminal artifacts with the exact provider run and attempt;
truth rejects mixed sessions, attempts, commits, trees, profiles, producers,
or inventories. Profile-v1 truth continues accepting schema-2 receipts without
a session manifest. Local automation that runs inside a provider process must
declare its local identity explicitly with `--local-producer-id`; the immutable
session then governs receipt producer binding instead of ambient provider
environment variables.

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

It can move audit evidence into `audits/`, rewrite exact references, and compact
completed phase artifacts into exact Git-history custody. A current closed truth
report adds its mechanically derived verification snapshot; without one, the
history row records authored completion only. Archive retention remains
fail-closed and requires the report plus its durable CI/release reference.
Product intent, architecture/security docs, runbooks, and semantic compaction
remain owner-reviewed work. Non-interactive apply requires `--yes`.

```bash
bcf cleanup --repo-root . --phase-retention-mode --apply
bcf cleanup --repo-root . --phase-retention-mode archive \
  --truth-report .artifacts/bcf/truth.json --apply # non-authoritative path; verify sha256 against retained CI
```

Use `--remove-governance-pack` only to decommission BCF. Dedicated BCF files and
CI can be removed; mixed workflows are reported for manual editing.

Evidence-session retention is a separate exact-root operation:

```bash
bcf ci-cleanup --repo-root . --prune-evidence-sessions
bcf ci-cleanup --repo-root . --prune-evidence-sessions --apply --yes
```

The dry run reads `session_retention_hours` from the artifact manifest and
considers only valid non-authoritative local sessions below the ignored `.artifacts/bcf/sessions`
root. Apply reloads each immutable manifest and revalidates its inode, device,
session ID, and digest immediately before deleting that exact session. It never
clears the general artifact root.

## Supporting commands

- `bcf validate`: schema and cross-file semantics.
- `bcf semantic-ownership`: source-first Python SOIP evaluation against the
  repository's canonical representation registry.
- `bcf ci local-pr`: exact local pull-request context and preflight.
- `bcf ci adopt github`: transactional GitHub reference-topology adoption.
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

Repositories with TypeScript can replace the registry's typed
`not_applicable_until_declared_by_consumer` value with a compiler contract that
declares the Node command, tsconfig, package lock, source roots, and browser
contract roots. BCF uses only tracked source and the already-installed
lock-matching `typescript` package. Missing tools, configuration diagnostics, or
version drift are infrastructure failures; the analyzer never downloads a
compiler or falls back to Docker.

CI-owned Docker resources use the exact
`io.bcf-governance.ci-run=<run-id>` label. BCF never infers ownership from names
or performs global Docker/build-cache pruning; it revalidates the exact ID and
label immediately before deletion and removes container anonymous volumes.
