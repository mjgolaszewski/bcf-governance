# Changelog

All notable changes to BCF Governance are recorded here. This file follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and the project uses
[Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

Release target: `0.8.0`.

### Added

- Added the schema-versioned `governance/ci-graph.yml` contract, digest-locked
  bounded project extensions, and deterministic graph validation, explanation,
  import, lock, diff, render, and GitHub adoption commands.
- Added a Standard-v2 reference graph with explicit candidate and trusted runner
  mappings, cheap preflight, grouped evidence lanes, exact fan-in, terminal truth,
  a single exact-main push entry, scheduled controls, and extension points for
  specialized and release behavior. Lite retains a reduced graph.
- Added a clean consumer fixture proving Standard-v2 installation, project
  extension composition, deterministic regeneration, rollback, and preservation
  of unrelated workflows.
- Added schema-backed custody for regression tests removed after a stronger
  canonical mechanical owner superseded their duplicate generated-YAML decoding.
- Added an exact read-only Chrysalis Identity preservation and performance audit
  covering 10 workflows, 46 job definitions, and five comparable green runs.
- Opened the 0.8.0 consumer-CI train to make one governed graph plus explicitly
  registered bounded extensions the mechanical source for generated GitHub workflows.
- Defined Identity workflow preservation and performance gates before any migration:
  existing jobs, stable checks, specialized lanes, schedules, runner topology, cleanup,
  authority, and evidence behavior may not be removed or silently normalized.

### Changed

- BCF now dogfoods the consumer graph compiler: all 14 repository workflows and
  24 logical jobs are rendered from the same root graph and registered extensions
  shipped to consumers, while exact workflow pins remain a separate Git authority.
- Agents and maintainers edit graph contracts rather than generated GitHub YAML.
  Graph compilation now checks exact profile-required PR gate ownership, graph
  cycles, fan-in, resource and trust mappings, semantic owners, action pins,
  extension applicability, hosted-wait prohibitions, and every job or component
  condition's `needs.*` references against its declared dependency edges before
  workflow rendering.
- Negative-control execution now mechanically refreshes registered graph input
  locks and generated projections inside each isolated mutant worktree, ensuring
  the oracle observes the intended semantic defect instead of incidental digest
  or parity drift.
- Preserved Chrysalis Identity unchanged because graph ownership alone predicted
  no runner-time savings against its already optimized CI graph and therefore did
  not meet the required 15 percent improvement gate. No Identity canary or remote
  Actions run was started.
- Permit Identity public-PR candidate work to return to fresh hosted runners while
  prohibiting polling, sleeping, local-capacity waiting, runner leasing, or hosted
  control-plane waiters.

### Fixed

- Completed trusted-controller rotation through mechanically ordered current-main
  bootstrap and independent probe runs on both trusted runners. Provider-compiled
  confirmation now promotes the exact installed controller, re-enables release roles,
  and regenerates every workflow and authority pin without operator-entered run,
  artifact, commit, tree, or workflow identities.
- Made setup-python the mechanical interpreter authority for every governed CI
  command. Rendered jobs now pass its absolute executable rather than a relative
  PATH token, and graph compilation rejects commands that consume the selected
  interpreter before the setup action runs.
- Closed trusted no-checkout job inputs: graph compilation rejects repository-relative
  scripts and policy files, and controller probing now reuses the provider-authenticated
  offline installer verification instead of relying on an undeclared workspace checkout.
- Made BCF release roles fail closed while a newly selected trusted controller is
  awaiting independent installation confirmation. The graph now distinguishes
  target from proven-installed controller custody, disables release authorization,
  collection, and publication during that interval, and leaves only the bounded
  bootstrap/probe rotation path active; a release cannot discover controller-CLI
  incompatibility after candidate build allocation.
- Made private evidence transport self-repairing and mechanically ordered. The
  graph now marks the single mode-restoration effect, requires it immediately
  after an exact session download and before gate execution, binds its root to
  the actual download destination, and requires its condition to match the
  transport step. Missing, skipped, delayed, or misdirected restoration fails
  compilation before artifact-service permission normalization can invalidate a run.
- Made fresh-install evidence workflow paths and required events a mechanical
  projection of the installed graph. Standard and Regulated route `main` only
  through exact-main authority, while Lite retains its direct `push` entry.
- Scoped workflow truth to the declared graph roots and taught it to resolve
  both grouped and mechanically sharded gate inventories; an unrelated workflow
  event can no longer satisfy a root workflow requirement.
- Kept trusted-controller rotation executable through the independently proven
  installed controller until the target controller is mechanically confirmed;
  changing the target pin no longer makes bootstrap depend on uninstalled bytes.
- Made validator negative-control target checks report the complete stale or
  ambiguous mutation set in one failure, avoiding serial check/fail/fix discovery.
- Removed secondary self-workflow tests that re-decoded generated workflow fields;
  retained unique trust, authority, release, and integration regressions under
  canonical graph, policy, and controller owners.
- Made the trusted publisher require `BCF_RELEASE_ADMIN_TOKEN` before resolution or
  attestation and use it only for final publication. GitHub's workflow token cannot read
  repository immutable-release settings; the short-lived credential contract requires
  repository Administration read, Attestations read, and Contents write and requires
  removal after publication.
- Corrected the post-release custody snapshots to defer current provider authority to the
  mechanical release inspector, removed unstable attestation cardinalities, and reconciled
  the completed 0.7.1 train and P13 next-work state.

## [0.7.1] - 2026-09-01

Published as an immutable GitHub release from exact certified merge
`5e8e41aeda9b6efa8e5e063f4c301ee78aef101b`.

### Security

- Added CI authority contract v1.1. Exact-main and release claims now bind one
  authenticated admission, its exact run attempt, workflow identity and bytes,
  candidate commit and tree, and the complete same-run producer inventory. A newer
  admitted failure, cancellation, or attempt revokes an older success.
- Removed operator-authored provider authority from exact-main, controller rotation,
  release authorization, verification, collection, and publication. Controller
  commands derive and validate run IDs, attempts, artifact IDs, provider digests,
  workflow pins, commit/tree identities, and closed file inventories before emitting
  typed job outputs. Workflow YAML wires those outputs and does not independently
  select provider state.
- Split release construction into a trusted no-checkout authorization step, a fresh
  hosted build, a separate fresh token-free runtime verifier, a non-executing provider
  authenticator, a trusted no-checkout collector, and a trusted exact-byte publisher.
  Candidate jobs cannot create an authoritative release receipt or publish a release.
- Closed release dependencies to a hash-admitted CPython 3.12/Linux x86-64 wheelhouse.
  Build and verification use the admitted files offline and reject missing, additional,
  changed, unsafe, or unhashed inputs.
- Added a mechanically checked self-workflow contract for BCF's own CI. It validates
  job inventories, trust classes, runner routes, activation guards, pinned actions,
  selected interpreters, descriptive names, controller identity, publisher inputs, and
  the absence of checkout, candidate scripts, hosted fallback, polling, or idle waits on
  trusted jobs.
- Activated the release publisher as an owner-and-main-only trusted workflow. It resolves
  the newest authenticated collector receipt, attests and publishes only its closed
  assets, performs no checkout or build, and receives no operator-entered release
  coordinates. The workflow token's unavailable repository-administration scope failed
  before provider mutation; the exact controller completed the authorized publication
  with the owner credential and the same authenticated invocation, receipt, and assets.

### Fixed

- Made cheap preflight the release front door for selected-interpreter and virtual-
  environment integrity, declared dependency versions, Python source entrypoints,
  package runtime assets, generated-pack parity, exposure scanning, exact test
  manifests, workflow authority, action pins, artifact namespaces, source locks, and
  syntax. These defects now fail before evidence, package, mutation, or release work.
- Made detached evidence and negative-control sessions preserve the selected interpreter
  and its executable directory while rejecting ambient editable installs and undeclared
  dependencies as authority.
- Made release artifact selection and file inventories controller-owned and exact,
  including current-attempt fan-in, controller wheels, wheelhouse inputs, runtime
  evidence, release assets, checksums, and collector receipts.
- Made scheduled mutation, local pull-request, and exact-main entrypoints run the same
  canonical preflight with mechanically derived base, subject, and event context.
- Added causal controls for workflow activation, publisher resolution, provider
  coordinates, attestation inventory, runner isolation, current-attempt selection,
  dependency closure, and release-byte verification. A control passes only for its
  declared failure cause after a green positive baseline.
- Reconciled `v0.7.0` as published and attested but provider-mutable historical custody.
  Its tag, release, assets, and attestations remain unchanged, and no authority-v1.1
  certification is claimed retroactively.

### Changed

- Preserved the 21-gate Standard-v2 public profile while requiring authority v1.1 only
  for new exact-main and release claims. Existing authority-v1.0 consumers and receipt
  schema 2.0 remain compatible.
- Consolidated self-workflow invariants under one production preflight owner and removed
  older tests that independently decoded the same YAML fields. Focused causal mutations
  remain for each security boundary; distinct public-contract and integration tests remain.
- Kept candidate code on fresh GitHub-hosted runners and short trusted no-checkout
  control work on uniquely labeled local runners. No job polls, sleeps, leases an idle
  runner, or silently falls back between trust classes.
- Retained current P13 records until a real successor phase opens. The 0.7.1 train is
  completed, and earlier phase triplets remain compacted to hash-bound Git history under
  the declared retention policy.
- Reorganized maintainer guidance around mechanical authority, exact evidence, runner
  trust boundaries, release custody, and explicit human judgment. AI and human operators
  may propose changes but cannot supply or self-certify mechanically derivable claims.
- Published release `380654208` with annotated unsigned tag object `dc55bc9b8e1d28359e937421f47c54b38462bca8`,
  three digest-bound assets, provider attestations, and `immutable=true`; `v0.7.0` remains
  unchanged and provider-mutable historical custody.

## [0.7.0] - 2026-08-31

### Added

- Opened exact-main release artifact construction with mechanically separated
  trusted authorization, disposable candidate build, and disabled publication.
- Added a disabled-by-default, event-driven exact-main admission, trusted
  finalizer, and status-publisher topology generated from the public adopter;
  its callbacks allocate no runner until explicitly activated after exact
  workflow identity is pinned.
- Added one canonical immutable-pin registry for GitHub-owned actions and
  causal controls for both action drift and premature CI-authority activation.
- Added immutable trusted callback envelopes and additive controller commands
  for acyclic event-driven fan-in without polling, waiting, or candidate
  artifact ingestion by the trusted finalizer.
- Added an owner-dispatched, no-checkout trusted bootstrap that authenticates
  and installs the exact-main controller wheelhouse offline on both uniquely
  addressed control runners.
- Added the trusted GitHub controller commands and an exact-main controller
  wheel artifact for hash-pinned control-plane provisioning.
- Added an owner-dispatched, no-checkout trusted-control probe so CI-authority
  activation verifies the installed control plane before enabling callbacks.
- Opened the BCF 0.7.0 release train for generalized SOIP, exact-commit CI
  authority, disposable candidate execution, Standard-v2 self-adoption, and
  certified immutable release artifacts.
- Added private, immutable evidence-session allocation and optional schema-2
  receipt binding, with exact commit, tree, profile, producer, run, attempt, and
  closed gate inventory material.
- Added independent profile-v2 truth recomputation for session manifests,
  inventory, producer, run, attempt, and per-receipt artifact bindings.
- Added a canonical cheap `bcf preflight` and contract-owned exact pytest
  manifests, replacing the self-gate runner's secondary test-node map.
- Hardened Docker cleanup with immediate exact-ID/owner revalidation, safe
  identity parsing, and anonymous-volume removal without global pruning.
- Bound governance artifact fan-in to the exact Actions run attempt, separated
  lane and terminal namespaces, and ordered evidence after canonical preflight.
- Proved canonical preflight remains valid after every retention-removable phase
  and hotfix artifact moves into exact Git commit and hash custody.
- Added a generalized, MIT-licensed Python semantic-ownership engine with
  source-first tracked inventory, one canonical registry, typed causal controls,
  declared-family enforcement, and repository-wide completeness mode.
- Added an optional, consumer-owned TypeScript Compiler API adapter and
  Python/TypeScript endpoint tracing that require the declared Node executable,
  tsconfig, package lock, and already-installed exact compiler version without
  network or Docker fallback.
- Added a compact exact-consumer reference proof and reproducible benchmark
  harness; the current Identity main proves 62 representations and 220 required
  browser traces with no unresolved or uncovered flow.
- Added provider-neutral CI authority, normalized certification, and typed N/A
  schemas plus a pure total-order state machine that authenticates workflow
  identity before admission precedence and binds exact producer, job, matrix,
  attempt, commit, and tree identity.
- Added authenticated provider snapshots, independent certification
  recomputation in truth, exact-attempt cancellation and status precedence,
  and output-only release receipts that bind already-certified artifact bytes
  without participating in the truth computation that creates them.
- Added a provider-authenticated GitHub run adapter and a transactional
  `bcf ci adopt github` reference topology with disjoint disposable candidate
  and no-checkout trusted roles, closed callback events, and no idle waiters.
- Added exact local pull-request context, fail-fast repository runtime/capacity
  contracts, repository-owned database bind roots, and digest-bound trusted
  external-input handoff.
- Added backward-compatible profile-contract v2 lifecycle integration, typed
  expiring capability N/A records, profile readiness diagnostics, and
  retention-bound evidence-session pruning with immediate identity checks.
- Added generated Standard-v2 release surfaces that allocate one immutable
  evidence session, execute each positive gate once, and bind fan-in to the
  exact Actions run and attempt without polling or waiter jobs.

### Changed

- Refreshed README-led documentation around BCF's measured architecture,
  explicit authority boundaries, adoption costs, and limitations, with
  separate canonical architecture, CI-authority, operator, maintainer, and
  installed-runbook owners.
- Published the exact annotated `v0.7.0` subject from the selected release
  run without rebuilding its attested bytes. GitHub reports the release as
  mutable; 0.7.1 records and remediates that provider-state limitation.
- Bound the least-privilege GitHub token explicitly to each trusted controller
  command step after live activation proved that workflow permissions alone do
  not populate the controller's required `GITHUB_TOKEN` environment.
- Prevented pull-request producer completions and failed finalizers from
  allocating trusted callback runners, enabling bounded exact-main authority
  activation without persistent-VM PR fanout.
- Staged the exact-main controller containing immutable workflow-definition
  custody and its provider-authenticated self CI authority without enabling
  automated callbacks.
- Bound trusted workflow authentication to an immutable definition commit,
  blob, and digest that must still match the active default-main bytes; advanced
  the disabled control plane to the latest exact-main controller artifact.
- Gave every repository job a concise purpose-oriented display name while
  retaining stable machine job IDs; presentation remains outside authority.
- Upgraded checkout, Python setup, and artifact transport to immutable current
  Node 24 action releases across live, generated, template, and packaged
  workflows.
- Moved the exact trusted-controller artifact pin into canonical runner policy,
  with owner-only bootstrap and probe workflows checked as exact mirrors and
  named by their human-visible purpose.
- Replaced opaque numeric evidence-job display names with concise descriptions
  whose workflow mirror is checked against the canonical shard contract.
- Split P10 structural self-adoption from its post-merge authority activation,
  because numeric workflow identity and trusted default-main bytes exist only
  after the structural workflow is merged; P10-HF01 owns that activation.
- Sequenced local 0.7 implementation independently from remote runner
  activation: each behavior commit now dogfoods its applicable governance, while
  P10 owns disposable-candidate and isolated-publisher proof before any remote
  candidate execution or release publication is enabled.
- Made BCF consume the same semantic-ownership schema, runtime, registry, CLI,
  gate contract, and evidence control that it packages for adopters.
- Made fresh Standard and Regulated installations select profile contract v2;
  Lite and existing repositories remain on v1 until explicit promotion.
- Separated workflow adoption from profile lifecycle: normal upgrades and
  promotions preserve installed workflow bytes, while fresh installs generate
  the selected profile's workflow surface.
- Promoted BCF itself to Standard profile contract v2 through the public
  promoter while retaining its 21 required gates, ten semantic-owner controls,
  and existing four-shard hosted execution topology.
- Bound BCF's four evidence shards and terminal truth to one immutable session
  and exact Actions run attempt without adding jobs, polling, or waiter capacity.
- Kept profile-generated evidence policy within its existing context budget by
  using deterministic 160-column YAML rendering as the control inventory grows.

### Fixed

- Bound every P12 causal control to a killer node in the contract gate's exact
  positive manifest and distinguished current-authority failure from release-run
  failure so a similar condition cannot mask the intended mutant.
- Kept generated Standard-v2 gate contracts and evidence policy within their
  existing context budgets by rendering negative-control mappings compactly
  without changing decoded semantics or weakening their causal tests.
- Made cheap governance validation reject completed workitems or closeout claims that cite
  non-required gates which cannot emit receipts, before evidence fanout begins.
- Required a completed authored phase before terminal CI can compute a closed release result;
  the P11 PR proved that a planned phase cannot pass by green producer evidence alone.
- Made source-distribution verification package exact test manifests and create
  clean tracked-file custody before exercising the complete extracted suite.
- Made pending producer completion a mechanically authenticated no-op and bound
  terminal publication to the exact triggering collector and callback bundle
  digest before any status write.
- Made cheap preflight execute applicable source-first semantic-ownership
  enforcement before evidence-session allocation, preventing a deterministic
  ownership defect from launching expensive evidence fanout.
- Reconstructed trusted workflow identity from authenticated GitHub API state,
  selected the latest admitted exact-main attempt without successful fallback,
  and kept manual runs outside admission precedence.
- Required the trusted finalizer to authenticate its own run before bundle
  creation and the publisher to reauthenticate that exact successful run,
  session identity, complete file inventory, hashes, and bundle semantics before
  writing repository status.
- Required every trusted-controller invocation workflow to restore the pinned
  selected-Python loader environment before executing the persisted offline
  controller.
- Kept trusted-controller virtual environments at their final commit-addressed
  paths so generated console-script shebangs remain executable, with scoped
  recovery of the two exact-provenance installations left by the failed
  bootstrap attempt.
- Made the source-tree preflight wrapper resolve BCF's package from any working
  directory, including fresh hosted-runner checkouts without an installed wheel.
- Distinguished the session-allocating job from admitted evidence producer jobs,
  preserving exact run/attempt binding across preflight-to-evidence fanout.
- Bound profile-v2 receipts to an explicit immutable session producer identity,
  so nested local validation cannot inherit an unrelated outer Actions run or
  job identity from ambient environment variables.
- Made doctor derive placeholder-scan exclusions from canonical declared
  template vendors while continuing to scan undeclared application paths.
- Projected execution-only test selectors out of evidence policy during profile
  promotion while retaining them in canonical gate contracts, so real
  selector-bearing repositories can promote to contract v2 transactionally.
- Kept generated profile, evidence-policy, and gate-contract YAML compact enough
  to satisfy the adopting repository's declared context budgets.
- Preserved an adopter's existing canonical semantic-ownership invocation and
  causal controls during no-config v2 promotion, using the generic Standard-v2
  gate only when no custom semantic contract exists.
- Made generated session-mode restoration a bounded `find -execdir` operation,
  keeping Standard-v2 workflows free of mechanically ambiguous shell waiter
  loops.
- Made the explicitly selected Python interpreter authoritative in positive and
  detached negative-control evidence sessions, including the loader environment
  required by toolcache Python installations, without changing canonical gate
  argv or schema-2 receipt compatibility.
- Kept non-authoritative local-artifact markers inside governed YAML scalar
  values so mutation reserialization cannot strip them and mask the intended
  causal diagnostic.
- Prevented dotted semantic identifiers such as `governance.local-pr-context`
  from being misclassified as private `.local` hostnames while retaining
  private-host detection at real token boundaries.

### Security

- Added an optional v1-compatible `admission_workflow` authority field and made
  Standard-v2 certification bind the control-plane workflow identity to that
  deterministic owner; existing v1 authority documents remain valid.
- Defined a hard separation between one-job disposable candidate workers and a
  persistent trusted control plane that never checks out or executes candidate
  code.
- Added a time-bounded owner-only local-runner fallback for exhausted hosted
  credits, with fork PR admission rejected before allocation; that window is
  now closed and privileged publication is limited to exact certified tag
  bytes on the isolated trusted runners.
- Protected `main` with pull-request-only updates, current governance checks,
  resolved conversations, and force-push/deletion prevention.
- Stopped checkout credentials from persisting on the temporary local workers
  and disabled both release execution and publication until the disposable
  candidate and isolated trusted substrates are available.
- Moved every candidate CI job to a fresh standard GitHub-hosted VM now that the
  repository is public; persistent local runners are excluded from candidate
  execution and reserved for short trusted control and publication work.
- Reduced governance evidence setup from 21 jobs to four mechanically derived
  shards while preserving exactly-once gate coverage and independent receipts.
- Made truth resolve those canonical-contract shards mechanically, and repaired
  mutation isolation so package-relative validator imports cannot be mistaken
  for successful causal mutant failures.

## [0.6.1] - 2026-08-14

### Added

- Made `README.md`, `LICENSE`, and `CHANGELOG.md` standard required governed
  artifacts with closed schema, semantic contract enforcement, and
  preserve-existing installation behavior.
- Required every pull request to update `CHANGELOG.md`, enforced against the
  exact PR base SHA by generated governance CI and contract tests.
- Put the BCF source repository under its own standard governance profile with
  executable gate contracts and schema-2 evidence.

### Changed

- Consolidated duplicated governance guidance and removed stale lifecycle,
  adoption, upgrade, and release instructions.
- Made repository-specific evidence gates bootstrap the isolated source checkout
  without relying on an ambient editable installation.
- Scoped pull-request changelog enforcement to an explicit, semantically
  validated CI contract so nested test repositories remain hermetic.

## [0.6.0] - 2026-08-14

### Added

- Added manifest-scoped transactional installation, monotonic profile
  promotion, exact-tree isolated evidence execution, and typed behavioral
  controls.
- Added schema-2 receipts, computed lifecycle consistency, profile-derived
  applicability, finding provenance, and artifact-level release verification.

### Changed

- Moved packaged implementation under `bcf_governance` and left root scripts as
  source-compatible thin wrappers.
- Made mutation profiles baseline-aware with explicit killer test nodes.

### Removed

- Removed unsafe `bcf install --force`, legacy `--gate-command`, and acceptance
  of BCF 0.5 evidence bundles.

## [0.5.0] - 2026-08-12

### Added

- Introduced evidence-backed computed `verified` and `closed` lifecycle states,
  truthfulness reports, exact-tree invalidation, finding accounting, and
  evidence semantic mutants.

[Unreleased]: https://github.com/mjgolaszewski/bcf-governance/compare/v0.7.0...HEAD
[0.7.0]: https://github.com/mjgolaszewski/bcf-governance/compare/v0.6.1...v0.7.0
[0.6.1]: https://github.com/mjgolaszewski/bcf-governance/compare/v0.6.0...v0.6.1
[0.6.0]: https://github.com/mjgolaszewski/bcf-governance/compare/v0.5.0...v0.6.0
[0.5.0]: https://github.com/mjgolaszewski/bcf-governance/releases/tag/v0.5.0
