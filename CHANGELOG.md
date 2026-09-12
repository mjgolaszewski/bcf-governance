# Changelog

All notable changes to BCF Governance are recorded here. This file follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and the project uses
[Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [1.2.0] - 2026-09-12

### Added

- Added issue #165's opt-in GitHub-native durable evidence-input contract,
  deterministic bounded archives, compact authenticated run manifests, cold
  resolver, provider-derived storage budgets, and reachability/lease retention
  planner. Identical inputs reuse one attested immutable non-product Release
  asset; required bytes never depend on a NAS or cache.
- Added graph-owned `durable-source`, `durable-reference`, and trusted
  `durable_publish` vocabulary plus `bcf evidence-store` validation,
  preparation, publication, resolution, retention-plan, and exact transient
  retention-apply operations. Apply repeats provider authentication and cold
  reconstruction, deletes no durable Release, and verifies each deleted
  Actions artifact is absent. Fresh installations receive the inactive
  contract; existing consumers remain unchanged until explicit adoption.

- Made retained Actions bytes and hosted job minutes co-equal governed release
  budgets with measured baselines, per-train forecasts, and hard stop ceilings.

### Fixed

- Split durable evidence publication into mechanically distinct ordinary-read,
  contents-write, and repository-settings-read credentials. Immutable-Release
  preflight now uses the Administration-read credential declared by the storage
  contract instead of a workflow token that GitHub cannot authorize for that
  endpoint.
- Made required durable-source and durable-reference uploads conditional on
  successful production. A failed producer now reports its original cause
  without a second always-run missing-output failure, while ordinary gate
  evidence continues to upload on failure for diagnosis.
- Gave GitHub Actions-artifact ZIPs and Release assets distinct, typed media
  types in one transport owner. Every authenticated GitHub JSON, upload, and
  binary request now uses its credential-safe redirect policy; cross-origin
  HTTPS redirects lose credentials and redirect downgrades are rejected.
- Kept the exact-main evidence fanout fail-closed during a controller rotation
  while allowing only the short read-only package producer needed to build the
  replacement controller. A pending controller can no longer force either a
  useless full evidence run or an impossible rotation.
- Required the selected Python runtime before every Python, installed-controller,
  or ephemeral-controller invocation. Trusted no-checkout durable publishers now
  provision the declared runtime without checking out candidate code, and fresh
  Standard graphs receive the same mechanical invariant.
- Split durable-publisher graph validation into cause-specific mechanical
  diagnostics and made each new storage negative control isolate the invariant
  it claims to prove. A masked same-workflow rejection and a non-causal
  projected-byte mutant can no longer appear to test those controls.
- Moved an applicable repository editorial-inventory check into canonical cheap
  preflight, before exact test-manifest collection, session allocation, or
  evidence fanout. Stale documentation custody now fails at the front door.
- Ratcheted BCF's own canonical gate-contract context ceiling from 96 to 100 KiB
  for the complete causal preflight, download, redirect, and controller-transition
  controls; installed consumer defaults remain unchanged.
- Preserved bounded project-owned package metadata classifications across
  upgrades so a newer pack schema does not invalidate an otherwise compatible
  consumer architecture contract.
- Fixed issue #164 by resolving direct Python `self.method()` operation edges
  to the exact method in their declaring lexical class. Writes and authority
  effects in private helpers can no longer disappear behind an unqualified
  `self` call.
- Made receiver rebinding, receiver and bound-method aliases, inheritance or
  override ambiguity, `super()`, reflective receiver dispatch, and missing
  same-instance targets fail closed instead of relying on suffix or basename
  guesses. Decorated classes or methods, metaclasses, dynamic attribute lookup,
  and method rebinding are likewise rejected when static ownership is not exact.

### Changed

- Added exact class, base, decorator, method-binding, receiver, and method-rebinding
  facts to the existing source-first Python inventory without adding another AST
  scan.
- Preserved pure helper traversal and exact declared helper ports. Component
  calls require an explicit operation port, while a raw declaration cannot
  conceal ambiguous same-instance dispatch.
- Added complete public-operation, source-layout, adversarial dispatch, lexical
  collision, consumer-method, and cause-verified regression coverage.
- Preserved receipt schema 2.0, profile and authority contracts, all 21 gate
  IDs, and the mechanically generated CI topology.
- Made fresh Standard-v2 and BCF self-graphs declare a mechanically validated
  run-and-done hosted-execution policy. Hosted command paths reject sleeping,
  polling, watching, shell wait loops, and local-runner lease coordination;
  dependency edges and completion events defer allocation in GitHub rather than
  occupying a hosted VM.
- Made BCF's exact-main admission require its mechanically confirmed controller.
  A pending controller rotation now stops before hosted evidence fanout and runs
  only the bounded package producer needed for mechanical controller rotation.
- Projected and independently confirmed the 1.2.0 trusted controller, including
  the corrected authenticated GitHub transport, from exact-main provider
  evidence on both trusted runners; provider coordinates and generated workflow
  bytes remain mechanically derived rather than operator-authored.
- Completed P23-HF03 on explicit owner authority from its exact local, protected
  PR, bootstrap, and probe evidence. The existing closure preflight rejected the
  omitted lifecycle transition before any evidence lane was allocated.
- Re-projected the controller target after the cold-runtime correction from the
  authenticated implementation-merge artifact; no controller coordinate or
  generated workflow value is hand-authored.
- Confirmed that controller installation through provider-compiled bootstrap
  and probe evidence from both trusted runners; release and exact-main roles
  activate only from the mechanically projected proof.
- Bound durable publication credentials, GitHub App permissions, source commit
  and tree, workflow bytes, job, run, attempt, provider assets, attestations,
  freshness, and materialized member bytes mechanically. Concurrent or
  interrupted publication is idempotent and contradictory provider state fails
  closed.
- Split trusted publication credentials by operation: the workflow token owns
  authenticated Actions, repository, Release, and attestation reads, while the
  short-lived App token is requested with only `contents:write` and performs
  only Release mutation.
- Added an owner-dispatched BCF qualification graph that prepares one bounded
  input on a hosted worker, publishes it after completion on trusted local
  control, and allocates the hosted cold resolver only after publication
  succeeds. No hosted job waits for local capacity.
- Preserved receipt schema 2.0 and Actions-only artifacts. Large Actions
  archives are bounded transient handoffs, compact references retain the
  existing schedule, and every detached evidence worktree re-verifies its
  declared durable inputs before gate execution.

## [1.1.1] - 2026-09-11

Published as immutable GitHub release `387251389` from exact certified merge
`fe85d200c16ef296280fef59c8f7888978e43d2c`.

### Fixed

- Fixed issue #159 by qualifying imported Python constructor identities through
  exact, declared import roots after the independent tracked-source inventory.
  Flat, `src/`, nested-source, relative-import, alias, and package re-export
  layouts now enforce the same canonical constructor identity.
- Rejected missing, empty, symlinked, overlapping, conflicting, and ambiguous
  import-root mappings instead of guessing from suffixes or basenames.

### Changed

- Added the optional `source_authority.python_import_roots` registry field.
  Existing consumers retain repository-root behavior when it is absent; new
  Standard-v2 templates declare `['.']`, and src-layout consumers declare the
  exact directories placed on Python's import path.
- Added focused consumer-layout regressions and a cause-verified control that
  proves bypassing constructor normalization restores the reported false pass.
- Preserved receipt schema 2.0, profile and authority contracts, all 21 gate
  IDs, and the generated CI topology.
- Projected the trusted-controller target from the authenticated exact-main
  artifact; provider coordinates and workflow bytes remain mechanically
  derived rather than operator-authored.
- Promoted that controller only after provider-compiled bootstrap and probe
  evidence proved the exact installation independently on both trusted
  runners.

## [1.1.0] - 2026-09-11

Published as immutable GitHub release `387076379` from exact certified merge
`e1053ae4530e595d3f5453668f6c93a35fec45fb`.

### Added

- Added `governance/semantic-families.yml`, a source-bound registry that makes
  every adopted material semantic family explicit and requires exact-base
  migration custody for retirement, downgrade, or ownership reassignment.
- Added `governance/application-operations.yml`, which closes configured public
  operation populations and classifies every entrypoint exactly once by
  CQRS-side behavior, mutation, authority, projection, and model-callability.
- Added derivation provenance for secondary representations, including isolated
  tracked-command reproduction, direct-edit detection, bounded expiring
  exceptions, and a mechanically derived `governance/semantic-lock.yml`.
- Added nested `bcf semantic-ownership scan`, `scaffold`, `adopt`, and `lock`
  interfaces. Existing no-subcommand scans remain compatible.
- Added aggregate adoption diagnostics that report every independently
  evaluable semantic blocker before a transaction can mutate its target.
- Added source, contract, and causal mutation coverage for each semantic owner,
  plus a complete exact-file editorial review.

### Changed

- Fixed issues #152, #153, and #154 by making family completeness, application
  operation classification, and representation provenance separate blocking
  capabilities for fresh Standard-v2 and Regulated consumers.
- BCF self-adopts all three capabilities without changing its 21 gate IDs, 18
  generated workflows, 29-job topology, receipt schema 2.0, profile contract
  2.0, or CI authority v1.1.
- Ordinary upgrades preserve consumer-owned semantic contracts and capability
  state. Fresh Standard-v2 and Regulated adoption requires a complete explicit
  semantic configuration before mutation; Lite remains unchanged.
- Closed population adapters reject duplicate Python decorators, exports,
  canonical-YAML entries and keys, and TypeScript exports instead of allowing
  one declaration to hide another.
- Negative-control target freshness is evaluated after the governed target's
  own semantics, so an active control reports its declared failure cause while
  stale controls in an unmodified baseline still fail closed.
- Primary semantic violations are reported before derived semantic-lock drift,
  preventing projection freshness from masking the defect that caused it.
- Documentation now distinguishes semantic scope, operation effects, parity,
  and provenance; patch-specific upgrade prose and the release checklist were
  consolidated into durable maintainer guidance and exact audit custody.
- Editorial custody remains mechanically verifiable in an extracted source
  distribution even when the original review-base Git object is unavailable.
- The self-hosting controller target is projected from the authenticated
  exact-main artifact; its provider identity and wheel digest are mechanically
  compiled rather than copied into workflow or policy files.
- The target becomes installed authority only after provider-compiled bootstrap
  and probe evidence succeeds independently on both declared trusted runners;
  release roles remain fail closed until that proof is projected.

### Compatibility

- Existing 1.0.x consumers remain readable and unchanged until explicit
  adoption. GitHub remains the only executable CI provider, GitHub Releases the
  distribution channel, and Linux x86-64 with CPython 3.11–3.14 the supported
  runtime matrix.

## [1.0.4] - 2026-09-10

Published as immutable GitHub release `386507232` from exact certified merge
`c3513576d76212ae0afd4d624df1dd8d4e665559`.

### Added

- Added one canonical selector-map owner that preserves the exact raw pytest
  selector associated with each JUnit-normalized test identity and rejects
  collisions.
- Added positive, adversarial, and causal coverage for module functions,
  pytest classes, `unittest.TestCase`, nested classes, parameterized nodes,
  missing mappings, ambiguous mappings, and unsafe selectors.
- Added one canonical audit-context artifact classifier with cause-verified
  controls for product-code admission and governance-evidence custody.

### Fixed

- Fixed issue #143: class-based negative controls now execute the raw selector
  admitted by selected-interpreter collection instead of guessing a filesystem
  path from the JUnit classname.
- Test-gate evidence verifies the collected mapping against the governed exact
  node manifest once per gate and reuses it across isolated mutants; collection
  errors, missing identities, and ambiguous identities fail closed.
- BCF's final 1.0.4 trusted-controller target is projected only from the
  authenticated exact-main package artifact after both issue corrections; a
  previously pending target is first re-proven on current main, and installed
  authority remains independently proven until the final bootstrap and probe
  complete on both trusted runners.
- The final controller becomes installed authority only after provider-compiled
  bootstrap and probe evidence succeeds on both declared trusted runners;
  release roles remain mechanically disabled before that confirmation.
- Fixed issue #146: regular Python or declared TypeScript code beneath the
  repository's declared source and test roots is no longer treated as misplaced
  governance evidence merely because an ancestor package is named `audit` or
  `audits`.
- Audit reports and evidence-like files outside the canonical `audits/` root
  remain rejected, including files concealed under source/test trees and files
  admitted through unsafe, linked, or audit-named root declarations.

### Compatibility

- Receipt schema 2.0, profile contracts, the 21-gate Standard profile, CI graph
  topology, cleanup behavior, and existing consumer graph configuration remain
  unchanged. Audit code recognition is bounded to BCF's supported Python and
  declared TypeScript source forms.

## [1.0.3] - 2026-09-10

Published as immutable GitHub release `385974512` from exact certified merge `bb8faf21116f644491e2997cb8ec7ea73e30bc83`.

### Added

- Added `bcf evidence select-session`, the canonical fail-closed selector for a
  dependent producer to locate one validated direct-child session manifest
  without mistaking retained receipt copies for additional sessions.
- Added the canonical `governance.evidence-receipt-admission.v1`
  representation and causal controls for session selection and duplicate
  receipt admission.
- Added `bcf ci graph audit`, a deterministic inventory and authority map for
  workflows, gates, tests, artifacts, receipts, dependencies, timeouts,
  generated parity, and remaining external authority.
- Added automation-producer contract v1.1 with typed dependency-manifest
  decoders so trusted changelog entries name the dependency and its exact
  previous and new versions without consuming pull-request prose.

### Fixed

- Generated gate-group jobs and BCF shard capture now share the same canonical
  session selector, so transported receipt-local manifest copies cannot prevent
  subsequent gates from starting.
- Truth rejects every receipt involved in a duplicate evidence identity or
  execution slot before gate grouping or claim selection; renamed,
  contradictory, or relocated copies can no longer satisfy closure.
- Evidence execution now consumes its deadline from the canonical gate contract,
  and graph compilation rejects an outer evidence timeout that cannot contain
  the longest inner deadline plus declared headroom.
- Scheduled mutation validation now rejects missing or ambiguous source targets
  before execution instead of replacing the first matching fragment.
- Package validation now derives the complete third-party import set from the
  runtime source and rejects undeclared runtime dependencies; `packaging` is
  declared explicitly for dependency-manifest decoding.
- Issue-remediation controls now belong to the exact contract-test population,
  including the explicit parametrized receipt-collision oracle identity.
- Trusted-controller bundles now derive all runtime requirements from package
  metadata, declare their build environment, prove recursive wheel closure,
  and complete a real offline install before upload; pin compilation rejects an
  incomplete bundle before either trusted runner is used.
- Release source tests now execute with import authority bound mechanically to
  the exact checked-out repository instead of inheriting an editable developer
  environment that can conceal clean-runner failures.
- Failed release commands now close and retain raw stdout, stderr, and JUnit
  evidence, replay their diagnostics to the job log, and always upload the
  same-attempt diagnostic bundle. The verifier remains gated on complete build
  success, so failed bundles cannot enter release authority.

### Changed

- Replaced the unconfirmed controller target whose authenticated bundle omitted
  `packaging` with the corrected exact-main artifact only after package-derived
  closure, recursive wheel checks, and an offline installation passed before
  upload. Workflow authority pins are derived from the preceding generated-byte
  freeze commit; the prior proven installation remains authoritative until the
  corrected target passes independent bootstrap and probe.
- Promoted that target only after bootstrap run `34419701832` and independent
  probe run `34419770290` authenticated and exercised it on both uniquely labeled
  trusted runners; installation proof and release-role availability are projected
  mechanically from those provider results.

### Compatibility

- Receipt schema 2.0, profile contracts, the 21-gate Standard profile, CI graph
  topology, and existing profile-v1 sessionless receipt support are unchanged.
- Automation-producer contract v1.0 remains readable; explicit new adoption uses
  v1.1. All 18 workflow paths, 29 job IDs and roles, runner mappings, required
  checks, events, edges, permissions, and failure semantics remain unchanged.

## [1.0.2] - 2026-09-03

Published as immutable GitHub release `381757666` from exact certified merge
`0c46175f0b6628721050bbd5b5526f18a61bb886`.

### Added

- Added an opt-in, schema-governed trusted automation producer that derives
  Dependabot scope from provider identity and `.github/dependabot.yml`, then
  writes one fixed, idempotent changelog entry through a contents-only GitHub
  App using a non-force compare-and-swap commit.
- Added bounded mechanical projection declarations for dependency inputs whose
  exact copies and SHA-256 manifests are repository-owned generated surfaces.
- Added exact-head PR aggregation and the reserved `bcf/pr-certification`
  publisher, plus a complete declarative provider-protection contract.

### Changed

- Defined BCF specifically as deterministic error correction for software
  produced by probabilistic AI agents; human-led development is no longer
  described as a design target.
- Routed automation admission, reconciliation, PR finalization, and status
  publication through mechanically rendered no-checkout trusted-control jobs.
- Put package fanout behind one cheap front door and made automation admission
  conditional on the authenticated Dependabot numeric actor ID.
- Projected the trusted controller target from an authenticated exact-main package
  artifact and retained separate installed-state proof until both trusted runners
  confirm the new bytes.
- Rotated the controller target again after the final protection-owner correction;
  the exact-main package artifact, not an operator-entered identity, supplies every
  run, commit, tree, provider, and wheel binding.
- Projected the dependency-output and fail-closed local-front-door controller only
  from the authenticated exact-main package artifact and checksum inventory.
- Confirmed that controller only after both uniquely labeled trusted runners
  independently installed and probed the exact provider-authenticated artifact.
- Recorded provider-compiled installation proof only after the generated bootstrap
  and probe passed independently on both trusted-control runners.
- Projected the controller containing the automation subject and tracked-surface
  repairs only from its authenticated exact-main package artifact and checksum
  inventory; the previously confirmed controller remains installed until proof.
- Confirmed that controller only after both uniquely labelled trusted runners
  independently installed and probed the provider-authenticated artifact.
- Projected the final generated-workflow exclusion controller from its
  authenticated exact-main package artifact while retaining the confirmed
  predecessor until independent installation proof.
- Confirmed that final controller only after independent bootstrap and probe
  success on both uniquely labelled trusted runners.
- Confirmed the final protection controller only after both trusted runners
  independently installed and probed the provider-selected artifact.
- Completed the authored P18 implementation state only after local validation and
  controller installation proof; release closure remains mechanically computed.
- Provisioned the protected-branch-only `bcf-trusted-automation` environment
  before installing the narrowly scoped changelog writer credentials.
- Replaced the three worker-level required checks with the unique mechanically
  aggregated `bcf/pr-certification` check after a successful controlled
  Dependabot canary; strict pull requests and all existing protection boundaries
  remain active.
- Deregistered the obsolete persistent Dependabot runner after mechanically
  confirming that no compiled workflow could select its name or labels.

### Fixed

- Kept the universal pull-request changelog rule without making automation PRs
  permanently fail or granting candidate code write, approval, merge, or
  certification authority.
- Made protection activation require one current successful controlled draft
  automation canary sourced from GitHub Actions App ID `15368` before replacing
  worker checks with the single aggregate status.
- Made protection activation update the canonical or sole exact-branch ruleset,
  compare provider rule order semantically, and reject ambiguous overlapping
  rulesets instead of creating a second protection plane.
- Made trusted-controller bootstrap work from an empty runner tool cache by
  staging the provider- and checksum-admitted wheel in a run-scoped environment
  before installing the persistent controller with the selected Python.
- Rotated BCF's own trusted controller to the exact merged cold-start-safe
  artifact, retaining the previous installation until independent bootstrap and
  probe runs mechanically confirmed the replacement on both trusted runners.
- Allowed self-controller rotation to authenticate one complete package producer
  from a partial exact-main admission without relaxing complete-inventory
  requirements for certification.
- Separated trusted default-main workflow-definition custody from an automation
  run's provider-resolved PR commit and tree. Admissions now reject stale run
  heads and PRs that advance while their provider state is being observed.
- Replaced root-only Dependabot path globs with exact Git-tracked dependency and
  eligible project-owned Actions surfaces derived from every configured update
  directory. Generated dependency copies and their hashes are outputs rather
  than independently accepted source changes.
- Excluded renderer-owned workflow bytes from Dependabot producer scope and made
  adoption reject an Actions updater with no project-owned surface. BCF now uses
  Dependabot only for Python inputs; action pins remain canonical source changes
  followed by mechanical rendering and authority pinning.
- Made the trusted reconciler derive declared exact-copy dependency surfaces and
  content-addressed manifest entries from authenticated source blobs. It rejects
  stale baselines, independent output edits, and output-only changes before the
  App creates one multi-path compare-and-swap commit.
- Made the generated local `release-check` preserve the preflight command's exit
  status before selecting its session path. A failed front door now stops before
  evidence capture instead of letting `tail` mask the failure and derive a root
  output path from an empty session value.
- Made the PR contract suite build an actual source archive and compare its
  contents with the complete Git-tracked source inventory. Release
  construction repeats the same check before upload, and all governed `.github`
  Python and YAML inputs are now included mechanically rather than by subdirectory.

## [1.0.1] - 2026-09-02

### Changed

- Reframed the README around BCF's deterministic error-correction thesis for
  probabilistic software production, with a compact failure-mode map and clear
  human/mechanical authority boundary.
- Added one focused reliability model covering verification redundancy,
  compute and attention costs, common objections, limitations, and the
  empirical measurements needed to evaluate the framework's economic thesis.
- Explained the architecture defaults as configurable reliability biases that
  trade some flexibility for mechanically observable structure.
- Reconciled release-facing installation guidance with the supported immutable
  GitHub Releases distribution channel.

### Fixed

- Made editorial validation require README and operator-guide release URLs to
  identify the exact current package version, preventing a current wheel name
  from concealing a stale release tag.

## [1.0.0] - 2026-09-02

Published as immutable GitHub release `381225147` from exact certified merge
`57bc2245b3c7913363169b42854b0899c04de401`.

### Changed

- Opened the stable 1.0 phase after mechanically verifying immutable
  `v1.0.0rc1` provider custody, and promoted only the canonical package and
  release identity from `1.0.0rc1` to `1.0.0`.
- Kept the release-candidate CLI, schemas, profiles, receipts, CI authority,
  graph extensions, platform matrix, provider, and distribution contracts
  frozen for the stable release.

### Fixed

- Made phase retention atomically move completed phases from both active
  roadmaps into hash-bound Git history, so cleanup no longer requires a human
  to synchronize the history boundary and roadmap projections.
- Made changelog validation use the canonical release-version parser, allowing
  canonical `a`, `b`, and `rc` headings without accepting non-SemVer spellings.
- Allowed an installed trusted controller to lag only an exact inert
  `bcf_governance/_version.py` literal during a version-only promotion. Any
  executable statement, noncanonical metadata form, imported runtime change,
  or packaged-schema change still fails the cheap compatibility preflight.

## [1.0.0rc1] - 2026-09-02

Published as immutable GitHub release `381170529` from exact certified merge
`d77b13860ce70d32f3754c4ede4e90d12573d76e`.

### Changed

- Opened the `1.0.0rc1` contract and adoption-hardening phase with an explicit
  supported-surface freeze, isolated legacy migration, transactional rollback,
  and five-cycle clean-clone soak requirements for BCF and Identity.
- Froze the release-candidate's supported top-level CLI and exit classes,
  active/readable schema contracts, Standard-v2 graph extension points and
  executors, Linux x86-64 CPython 3.11–3.14 runtime matrix, GitHub CI provider,
  GitHub Releases distribution, and compatibility/deprecation boundaries in one
  mechanically validated public-contract registry.
- Made ordinary upgrades refresh only pack-owned runtime and schema surfaces.
  Project-owned profiles, gate contracts, evidence policy, graphs, extensions,
  generated and unrelated workflows, and legacy lifecycle state remain byte
  preserving; legacy contract migration is an explicit fail-closed transaction.
- Replaced the obsolete regression for implicit upgrade-time evidence migration
  with preservation and isolated-migration coverage, and added five clean-clone
  install/upgrade/customize/rollback cycles.
- Recorded immutable `v0.8.0` provider custody after the exact PR, merged-main,
  scheduled-mutant, release-verifier, collector, and no-rebuild publisher chain passed.
  P14 is now compacted under exact Git and SHA-256 custody while P15 is the sole
  active phase triplet.

### Added

- Added typed CI graph prerequisite diagnostics for runners, tools, permissions,
  secrets, events, and graph inputs, plus one mechanically composed first-step
  environment check before checkout or governed work.
- Added an offline five-cycle BCF/Identity adoption soak that uses disposable
  clones, preserves project-owned governance and workflows exactly, proves
  pack-owned refresh is idempotent, restores each clone to its exact source,
  requires Identity legacy migration to fail closed with complete blockers, and
  launches no Actions runs.
- Made the soak consume NUL-delimited Git porcelain without trimming status
  prefixes, reject rename/copy records, and retain the first changed path exactly.
- Recorded five passing clean-clone soak cycles for exact BCF commit `0172f8a`
  and Identity commit `0569e6d`: project-owned bytes and all 10 Identity workflows
  were preserved, pack refresh was idempotent, rollback was exact, and zero
  Actions runs were launched.
- Added canonical pre-release version parsing for `a`, `b`, and `rc` packages so
  release inputs, tags, API validation, and GitHub prerelease state share one
  owner.

### Fixed

- Made trusted-controller freshness a cheap mechanical precondition instead of
  an operator sequencing obligation. Preflight now derives the trusted GitHub
  command import closure and packaged schema inventory, compares those exact
  committed bytes with the authenticated controller target, and reports every
  stale path together. Release authorization, collection, and publication stay
  disabled until independent bootstrap and probe evidence promotes that target
  on every declared trusted runner.
- Projected the provider-compiled bootstrap and probe proof into the installed
  controller identity, regenerated every trusted workflow against that proven
  controller, and re-enabled release roles without operator-authored run,
  artifact, commit, tree, digest, or workflow values.
- Removed release publication's dependency on the version of a previously
  installed trusted controller. The graph now resolves the tag from the
  digest-locked current release contract, generated workflow bytes carry that
  value mechanically, and the controller independently requires the wheel and
  source archive to name the same distribution and version before any provider
  mutation. Current-main contract paths and versions, mixed archive identities,
  missing attestations, generated tag drift, and archive/tag drift all fail
  closed under causal controls.
- Moved release-attestation completeness ahead of draft creation. Publication
  now validates immutable-release state, annotated-tag identity, closed archive
  identity, checksums, receipt custody, and attestations before it creates or
  uploads a GitHub Release.
- Replaced ambiguous YAML text mutations with typed semantic paths and encoded
  typed values. Literal byte mutation now requires a documented byte-level
  reason, preventing formatting drift from masquerading as a causal control.
- Ensured Standard applicability excludes only explicitly `not_applicable`
  gates while retaining required, deferred, and optional migration targets.
- Made upgrade preservation paths executable installer data consumed by public
  contract validation and the adoption soak rather than repeated hand-maintained
  lists.
- Made generated local Make targets route every Python gate through the selected
  `$(PYTHON)` authority. Workflow contract tests now locate mechanically named
  steps instead of duplicating renderer positions, while the one security-relevant
  first-step environment ordering remains explicitly enforced.
- Made cheap preflight report every stale negative-control oracle in one defect
  class before evidence capture, and rebound the exact-main activation mutant to
  the semantic condition owner it is intended to challenge.
- Made local evidence-session allocation reject a producer ID that is absent from
  its admitted producer inventory before creating a session or running a gate.
  Workflow sessions retain their intentional allocator-to-downstream-job split.
- Separated implementation completion from immutable provider publication:
  exact-main closure requires completed workitems, while build, verification,
  collection, and publication remain post-closure provider actions whose custody
  is recorded by the following phase.

## [0.8.0] - 2026-09-02

Published as an immutable GitHub release from exact certified merge
`bf8490777c9ecc90fb0e4a44deadb24d7cb7050a`.

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

- Made release CLI argument ownership operation-specific and mechanically exercised
  all ten release dispatch paths. Verifier-bundle staging now runs only for the
  `verify-evidence` operation; the release builder cannot reach arguments declared
  by another subcommand after completing its expensive source-test pass.
- Bound both hosted release-verifier jobs to the exact controller selected by their
  triggering authorization run and attempt. The verifier downloads that trusted
  artifact directly, checks its closed inventory and authorization-owned wheel digest,
  and no longer depends on a potentially older global bootstrap controller.
- Derived release-operation inventory from the parser and exercised every canonical
  graph-owned release command through its real dispatch branch before remote execution.
- Made artifact storage for every trusted no-checkout job independent of persistent
  runner workspace state. The graph renderer now uses run-and-attempt-scoped
  directories under the runner temporary root for declared inputs and outputs, and
  compilation rejects repository-relative artifact roots for this entire trust class.
- Moved exact-main lifecycle eligibility into cheap preflight. Closure evaluation
  reports the active phase, phase log, and complete open-hotfix inventory together
  and stops before evidence-session allocation; PR validation and scheduled controls
  retain their existing execution semantics.
- Made direct-event input defaults a graph-wide invariant. The compiler rejects raw
  workflow inputs in command arguments or environments, action inputs, reusable-
  workflow inputs, and job outputs when a workflow also has a direct trigger, preventing
  absent `workflow_call` inputs from reaching runtime commands as empty strings.
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
  bootstrap/probe rotation path active; trusted local roles cannot execute an
  unconfirmed target controller.
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
- Made the trusted publisher require `BCF_RELEASE_ADMIN_TOKEN` for final publication
  while its resolver and attestation steps retain their narrower workflow permissions.
  GitHub's workflow token cannot read
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

[Unreleased]: https://github.com/mjgolaszewski/bcf-governance/compare/v1.2.0...HEAD
[1.2.0]: https://github.com/mjgolaszewski/bcf-governance/compare/v1.1.1...v1.2.0
[1.1.1]: https://github.com/mjgolaszewski/bcf-governance/compare/v1.1.0...v1.1.1
[1.1.0]: https://github.com/mjgolaszewski/bcf-governance/compare/v1.0.4...v1.1.0
[1.0.4]: https://github.com/mjgolaszewski/bcf-governance/compare/v1.0.3...v1.0.4
[1.0.3]: https://github.com/mjgolaszewski/bcf-governance/compare/v1.0.2...v1.0.3
[1.0.2]: https://github.com/mjgolaszewski/bcf-governance/compare/v1.0.1...v1.0.2
[1.0.1]: https://github.com/mjgolaszewski/bcf-governance/compare/v1.0.0...v1.0.1
[1.0.0]: https://github.com/mjgolaszewski/bcf-governance/compare/v1.0.0rc1...v1.0.0
[1.0.0rc1]: https://github.com/mjgolaszewski/bcf-governance/compare/v0.8.0...v1.0.0rc1
[0.8.0]: https://github.com/mjgolaszewski/bcf-governance/compare/v0.7.1...v0.8.0
[0.7.1]: https://github.com/mjgolaszewski/bcf-governance/compare/v0.7.0...v0.7.1
[0.7.0]: https://github.com/mjgolaszewski/bcf-governance/compare/v0.6.1...v0.7.0
[0.6.1]: https://github.com/mjgolaszewski/bcf-governance/compare/v0.6.0...v0.6.1
[0.6.0]: https://github.com/mjgolaszewski/bcf-governance/compare/v0.5.0...v0.6.0
[0.5.0]: https://github.com/mjgolaszewski/bcf-governance/releases/tag/v0.5.0
