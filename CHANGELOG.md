# Changelog

All notable changes to BCF Governance are recorded here. This file follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and the project uses
[Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

Release target: `0.7.1` (authority-v1.1 acceptance is complete; publication remains
disabled pending the explicit immutable-release and tag/publication owner actions).

### Security

- Opened the 0.7.1 authority-remediation train after post-release review found
  that same-SHA producer runs lacked common-admission membership and release
  selection duplicated success-prefiltered provider authority in workflow shell.
- Added fail-closed provider registration seams for independent release verification,
  trusted collection, immutable publication, and authority-revocation canaries; every
  new job remains disabled until its numeric workflow identity and final bytes are pinned.
- Added one mechanically governed provider-artifact decoder that binds every privileged
  release artifact to its exact role, run, attempt, repository, commit, name, ID, and
  provider SHA-256 before authorization, collection, or publication can proceed.
- Replaced operator-copied workflow hashes, definition commits, job display names, and
  controller-artifact projections with Git/provider-derived compilers checked by cheap
  preflight and cause-verified mutants.
- Made profile-v2 gate contracts the sole executable owner of evidence assertions and
  negative controls; validation rejects duplicated evidence-policy overrides instead of
  asking an operator to keep parallel declarations synchronized.
- Added a trusted release-input resolver that derives exact-main, finalizer, controller,
  run, attempt, artifact, commit, tree, and provider-digest custody from authenticated
  provider state instead of accepting operator-authored release authority.
- Rotated the pending trusted-controller target from the resolver-selected exact-main
  package artifact; provider IDs, digests, wheel hash, commit, and tree are compiler
  output rather than operator-entered release inputs.
- Promoted that controller only after provider-compiled bootstrap and independent
  probe evidence proved its installation on both uniquely labeled trusted runners.
- Bound the release dependency lock and wheelhouse manifest to authenticated exact-main
  Git blob bytes, and made the verifier controller own offline wheel/sdist/Twine
  execution plus raw stdout, stderr, JUnit, interpreter, and artifact evidence.
- Rotated the pending trusted-controller target to the mechanically resolved exact-main
  artifact containing that release-runtime verifier; the installed controller remains
  authoritative until bootstrap and probe independently confirm both trusted runners.
- Promoted the release-runtime controller only after provider-compiled bootstrap and
  probe evidence independently proved the exact installation on both trusted runners.
- Split hosted release verification into token-free candidate runtime execution and a
  non-executing provider-authentication step, with a closed subprocess environment that
  cannot inherit GitHub, Actions, cloud, or runner credentials.
- Rotated the pending trusted-controller target to the mechanically resolved artifact
  containing that token-isolated release verifier; active authority remains unchanged
  until both trusted runners independently install and probe the target.
- Promoted the token-isolated release controller only after provider-authenticated
  bootstrap and independent probe runs proved its exact installation on both trusted
  runners; the provider compiler remains the sole owner of promotion inputs.
- Activated publication-disabled release authorization, fresh hosted build, isolated
  token-free runtime verification, separate provider authentication, and trusted
  no-checkout collection while leaving the publisher fail-closed.
- Eliminated the resolver/authorizer artifact-shape split exposed by the first
  publication-disabled run, and mechanically selected its exact-main successor
  controller for independent installation on both trusted runners.
- Promoted that successor only after bootstrap and probe independently proved
  the exact installation on both uniquely labeled trusted runners.
- Completed the remediated phase state only after the promoted controller passed
  every exact-main producer and all 21 required gate receipts.
- Replaced workflow-maintained release and runtime-evidence file lists with exact
  controller-owned directory inventories that reject extra, missing, unsafe, or
  undeclared members.
- Rotated the pending trusted-controller target to the provider-resolved exact-main
  artifact containing the activated release workflows; the installed controller
  remains authoritative until bootstrap and probe independently prove both runners.
- Promoted the release-activation controller only after provider-authenticated
  bootstrap and independent probe runs proved the exact installation on both
  uniquely labeled trusted runners.

### Fixed

- Made cheap preflight derive and validate every tracked Python source entrypoint's
  repository-root import authority. Exact-main controller verification now runs in
  isolated interpreter mode, so editable installs and ambient import paths cannot
  mask a broken source command or defer it to package, evidence, mutant, or release work.
- Selected the repaired exact-main controller solely through authenticated provider
  state and compiled artifact bytes; the active trusted controller remains unchanged
  until both local control runners independently install and probe the target.
- Promoted the repaired source-entrypoint controller only after provider-authenticated
  bootstrap and independent probe runs proved its exact installation on both uniquely
  labeled trusted runners; no run, artifact, commit, tree, or digest value was transcribed.
- Completed the pre-publication authority rehearsal through exact-main certification,
  both scheduled mutant profiles, same-SHA success revocation and attempt precedence,
  closed release construction, token-free byte verification, and the sole trusted
  release receipt; final evidence must be recaptured after this reconciliation merges.
- Made extracted-source workflow custody verify the exact packaged workflow bytes and
  compiled inventories without claiming unavailable Git history; the normal repository
  path still requires exact definition-commit ancestry. Failed verifier attempts now
  retain raw runtime evidence for deterministic diagnosis.
- Replaced independently maintained resolver and authorizer artifact field sets with one
  projection derived from the `ProviderArtifact` dataclass, and fail closed on any extra,
  missing, or differently shaped download coordinates before release build allocation.
- Made cheap preflight verify the generated pack's exact hash manifest before session,
  package, test, or mutant work, with a causal control for bypassing that boundary.
- Made authenticated nonterminal workflow inspection accept only a nonempty subset of
  the pinned job inventory while terminal certification still requires the complete
  exact set, preventing release authorization from depending on future job materialization.
- Selected the corrected trusted-controller artifact through authenticated provider
  state and exact downloaded bytes; bootstrap/probe inputs remain compiler output.
- Promoted the corrected controller only after both uniquely labeled trusted runners
  passed provider-authenticated bootstrap and independent probe inventories.
- Kept interpreter, virtual-environment, runtime, development, gate-specific, and
  build-system dependency integrity at the canonical cheap preflight boundary. The
  bootstrap requirements file is now an exact generated projection of those owners,
  and failed prerequisites emit a causal terminal observation instead of a missing
  fan-in error. Generated local release checks also pass truth only the fresh session
  they just allocated, so retained sessions cannot contaminate a current run; evidence,
  mutant, package-test, and release-runtime work cannot be the first mechanism to
  discover a broken selected environment.
- Replaced hand-transcribed Identity reference custody with a tracked importer that
  authenticates the exact provider run, attempt, workflow, subject, artifact membership,
  and provider digest before projecting benchmark and SOIP results into governed audits.
- Completed the hosted Identity reference proof with the runtime-complete packaged
  controller: all 62 representations and 221 cross-language traces passed with zero
  violations, escapes, or uncovered required browser traces.
- Made package metadata admit every mechanically discovered non-Python runtime asset,
  and made cheap package preflight plus built-wheel inspection reject missing tools or
  analyzer payloads before controller publication, evidence capture, or mutation work.
- Supplied package preflight with provider-derived pull-request base and enforcement
  context so local and remote front doors make the same decision without operator input.
- Rotated the pending trusted-controller target from the provider-selected exact-main
  artifact whose wheel passed the new source-derived runtime-asset inspection; no run,
  artifact, commit, tree, provider digest, or wheel digest was operator-authored.
- Promoted the runtime-complete controller only after provider-compiled bootstrap and
  independent probe inventories proved the exact installation on both trusted runners.
- Reconciled v0.7.0 as published and attested but provider-mutable historical
  custody; its tag, release, assets, and attestations remain unchanged, and no
  corrected-authority certification is claimed retroactively.
- Pinned the trusted bootstrap and probe to the exact controller artifact built
  by the merged authority-v1.1 structural commit, and made offline installation
  select the sole authenticated controller wheel instead of a stale versioned name.
- Advanced that bootstrap custody to the fail-closed provider-registration merge,
  whose controller contains the mechanical bootstrap and terminal-revocation fixes.
- Allowed one authenticated admission's pending status to transition to its terminal
  result, and made a failed finalizer publish a higher-authority failure instead of
  leaving an older green status in place.
- Replaced independent default-branch governance runs with one exact-main admission
  whose reusable governance and package producers share the authenticated run and
  attempt; the trusted finalizer and publisher now consume every terminal outcome.
- Bound the governance workflow contract to direct pull requests and same-run
  `workflow_call` execution, removing the stale independent-push requirement from
  terminal truth.
- Mapped exact-main reusable execution to release preflight and closure truth,
  while direct pull requests retain their exact-base PR evaluation contract.
- Made reusable evaluation mode depend on its explicit typed input rather than
  the caller event name, which remains `push` inside an exact-main call.
- Made exact-main controller construction depend on a separate typed reusable-workflow
  input; direct pull requests cannot build it, and caller event presentation cannot
  silently skip it.
- Required release authorization and build to share one workflow attempt, required
  collection to select the newest same-SHA release admission, and required publication
  to authenticate the collector receipt and its exact asset inventory.
- Made independent verification require exactly one wheel, one source archive, and a
  `SHA256SUMS` file whose two declarations match the archive bytes.
- Required the trusted authorizer to hash the downloaded controller wheel instead of
  accepting its expected wheel digest as authority.
- Moved cross-workflow build and verification artifact resolution into the controller,
  eliminating workflow-authored provider selectors.
- Made status reconstruction select the highest admission and attempt mechanically,
  then let its single terminal conclusion dominate pending observations independent
  of provider list order; conflicting terminal conclusions fail closed.
- Raised only the canonical semantic-registry byte budget from 32 to 40 KiB as provider
  artifact and workflow-authority compiler ownership were added; the 200-line cap is
  unchanged and both additions remain blocking semantic families.
- Made the cheap preflight derive the selected interpreter's required distributions
  from project dependencies, declared optional groups, and gate-specific tool
  requirements; a missing `pip` or test dependency now fails before evidence capture.
- Made cause-verified test controls execute only their declared pytest oracle nodes in
  isolated worktrees after one full positive baseline; diagnostic controls retain the
  canonical gate command, eliminating repeated full-suite mutant executions.
- Preserved the authority-v1.1 base workflow shape during self-controller rotation so
  the installed pre-enrichment controller can admit the exact-main build; privileged
  job inventories remain absent and therefore fail closed until its successor is installed.
- Mechanically selected the successor controller from the newest exact-main package
  producer, verified its provider archive and closed wheel inventory, and projected its
  single canonical pin into the trusted control workflows without operator-authored custody.
- Made that same controller pin mechanically own the GitHub topology controller commit,
  removing the former duplicated commit literal from self-adoption and profile readiness.
- Separated the controller proven installed on trusted runners from the next authenticated
  artifact target. Rotation now keeps active control jobs on proven bytes, uses those bytes
  to install the target, and accepts a promotion only from exact-main bootstrap and probe
  runs compiled from authenticated provider state.
- Made canonical local-PR validation enable the same changelog contract as remote pull
  requests, using the fetched exact base SHA before any evidence can be allocated.
- Made authority-v1.1 pinning derive every privileged workflow's exact matrix-expanded
  job inventory from committed workflow bytes. The compatibility bridge can now be
  retired without restoring hand-maintained display names or job lists.
- Made cheap preflight validate the selected executable, virtual-environment prefix and
  isolation, Python constraint, and every declared dependency version. BCF's generated
  governance requirements now install its governed pytest 9.0.3 instead of a conflicting
  pre-9 range, so environment drift fails before evidence or mutant execution.
- Made workflow-byte compilation persist the uniquely derived admission and reusable-
  producer source-role map. Installed controllers no longer depend on a newer controller
  merely to interpret an enriched authority document, and no operator copies job keys.
- Compiled the next trusted-controller target from exact-main run `33463382955` and its
  provider-digested artifact after the installed controller admitted the persisted role
  map; active authority remains on the separately proven installation until bootstrap
  and probe confirmation.
- Required both scheduled mutant profiles to run the canonical selected-interpreter and
  repository preflight before any mutant. Environment, manifest, syntax, source-lock,
  and ownership defects now fail before mutation work begins.
- Required scheduled mutant checkouts to fetch complete Git custody before preflight,
  so compacted phase records are mechanically verifiable before mutation work begins.
- Added exact-subject scheduled mutant result documents and always-run, run/attempt-
  scoped artifact upload so scheduled failures retain evidence without rerunning mutants.
- Made `bcf ci local-pr` default to the canonical selected-interpreter preflight
  documented for contributors, removing a hidden argv sequencing requirement while
  retaining an explicit-command override.
- Promoted that target only after provider-compiled bootstrap run `33464640838` and
  independent probe run `33464672319` proved the exact controller on both trusted runners.
- Made every trusted GitHub controller command validate its output channel before provider
  access or mutation, and made controller confirmation publish its authority document only
  after the output channel accepts the computed result.
- Activated an owner-dispatched authority-revocation canary with typed deterministic
  scenarios, fresh secretless hosted producers, and an always-run trusted observer that
  publishes only to the isolated canary status context.

### Changed

- Clarified the README for traditional DevOps engineers with a direct
  human-centric versus agentic DevSecOps comparison, including the boundary
  between human judgment and mechanically computed claims.
- Enabled honest Git-history compaction for completed phases that lack a
  historical closed receipt; such rows retain exact hashes while omitting any
  retroactive derived-state claim. Cleanup now also preserves linked-worktree
  Git control files and avoids unrelated audit-root rewrites. Transactional
  profile checks and applies retain Git custody while validating their shadow.
- Made source-distribution verification distinguish portable package tests from
  the two BCF self-adoption proofs that require the original repository's Git
  objects; JUnit validation rejects any broader or narrower skip set.
- Replaced the transitional inline bootstrap with thin controller-owned installation
  after the exact artifact was independently installed and probed on both trusted
  runners.

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
