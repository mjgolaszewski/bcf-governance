# Issue #394 Phase 0 — consumer-to-invariant reconstruction

Status: **speculative / non-authoritative**. Source baseline: `main` at branch creation. The machine-readable evidence is `spec/phase0/release-train-backtrace.yml`.

## Finding

The observed defect is real, but P31 already supplies the canonical lower-level primitive that Phase 0 should compose rather than replace. `ci_graph_edges.py::compile_edge_contracts` constructs an `EdgeContract` for every ordered CI job pair. Reachable pairs require mechanism, subject binding, custody, applicability, permissions, lifecycle, authority and failure semantics; unreachable pairs require a typed exclusion. `test_canonical_graph_closes_or_excludes_every_producer_consumer_pair` proves the complete N×(N−1) job-pair population.

The gap is therefore **not CI-edge closure**. The gap is that release-train states and terminal consumers in `RELEASE_TRAIN_STATE_DAG.md` are still prose and are not mechanically joined to those edge contracts, canonical invariant/claim owners, authenticated facts, lifecycle authority, recovery, release publication and adopter qualification.

## Backward trace from terminal consumers

| Terminal consumer/result | Immediate authority owner | Required predecessor | Canonical primitive(s) | Governing invariant IDs |
|---|---|---|---|---|
| terminal release custody | release custody audit | immutable publication + exact asset identity | SubjectIdentity, AuthorityIdentity | INV-RT-001, INV-RT-008, INV-RT-010 |
| immutable publication | provider release publication | exact adopter qualification + release upload identity | AuthorityIdentity, Qualification | INV-RT-004, INV-RT-008 |
| adopter qualification | adopter qualification harness | exact verified wheel/sdist/checksum inventory | Qualification, SubjectIdentity | INV-RT-005, INV-RT-008, INV-RT-010 |
| exact asset verification | release collector/verifier | terminal release authorization | SubjectIdentity, AuthorityIdentity | INV-RT-001, INV-RT-005, INV-RT-008 |
| release authorization | `ci_github_release.py` | exact terminal lifecycle certification | AuthorityIdentity, LifecycleState | INV-RT-004, INV-RT-008 |
| controller custody/rotation | `ci_graph_controller_lifecycle.py` | authenticated lifecycle certification + typed recovery/rotation authority | RecoveryAuthority, AuthorityIdentity | INV-RT-004, INV-RT-009, INV-RT-012 |
| bounded/terminal lifecycle certification | trusted finalizer/status publisher | exact-main truth from same admission | LifecycleState, SubjectIdentity, AuthorityIdentity | INV-RT-001, INV-RT-004, INV-RT-005, INV-RT-007 |
| exact-main truth | `governance_truth.py` | exact-main admission + produced/reused eligible claims | ClaimIdentity, EvidenceReceipt, ApplicabilityDecision | INV-RT-001, INV-RT-002, INV-RT-005, INV-RT-011 |
| exact-main admission | `ci_github_automation.py` | protected merged main + installed controller + lifecycle | SubjectIdentity, AuthorityIdentity, LifecycleState | INV-RT-001, INV-RT-004, INV-RT-006, INV-RT-007, INV-RT-009 |
| protected merge | provider branch protection | successful canonical PR certification | AuthorityIdentity | INV-RT-004 |
| PR certification | protected-base / installed-controller finalizer | independently authenticated candidate truth | EdgeContract, SubjectIdentity, AuthorityIdentity | INV-RT-001, INV-RT-003, INV-RT-004, INV-RT-005 |
| candidate truth | `governance_truth.py` | exact receipts/reuse satisfying required claims | ClaimIdentity, ExecutionGroupIdentity, EvidenceReceipt | INV-RT-001, INV-RT-002, INV-RT-005, INV-RT-011 |
| evidence result | canonical execution-group producer | complete exact plan | ExecutionGroupIdentity, DependencyClosure | INV-RT-001, INV-RT-002, INV-RT-005 |
| execution plan | `evidence_planning.py` | cheap preflight + canonical claim model + authenticated prior proof | ClaimIdentity, DependencyClosure, ApplicabilityDecision | INV-RT-001, INV-RT-002, INV-RT-005, INV-RT-011 |
| preflight success | governance validation runner + CI graph compiler | canonical authored repository state | CompiledCIGraph, EdgeContract | INV-RT-003, INV-RT-006, INV-RT-007, INV-RT-010 |

This trace intentionally terminates at existing invariant/primitive owners. It does not introduce a scheduler-specific truth vocabulary.

## Construction consequence

The Phase-0 implementation should extend the existing CI edge contract into a typed **release-train composition**, with stable IDs for release-train states/transitions and references to existing canonical primitive identities. It should not copy the CI graph into a second YAML model. The normative contract must be able to answer, mechanically:

1. Which invariant requires this consumer result?
2. Which canonical primitive carries the proposition?
3. Which authenticated producer is allowed to create it?
4. Which exact edge transports it to this consumer?
5. Which authority effect may the consumer exercise?
6. Which cost boundary is crossed?
7. What cause-specific rejection occurs when the contract is violated?
8. Which bounded recovery edge is legal?
9. Which positive test proves the transition?
10. Which cause-specific negative test proves the invariant?
11. Which terminal consumer depends on the result?

If any answer is absent, changed production/contracts must stop before expensive allocation.

## Existing proof that must be reused

The P31 CI graph already closes all ordered producer/consumer pairs. The Phase-0 contract should reference the compiled `EdgeContract` population and its digest/identity, then add only the missing release-train composition around provider/lifecycle/release/adopter transitions. This preserves SOIP and avoids a second graph evaluator.

Existing canonical primitives from the P26 invariant-ownership inventory should be reused by their existing names: `SubjectIdentity`, `TreeIdentity`, `ClaimIdentity`, `ExecutionGroupIdentity`, `ExecutionProvenance`, `AuthorityIdentity`, `DependencyClosure`, `Qualification`, `EvidenceReceipt`, `EvidenceReference`, `ApplicabilityDecision`, `InvalidationReason`, `ReuseAttestation`, `LifecycleState`, and `RecoveryAuthority`.

## Validation work intentionally left to the next agent

The branch is deliberately speculative. Before adoption, independently bind each `TR-001` through `TR-015` to exact implementation symbols and actual compiled CI edges; enumerate every alternate/recovery transition; attach a positive test and cause-specific negative test to every transition; prove every structurally unreachable release-train state pair has a closed exclusion; generate the prose DAG/matrix/diagram from the machine contract; and prove byte-stable regeneration plus self/Lite/Standard-v3/Regulated parity.

Most importantly, do **not** mark Phase 0 complete merely because the current suite is green. The exit condition is complete traceability from invariant → canonical owner → primitive → edge/contract → producer → consumer → authority effect → terminal result, with independent reverse tracing from every runtime authority effect back to its invariant.
