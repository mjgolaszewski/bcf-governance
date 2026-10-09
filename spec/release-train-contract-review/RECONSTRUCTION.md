# Reconstructed release-train architecture — review summary

**Status: proposed, not production-certified.**

## Normal path (logical ordering)

1. Validate authored state and local admission before mutation or expensive work.
2. Reconcile canonical projections to a fixed point, including workflow definition and authority.
3. Authenticate controller applicability and provider event comparison context.
4. Derive affected proofs, reuse exact applicable evidence, execute unresolved complete partitions.
5. Authenticate PR evidence and independent PR certification.
6. Perform legal protected merge with exact base/head/tree identity.
7. Admit exact-main; if required, rotate controller N→N+1 with independent build/bootstrap/probe/confirmation and fresh exact-main attempt.
8. Resolve bounded or terminal proposition; trusted finalizer and status publisher must preserve exact scope.
9. Only terminal phase closure authorizes release.
10. Authorize exact main, build from exact source, independently verify, and collect exact assets into a trusted receipt.
11. **Before publication**, qualify exact unpublished assets against every required adopter class with fixed-point reconciliation and applicable proof.
12. Authenticate tag, attestations, assets, receipt, controller, and short-lived credential; publish exact bytes immutably.
13. Retire credential, verify same-byte custody without recomputing unchanged product evidence, close release and activate successor only when entitled.

## Conditional state families

- Authored contradiction → typed stop, zero mutation.
- Stale derived projection → dependency-ordered reconciliation; forced full equivalence.
- Base advanced or stacked PR → exact reconstitution or closed alternate lane.
- Provider transient GET → bounded identical-request retry; identity/auth failures terminal.
- Controller current/pending/alternate/recovery → typed legal next action, no generic bypass.
- Bounded workitem certification → successor eligibility only, never release.
- Affected-proof ambiguity → conservative execution; independent truth checks completeness.
- Local proof → local observation only; provider authority not inherited.
- Partial publication → idempotent exact transaction or conflict stop; no force-moving tags.
- Published without prerequisite adopter qualification → immutable but **noncustodied**, successor blocked; superseding patch release required.

## Historical contradiction

The older `## Canonical DAG` in `spec/RELEASE_TRAIN_STATE_DAG.md` places adopter qualification after publication. The later P30/P31 state matrix and publication qualification contracts require exact-asset adopter qualification **before** publication. The latter is the normative target. Keep the older text as explicitly superseded history or regenerate a single canonical diagram.

## Confirmed implementation owners (not exhaustive)

- `bcf_governance/tooling/ci_recovery_frontier.py`: closed recovery edge table and typed next-action projection.
- `bcf_governance/tooling/affected_proof_closure.py`: derive/verify affected-proof set.
- `bcf_governance/tooling/governance_truth.py`: independent affected-proof verification consumer.
- `bcf_governance/tooling/ci_authority_submit.py`: canonical candidate submission.
- `bcf_governance/tooling/reconcile_stage_ledger.py`: reconcile stage digest ledger.
- `bcf_governance/tooling/routine_controller_decision.py`: typed controller decisions.
- `bcf_governance/tooling/ci_github_release.py`: authorize/build/verify/collect/publish release functions.
- `bcf_governance/tooling/release_adopter_qualification.py`: exact-asset adopter qualification.
- `bcf_governance/tooling/ci_github_release_qualification.py`: provider-bound qualification authentication and publication prerequisites.
- `bcf_governance/tooling/release_tag_publication.py`: exact tag handling.

## Priority recommendations

1. Establish one canonical machine-readable transition contract, using existing code owners for facts and effects.
2. Make every transition reference a typed authenticated fact producer, exact guard, allowed effect, successor, and closed failure.
3. Resolve normative contradictions, beginning with prepublication qualification.
4. Derive human diagrams and acceptance matrices from that same contract.
5. Test all reachable event, controller, provider, proof, phase, and publication permutations, including negative and recovery cases.
6. Require source-to-contract and test-to-contract traceability; unresolved findings remain explicit.
7. No migration or runtime activation until an independent implementation agent has demonstrated conformance.
