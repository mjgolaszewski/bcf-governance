# Release-train contract reconstruction — agent review

Status: **PROPOSED / NON-AUTHORITATIVE**. This branch is for review only; it must not change BCF's canonical runtime, CI graph, authority, release, or custody behavior.

## Purpose

Reconstruct the current release-train state DAG from `spec/RELEASE_TRAIN_STATE_DAG.md` and the implementation, then specify a single executable contract for independent agent validation.

Source audit snapshot: Git tree `7f18153d91b367c05f42a6c32a769fad586543cb`. The reconstruction was a source-informed partial audit, **not** an exhaustive caller/consumer conformance proof.

## Review order

1. Read [reconstruction findings](RECONSTRUCTION.md).
2. Read [implementation-agent handoff](AGENT_HANDOFF.md).
3. Compare all claims with the live code and the historical DAG; produce source-to-transition mapping and discrepancy reports.
4. Do not promote this review into authority or weaken an invariant to make tests green.

## Package provenance and scope

The complete original off-repository artifact package consists of:
- `release_train_contract.json` — proposed structural transition model (32 transitions, 15 invariants)
- `structural_contract_checker.py` — **structural** guard checker, not provider authority
- `RECONSTRUCTION_AND_RECOMMENDATIONS.md`
- `IMPLEMENTATION_AGENT_HANDOFF.md`

The two Markdown review summaries here are a **review staging copy**, not a byte-for-byte mirror of the original package. The original ZIP and machine-readable files were produced in the ChatGPT conversation and should be provided to the implementation agent as attachments for exact import. **Do not treat the absence of those files on this branch as successful complete staging.**

## Non-negotiable boundaries

- No candidate self-certification.
- No caller-authored Boolean guard becomes authority.
- Prepublication qualification of exact assets precedes immutable publication.
- Only terminal exact-main phase truth may authorize release.
- Fail closed on missing, stale, conflicting, or ambiguous provider state.
- Retain existing canonical owners; do not create a parallel state authority.
- Preservation and invalidation of proof must be exact and independently checked.
