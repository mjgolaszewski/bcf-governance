# Implementation agent review instructions

**Review only. Do not merge or activate this branch as runtime authority.**

## Objective

Build a complete, falsifiable, executable release-train contract from current BCF code and historical requirements, without introducing a second decision authority.

## Required deliverables

1. Full state and transition inventory including conditional/recovery subgraphs.
2. Exact source-to-contract traceability: function, caller, consumer, schema, graph node, workflow, tests.
3. Machine-readable contract with typed inputs, authenticated fact owners, guards, permitted effects, result schemas, and recovery.
4. Human-readable DAG mechanically generated from the same contract.
5. Conformance matrix: implemented / partial / missing / contradictory / superseded / unverified.
6. Adversarial acceptance tests, including malformed, stale, moved, wrong-subject, wrong-attempt, wrong-controller, provider conflict, partial publication, and qualification failures.
7. Prioritized non-destructive implementation plan with impact on existing authority and proof.

## Required acceptance conditions

- A green workflow alone never implies terminal truth.
- A bounded workitem proposition cannot authorize publication.
- Every exact-main push carries authenticated comparison context.
- Candidate execution cannot certify itself or mutate protected authority.
- Controller rotation cannot use target bytes as evidence of their own installation.
- Reuse requires exact applicability and preserved authority/freshness; ambiguity executes.
- PRUNE omissions are independently detected by truth.
- SPLINTER must cover exact unresolved nodes once, with no overlap, and preserve negative controls.
- Publication requires independently verified exact assets **and complete prepublication adopter qualification**.
- Missing prerequisite qualification cannot be backfilled after publication.
- Tags are never force-moved, releases never silently rebuilt, credentials retire on terminal paths.
- Recovery must preserve unrelated proof and expose only legal next actions.
- Lite, Standard-v3, regulated and self-managed controller lanes remain distinct.
- Existing tests, protection, permissions, release paths and custody are preserved unless explicitly superseded.

## Change-control rule

If the proposed contract conflicts with code or another contract, report a structured finding with exact source and evidence. Do not silently edit the requirement to match the implementation. Do not manufacture success with caller-supplied Boolean guards.

## Verification limitation

The preliminary ChatGPT audit did not execute repository CI or exhaustively inspect every caller. The implementation agent must complete that verification. No declaration of conformance is authorized by this branch alone.
