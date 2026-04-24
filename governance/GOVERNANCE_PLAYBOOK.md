# Governance Playbook

## Purpose

Use governance files as executable project state. The goal is to make product scope, delivery sequence, active work, evidence, and release readiness inspectable without relying on operator memory.

## Authority Order

Use this order when artifacts disagree:

1. user or owner instructions
2. `AGENTS.yml`
3. product spec
4. build plan
5. phase ledger
6. `governance-profile.yml` and `architecture-boundaries.yml`
7. `MEMORY.yml`
8. phase logs

`AGENTS.yml` defines how the system works. It should not become a transcript.

## Canonical Artifacts

- `AGENTS.yml`: governance rules, authority ordering, architecture policy, quality policy.
- `governance-profile.yml`: selected adoption profile and release gate classification.
- `architecture-boundaries.yml`: configurable source roots, layer tokens, and AST import rules.
- `schemas/*.json`: structural contracts for governed YAML artifact shapes.
- `MEMORY.yml`: stable decisions, environment facts, reusable commands, active artifact pointers.
- `plans/product-spec.yml`: product scope, positioning, constraints, phase catalog.
- `plans/build-plan.yml`: machine-readable sequence, gates, dependencies, delivery rules.
- `plans/phase-ledger.yml`: active phase, validation commands, hotfix lane, release train status.
- `plans/phase-NN-plan.yml`: scoped phase contract.
- `plans/phase-NN-workitems.yml`: phase workitem ledger.
- `phases/phase-NN-log.yml`: execution evidence and closeout.
- `phases/phase-NN-hotfix##.yml`: governed hotfix execution evidence tied to the last landed phase.

## Change Rules

- Default to the smallest valid vertical slice rather than broad cross-cutting refactors.
- Behavior or environment contract changes update the spec, build plan, phase ledger, memory, and tests together.
- Public contracts are preserved by default unless an explicit instruction authorizes a breaking change and the migration note is recorded.
- Active phase rollover updates `plans/phase-ledger.yml` and `MEMORY.yml` in the same change.
- `document.path` values must be repo-relative POSIX paths and must exactly match artifact locations.
- Governance validation should run structural schema checks before semantic cross-artifact checks.
- Governance changes run semantic validation, not only YAML parsing.
- Declared phase catalogs in the product spec and build plan must stay aligned.
- Phase workitems must cover phase-plan deliverables, and phase-log workitem status must stay aligned with the workitem ledger.
- Completed release trains must retain non-planned governed history for every declared phase they include.
- Release gates must fail closed until repo-specific commands are wired; placeholder or echo-only gates are not acceptable release evidence.
- Execution evidence goes in phase logs.
- Repeated fields need a declared canonical owner.

## Adoption Profiles

- `lite`: use for prototypes or small internal services that need active state, memory, build sequence, and validation without full evidence overhead.
- `standard`: use for production-bound agent-led work that needs phase plans, workitems, logs, architecture gates, and configured release checks.
- `regulated`: use when provenance, hotfix reconciliation, security evidence, SBOM/vulnerability checks, or formal release closeout are mandatory.

Start with the smallest profile that matches the risk. Raise the profile when release, audit, security, or team coordination pressure increases.

## Active Phase Lifecycle

Use these statuses:

- `planned`: artifacts exist and work is defined.
- `active`: implementation is in flight.
- `blocked`: execution is stopped until `blocked_reason` and `unblock_condition` are resolved.
- `paused`: execution is intentionally parked until `paused_reason` and `resume_condition` are resolved.
- `completed`: implementation is done and acceptance-critical checks are ready or partially run.
- `verified`: required checks passed in the required environment.
- `closed`: verified and included in the latest required rerun for the touched scope.
- `abandoned`: the phase will not continue and the abandonment reason is recorded.

## Phase Log Statuses

Phase log documents use the narrower closeout taxonomy:

- `planned`
- `completed`
- `verified`
- `closed`

## Minimum Closeout Evidence

A verified or closed phase log should include:

- `all_tickets_closed`
- `required_suites_green`
- `ast_architecture_gates_green`
- `health_checks_green`
- `known_warnings`
- `known_constraints`

## Operating Rhythm

1. Open a phase with the scaffold script.
2. Execute only the scoped workitems.
3. Record command evidence in the phase log.
4. Update `MEMORY.yml` only for stable decisions and durable facts, and revalidate aging environment facts on phase rollover.
5. Run governance validation before closeout.
6. Open the successor phase before moving the active pointer.
