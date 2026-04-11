# Artifact Ownership

## Canonical Owner Map

Use one canonical owner for each repeated concept:

| Concept | Canonical owner |
| --- | --- |
| Governance rules and authority order | `AGENTS.yml` |
| Product scope and phase catalog | `plans/product-spec.yml` |
| Delivery sequence and dependencies | `plans/build-plan.yml` |
| Active phase and validation commands | `plans/phase-ledger.yml` |
| Durable context and active artifact pointers | `MEMORY.yml` |
| Execution evidence | `phases/*.yml` |
| Release and operations commands | `docs/OPERATIONS.md` and Makefile |

## Duplication Rules

- Mirrored fields must change with their canonical source.
- Derived fields should say what they derive from.
- Phase ids, build blocks, and artifact paths should be validated across files.
- Historical phase artifacts should not remain `planned` after a successor is active.

## Practical Review Checklist

- Does this change alter product behavior, environment assumptions, release gates, or governance?
- If yes, did the relevant canonical owner change?
- Did `MEMORY.yml` change only for durable facts?
- Did phase logs receive execution evidence instead of governance prose?
- Did validation commands run and get recorded?
