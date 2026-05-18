# Architecture Boundaries

## Source Pattern

The template encodes CQRS-lite with strict ports: commands mutate through ports, queries do not mutate, handlers orchestrate, domain owns business rules, ports define persistence contracts, adapters implement integrations, and routers translate HTTP then delegate.

Repo evidence: `template-repo/AGENTS.yml`, `template-repo/architecture-boundaries.yml`.

## Structural Rules

Default structural gates cover production module LOC cap, exactly-one layer, exactly-one bounded context, forbidden imports, CQRS command/query separation, router thinness, bounded-context duplication, and shared abstractions with at least two real call sites.

If a requested change violates a boundary or LOC cap, stop and propose a module split or boundary update before editing.

Repo evidence: `template-repo/backend/tests/architecture/test_boundaries_ast.py`, `tests/test_template_architecture_gate.py`.

## Delivery Default

Use the smallest valid vertical slice: contracts, ports, tests, use case or handler, router, and infrastructure adapter only when required. Preserve public contracts unless explicitly authorized.

Repo evidence: `template-repo/AGENTS.yml` contract-first rules and review gate.

## Configuration

Adapt `architecture-boundaries.yml` before treating `make architecture-test` as release evidence. The config controls source roots, layer tokens, context tokens, forbidden import prefixes, forbidden layer imports, CQRS tokens, router complexity, duplication threshold, and shared-helper tokens.

Repo evidence: `template-repo/architecture-boundaries.yml`, `template-repo/schemas/architecture-boundaries.schema.json`.

## Enforcement

Boundary rules belong in executable tests, not prose alone. The included AST harness reads `architecture-boundaries.yml` and defaults to `backend/src`.

Repo evidence: `template-repo/Makefile.fragment`, `template-repo/backend/tests/architecture/test_boundaries_ast.py`.
