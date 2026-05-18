# Architecture Boundaries

## Source Pattern

The template pack now encodes CQRS-lite with strict ports:

- command = mutation use case
- query = read use case
- handler = orchestration only
- domain = rules
- repository or port = persistence contract
- infrastructure = SQLAlchemy and external systems
- router = HTTP translation only

This is intentionally lighter than full CQRS. The template does not require buses, event sourcing, or separate read models by default. It does require an explicit separation between mutation use cases, read use cases, orchestration, domain rules, ports, and adapters.

The starter policy also requires deliberate structural guardrails:

- production modules must stay under the configured LOC cap, defaulting to 800 lines
- every production module must map to exactly one architectural layer
- every production module must map to exactly one bounded context or domain concern
- command-side code may mutate state through ports but must not return read-model shapes
- query-side code may return read models but must not mutate state
- routers and controllers validate transport input, invoke application commands or queries, and map responses only
- domain services and entities contain business rules only and must not import infrastructure, framework, persistence, cache, queue, cloud, HTTP, or telemetry clients directly
- repositories and adapters contain persistence and integration details only
- shared abstractions require ownership, tests, rationale, and at least two real call sites unless an explicit shared-kernel decision exists

If a requested change would violate the LOC cap or cross a DDD/CQRS boundary, stop and propose a module split or boundary update before editing.

## Delivery Default

Changes should land in the smallest valid vertical slice.

Default sequence:

1. define or update contracts
2. define or update ports
3. add or update tests
4. implement the use case or handler
5. wire the router
6. update infrastructure only if required

The pack does not require one exact filesystem shape. It does require that ownership and dependency boundaries remain explicit.

## Recommended Slice Shape

Use this as the default feature-local shape when the repo does not already define a better one:

- `contract.py`: request DTOs, response DTOs, command/query inputs, stable public schema
- `policy.py`: authorization or capability decisions when needed
- `use_case.py`: orchestration, transaction coordination, calling domain rules and ports
- `ports.py`: repository and external-service contracts
- `domain.py`: business invariants, value objects, state transitions
- `router.py`: HTTP definitions, dependency injection, request/response translation, status mapping
- `repo_sqlalchemy.py`: SQLAlchemy implementation of ports when persistence is touched
- `tests/`: use case, router contract, and repository contract coverage as needed

Commands and queries are operation kinds, not required directory names. Repos may model them in separate modules or as clearly named operations inside `use_case.py`.

## Configurable Rule Set

The starter rules live in `architecture-boundaries.yml`. Adapt that file to the target stack before treating `make architecture-test` as release evidence.

The config declares:

- `source_roots`: repo-relative roots scanned for Python files.
- `layers`: named boundary layers.
- `path_tokens`: directory names that identify each layer.
- `forbidden_import_prefixes`: framework, client, or persistence imports denied in that layer.
- `forbidden_layer_imports`: layer names this layer must not import.
- `forbidden_import_names`: specific imported symbols denied in that layer.

The default policy encodes these rules:

- domain code must not import HTTP frameworks, database clients, or cloud SDKs
- commands and queries must not import HTTP frameworks, request objects, or infrastructure clients directly
- handlers should coordinate commands, queries, domain logic, and ports without embedding business rules
- repository or port abstractions should define persistence contracts without SQLAlchemy or client imports
- routers should translate HTTP DTOs, status codes, and request context before delegating to handlers, commands, or queries
- infrastructure adapters should implement ports rather than leak client details into domain logic
- preserve public contracts by default; breaking changes require an explicit migration note and updated contract tests
- generic shared helpers are a last resort and require proven reuse
- duplicated logic inside one bounded context should be detected by executable gates before it becomes structural drift
- frontend presentation components should not call HTTP directly
- route modules should be thin and delegate orchestration
- API DTOs should be mapped at the boundary before UI consumption

## Enforcement

Put boundary rules in tests. Prose is useful, but tests prevent drift.

Recommended lanes:

- AST import boundary tests
- production module LOC tests
- layer and bounded-context membership tests
- command/query side-effect and read-model separation tests
- router thinness tests
- bounded-context duplication tests
- dependency direction tests
- contract tests at public API boundaries
- fixtures that exercise real code paths rather than no-op green checks

The included `template-repo/backend/tests/architecture/test_boundaries_ast.py` is a config-driven starter skeleton for the CQRS-lite with strict ports layout. It defaults to `backend/src`, but reads `architecture-boundaries.yml` so non-default source roots and layer names do not require editing the test code first.
