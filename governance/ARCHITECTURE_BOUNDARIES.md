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

## Template Rule Set

Adapt the rules to the target stack:

- domain code must not import HTTP frameworks, database clients, or cloud SDKs
- commands and queries must not import HTTP frameworks, request objects, or infrastructure clients directly
- handlers should coordinate commands, queries, domain logic, and ports without embedding business rules
- repository or port abstractions should define persistence contracts without SQLAlchemy or client imports
- routers should translate HTTP DTOs, status codes, and request context before delegating to handlers, commands, or queries
- infrastructure adapters should implement ports rather than leak client details into domain logic
- preserve public contracts by default; breaking changes require an explicit migration note and updated contract tests
- generic shared helpers are a last resort and require proven reuse
- frontend presentation components should not call HTTP directly
- route modules should be thin and delegate orchestration
- API DTOs should be mapped at the boundary before UI consumption

## Enforcement

Put boundary rules in tests. Prose is useful, but tests prevent drift.

Recommended lanes:

- AST import boundary tests
- dependency direction tests
- contract tests at public API boundaries
- fixtures that exercise real code paths rather than no-op green checks

The included `template-repo/backend/tests/architecture/test_boundaries_ast.py` is a starter skeleton for the CQRS-lite with strict ports layout.
