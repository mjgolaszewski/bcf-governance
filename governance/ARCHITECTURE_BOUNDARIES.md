# Architecture Boundaries

## Source Pattern

The source repo uses strict DDD/CQRS and hexagonal boundaries:

- domain layer stays framework-free and side-effect free
- application layer coordinates use cases, buses, ports, and policies
- interface layer owns HTTP and request/response contracts
- infrastructure layer owns persistence, cache, telemetry, and external service adapters
- shared CQRS dispatch primitives stay centralized

## Template Rule Set

Adapt the rules to the target stack:

- domain code must not import HTTP frameworks, database clients, or cloud SDKs
- application code must not import HTTP frameworks directly
- interfaces should delegate to application handlers or buses
- infrastructure adapters should implement ports rather than leak client details into domain logic
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

The included `template-repo/backend/tests/architecture/test_boundaries_ast.py` is a starter skeleton.
