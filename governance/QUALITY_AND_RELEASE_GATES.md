# Quality And Release Gates

## Baseline Gate Families

Adapt these to the target stack:

- governance validation
- architecture module-size tests
- architecture layer-membership tests
- architecture bounded-context membership tests
- architecture import-boundary tests
- architecture CQRS side-effect and read-model separation tests
- architecture router-thinness tests
- architecture bounded-context duplication tests
- lint
- typecheck
- unit tests
- integration tests
- API or contract tests
- browser or end-to-end tests when there is a UI
- adversarial or boundary-condition tests for critical APIs
- database integration tests when persistence exists
- performance or soak rehearsal for long-running workflows
- secret scanning
- SBOM generation and vulnerability scanning
- Docker compose validation
- production image build
- production runtime smoke check

## Suggested Make Targets

- `make governance-validate`
- `make architecture-test`
- `make architecture-module-size`
- `make architecture-layer-membership`
- `make architecture-context-membership`
- `make architecture-import-boundaries`
- `make architecture-cqrs-side`
- `make architecture-router-thinness`
- `make architecture-duplication`
- `make lint`
- `make typecheck`
- `make test`
- `make contract-test`
- `make security-secret-scan`
- `make security-dependency-audit`
- `make security-sbom`
- `make security-vulnerability-scan`
- `make runtime-smoke`
- `make release-check`

## Gate Policy

- A phase can be complete only for its declared scope.
- Governance validation should cover structural schema validation and semantic cross-artifact validation.
- `governance-profile.yml` declares whether each gate is `required`, `optional`, `deferred`, or `not_applicable`.
- `required` gates must be invoked by `make release-check`.
- `optional` gates may be omitted from `make release-check`, but if they are invoked they must be real commands that satisfy their declared command policy.
- `deferred` and `not_applicable` gates must not be invoked by `make release-check`.
- Starter placeholder targets must fail closed. An instantiated repo must replace them with repo-specific commands before validation can pass.
- Echo-only, placeholder, version-probe, or no-op gates are not release evidence.
- Contract-first sequencing is the default: contracts, ports, tests, use case, router, and infrastructure only as required.
- Public contracts are preserved by default; breaking changes require explicit authorization, a migration note, and updated contract tests.
- A release candidate should run the broadest gate that covers touched surfaces.
- Router contract tests should cover request validation, response schemas, and HTTP status mapping when public behavior changes.
- Repository or adapter contract tests should run when ports, query semantics, persistence mappings, or transaction behavior change.
- Security scans should publish machine-readable artifacts.
- Runtime smoke checks should run outside the dev-only dependency environment.
- Generated clients or SDKs should be checked for drift when API contracts change.
- Required push CI lanes should be declared when a hosted or local runner is available, and jobs must be self-seeding rather than relying on ambient workstation state.
- Every mandatory architectural rule should have an executable baseline gate or an explicit `human_review_only` rationale.

## Evidence Policy

Record evidence in `phases/phase-NN-log.yml`:

- commands run
- pass/fail summary
- known warnings
- known constraints
- follow-up work

Avoid writing evidence into `AGENTS.yml`; keep it instruction-only.
