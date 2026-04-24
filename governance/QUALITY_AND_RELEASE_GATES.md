# Quality And Release Gates

## Baseline Gate Families

Adapt these to the target stack:

- governance validation
- architecture boundary tests
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
- `make lint`
- `make typecheck`
- `make test`
- `make contract-test`
- `make security-scan`
- `make docker-build`
- `make docker-runtime-smoke`
- `make release-check`

## Gate Policy

- A phase can be complete only for its declared scope.
- Governance validation should cover structural schema validation and semantic cross-artifact validation.
- `governance-profile.yml` declares whether each gate is `required`, `optional`, `deferred`, or `not_applicable`.
- `make release-check` must invoke every required or optional gate declared by the active profile.
- Starter placeholder targets must fail closed. An instantiated repo must replace them with repo-specific commands before validation can pass.
- Echo-only, placeholder, or no-op gates are not release evidence.
- Contract-first sequencing is the default: contracts, ports, tests, use case, router, and infrastructure only as required.
- Public contracts are preserved by default; breaking changes require explicit authorization, a migration note, and updated contract tests.
- A release candidate should run the broadest gate that covers touched surfaces.
- Router contract tests should cover request validation, response schemas, and HTTP status mapping when public behavior changes.
- Repository or adapter contract tests should run when ports, query semantics, persistence mappings, or transaction behavior change.
- Security scans should publish machine-readable artifacts.
- Runtime smoke checks should run outside the dev-only dependency environment.
- Generated clients or SDKs should be checked for drift when API contracts change.

## Evidence Policy

Record evidence in `phases/phase-NN-log.yml`:

- commands run
- pass/fail summary
- known warnings
- known constraints
- follow-up work

Avoid writing evidence into `AGENTS.yml`; keep it instruction-only.
