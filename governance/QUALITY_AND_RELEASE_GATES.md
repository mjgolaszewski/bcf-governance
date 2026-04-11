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
- A release candidate should run the broadest gate that covers touched surfaces.
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
