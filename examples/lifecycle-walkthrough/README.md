# Lifecycle Walkthrough

This walkthrough shows the expected adoption path for a new repo:

1. install a strict `lite` profile,
2. promote to `standard` by wiring real release gates,
3. close the first phase with recorded evidence.

## 1. Lite Install

```bash
python3 -m pip install bcf-governance

bcf install \
  --target /tmp/demo-governed-app \
  --profile lite \
  --project-id demo-governed-app \
  --project-name "Demo Governed App" \
  --product-name "Demo Governed App" \
  --date "$(date -u +%F)" \
  --require-strict-validation
```

Expected result:

```text
installed governance pack into /tmp/demo-governed-app
profile: lite
validation: strict pass
```

The lite profile installs the core governed state and keeps release validation focused on `make governance-validate`.

## 2. Promote To Standard

Replace placeholder gate commands with real commands for the target stack. For a Python service:

```bash
bcf install \
  --target /tmp/demo-governed-app \
  --profile standard \
  --project-id demo-governed-app \
  --project-name "Demo Governed App" \
  --product-name "Demo Governed App" \
  --date "$(date -u +%F)" \
  --force \
  --gate-command "architecture-test=python3 -m pytest backend/tests/architecture" \
  --gate-command "architecture-module-size=python3 -m pytest backend/tests/architecture -k production_modules_respect_loc_cap" \
  --gate-command "architecture-layer-membership=python3 -m pytest backend/tests/architecture -k production_modules_map_to_exactly_one_layer" \
  --gate-command "architecture-context-membership=python3 -m pytest backend/tests/architecture -k production_modules_map_to_exactly_one_bounded_context" \
  --gate-command "architecture-import-boundaries=python3 -m pytest backend/tests/architecture -k do_not_import" \
  --gate-command "architecture-cqrs-side=python3 -m pytest backend/tests/architecture -k cqrs" \
  --gate-command "architecture-router-thinness=python3 -m pytest backend/tests/architecture -k routers_remain_thin" \
  --gate-command "architecture-duplication=python3 -m pytest backend/tests/architecture -k duplication" \
  --gate-command "lint=ruff check ." \
  --gate-command "typecheck=mypy ." \
  --gate-command "test=pytest tests" \
  --gate-command "contract-test=pytest tests/contracts" \
  --gate-command "security-secret-scan=gitleaks detect --source ." \
  --gate-command "security-dependency-audit=pip-audit" \
  --gate-command "security-sbom=syft dir:." \
  --gate-command "security-vulnerability-scan=trivy fs ." \
  --gate-command "runtime-smoke=docker compose config" \
  --require-strict-validation
```

Then inspect remaining adoption work:

```bash
bcf doctor --repo-root /tmp/demo-governed-app
```

Expected result:

```text
doctor-pass
```

If a command is still a placeholder, echo, no-op, or version probe, `bcf doctor` names the target to replace.

## 3. Phase Closeout

After implementing the first scoped workitems, update `phases/phase-01-log.yml` from `planned` to `verified` or `closed` and record evidence:

```yaml
document:
  status: verified
summary:
  outcome: governed foundation installed and validated
all_tickets_closed: true
required_suites_green:
  - make governance-validate
  - make architecture-test
  - make architecture-module-size
  - make architecture-layer-membership
  - make architecture-context-membership
  - make architecture-import-boundaries
  - make architecture-cqrs-side
  - make architecture-router-thinness
  - make architecture-duplication
  - make lint
  - make typecheck
  - make contract-test
  - make test
  - make security-secret-scan
  - make security-dependency-audit
  - make security-sbom
  - make security-vulnerability-scan
  - make runtime-smoke
ast_architecture_gates_green: true
health_checks_green: true
known_warnings: []
known_constraints:
  - release gates are wired to repo-native commands
execution_evidence:
  executed_commands:
    - command: make release-check
      result: pass
      executed_at_utc: "2026-04-25T00:00:00Z"
```

Move `plans/phase-ledger.yml` active phase lifecycle to `verified` or `closed` in the same change. Then run:

```bash
bcf validate --repo-root /tmp/demo-governed-app
bcf doctor --repo-root /tmp/demo-governed-app
```

A closeout is complete only when validation and doctor both pass.
