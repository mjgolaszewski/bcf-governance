# Template And Governance Pack

This pack is a reusable governance system for agent-led software delivery.

Current release: `v0.1.0`.

It is intentionally split into two parts:

- `template-repo/`: files you can copy into a new repository and replace placeholder values.
- `governance/`: playbooks that explain the operating model behind the templates.
- `bcf`: installable CLI for installing, validating, scaffolding, and diagnosing governed artifacts.
- `scripts/`: source-compatible helper scripts kept for direct repo use and template installs.
- `template-repo/schemas/`: structural schemas for governed YAML artifacts.

## Source Model

This pack is based on these repo conventions:

- `AGENTS.yml` is the canonical governance authority.
- `MEMORY.yml` is durable project memory, not a transcript.
- `governance-profile.yml` declares whether the repo is using the lite, standard, or regulated profile and how release gates are classified.
- `architecture-boundaries.yml` configures source roots, layer path tokens, and forbidden imports for the AST architecture gate.
- `plans/build-plan.yml` is the machine-readable delivery sequence.
- `plans/phase-ledger.yml` is the active-phase pointer and validation command ledger.
- `plans/phase-NN-plan.yml`, `plans/phase-NN-workitems.yml`, and `phases/phase-NN-log.yml` keep execution scoped and auditable.
- `bcf validate` prevents cross-artifact drift.
- `schemas/*.json` define the structural contract for governed YAML artifacts.
- `document.path` values are repo-relative POSIX paths and must exactly match each artifact location.
- `bcf validate` now checks the full declared phase catalog, workitem/log consistency, completed release-train history coverage, and hotfix log alignment.
- `bcf validate` now runs structural schema validation before semantic cross-artifact checks.
- `bcf validate` fails on unresolved placeholders in instantiated governed artifacts.
- `bcf validate` rejects placeholder, echo-only, no-op, and version-probe release gates before `make release-check` is trusted.
- `bcf install` installs the pack into a target repo, replaces placeholders, applies a profile, and opens the first governed phase.
- `bcf scaffold` creates phase and hotfix artifacts with the expected shape and names hotfix logs as `phase-NN-hotfix##.yml`.
- `bcf doctor` reports unresolved placeholders, unwired release gates, inactive gate invocations, and non-evidence gate commands.
- backend governance defaults to CQRS-lite with strict ports rather than full CQRS.
- backend delivery defaults to contract-first vertical slices with public-contract preservation by default.
- architecture rules are enforced with tests, not prose alone.
- validator output can stay human-readable by default or switch to compact machine-readable JSON.
- release gates include governance validation, lint, typecheck, tests, contract checks, security checks, and Docker/runtime checks as appropriate for the repo.

## Bootstrap A New Repo

Install the CLI from a released source archive, local checkout, or Git URL:

```bash
python3 -m pip install .
bcf --version
```

Then install the pack into a target repo:

```bash
bcf install \
  --target /path/to/target-repo \
  --profile standard \
  --project-id your-project \
  --project-name "Your Project" \
  --product-name "Your Product" \
  --date "$(date -u +%F)"
```

The installer:

- copies `template-repo/` into the target repo
- removes the `phase-NN` example artifacts after copying
- replaces known placeholders, including hidden workflow files
- applies the requested `lite`, `standard`, or `regulated` profile
- generates the first active phase artifacts
- refuses to overwrite existing governance files unless `--force` is passed
- runs strict validation when possible and falls back to bootstrap validation when standard or regulated release gates still need repo-specific commands

For a minimal installation that can pass strict validation before repo-specific release gates are wired:

```bash
bcf install \
  --target /path/to/target-repo \
  --profile lite \
  --project-id your-project \
  --project-name "Your Project" \
  --require-strict-validation
```

For standard or regulated installs, wire real gate commands during install when they are already known:

```bash
bcf install \
  --target /path/to/target-repo \
  --profile standard \
  --project-id your-project \
  --date "$(date -u +%F)" \
  --gate-command "architecture-test=python3 -m pytest backend/tests/architecture" \
  --gate-command "lint=ruff check ." \
  --gate-command "typecheck=mypy ." \
  --gate-command "test=pytest tests" \
  --gate-command "contract-test=pytest tests/contracts" \
  --require-strict-validation
```

The installer intentionally does not edit an existing repo Makefile. After installation, merge `Makefile.fragment` into the repo Makefile or include it from the repo Makefile.

Use doctor to see remaining wiring gaps:

```bash
bcf doctor --repo-root /path/to/target-repo
bcf doctor --repo-root /path/to/target-repo --format json --compact
```

Generate hotfix logs with the helper if urgent repair work appears:

```bash
bcf scaffold hotfix \
  --project-id your-project \
  --hotfix-id HF-001 \
  --mode full \
  --hotfix-number 1 \
  --summary "release-blocking fix" \
  --related-phase-id P01 \
  --date "$(date -u +%F)" \
  --validation-command "make governance-validate" \
  --validation-command "make release-check"
```

Install governance dependencies and run validation before the first governed commit:

```bash
python3 -m pip install -r requirements-governance.txt
bcf validate
bcf validate --format json --compact
```

Use the scaffold helpers for real `plans/phase-*.yml` and `phases/phase-*.yml` artifacts. The `phase-NN` files in the pack are templates, not long-term working files.

## Governance Profiles

Choose the smallest profile that proves the current risk:

- `lite`: `AGENTS.yml`, `MEMORY.yml`, product/build/ledger state, scaffolding, and validation.
- `standard`: lite plus phase plans, workitems, logs, architecture gates, and configured release gates.
- `regulated`: standard plus provenance, hotfix formalism, security/SBOM evidence, and full release-gate closeout.

The template defaults to `standard` in `governance-profile.yml`. Gate statuses mean:

- `required`: `release-check` must invoke the gate and the target must satisfy its declared command policy.
- `optional`: `release-check` may omit the gate, but if invoked the target must satisfy its declared command policy.
- `deferred`: known future gate; do not invoke it from `release-check` yet.
- `not_applicable`: intentionally absent; do not invoke it from `release-check`.

If a gate is genuinely not applicable, mark it `not_applicable` or `deferred` with a rationale and remove it from `release-check`; do not leave a fake Make target in place.

## Example Walkthrough

See `examples/lifecycle-walkthrough/` for a complete adoption walkthrough: strict lite install, standard promotion with real gate commands, and phase closeout evidence.

## Recommended First Commit Shape

For a new repo, keep the first governance commit small:

- root governance files: `AGENTS.yml`, `MEMORY.yml`
- profile and architecture config: `governance-profile.yml`, `architecture-boundaries.yml`
- plan files: `plans/product-spec.yml`, `plans/build-plan.yml`, `plans/phase-ledger.yml`
- first phase files generated by the scaffold script
- hotfix logs generated by the scaffold script when urgent repair work is required
- scripts: `scripts/validate_governance_yaml.py`, `scripts/scaffold_governance_artifacts.py`
- release and architecture test hooks appropriate to the stack

## Notes

The templates use YAML because the source repo treats governance as machine-readable project state. Keep execution evidence in phase logs, not in `AGENTS.yml`.
Structural shape lives in `schemas/`; semantic truth lives in `scripts/validate_governance_yaml.py`.
Keep `document.path` values repo-relative, POSIX-style, and exact; generated artifacts already do this.

For AI task-scoping guidance that should remain optional rather than validator-enforced, use `governance/AGENT_TASK_CONTRACT.md`.

To sanity-check this uninstantiated template pack before replacing placeholders, run:

```bash
bcf validate --repo-root template-repo --allow-placeholders --allow-release-gate-placeholders
```

For pack maintenance in this repo itself, the main self-checks are:

- `pytest tests`
- `python3 .github/scripts/run_validator_mutants.py --profile high-value`
- `python3 .github/scripts/run_validator_mutants.py --profile full`
