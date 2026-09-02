# BCF Governance

<p align="center">
  <img src="docs/assets/bcf-governance-pack-hero.jpg" alt="BCF Governance" width="760">
</p>

BCF is an executable governance framework for agent-led software delivery. It
is also usable by human-led teams that want explicit release rules, exact
evidence, and reproducible repository state. BCF keeps product scope, active
work, release gates, findings, and evidence in a small machine-readable model,
then separates two questions:

- `bcf validate`: is the governed repository structurally legal and internally
  consistent?
- `bcf truth`: are lifecycle and release claims supported by current evidence
  for the exact Git subject?

Development package version: `v1.0.0rc1`. The latest certified public release is
immutable `v0.8.0` while the 1.0 release-candidate train is under review.

## Why these defaults

AI-assisted development makes fast, broad changes practical, but a model's
output is probabilistic and its working context is bounded. BCF therefore
treats AI as a proposer and reviewer, not as the authority that certifies its
own work. Deterministic programs compute lifecycle and release state from
versioned policy and evidence; explicitly named human or service roles make the
few decisions that cannot be reduced to code.

BCF is intentionally opinionated about several engineering defaults:

- **CQRS-lite** separates state-changing commands from inspections. This makes
  it easier to distinguish a proposed change from a computed observation. It
  adds command and query boundaries, but does not require event sourcing.
- **Single-owner invariant principle (SOIP)** gives each governed
  representation, normalization, default, and state transition one canonical
  semantic owner. This limits inconsistent copies across code, tests, and
  workflows. Registry maintenance is an adoption cost, and structural
  ownership does not prove arbitrary business correctness.
- **Mechanical constraints** replace review discretion when a rule can be
  evaluated repeatably. They improve reproducibility and reduce dependence on
  any one agent's context. The rules and fixtures still need maintenance.
- **Causal negative controls** deliberately introduce a declared defect and
  require the responsible gate to fail for the declared reason. They provide
  stronger evidence than a green positive run alone, at the cost of additional
  compute.
- **Exact-commit evidence** binds receipts to commit, tree, workflow identity,
  run, and attempt. Similar files and green presentation labels cannot
  substitute for the certified subject. Stronger custody increases setup and
  storage work.
- **Bounded modules and context** reduce incomplete-context errors for agents
  and reviewers. Boundaries can require refactoring when a concept grows.
- **Cheap preflight before expensive work** catches deterministic defects
  before runner fanout. Preflight must remain fast and cannot replace deeper
  integration or runtime tests.

These are defaults rather than claims that every repository needs the same
architecture. Profiles and typed not-applicable records make scope explicit;
security boundaries and release claims still fail closed where the selected
profile requires them. See [Architecture](docs/ARCHITECTURE.md) for the design
and its limits.

## The Philosophy: Shifting from Human DevOps to Agentic DevSecOps

Traditional DevOps usually assumes that people are the scarce execution
engine. Reviews, runbooks, and CI summaries are shaped around changes that a
person can produce and keep in working memory. Coding agents change that
constraint: they can propose broad changes faster than a reviewer can
reconstruct every decision. Running the old control model at agent speed makes
reviewer memory and interpretation the safety boundary.

BCF moves that boundary into versioned contracts and deterministic programs:

| Human-centric DevOps default | Agentic DevSecOps default |
|---|---|
| Reviewer memory connects requirements, code, tests, and release state. | One canonical owner and machine-readable contracts connect each governed claim. |
| A green job shows that a command exited successfully. | Positive evidence plus a causal negative control shows what the gate detects. |
| A branch, tree, or familiar workflow name can stand in for the release subject. | Evidence binds the exact commit, tree, workflow bytes, run, and attempt. |
| CI runs expensive work, then people diagnose deterministic defects one at a time. | Cheap preflight rejects deterministic defects before fanout or costly gates. |
| Long-lived workers are trusted because the team operates them. | Candidate code is disposable; trusted control code is isolated and narrowly authorized. |
| A person interprets checks and decides whether the repository is verified. | Code computes verifiable lifecycle and release claims from policy and current evidence. |

This does not remove people from delivery. Humans still choose product intent,
risk appetite, architecture, exceptions, and whether to merge. Agents may
propose, implement, review, and remediate, but an agent cannot certify its own
output. The practical shift is simple: people govern the rules and the
decisions that require judgment; mechanical invariants decide the claims that
can be proved repeatably.

That stricter boundary costs setup time, control execution, and evidence
storage. It is useful when agent throughput would otherwise outrun reliable
human reconstruction; it is unnecessary ceremony for claims a repository does
not make. BCF profiles and typed N/A records keep that scope explicit.

## Lifecycle and evidence

Phase authors may report `planned` or `completed`. They cannot author
`verified`, `closed`, release readiness, suite health, security-review
completion, or finding closure.

`verified` is computed when every required claim has valid schema-2 evidence
from the governed commit and tree. `closed` additionally requires current
reconciliation, `findings_resolved` evidence, and no profile-blocking finding.
A relevant source, test, workflow, audit, or governance change makes affected
evidence stale.

Evidence capture executes exact argv from `governance/gate-contracts.yml` in
pristine detached worktrees. Every mandatory gate has a typed negative control;
arbitrary crashes, missing commands, timeouts, and all-skipped test lanes do not
prove the claimed behavior. Profile-v2 evidence shares one immutable session
manifest and rejects mixed commits, trees, runs, attempts, or producers.

CI-backed release claims use provider-authenticated workflow identity and an
ordered admission model. Candidate code runs on disposable workers; trusted
control and publication jobs do not check out or execute candidate code. The
GitHub reference implementation uses callbacks instead of runners that poll or
wait. See [CI authority](docs/CI_AUTHORITY.md).

## Governed CI graph

Profile-contract v2 repositories may make `governance/ci-graph.yml` the single
orchestration owner. It declares events, stable job IDs, descriptive names,
dependencies, resource classes, runner mappings, permissions, evidence fan-in,
truth, exact-main authority, scheduled controls, and optional release roles.
Project-specific behavior belongs in registered, digest-locked
`governance/ci-extensions/*.yml` files. Extensions can add bounded nodes and
edges, but cannot bypass preflight or truth, weaken trust and permissions, or
inject raw workflow YAML or unrestricted shell fragments.

Agents and maintainers edit those contracts. Deterministic code composes them,
checks that profile-required gates have exactly one pull-request owner, and
renders the GitHub workflows. Generated workflow files carry provenance and are
not an editing surface; byte drift fails validation. This keeps specialized CI
possible without making a probabilistic operator responsible for synchronizing
a pile of YAML.

The Standard-v2 reference graph includes cheap preflight, grouped evidence
lanes, exact run/attempt artifact fan-in, terminal truth, one main-push entry,
scheduled controls, and explicit candidate/trusted runner classes. It is a
starting contract, not a claim that one topology fits every repository. Mature
graphs should first be imported and preservation-checked, then expressed with
bounded extensions. No migration should proceed merely to change ownership if
it cannot preserve behavior and meet the repository's performance threshold.

## Install

Install the current published wheel:

```bash
python3 -m pip install https://github.com/mjgolaszewski/bcf-governance/releases/download/v0.8.0/bcf_governance-0.8.0-py3-none-any.whl
```

Immutable `bcf_governance-0.8.0-py3-none-any.whl` is the published
installation source. The 1.0.0rc1 development tree builds
`bcf_governance-1.0.0rc1-py3-none-any.whl`; it is not an installation source until
its own exact-main certification and immutable release complete.

Git is required. `lite` is the bootstrap profile:

```bash
bcf install \
  --target /path/to/repo \
  --profile lite \
  --project-id example \
  --project-name "Example" \
  --require-strict-validation
```

Fresh Standard and Regulated installs use profile contract v2 and require a
complete configuration before mutation:

```bash
bcf install \
  --target /path/to/repo \
  --profile standard \
  --profile-config /path/to/standard-gates.yml \
  --project-id example \
  --project-name "Example" \
  --candidate-runner-label ubuntu-24.04 \
  --candidate-runner-kind hosted \
  --trusted-runner-label self-hosted \
  --trusted-runner-label example-trusted-control \
  --trusted-runner-kind self-hosted \
  --require-strict-validation
```

Promotion and GitHub CI adoption are separate, explicit transactions:

```bash
bcf profile promote --repo-root . --to standard --contract-version 2.0 --check
bcf profile promote --repo-root . --to standard --contract-version 2.0 --apply
bcf ci graph validate --repo-root .
bcf ci graph diagnose --repo-root .
bcf ci graph render --repo-root . --check
bcf ci adopt github --repo-root . --check
# Repeat with --apply after reviewing the check output.
```

Use `--adoption-mode existing` for an established repository. Normal
`bcf install --upgrade` refreshes pack-owned runtime and schema files while
preserving project-owned profile, gate, evidence, graph, extension, and workflow
bytes. Legacy contracts move only through the explicit, fail-closed
`bcf migrate-contract` command. The destructive replacement path is the
explicitly confirmed `--force-rescaffold`; BCF has no generic `--force` bypass.

The 1.0 release-candidate contract supports Linux x86-64 and CPython 3.11–3.14.
GitHub is its only executable CI provider and GitHub Releases is its distribution
channel. The mechanically frozen CLI surface is the top-level command inventory
and its exit-code classes; nested arguments remain documented interfaces until
the stable-release review completes.

## Operate

```bash
bcf validate
bcf exposure-scan
bcf doctor --repo-root .
bcf preflight --repo-root . --mode pr
bcf ci local-pr --repo-root .
bcf evidence run --gate test --output .artifacts/bcf/test
bcf truth --evidence-dir .artifacts/bcf
```

`README.md`, `LICENSE`, and `CHANGELOG.md` are governed root artifacts. Every
pull request updates the changelog against its exact base SHA. Evidence bundles
stay outside the tracked tree and are retained by digest in CI or release
storage.

## Package development

```bash
python3 -m pip install -e ".[dev]"
python3 -m pytest tests
python3 .github/scripts/run_validator_mutants.py --profile high-value
```

The packaged implementation lives under `bcf_governance`. Root scripts are
thin source-checkout wrappers; installed standalone tooling uses the private
`scripts/_bcf_runtime` namespace. Contract tests keep canonical and generated
copies byte-identical.

## Documentation map

| Document | Canonical responsibility |
|---|---|
| [Architecture](docs/ARCHITECTURE.md) | Design positions, boundaries, costs, and limitations |
| [CI authority](docs/CI_AUTHORITY.md) | State flow, trust boundary, admission, and GitHub reference topology |
| [Using BCF](docs/USAGE.md) | Operator commands, profiles, adoption, evidence, cleanup, and safety |
| [Maintaining BCF](docs/MAINTAINING.md) | Source ownership, tests, generation, editorial checks, and releases |
| [Installed operations](template-repo/docs/OPERATIONS.md) | Runbook copied into governed repositories |

The adoption, cleanup, hotfix, model-risk, and walkthrough material in the
template repository branches from those owners and is scoped to its named
procedure. BCF is licensed under the [MIT License](LICENSE); release history is
in the [changelog](CHANGELOG.md).
