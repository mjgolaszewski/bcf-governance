# BCF Governance

<p align="center">
  <img src="docs/assets/bcf-governance-pack-hero.jpg" alt="BCF Governance" width="760">
</p>

BCF is a deterministic error-correction framework for software produced by
probabilistic artificial-intelligence agents. It is designed specifically to
govern agent-led delivery by moving structural, evidentiary, lifecycle, and
release authority into deterministic programs and explicit human decisions;
human-led development is not its design target. BCF keeps product scope, active
work, release gates, findings, and evidence in a machine-readable model, then
separates two questions:

- `bcf validate`: is the governed repository structurally legal and internally
  consistent?
- `bcf truth`: are lifecycle and release claims supported by current evidence
  for the exact Git subject?

Development package version: `v1.0.2`. Release artifacts are published through
immutable GitHub Releases after exact-main certification.

## Design thesis

A capable coding agent remains a probabilistic software producer. It can reason
incorrectly from incomplete context, drift across successive changes, create a
second interpretation of an existing rule, write a plausible test that agrees
with an incorrect implementation, or overstate what a green run establishes.
This is an engineering failure model, not a claim that models are incompetent
or malicious.

BCF assumes some of those errors will occur. It does not principally respond by
asking the producer to be more careful. It places deterministic constraints,
independent observations, causal challenges, exact provenance, and computed
claims around the production process:

> Generate probabilistically → constrain structurally → challenge causally
> → observe exactly → compute truth deterministically.

Common failure modes have explicit responses:

| Failure mode | BCF response |
|---|---|
| Incomplete context | Bounded modules and context budgets |
| Architectural drift | Executable architecture boundaries |
| Competing representations | Single-owner invariant principle (SOIP) |
| Test agrees with a defective implementation | Causal negative controls |
| Gate does not detect its claimed defect | Typed failure oracles |
| Test population silently changes | Exact test manifests |
| CI topology drifts | Canonical compiled CI graph |
| Stale evidence appears current | Exact-tree binding and invalidation |
| A rerun borrows an earlier success | Exact run, attempt, and session custody |
| Producer declares terminal success | Computed lifecycle state |
| Candidate certifies itself | Independent truth and trusted authority |
| Hidden worker state affects results | Pristine worktrees and fresh candidate workers |
| Released bytes differ from verified bytes | Certified no-rebuild publication |

BCF deliberately permits redundant verification while resisting duplicated
semantic authority. Tests challenge an implementation; negative controls
challenge the tests; truth recomputes evidence; trusted code reconstructs
provider state; hashes challenge artifacts; and rendered workflows are checked
against their one graph owner. The goal is multiple observations of one defined
claim, not multiple competing definitions of it.

Human authority remains necessary. People choose intent, risk appetite,
architecture, exceptions, merges, and publication. That boundary does not make
human-led development a BCF target. An agent may propose implementation or
policy, but it cannot authenticate provider facts or author authoritative
workflow bytes; an agent cannot certify its own output or determine lifecycle
and release state. Mechanical invariants decide only the claims that the
repository has made mechanically decidable.

## What BCF establishes

A green BCF result establishes only the claims represented by the selected
profile, current contracts, and accepted evidence for the exact subject. It
does not discover an omitted requirement, prove arbitrary business correctness,
establish the absence of every vulnerability, or repair incorrect product
intent. Deterministic evaluation is only as sound as its inputs and rules.

If one authority may redefine intent, implementation, tests, and governing
policy together, internal consistency cannot prove the original intent was
right. Independent acceptance criteria, review, and policy authority increase
assurance where that risk matters. BCF reduces dependence on probabilistic
correctness; it does not turn an incomplete or incorrect specification into a
correct one.

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

These are reliability biases, not claims that every repository needs the same
architecture. Architectural flexibility is intentionally exchanged for
additional structural predictability where the selected profile and repository
configuration choose these controls. Thresholds such as module budgets are
explicit, configurable heuristics that can be measured and challenged; they are
not universal laws. Profiles and typed not-applicable records make scope
explicit, while selected security boundaries and release claims fail closed.
See [Architecture](docs/ARCHITECTURE.md) for the detailed design and limits.

## Verification cost and scope

BCF may perform more computation than conventional CI: structural checks,
behavioral tests, causal controls, isolated worktrees, exact-manifest checks,
evidence capture, provider-state reconstruction, truth recomputation, artifact
verification, and scheduled controls. That overhead is real. The intended
trade is to spend machine time to protect correctness and conserve human
attention.

This is not a claim that more tests are always better. BCF runs cheap
deterministic preflight before expensive fanout, gives negative controls a
declared invariant and failure oracle, separates scheduled assurance from PR
latency, and permits graph optimization without dropping required controls. A
single change may take longer to validate even if fewer defects, remediation
cycles, and reconstruction tasks improve sustainable delivery throughput.

BCF has not established a universal return on that trade. The useful empirical
question is how much compute and latency buy how much reduction in escaped
defects, drift, remediation, and human reconstruction for a given repository.
Lite is appropriate when the stronger assurance cost is unjustified. The
[Reliability model](docs/RELIABILITY_MODEL.md) addresses the common objections,
operational costs, and measurements in more detail.

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

Install the `v1.0.2` wheel from its immutable GitHub Release:

```bash
python3 -m pip install https://github.com/mjgolaszewski/bcf-governance/releases/download/v1.0.2/bcf_governance-1.0.2-py3-none-any.whl
```

GitHub Releases is the supported distribution channel. Release publication
uses the exact certified wheel and source archive without rebuilding them in
the publisher.

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

The 1.0 contract supports Linux x86-64 and CPython 3.11–3.14.
GitHub is its only executable CI provider and GitHub Releases is its distribution
channel. The mechanically frozen CLI surface is the top-level command inventory
and its exit-code classes; nested arguments remain documented interfaces governed
by the published compatibility and deprecation policy.

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
| [Reliability model](docs/RELIABILITY_MODEL.md) | Failure model, verification economics, objections, limits, and empirical measures |
| [Architecture](docs/ARCHITECTURE.md) | Design positions, boundaries, costs, and limitations |
| [CI authority](docs/CI_AUTHORITY.md) | State flow, trust boundary, admission, and GitHub reference topology |
| [Using BCF](docs/USAGE.md) | Operator commands, profiles, adoption, evidence, cleanup, and safety |
| [Maintaining BCF](docs/MAINTAINING.md) | Source ownership, tests, generation, editorial checks, and releases |
| [Installed operations](template-repo/docs/OPERATIONS.md) | Runbook copied into governed repositories |

The adoption, cleanup, hotfix, model-risk, and walkthrough material in the
template repository branches from those owners and is scoped to its named
procedure. BCF is licensed under the [MIT License](LICENSE); release history is
in the [changelog](CHANGELOG.md).
