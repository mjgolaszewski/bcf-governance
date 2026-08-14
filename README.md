# BCF Governance

<p align="center">
  <img src="docs/assets/bcf-governance-pack-hero.jpg" alt="BCF Governance" width="760">
</p>

BCF is an executable governance framework for agent-led software delivery. It
keeps product scope, active work, release gates, findings, and evidence in a
small machine-readable model, then separates two questions that governance
systems often blur:

- `bcf validate`: is the governed repository structurally legal and internally
  consistent?
- `bcf truth`: are its lifecycle and release claims supported by independently
  measurable evidence from the current Git tree?

Current release: `v0.6.1`.

## Lifecycle contract

Phase authors may report `planned` or `completed`. They cannot author
`verified`, `closed`, release readiness, suite health, security-review
completion, or finding closure.

`verified` is computed when every required claim has valid schema-2 evidence
from the governed commit and tree. `closed` is computed when the phase is
verified, reconciliation is current, `findings_resolved` has current evidence,
and no profile-blocking finding remains. A relevant source, test, workflow,
audit, or governance mutation makes affected evidence stale and returns the
effective phase state to `completed`.

Evidence capture runs exact argv from `governance/gate-contracts.yml` in
pristine detached worktrees. Every mandatory gate has a negative behavioral
control with a typed failure oracle; arbitrary crashes, missing commands,
timeouts, and all-skipped test lanes do not prove behavior.

## Standard repository artifacts

Every BCF-governed repository has three root artifacts declared in
`governance/artifact-manifest.yml`:

- `README.md`, beginning with a project heading;
- `LICENSE`, containing substantive license or copyright terms;
- `CHANGELOG.md`, following Keep a Changelog headings with one
  `## [Unreleased]` section.

Every pull request must update `CHANGELOG.md`. Generated governance CI checks
the pull-request base-to-HEAD diff and fails closed if the base commit is not
available.

Fresh installation scaffolds missing artifacts. Existing valid artifacts are
preserved byte-for-byte; BCF never replaces an application README, license, or
changelog.

## Install

Install the public wheel:

```bash
python3 -m pip install https://github.com/mjgolaszewski/bcf-governance/releases/download/v0.6.1/bcf_governance-0.6.1-py3-none-any.whl
```

Git is required. `lite` is the bootstrap profile and has only the two built-in
governance gates:

```bash
bcf install \
  --target /path/to/repo \
  --profile lite \
  --project-id example \
  --project-name "Example" \
  --require-strict-validation
```

Fresh `standard` and `regulated` installs require a complete profile contract
before any target mutation:

```bash
bcf install \
  --target /path/to/repo \
  --profile standard \
  --profile-config /path/to/standard-gates.yml \
  --project-id example \
  --project-name "Example" \
  --require-strict-validation
```

The profile contract declares exact argv, repo-relative cwd, non-secret
environment, required environment names, outputs, measurements, and contained
negative controls for every non-built-in gate. Shell commands, no-ops,
incomplete gate sets, and dynamic mandatory paths fail before installation.

Promote a lite repository transactionally without regenerating phase state:

```bash
bcf profile promote --repo-root . --to standard --config standard-gates.yml --check
bcf profile promote --repo-root . --to standard --config standard-gates.yml --apply
```

Use `--adoption-mode existing` when installing into an established repository.
Use `bcf install --upgrade` for normal pack updates. The only destructive
replacement command is explicitly confirmed `--force-rescaffold`; the removed
`--force` option is not accepted.

## Operate

```bash
bcf validate
bcf exposure-scan
bcf doctor --repo-root .
bcf evidence run --gate test --output .artifacts/bcf/test
bcf truth --evidence-dir .artifacts/bcf
```

Evidence bundles and truth reports stay outside the tracked governed tree and
are retained in CI or release storage by SHA-256. BCF 0.5 receipts are rejected
as `unsupported_schema_version` and must be recaptured.

Other commands scaffold phase/hotfix artifacts, migrate 0.5 state, plan and
apply governance cleanup, remove exactly labelled CI resources, and run an
opt-in redacted full-history publication audit. See [Using BCF](docs/USAGE.md)
for profiles, adoption, evidence, cleanup, and command details.

## Package development

```bash
python3 -m pip install -e ".[dev]"
pytest tests
python3 .github/scripts/run_validator_mutants.py --profile high-value
```

The packaged implementation lives under `bcf_governance`. Root scripts are
thin source-checkout wrappers; installed standalone tooling uses the private
`scripts/_bcf_runtime` namespace. Canonical and copied runtime surfaces are
kept byte-identical by contract tests.

See [Maintaining and releasing BCF](docs/MAINTAINING.md) for synchronization,
artifact tests, mutation rules, versioning, and the release process.

## Documentation map

- [Using BCF](docs/USAGE.md): installation, profiles, lifecycle, evidence,
  adoption, cleanup, and operational safety.
- [Maintaining BCF](docs/MAINTAINING.md): source ownership, tests, generated
  copies, documentation policy, and releases.
- `template-repo/docs/OPERATIONS.md`: the concise runbook installed into a
  governed repository.
- `template-repo/AGENTS.yml`: canonical installed agent policy.
- `template-repo/governance/evidence-policy.yml`: computed-claim and
  invalidation policy.

BCF is licensed under the [MIT License](LICENSE). Release history is in the
[changelog](CHANGELOG.md).
