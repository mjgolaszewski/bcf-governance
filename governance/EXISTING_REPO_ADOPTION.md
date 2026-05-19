# Existing Repo Adoption

## Purpose

Use this playbook when converting an established repository into a BCF-governed repo without rewriting the application during the first governance commit.

The adoption goal is structural truth first: install governed artifacts, inventory the existing architecture and CI surface, classify gaps, and wire executable gates before claiming release readiness.

Repo evidence: `scripts/install_governance_pack.py` keeps these playbooks only for `--adoption-mode existing`; fresh installs omit them.

## Installer Mode

Use the existing-repo mode when bootstrapping into a non-empty repository:

```bash
bcf install \
  --target /path/to/existing-repo \
  --adoption-mode existing \
  --profile lite \
  --project-id your-project \
  --project-name "Your Project" \
  --date "$(date -u +%F)" \
  --require-strict-validation
```

Start with `lite` when the existing repo has not yet mapped its architecture, CI, and release gates. Promote to `standard` after the mandatory gates are wired or explicitly classified.

Before deleting or rescaffolding a drifted governance tree, run a dry cleanup plan:

```bash
bcf cleanup --repo-root /path/to/existing-repo
bcf cleanup --repo-root /path/to/existing-repo --format json --compact
```

Apply only the deterministic path moves when the plan looks correct:

```bash
bcf cleanup --repo-root /path/to/existing-repo --apply
```

`bcf cleanup` moves legacy audit/review evidence into `audits/` and rewrites exact path references. It only reports semantic compaction work; it does not rewrite product specs, phase history, architecture docs, security docs, runbooks, or vendored governance.

## Conversion Sequence

1. Install the pack in `existing` adoption mode.
2. Run `bcf cleanup` when legacy audit or governance evidence exists outside canonical roots.
3. Keep the first commit limited to governance artifacts, docs, scripts, schemas, CI fragments, and phase records.
4. Inventory source roots, bounded contexts, architectural layers, command/query paths, read-model names, write API names, generated-file exclusions, and runtime surfaces.
5. Update `architecture-boundaries.yml` to match the repo before treating architecture tests as release evidence.
6. Merge or include `Makefile.fragment`.
7. Wire real gate commands or mark genuinely unavailable gates as `deferred` or `not_applicable` with rationale.
8. Add push CI lanes for required gates when a local or hosted runner is available.
9. Record adoption evidence and known gaps in the active phase log.
10. Promote from `lite` to `standard` only after structural gates are executable or deliberately classified.

## Required Inventory

- production source roots
- generated, vendored, migration, fixture, and snapshot exclusions
- bounded context path tokens
- layer path tokens
- command-side and query-side path tokens
- read model naming tokens
- write method names that queries must not call
- framework, persistence, cache, queue, cloud, telemetry, and HTTP client imports
- required local and push CI lanes
- runner labels, capabilities, secrets, and cleanup expectations

## Evidence

Record conversion evidence in the active phase log:

- commands run
- CI jobs wired or deferred
- structural gates passing or classified
- known warnings
- known constraints
- follow-up phase work

Do not treat adoption as complete because files were copied. Adoption is complete when governance validation, doctor diagnostics, and the declared release gates agree.
