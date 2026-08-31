# Existing Repo Adoption

## Purpose

Use this playbook when converting an established repository into a BCF-governed
repo without rewriting the application during the first governance commit. The
installed `docs/OPERATIONS.md` owns routine commands; this document covers only
the adoption branch.

The first goal is structural validity: install governed artifacts, inventory
the existing architecture and CI surface, classify gaps, and wire executable
gates before making release claims.

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

Start with `lite` when the existing repo has not yet mapped its architecture,
CI, and release gates. Promote to `standard` only after every mandatory gate
has a complete executable contract and behavioral control.

Use `bcf install --upgrade` for normal pack updates. It refreshes support
scripts, schemas, workflow, and missing current governance fields while
preserving product and phase state. Use `--force-rescaffold` only when the
owner intends to replace the active BCF layer.

Before deleting or rescaffolding a drifted governance tree, run a dry cleanup plan:

```bash
bcf cleanup --repo-root /path/to/existing-repo
bcf cleanup --repo-root /path/to/existing-repo --format json --compact
```

Apply only the deterministic path moves when the plan looks correct:

```bash
bcf cleanup --repo-root /path/to/existing-repo --apply
```

In non-TTY automation, append `--yes` only after reviewing the dry-run;
otherwise apply refuses before mutation.

`bcf cleanup` moves legacy audit/review evidence into `audits/` and rewrites exact path references. It only reports semantic compaction work; it does not rewrite product specs, phase history, architecture docs, security docs, runbooks, or vendored governance. Archived phase-history rows must retain artifact hashes.

Use `governance/repo-cleanup-contract.yml` as the cleanup contract and `governance/REPO_CLEANUP.md` as the terse human sequence. Documentation currency is semantic work: update each section against current repo evidence before closeout.

## Conversion Sequence

1. Install the pack in `existing` adoption mode.
2. Run `bcf cleanup` when legacy audit or governance evidence exists outside canonical roots.
3. Review documentation currency section by section against repo files, commands, and tests.
4. Keep the first commit limited to governance artifacts, docs, scripts, schemas, CI fragments, and phase records.
5. Inventory source roots, bounded contexts, architectural layers, command/query paths, read-model names, write API names, generated-file exclusions, and runtime surfaces.
6. Update `architecture-boundaries.yml` to match the repo before treating architecture tests as release evidence.
7. Merge or include `Makefile.fragment`.
8. Build a complete standard profile config with real argv, measurements,
   outputs, environment assertions, and negative controls for every gate.
9. Preview and apply `bcf profile promote`; use the generated static CI matrix.
10. Record adoption evidence and known gaps in the active phase log.
11. Treat unavailable mandatory gates as adoption work; standard and regulated
    profiles do not permit partial gate configuration.

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
- CI jobs wired by the generated profile matrix
- structural gate contracts and controls passing
- known warnings
- known constraints
- follow-up phase work

Do not treat adoption as complete because files were copied. Adoption is complete when governance validation, doctor diagnostics, and the declared release gates agree.
