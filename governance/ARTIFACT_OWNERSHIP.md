# Artifact Ownership

## Canonical Owner Map

| Concept | Canonical owner |
| --- | --- |
| Agent rules and authority order | `AGENTS.yml` |
| Profile and release-gate classification | `governance-profile.yml` |
| Artifact roots, vendored packs, audit lane, context budgets, phase retention policy | `governance/artifact-manifest.yml` |
| Repo cleanup contract and documentation currency rules | `governance/repo-cleanup-contract.yml` |
| Architecture source roots, layer/context tokens, structural rules | `architecture-boundaries.yml` |
| Structural shapes | `schemas/*.json` |
| Product scope and phase catalog | `plans/product-spec.yml` |
| Delivery sequence and dependencies | `plans/build-plan.yml` |
| Active phase, validation commands, hotfix records | `plans/phase-ledger.yml` |
| Compact archived phase history and artifact hashes | `plans/phase-history.yml` |
| Durable context and active artifact pointers | `MEMORY.yml` |
| Execution evidence | `phases/*.yml` |
| Human-requested codebase audits and sprint reports | `audits/` |
| Runtime and release commands | `Makefile.fragment`, `docs/OPERATIONS.md` |
| Existing-repo conversion | installed only with `--adoption-mode existing` |

Repo evidence: `template-repo/AGENTS.yml`, `scripts/install_governance_pack.py`, `tests/test_install_governance_pack.py`.

## Duplication Rules

- Change derived fields with their canonical source.
- Keep `document.path` repo-relative, POSIX, and exact.
- Keep active phase, phase workitems, phase logs, hotfix records, and release-gate targets aligned.
- Keep closed phase triplets active only while retained by `phase_retention_policy`; archive deterministic triplets with `bcf cleanup --archive-closed-phases --apply`.
- Keep audits in `audits/`; `docs/` is for user and operator documentation.
- Declare nested governance packs and vendored artifacts in `governance/artifact-manifest.yml`.
- Use `bcf cleanup` for deterministic audit-root moves and exact reference rewrites before manual documentation compaction.
- Use `governance/repo-cleanup-contract.yml` to separate deterministic cleanup from LLM or human semantic review.
- Do not write execution evidence into `AGENTS.yml` or `MEMORY.yml`.

Repo evidence: `scripts/validate_governance_yaml.py`, `scripts/cleanup_governance_pack.py`, `tests/test_validate_governance_yaml.py`.

## Review Checklist

- Did behavior, environment, release gates, or governance change?
- Did the canonical owner change in the same patch?
- Are append entries terse while preserving intent, action/evidence, and consequence?
- Did validation run and get recorded in the phase log when applicable?
