# Repo Cleanup

Use this when a BCF-governed repo has drifted: old phase sprawl, audit files in
the wrong roots, nested governance, stale docs, or abandoned YAML.

Machine contract: `governance/repo-cleanup-contract.yml`.

## Sequence

1. Run `bcf cleanup --repo-root .` and read safe actions separately from manual actions.
2. Apply only approved deterministic moves with `bcf cleanup --repo-root . --apply`.
3. Archive verified or closed phase triplets only when `bcf cleanup --repo-root . --archive-closed-phases` reports safe actions and retained artifact hashes.
4. Index retained history or declare git history as the retention source.
5. Use `bcf install --target . --force-rescaffold` only after accepting the destructive warning.
6. Use `bcf cleanup --repo-root . --remove-governance-pack` only when intentionally decommissioning BCF governance.
7. Tune architecture gates to the repo's real layout; do not delete gates to make validation pass.
8. Review README, docs, runbooks, plans, and phase logs section by section against repo evidence.
9. Record command outcomes and unresolved constraints in the active phase log.

## Deterministic Work

BCF can move audit/review evidence into `audits/`, create `audits/README.md`,
rewrite exact path references, archive closed phase triplets into
`governance/archive/phase-artifacts/` with `plans/phase-history.yml` hashes,
remove known BCF-owned files and dedicated governance CI gates, and reinstall
known BCF-owned files.

Phase-history entries must be compact and evidence-backed; do not replace
removed triplets with empty history rows.

## LLM Or Human Review

Use judgment for documentation currency, product specs, architecture/security
docs, runbooks, semantic phase history compaction, abandoned YAML, and nested governance.
Each change must preserve intent while removing stale or duplicate surfaces.

## Closeout

Cleanup is complete only when the active governance files are compact, historical
evidence is retained or indexed, docs match repo behavior, release gates are
repo-specific, and `bcf validate` plus declared release checks are recorded.
