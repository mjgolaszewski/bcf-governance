# Repo Cleanup

Use this when a BCF-governed repo has drifted: old phase sprawl, audit files in
the wrong roots, nested governance, stale docs, or abandoned YAML.

Machine contract: `governance/repo-cleanup-contract.yml`.
Routine commands remain in `docs/OPERATIONS.md`; this document covers only the
cleanup branch.

Interactive apply requests confirmation. Non-TTY apply must include `--yes` or
it fails before mutation. Proposed changes are validated in a temporary shadow
worktree and transferred atomically with rollback.

## Sequence

1. Run `bcf cleanup --repo-root .` and read safe actions separately from manual actions.
2. Apply only approved deterministic moves with `bcf cleanup --repo-root . --apply`.
3. Retrieve a passing truth report that computed each completed phase closed on its governed tree and records its retained CI/release artifact as `durable_ref`.
4. Remove stale closed triplets with `bcf cleanup --repo-root . --phase-retention-mode --truth-report .artifacts/bcf/truth.json --apply` when git history should retain the old artifact bytes; the local path is non-authoritative and its sha256 must match a retained CI artifact.
5. Move stale closed triplets with `bcf cleanup --repo-root . --phase-retention-mode archive --truth-report .artifacts/bcf/truth.json --apply` when local ignored archive storage is preferred; the local path is non-authoritative and its sha256 must match a retained CI artifact.
6. Use `bcf install --target . --force-rescaffold` only after accepting the destructive warning.
7. Use `bcf cleanup --repo-root . --remove-governance-pack` only when intentionally decommissioning BCF governance.
8. Tune architecture gates to the repo's real layout; do not delete gates to make validation pass.
9. Review README, docs, runbooks, plans, and phase logs section by section against repo evidence.
10. Record command outcomes and unresolved constraints in the active phase log.

## Deterministic Work

BCF can move audit/review evidence into `audits/`, create `audits/README.md`,
rewrite exact path references, remove completed phase artifacts only after a
supplied passing truth report computed them closed, record an evidence-backed
historical snapshot in `plans/phase-history.yml`, archive artifacts into ignored
`governance/archive/phase-artifacts/` storage, prune related hotfix lane records, remove known BCF-owned files
and dedicated governance CI gates, and reinstall known BCF-owned files.

With no phase-retention switch, cleanup preserves current historical triplet
behavior. Once a mode is selected, validation enforces the active retention
window and rejects stale historical triplets or phase-scoped hotfix logs that
remain active. Phase-history entries must be compact and evidence-backed; do
not replace removed artifacts with empty history rows.

## Human or model-assisted review

Use judgment for documentation currency, product specs, architecture/security
docs, runbooks, semantic phase history compaction, abandoned YAML, and nested
governance. A model may propose those edits, but deterministic validation and
the declared approval role remain authoritative. Each change must preserve
intent while removing stale or duplicate surfaces.

## Closeout

Cleanup is complete only when the active governance files are compact, historical
evidence is retained or indexed, docs match repo behavior, release gates are
repo-specific, and both `bcf validate` and `bcf truth` outcomes are recorded.
