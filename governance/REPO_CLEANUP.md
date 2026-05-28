# Repo Cleanup

Use this contract when a BCF-governed repo has drifted: old phase sprawl,
misplaced audits, nested governance, stale docs, or abandoned YAML.

Installed repos get `governance/repo-cleanup-contract.yml` as the machine
contract and `governance/REPO_CLEANUP.md` as the human guide.

## Rule

Separate deterministic cleanup from semantic cleanup.

Deterministic work may move files, rewrite exact references, create canonical
roots, remove or archive verified/closed historical phase artifacts only after
`plans/phase-history.yml` is updated with compact summaries, artifact hashes,
and the declared retention source, and rescaffold known BCF-owned files after
confirmation. Phase-scoped hotfix logs and matching hotfix lane records leave
active governance with their related phase. It may also remove known BCF-owned
files and dedicated governance CI gates when decommissioning the pack. Semantic
work needs human or LLM review: documentation currency, product specs, semantic
phase-history compaction, runbooks, architecture gates, and vendored governance.

Phase-history entries are not narrative logs. They must stay terse, name the
outcome, and point to retained artifacts or git-history refs with hashes.

## Closeout

Do not claim cleanup complete until active governance is compact, historical
evidence is retained or indexed, docs match repo behavior, architecture gates
match the repo shape, and validation evidence is recorded.
