# Agent Task Contract

## Purpose

Use this playbook when assigning a bounded coding task to an AI agent. This is guidance for task scoping and review. It is not a validator-enforced repo contract.

## Default Task Shape

Every task should specify:

- intent
- bounded context
- feature name
- allowed files
- forbidden files
- acceptance criteria
- tests to add or update
- commands to run
- rollback notes

## Scope Heuristics

- Default to the smallest valid vertical slice.
- Prefer feature-local files over shared modules.
- Do not change public contracts unless explicitly instructed.
- Do not introduce cross-cutting middleware, migrations, dependency upgrades, or auth-framework changes without escalation.
- Prefer touching the feature slice and its tests before shared or infrastructure surfaces.

## Suggested Prompt Template

```text
Task:
  <specific change>

Intent:
  <command|query|router|repo|test|refactor>

Bounded context:
  <name>

Feature:
  <name>

Allowed files:
  - <paths>

Forbidden files:
  - <paths>

Acceptance criteria:
  - <observable behavior>

Tests:
  - <tests to add/update/run>

Constraints:
  - Preserve public contracts unless explicitly listed.
  - Do not introduce cross-cutting changes.
  - Do not move code outside the slice without authorization.
  - Do not modify unrelated files.

Completion proof:
  - Show changed files.
  - Show tests run.
  - Summarize behavior change.
  - List risks or follow-ups.
```

## Escalation Triggers

Escalate before proceeding when the task requires:

- database migrations
- dependency upgrades
- authentication or authorization framework changes
- cross-cutting middleware
- global exception handling changes
- logging or telemetry framework changes
- public API contract changes

## Review Heuristics

- Reject changes that leave the authorized slice without explanation.
- Reject changes that remove tests instead of fixing behavior.
- Reject changes that add generic helpers without proven reuse.
- Reject changes that weaken auth or validation to make tests pass.
- Prefer low-churn diffs with explicit rollback notes.
