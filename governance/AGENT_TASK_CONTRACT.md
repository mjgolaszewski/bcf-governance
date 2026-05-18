# Agent Task Contract

## Purpose

Use this optional playbook when assigning bounded coding tasks to an AI agent. Canonical enforcement remains in `AGENTS.yml`, `architecture-boundaries.yml`, release gates, and tests.

Repo evidence: `template-repo/AGENTS.yml`, `template-repo/backend/tests/architecture/test_boundaries_ast.py`.

## Required Task Shape

Specify intent, bounded context, architectural layer, command/query side, target modules, allowed files, forbidden files, acceptance criteria, tests, commands to run, and rollback notes.

Before editing production code, the agent must identify scope and forbidden surfaces. If scope is ambiguous, narrow it before editing.

## Prompt Template

```text
Task:
Intent:
Bounded context:
Architectural layer:
Command/query side:
Target modules:
Allowed files:
Forbidden files:
Acceptance criteria:
Tests:
Commands:
Rollback notes:
```

## Escalation Triggers

Escalate before database migrations, dependency upgrades, auth changes, cross-cutting middleware, global exception handling, logging or telemetry framework changes, or public API contract changes.

## Review Heuristics

Reject slice drift, removed tests, unjustified generic helpers, weakened auth or validation, and unrelated formatting churn.

Repo evidence: `template-repo/AGENTS.yml` review gate and structural guardrails.
