"""Project provider expressions into inert generated-shell data channels."""

from __future__ import annotations

import re
from typing import Any


_WORKFLOW_EXPRESSION = re.compile(r"\$\{\{.*?\}\}")
_INTERPRETER_SINK = re.compile(
    r"(?m)(?:^|[;&|]\s*|\s)(?:eval|source)\s+"
    r"|(?:^|[;&|]\s*)\.\s+"
    r"|(?:^|\s)(?:[\"']?\$BCF_PYTHON[\"']?|(?:\S*/)?(?:ba|da|k|z)?sh|"
    r"(?:\S*/)?python(?:3(?:\.\d+)?)?)\s+(?:-\S+\s+)*-c(?:\s|$)"
)
RESERVED_GOVERNANCE_ENVIRONMENT = frozenset({
    "BCF_COMPARISON_BASE_SHA",
    "BCF_ENFORCE_PR_CHANGELOG",
    "BCF_EVALUATION_MODE",
    "BCF_EVALUATION_TARGET",
    "BCF_PROVIDER_EVENT",
    "BCF_PR_BASE_SHA",
})


def require_available_environment_names(
    environment: dict[str, Any], names: frozenset[str] = RESERVED_GOVERNANCE_ENVIRONMENT
) -> None:
    """Reject authored overrides of canonical evaluation/context ownership."""

    collisions = sorted(set(environment) & names)
    if collisions:
        raise AssertionError(
            f"governed environment overrides reserved context: {collisions}"
        )


def require_available_generated_slots(
    environment: dict[str, Any], prefix: str
) -> None:
    """Reject authored ownership of renderer-reserved environment slots."""

    collisions = sorted(name for name in environment if name.startswith(prefix))
    if collisions:
        raise AssertionError(
            f"governed environment claims reserved {prefix} slots: {collisions}"
        )


def _quote_state(source: str, position: int) -> str | None:
    state: str | None = None
    escaped = False
    for character in source[:position]:
        if escaped:
            escaped = False
        elif character == "\\" and state != "'":
            escaped = True
        elif character in {"'", '"'}:
            state = None if state == character else character if state is None else state
    return state


def hoist_run_expressions(steps: list[dict[str, Any]]) -> None:
    """Move workflow expressions from shell source into deterministic env slots."""

    for step in steps:
        source = step.get("run")
        if not isinstance(source, str):
            continue
        environment = step.setdefault("env", {})
        if not isinstance(environment, dict):
            raise AssertionError("governed shell-step environment must be an object")
        require_available_generated_slots(environment, "BCF_RUN_EXPRESSION_")
        if _WORKFLOW_EXPRESSION.search(source) and _INTERPRETER_SINK.search(source):
            raise AssertionError(
                "workflow expression cannot enter an interpreter source sink"
            )
        expressions: dict[str, str] = {}

        def replace(match: re.Match[str]) -> str:
            expression = match.group(0)
            if expression not in expressions:
                expressions[expression] = f"BCF_RUN_EXPRESSION_{len(expressions)}"
            variable = f"${{{expressions[expression]}}}"
            state = _quote_state(source, match.start())
            if state == '"':
                return variable
            if state == "'":
                return f"'\"{variable}\"'"
            return f'"{variable}"'

        step["run"] = _WORKFLOW_EXPRESSION.sub(replace, source)
        for expression, name in expressions.items():
            if name in environment and environment[name] != expression:
                raise AssertionError("governed expression environment slot collides")
            environment[name] = expression
        if "${{" in step["run"]:
            raise AssertionError("workflow expression remained in shell source")
