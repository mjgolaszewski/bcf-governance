"""Project provider expressions into inert generated-shell data channels."""

from __future__ import annotations

import re
from typing import Any


_WORKFLOW_EXPRESSION = re.compile(r"\$\{\{.*?\}\}")


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
