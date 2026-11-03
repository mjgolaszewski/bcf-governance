"""Closed authored condition syntax and same-job step dependency validation."""
from __future__ import annotations

import re
from pathlib import PurePosixPath
from typing import Any

from .ci_graph_errors import CIGraphError

STATUS = r"(?:always|success|failure|cancelled)\(\)"
IDENTIFIER = r"[A-Za-z0-9_.-]+"
COMPARISON = IDENTIFIER + r"[ ]*(?:==|!=)[ ]*(?:true|false|[1-9][0-9]*|'[A-Za-z0-9_./:-]*')"
HASH = r"hashFiles\('[A-Za-z0-9_./*?-]+'\)[ ]*(?:==|!=)[ ]*''"
TERM = "(?:" + STATUS + "|" + COMPARISON + "|" + HASH + "|!?" + IDENTIFIER + ")"
CONDITION_PATTERN = "^" + TERM + r"(?:[ ]*(?:&&|\|\|)[ ]*" + TERM + ")*$"
_CONDITION = re.compile(CONDITION_PATTERN)
_HASH = re.compile(r"hashFiles\('([^']+)'\)")
_STEP = re.compile(r"\bsteps\.([A-Za-z0-9_-]+)\.(?:outcome|conclusion|outputs\.[A-Za-z0-9_-]+)\b")


def validate_authored_conditions(graph: dict[str, Any]) -> None:
    """Do not turn named projection into an arbitrary expression channel."""
    for expression in graph["conditions"].values():
        if len(expression) > 4096 or _CONDITION.fullmatch(expression) is None:
            raise CIGraphError("authored condition is outside the closed expression grammar")
        for match in _HASH.finditer(expression):
            path = PurePosixPath(match.group(1))
            if path.is_absolute() or ".." in path.parts:
                raise CIGraphError("hashFiles condition must stay inside the repository")
    for workflow in graph["workflows"]:
        for job in workflow.get("jobs", []):
            component_ids = job["executor"].get("components", [])
            if any(key not in graph["step_components"] for key in component_ids):
                # The existing graph compiler owns undeclared-component errors.
                # Do not replace that typed refusal with an early KeyError.
                continue
            positions: dict[str, int] = {}
            for index, component_id in enumerate(component_ids):
                step_id = graph["step_components"][component_id].get("id")
                if step_id is not None:
                    if step_id in positions:
                        raise CIGraphError("CI graph step IDs must be unique within a job")
                    positions[step_id] = index
            for index, component_id in enumerate(component_ids):
                component = graph["step_components"][component_id]
                expression = graph["conditions"].get(component.get("condition"), "")
                scoped_expression = re.sub(r"'[^']*'", "''", expression)
                for match in _STEP.finditer(scoped_expression):
                    if match.group(1) not in positions or positions[match.group(1)] >= index:
                        raise CIGraphError("step condition references an unavailable earlier step")
