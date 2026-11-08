"""Validate declared reusable caller inheritance against actual callee bounds."""
from __future__ import annotations

from typing import Any

from .ci_graph_errors import CIGraphError


def validate_permission_projection(graph: dict[str, Any]) -> None:
    """Keep native derived execution permissions separate from caller inheritance."""
    for workflow in graph["workflows"]:
        for job in workflow.get("jobs", []):
            style = job.get("permissions_style")
            if style is None:
                continue
            if job["executor"]["kind"] != "reusable_workflow":
                raise CIGraphError("inherited permissions require a reusable caller with the exact workflow permission bound")
            if style == "inherit-workflow":
                if job["permissions"] != workflow["permissions"]:
                    raise CIGraphError("inherited permissions require a reusable caller with the exact workflow permission bound")
                continue
            if style != "inherit-callee-bound":
                raise CIGraphError("unknown reusable permission projection style")
            bound = job["permissions"]
            caller = workflow["permissions"]
            callee = next((candidate for candidate in graph["workflows"]
                           if candidate.get("path") == job["executor"]["path"]), None)
            if (not bound or any(value not in {"read", "none"} for value in bound.values())
                    or any(value not in {"read", "none"} for value in caller.values())
                    or any(caller.get(name, "none") != "read" for name, value in bound.items() if value == "read")
                    or callee is None or callee["permissions"] != bound
                    or not callee["jobs"]):
                raise CIGraphError("callee-bound inheritance requires explicit covered readonly callee permissions")
            for child in callee["jobs"]:
                if (child["executor"]["kind"] == "reusable_workflow"
                        or (child["permissions"] and child["permissions"] != bound)):
                    raise CIGraphError("callee-bound inheritance requires direct jobs with the exact explicit callee bound")
