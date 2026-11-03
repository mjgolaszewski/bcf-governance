"""Project a protected environment only from a successful declared verifier."""
from __future__ import annotations

import re
from typing import Any

from .ci_graph_errors import CIGraphError

_OUTPUT = re.compile(r"^\$\{\{ steps\.([A-Za-z0-9_-]+)\.outputs\.([A-Za-z0-9_-]+) \}\}$")


def validate_environment_output_bindings(graph: dict[str, Any]) -> None:
    """Bind one needs output; never accept an arbitrary environment expression."""
    for workflow in graph["workflows"]:
        jobs = {job["id"]: job for job in workflow.get("jobs", [])}
        for job in workflow.get("jobs", []):
            binding = job.get("protected_environment_from")
            if binding is None:
                continue
            producer = jobs.get(binding["job"])
            if ("protected_environment" in job or producer is None
                    or producer is job or binding["job"] not in job["needs"]
                    or job["executor"]["kind"] != "component_sequence"
                    or job["condition"] != "success" or producer["condition"] != "success"
                    or any(item["trust"] != "candidate" for item in [job, producer])
                    or any(value == "write" for item in [job, producer] for value in item["permissions"].values())):
                raise CIGraphError("environment binding requires a direct successful read-only verifier")
            expression = producer.get("outputs", {}).get(binding["output"], "")
            match = _OUTPUT.fullmatch(expression)
            if match is None or producer["executor"]["kind"] != "component_sequence":
                raise CIGraphError("environment binding requires a declared verifier step output")
            keys = producer["executor"]["components"]
            if any(key not in graph["step_components"] for key in keys):
                raise CIGraphError("environment verifier references an unknown step component")
            steps = [graph["step_components"][key] for key in keys]
            verification = [step for step in steps if step.get("id") == match.group(1)]
            if (len(verification) != 1 or verification[0]["kind"] != "command"
                    or verification[0].get("condition") not in {None, "success"}
                    or any(step.get("continue_on_error", False) for step in steps)):
                raise CIGraphError("environment verifier must be an unskipped noncontinued command")
