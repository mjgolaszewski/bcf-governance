"""Typed CI graph diagnostics shared by validation and operator commands."""

from __future__ import annotations

import re


class CIGraphError(ValueError):
    """Raised when graph bytes do not define one safe executable topology."""

    def __init__(
        self, message: str, *, kind: str = "graph_input", identifier: str = "ci-graph"
    ) -> None:
        super().__init__(message)
        self.kind = kind
        self.identifier = identifier

    def diagnostic(self) -> dict[str, str]:
        return {
            "kind": self.kind,
            "identifier": self.identifier,
            "status": "missing_or_invalid",
            "remediation": str(self),
        }


def execution_graph_error(issue: str, *, job_id: str) -> CIGraphError:
    """Classify a canonical execution-contract issue without parsing it in YAML."""

    environment = re.search(r"environment binding ([A-Z][A-Z0-9_]*)", issue)
    identifier = environment.group(1) if environment else job_id
    kind = (
        "secret"
        if environment and identifier.endswith(("TOKEN", "SECRET"))
        else "tool"
    )
    return CIGraphError(issue, kind=kind, identifier=identifier)
