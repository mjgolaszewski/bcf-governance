"""Typed terminal diagnostics for governance preflight executions."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any, Mapping


def write_preflight_diagnostic(
    output: Path,
    *,
    mode: str,
    evaluation_mode: str,
    report: Mapping[str, Any] | None = None,
    error: str | None = None,
) -> None:
    """Write exactly one terminal diagnostic for success or failure."""

    if (report is None) == (error is None):
        raise ValueError("preflight diagnostic requires exactly one outcome")
    payload: dict[str, Any] = {
        "kind": "governance_preflight_diagnostic",
        "status": "failure" if error is not None else "success",
        "mode": mode,
        "evaluation_mode": evaluation_mode,
    }
    if error is not None:
        payload["error"] = error
    else:
        assert report is not None
        payload["subject"] = report["subject"]
        payload["repository_context"] = report["pr_context"]
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n", encoding="utf-8")
