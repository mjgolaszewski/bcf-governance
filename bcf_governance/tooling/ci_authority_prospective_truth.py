"""Existing prospective truth-result acceptance; no independent authority."""

from __future__ import annotations

from typing import Any, Mapping

from .local_pr_context import ProspectiveValidationError


def require_truth(report: Mapping[str, Any], *, boundary: str) -> dict[str, Any]:
    if report.get("status") != "pass":
        detail = ", ".join(str(value) for value in report.get("issues") or ())
        raise ProspectiveValidationError(
            f"{boundary} rejected candidate: {detail or 'truth failed'}"
        )
    return dict(report)
