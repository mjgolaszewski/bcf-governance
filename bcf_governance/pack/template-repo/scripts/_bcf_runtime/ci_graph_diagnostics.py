"""Typed, pre-execution diagnostics for governed CI graph prerequisites."""

from __future__ import annotations

import re
from pathlib import Path
from typing import Any

from .ci_graph_contracts import CIGraphError, validate_ci_graph


_SECRET = re.compile(r"\$\{\{\s*secrets\.([A-Z_][A-Z0-9_]*)\s*\}\}")


def _strings(value: Any) -> tuple[str, ...]:
    if isinstance(value, str):
        return (value,)
    if isinstance(value, dict):
        return tuple(item for nested in value.values() for item in _strings(nested))
    if isinstance(value, list):
        return tuple(item for nested in value for item in _strings(nested))
    return ()


def _entry(kind: str, identifier: str, status: str, remediation: str) -> dict[str, str]:
    return {
        "kind": kind,
        "identifier": identifier,
        "status": status,
        "remediation": remediation,
    }


def diagnose_ci_graph(repo_root: Path) -> dict[str, object]:
    """Compile once, then emit every derivable prerequisite before runner allocation."""

    try:
        compiled = validate_ci_graph(repo_root)
    except CIGraphError as exc:
        return {"status": "fail", "diagnostics": [exc.diagnostic()]}
    graph = compiled.graph
    diagnostics: list[dict[str, str]] = []
    for resource_id, resource in sorted(graph["resource_classes"].items()):
        diagnostics.append(
            _entry(
                "runner",
                resource_id,
                "declared",
                f"confirm provider runner mapping {resource['runner']!r} before dispatch",
            )
        )
        for capability in sorted(resource["capabilities"]):
            diagnostics.append(
                _entry(
                    "tool",
                    f"{resource_id}:{capability}",
                    "declared",
                    "provision through the declared resource class before governed commands",
                )
            )
    for workflow in sorted(compiled.workflows, key=lambda item: item["id"]):
        for event in sorted({item["type"] for item in workflow["events"]}):
            diagnostics.append(
                _entry(
                    "event",
                    f"{workflow['id']}:{event}",
                    "declared",
                    "render and validate this event from the canonical graph",
                )
            )
        for job in sorted(workflow["jobs"], key=lambda item: item["id"]):
            diagnostics.append(
                _entry(
                    "permission",
                    f"{workflow['id']}:{job['id']}",
                    "declared",
                    "keep job permissions at or below the compiled trust boundary",
                )
            )
    secrets = sorted(
        {
            match.group(1)
            for value in _strings(graph)
            for match in _SECRET.finditer(value)
        }
    )
    diagnostics.extend(
        _entry(
            "secret",
            name,
            "provider_required",
            "configure this GitHub secret; the generated job validates it before checkout or work",
        )
        for name in secrets
    )
    diagnostics.append(
        _entry(
            "graph_input",
            "governance/ci-graph.yml",
            "validated",
            "edit the canonical graph or a registered extension, then lock and render",
        )
    )
    diagnostics.extend(
        _entry(
            "graph_input",
            path,
            "validated",
            "refresh its registered digest with `bcf ci graph lock --apply` after review",
        )
        for path, _ in (*compiled.extension_sha256, *compiled.input_sha256)
    )
    return {"status": "pass", "diagnostics": diagnostics}
