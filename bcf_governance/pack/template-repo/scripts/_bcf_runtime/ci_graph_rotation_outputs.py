"""CI-graph ownership for provider-authenticated rotation receipt outputs."""

from __future__ import annotations

from typing import Any

from .ci_graph_errors import CIGraphError


def validate_rotation_output_directories(
    graph: dict[str, Any], job: dict[str, Any], executor: dict[str, Any]
) -> None:
    """Require routine transition receipts to have graph-owned output roots."""

    prepared: set[str] = set()
    for component_id in executor["components"]:
        component = graph["step_components"][component_id]
        if component["kind"] == "directory_setup":
            prepared.update(str(path).rstrip("/") for path in component["paths"])
            continue
        if component["kind"] != "command":
            continue
        argv = graph["commands"][component["command"]]["argv"]
        if len(argv) < 4 or argv[1:3] != ["ci-github", "controller-rotation"]:
            continue
        if argv[3] not in {"authorize", "advance"} or "--output" not in argv:
            continue
        output_index = argv.index("--output") + 1
        if output_index >= len(argv):
            raise CIGraphError(
                f"CI graph job {job['id']} routine transition output is missing"
            )
        output = str(argv[output_index])
        parent = output.rsplit("/", 1)[0] if "/" in output else ""
        if parent not in prepared:
            raise CIGraphError(
                f"CI graph job {job['id']} routine transition output parent "
                "must be allocated before execution"
            )
