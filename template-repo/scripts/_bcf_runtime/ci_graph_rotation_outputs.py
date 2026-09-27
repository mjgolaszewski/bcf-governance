"""CI-graph ownership for provider-authenticated rotation receipt outputs."""

from __future__ import annotations

from typing import Any

from .ci_graph_errors import CIGraphError


def validate_rotation_output_directories(
    graph: dict[str, Any], job: dict[str, Any], executor: dict[str, Any]
) -> None:
    """Require routine transition receipts to have graph-owned output roots."""

    prepared: set[str] = set()
    operations: list[tuple[str, str]] = []
    for component_index, component_id in enumerate(executor["components"]):
        component = graph["step_components"][component_id]
        if component["kind"] == "directory_setup":
            prepared.update(str(path).rstrip("/") for path in component["paths"])
            continue
        if component["kind"] != "command":
            continue
        argv = graph["commands"][component["command"]]["argv"]
        if len(argv) < 4 or argv[1:3] != ["ci-github", "controller-rotation"]:
            continue
        operations.append((component_id, str(argv[3])))
        if argv[3] == "advance":
            preceding = executor["components"][:component_index]
            if argv[0] != "{ephemeral_controller}" or not any(
                graph["step_components"][item]["kind"] == "controller_install"
                for item in preceding
            ):
                raise CIGraphError(
                    f"CI graph job {job['id']} must advance custody through the "
                    "exact staged target controller"
                )
        if argv[3] not in {
            "authorize", "advance", "materialize-authorization"
        } or "--output" not in argv:
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
    if not any(operation == "authorize" for _, operation in operations):
        return
    materializers = [
        component_id for component_id, operation in operations
        if operation == "materialize-authorization"
    ]
    if len(materializers) != 1:
        raise CIGraphError(
            f"CI graph job {job['id']} must mechanically materialize every "
            "rotation-required authorization"
        )
    materializer = graph["step_components"][materializers[0]]
    condition_id = materializer.get("condition")
    condition = graph["conditions"].get(condition_id)
    if condition != "steps.authorize-transition.outputs.decision != 'no_transition'":
        raise CIGraphError(
            f"CI graph job {job['id']} may skip only an exact no-transition decision"
        )
    expected_applicable = (
        f"${{{{ steps.{materializer.get('id')}.outputs.applicable }}}}"
    )
    if job.get("outputs", {}).get("applicable") != expected_applicable:
        raise CIGraphError(
            f"CI graph job {job['id']} applicability must derive from the "
            "materialized rotation authorization"
        )
