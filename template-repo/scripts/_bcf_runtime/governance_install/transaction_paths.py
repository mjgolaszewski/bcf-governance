"""Mechanical install-transaction destination closure."""

from __future__ import annotations

from pathlib import Path
from typing import Any

from ..ci_graph_render import managed_generated_paths
from .ci_graph import reference_ci_graph


def install_transaction_paths(
    args: Any,
    *,
    contract: dict[str, Any] | None,
    contract_version: str,
    target_root: Path,
    baseline: tuple[str, ...],
) -> tuple[str, ...]:
    graph_path = target_root / "governance/ci-graph.yml"
    prospective = (
        tuple(
            str(workflow["path"])
            for workflow in reference_ci_graph(args, contract)["workflows"]
        )
        if not args.upgrade
        and contract is not None
        and (args.profile == "lite" or contract_version in {"2.0", "3.0"})
        else ()
    )
    existing = managed_generated_paths(target_root) if graph_path.is_file() else ()
    return tuple(dict.fromkeys(baseline + existing + prospective))
