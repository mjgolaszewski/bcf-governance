"""Portable planner-derived evidence shard execution."""

from __future__ import annotations

import argparse
import subprocess
import sys
from pathlib import Path
from typing import Any

import yaml

from .evidence_sessions import load_session, select_session


SHARD_DISPLAY_NAMES = tuple(f"Evidence shard {index}" for index in range(4))


def _mapping(path: Path, repo_root: Path) -> dict[str, Any]:
    value = yaml.safe_load(path.read_text(encoding="utf-8"))
    if not isinstance(value, dict):
        raise ValueError(f"{path.relative_to(repo_root)} must contain an object")
    return value


def required_gate_targets(repo_root: Path) -> list[str]:
    """Resolve required targets from profile applicability and executable ownership."""

    profile = _mapping(repo_root / "governance-profile.yml", repo_root)
    contracts = _mapping(repo_root / "governance/gate-contracts.yml", repo_root)
    catalog = contracts.get("gate_catalog")
    executable = contracts.get("gates")
    configured = profile.get("release_gate_profile", {}).get("gates")
    if not all(isinstance(value, dict) for value in (catalog, executable, configured)):
        raise ValueError("gate profile and contracts must contain mappings")
    targets = sorted(
        str(value["target"])
        for value in configured.values()
        if isinstance(value, dict) and value.get("status") == "required"
    )
    if len(targets) != len(set(targets)):
        raise ValueError("required gate targets must be unique")
    catalog_targets = {
        str(value.get("target")) for value in catalog.values() if isinstance(value, dict)
    }
    if any(target not in executable or target not in catalog_targets for target in targets):
        raise ValueError("every required target needs one executable catalog owner")
    return targets


def partition_required_gates(
    repo_root: Path,
    *,
    shard_index: int,
    shard_count: int,
    planned_targets: list[str] | None = None,
    execution_dag: dict[str, Any] | None = None,
) -> list[str]:
    if shard_count < 1 or shard_index < 0 or shard_index >= shard_count:
        raise ValueError("shard index must be within the positive shard count")
    if execution_dag is not None:
        nodes = execution_dag.get("nodes")
        if not isinstance(nodes, list):
            raise ValueError("planned execution DAG must contain nodes")
        assignments: dict[str, int] = {}
        for node in nodes:
            if not isinstance(node, dict):
                raise ValueError("planned execution DAG node must be an object")
            producer = node.get("producer")
            assigned = node.get("assigned_shard")
            if (
                not isinstance(producer, str)
                or not producer
                or isinstance(assigned, bool)
                or not isinstance(assigned, int)
                or assigned < 0
                or assigned >= shard_count
                or producer in assignments
            ):
                raise ValueError("planned shard assignment is incomplete or ambiguous")
            assignments[producer] = assigned
        targets = planned_targets or []
        if set(assignments) != set(targets):
            raise ValueError("planned shard assignment differs from gate inventory")
        return sorted(
            producer for producer, assigned in assignments.items() if assigned == shard_index
        )
    targets = planned_targets if planned_targets is not None else required_gate_targets(repo_root)
    return [gate for index, gate in enumerate(targets) if index % shard_count == shard_index]


def workflow_shard_matrix() -> dict[str, list[Any]]:
    return {
        "shard": list(range(len(SHARD_DISPLAY_NAMES))),
        "include": [
            {"shard": index, "display_name": display_name}
            for index, display_name in enumerate(SHARD_DISPLAY_NAMES)
        ],
    }


def main(argv: list[str] | None = None) -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--repo-root", type=Path, default=Path.cwd())
    parser.add_argument("--shard-index", type=int, required=True)
    parser.add_argument("--shard-count", type=int, required=True)
    parser.add_argument("--output-root", type=Path)
    parser.add_argument("--session-manifest", type=Path)
    parser.add_argument("--session-root", type=Path)
    args = parser.parse_args(argv)
    repo_root = args.repo_root.resolve()
    explicit = args.output_root is not None or args.session_manifest is not None
    if explicit == (args.session_root is not None):
        raise SystemExit("provide both --output-root/--session-manifest or only --session-root")
    if explicit:
        if args.output_root is None or args.session_manifest is None:
            raise SystemExit("explicit evidence session requires both paths")
        output_root = args.output_root
        session_manifest = args.session_manifest
        session = load_session(session_manifest) if session_manifest.is_file() else None
    else:
        session = select_session(args.session_root)
        session_manifest = session.manifest_path
        output_root = session.root
    planned = (
        [str(value) for value in session.payload.get("expected_gate_inventory", [])]
        if session is not None and session.payload.get("schema_version") == "2.0"
        else None
    )
    gates = partition_required_gates(
        repo_root,
        shard_index=args.shard_index,
        shard_count=args.shard_count,
        planned_targets=planned,
        execution_dag=(
            session.payload.get("execution_dag")
            if session is not None and session.payload.get("schema_version") == "2.0"
            else None
        ),
    )
    for gate in gates:
        result = subprocess.run(
            [
                sys.executable,
                "scripts/governance_evidence.py",
                "--repo-root",
                ".",
                "run",
                "--gate",
                gate,
                "--output",
                str(output_root / gate),
                "--python",
                sys.executable,
                "--session-manifest",
                str(session_manifest),
            ],
            cwd=repo_root,
            check=False,
        )
        if result.returncode:
            raise SystemExit(result.returncode)


if __name__ == "__main__":
    main()
