"""Capture one mechanically derived shard of required BCF evidence gates."""

from __future__ import annotations

import argparse
import subprocess
import sys
from pathlib import Path
from typing import Any

import yaml


REPO_ROOT = Path(__file__).resolve().parents[2]
SHARD_DISPLAY_NAMES = (
    "Boundaries, contracts, runtime, types, and secrets",
    "CQRS, module size, exposure, and dependency risk",
    "Duplication, routers, governance, and ownership",
    "Full tests, lint, import boundaries, and SBOM",
)


def _mapping(path: Path) -> dict[str, Any]:
    value = yaml.safe_load(path.read_text(encoding="utf-8"))
    if not isinstance(value, dict):
        raise ValueError(f"{path.relative_to(REPO_ROOT)} must contain an object")
    return value


def required_gate_targets(repo_root: Path) -> list[str]:
    """Resolve required targets from profile applicability and executable ownership."""
    profile = _mapping(repo_root / "governance-profile.yml")
    contracts = _mapping(repo_root / "governance/gate-contracts.yml")
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
    repo_root: Path, *, shard_index: int, shard_count: int
) -> list[str]:
    if shard_count < 1 or shard_index < 0 or shard_index >= shard_count:
        raise ValueError("shard index must be within the positive shard count")
    return [
        gate
        for index, gate in enumerate(required_gate_targets(repo_root))
        if index % shard_count == shard_index
    ]


def workflow_shard_matrix() -> dict[str, list[Any]]:
    """Return the canonical workflow mirror for the fixed self-governance shards."""
    return {
        "shard": list(range(len(SHARD_DISPLAY_NAMES))),
        "include": [
            {"shard": index, "display_name": display_name}
            for index, display_name in enumerate(SHARD_DISPLAY_NAMES)
        ],
    }


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--shard-index", type=int, required=True)
    parser.add_argument("--shard-count", type=int, required=True)
    parser.add_argument("--output-root", type=Path, required=True)
    parser.add_argument("--session-manifest", type=Path, required=True)
    args = parser.parse_args()
    gates = partition_required_gates(
        REPO_ROOT, shard_index=args.shard_index, shard_count=args.shard_count
    )
    if not gates:
        raise SystemExit("evidence shard selects zero required gates")
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
                str(args.output_root / gate),
                "--python",
                sys.executable,
                "--session-manifest",
                str(args.session_manifest),
            ],
            cwd=REPO_ROOT,
            check=False,
        )
        if result.returncode:
            raise SystemExit(result.returncode)


if __name__ == "__main__":
    main()
