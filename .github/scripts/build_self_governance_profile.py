"""Emit BCF's self profile by consuming the canonical gate-contract owner."""

from __future__ import annotations

import argparse
from copy import deepcopy
from pathlib import Path
import sys
from typing import Any

import yaml


REPO_ROOT = Path(__file__).resolve().parents[2]
BUILTIN_GATES = frozenset({"governance-validate", "governance-exposure-scan"})


def build(repo_root: Path = REPO_ROOT) -> dict[str, Any]:
    source = yaml.safe_load(
        (repo_root / "governance/gate-contracts.yml").read_text(encoding="utf-8")
    )
    if not isinstance(source, dict) or not isinstance(source.get("gates"), dict):
        raise ValueError("governance/gate-contracts.yml must contain a gates mapping")
    gates = {
        str(gate_id): deepcopy(contract)
        for gate_id, contract in source["gates"].items()
        if gate_id not in BUILTIN_GATES
    }
    return {
        "schema_version": source.get("schema_version"),
        "target_profile": source.get("target_profile"),
        "gates": gates,
        "provenance": deepcopy(source.get("provenance", {})),
    }


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--output", type=Path)
    args = parser.parse_args()
    text = yaml.safe_dump(build(), sort_keys=False, width=120)
    if args.output is None:
        sys.stdout.write(text)
    else:
        args.output.write_text(text, encoding="utf-8")


if __name__ == "__main__":
    main()
