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


def sync_evidence_policy(repo_root: Path = REPO_ROOT) -> Path:
    sys.path.insert(0, str(repo_root))
    from bcf_governance.tooling.profile_yaml import render_profile_surface

    profile = yaml.safe_load(
        (repo_root / "governance-profile.yml").read_text(encoding="utf-8")
    )
    if str(profile.get("profile_contract_version", "1.0")) != "2.0":
        raise ValueError("self evidence-policy projection requires profile contract v2")
    path = repo_root / "governance/evidence-policy.yml"
    policy = yaml.safe_load(path.read_text(encoding="utf-8"))
    policy["gate_overrides"] = {}
    path.write_text(render_profile_surface(policy, width=160), encoding="utf-8")
    return path


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--output", type=Path)
    parser.add_argument("--sync-evidence-policy", action="store_true")
    args = parser.parse_args()
    if args.sync_evidence_policy:
        print(sync_evidence_policy())
        return
    text = yaml.safe_dump(build(), sort_keys=False, width=120)
    if args.output is None:
        sys.stdout.write(text)
    else:
        args.output.write_text(text, encoding="utf-8")


if __name__ == "__main__":
    main()
