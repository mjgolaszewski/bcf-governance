"""Executable coverage guard for changed CI state-transition contracts."""

from __future__ import annotations

import os
from pathlib import Path
import subprocess
from typing import Any

import yaml


class CIStateMatrixError(ValueError):
    """Raised when changed CI semantics lack prospective state coverage."""


MATRIX_PATH = "spec/RELEASE_TRAIN_STATE_DAG.md"
BACKTRACE_PATH = "spec/phase0/release-train-backtrace.yml"
REQUIRED_MARKERS = (
    "### P30/P31 state matrix",
    "### P30 workitem DAG",
    "### P31 workitem DAG",
    "### P30/P31 outward construction tree",
    "### Changed-contract downstream permutation rule",
    "controller pending rotation",
    "scheduled control run",
    "adopter qualification",
)


def _git(repo_root: Path, *args: str) -> str | None:
    result = subprocess.run(
        ["git", *args], cwd=repo_root, capture_output=True, text=True, check=False
    )
    return result.stdout.strip() if result.returncode == 0 else None


def _comparison_base(repo_root: Path) -> str | None:
    declared = os.environ.get("BCF_COMPARISON_BASE_SHA", "")
    if declared:
        return declared
    return _git(repo_root, "merge-base", "HEAD", "origin/main")


def _transition_contract(path: str) -> bool:
    name = Path(path).name
    return (
        path == "governance/ci-graph.yml"
        or path.startswith(".github/workflows/")
        or path.startswith("schemas/ci-")
        or path.startswith("spec/RELEASE_TRAIN_STATE_DAG")
        or (
            path.startswith("bcf_governance/tooling/")
            and any(
                token in name
                for token in (
                    "ci_", "controller", "evidence", "evaluation", "preflight", "release"
                )
            )
        )
    )


def _validate_machine_backtrace(repo_root: Path) -> dict[str, int]:
    path = repo_root / BACKTRACE_PATH
    if not path.is_file():
        raise CIStateMatrixError("machine-readable CI state backtrace is unavailable")
    try:
        payload = yaml.safe_load(path.read_text(encoding="utf-8"))
    except (OSError, yaml.YAMLError) as exc:
        raise CIStateMatrixError(f"machine-readable CI state backtrace is unreadable: {exc}") from exc
    if not isinstance(payload, dict):
        raise CIStateMatrixError("machine-readable CI state backtrace must be a mapping")
    transaction = payload.get("adopter_compatibility_observation")
    if not isinstance(transaction, dict):
        raise CIStateMatrixError("machine-readable adopter compatibility graph is missing")
    if transaction.get("publication_prerequisite") is not False:
        raise CIStateMatrixError(
            "adopter compatibility must not become a publication prerequisite"
        )
    declared = transaction.get("edge_contract_fields")
    edges = transaction.get("edges")
    if not isinstance(declared, list) or not declared or not isinstance(edges, list) or not edges:
        raise CIStateMatrixError("machine-readable adopter edge contract is incomplete")
    required = {str(value) for value in declared}
    edge_ids: set[str] = set()
    for edge in edges:
        if not isinstance(edge, dict):
            raise CIStateMatrixError("machine-readable adopter edge must be a mapping")
        missing = sorted(required - set(edge))
        if missing:
            raise CIStateMatrixError(
                f"machine-readable adopter edge {edge.get('id', '<missing>')} lacks: "
                + ", ".join(missing)
            )
        edge_id = str(edge["id"])
        if edge_id in edge_ids:
            raise CIStateMatrixError(f"duplicate machine-readable adopter edge: {edge_id}")
        edge_ids.add(edge_id)
        for field in ("required", "identity_binding", "reject"):
            if not isinstance(edge[field], list) or not edge[field]:
                raise CIStateMatrixError(f"machine-readable adopter edge {edge_id} has empty {field}")
        if edge["authority_effect"] == "":
            raise CIStateMatrixError(f"machine-readable adopter edge {edge_id} lacks authority effect")
    transitions = payload.get("transitions")
    if not isinstance(transitions, list) or not transitions:
        raise CIStateMatrixError("machine-readable release transitions are missing")
    transition_fields = {
        "id", "from", "to", "invariants", "producer", "consumer", "cost", "rejection",
    }
    for transition in transitions:
        if not isinstance(transition, dict) or transition_fields - set(transition):
            raise CIStateMatrixError("machine-readable release transition contract is incomplete")
    return {"edges": len(edges), "transitions": len(transitions)}


def validate_ci_state_matrix(repo_root: Path) -> dict[str, Any]:
    """Require state/DAG coverage in every candidate changing CI semantics."""

    path = repo_root / MATRIX_PATH
    self_governance = (repo_root / "governance/self-governance-policy.yml").is_file()
    if not path.is_file() and not self_governance:
        return {
            "status": "not_applicable_to_adopter",
            "comparison_base": None,
            "changed_contracts": [],
        }
    try:
        text = path.read_text(encoding="utf-8")
    except OSError as exc:
        raise CIStateMatrixError(f"CI state matrix is unavailable: {exc}") from exc
    missing = [marker for marker in REQUIRED_MARKERS if marker not in text]
    if missing:
        raise CIStateMatrixError("CI state matrix lacks required coverage: " + ", ".join(missing))
    machine = _validate_machine_backtrace(repo_root)
    base = _comparison_base(repo_root)
    if base is None:
        return {
            "status": "covered", "comparison_base": None, "changed_contracts": [],
            "machine_backtrace": machine,
        }
    changed_text = _git(repo_root, "diff", "--name-only", base, "--")
    if changed_text is None:
        raise CIStateMatrixError("cannot derive changed CI contracts from comparison base")
    changed = sorted(line for line in changed_text.splitlines() if line)
    contracts = [relative for relative in changed if _transition_contract(relative)]
    if contracts and MATRIX_PATH not in changed:
        raise CIStateMatrixError(
            "changed CI contracts require a same-candidate state matrix update: "
            + ", ".join(contracts)
        )
    return {
        "status": "covered", "comparison_base": base, "changed_contracts": contracts,
        "machine_backtrace": machine,
    }
