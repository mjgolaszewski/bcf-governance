"""Executable coverage guard for changed CI state-transition contracts."""

from __future__ import annotations

import os
import json
from pathlib import Path
import subprocess
from typing import Any

from jsonschema import Draft202012Validator, SchemaError

from ..ci_graph_composition import validate_backtrace_transition_references
from ..ci_graph_errors import CIGraphError
from ..ci_graph_yaml import GraphYAMLError, load_yaml_path
from .preflight_repository_context import pr_context


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
    context_keys = (
        "BCF_PROVIDER_EVENT", "GITHUB_EVENT_NAME", "BCF_INVOCATION_KIND",
        "BCF_ORIGIN_COMPARISON_BASE_SHA", "BCF_CALLER_COMPARISON_BASE_SHA", "BCF_PR_BASE_SHA",
    )
    if any(os.environ.get(key) for key in context_keys):
        event = os.environ.get("BCF_PROVIDER_EVENT") or os.environ.get("GITHUB_EVENT_NAME")
        mode = "release" if event in {"push", "schedule", "workflow_dispatch"} else "pr"
        try:
            context = pr_context(repo_root, mode)
        except ValueError as exc:
            raise CIStateMatrixError(f"CI comparison context is invalid: {exc}") from exc
        return context["base_sha"] if context["applicable"] else None
    derived = _git(repo_root, "merge-base", "HEAD", "origin/main")
    if declared and declared != derived:
        raise CIStateMatrixError("CI comparison assertion differs from derived local base")
    return derived


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



def _validate_backtrace_references(payload: dict[str, Any]) -> None:
    """Check authored references, never runtime population or authority truth."""
    populations: dict[str, set[str]] = {}
    for section in ("invariants", "primitives", "states", "transitions"):
        identities = [row["id"] for row in payload[section]]
        if len(identities) != len(set(identities)):
            raise CIStateMatrixError(f"machine-readable backtrace has duplicate {section} identity")
        populations[section] = set(identities)
    for row in [*payload["primitives"], *payload["transitions"]]:
        if set(row["invariants"]) - populations["invariants"]:
            raise CIStateMatrixError("machine-readable backtrace has an undeclared invariant reference")
    transitions = {row["id"]: row for row in payload["transitions"]}
    for transition in payload["transitions"]:
        if {transition["from"], transition["to"]} - populations["states"]:
            raise CIStateMatrixError("machine-readable backtrace has an undeclared state reference")
    try:
        validate_backtrace_transition_references(transitions)
    except CIGraphError as exc:
        raise CIStateMatrixError(f"machine-readable backtrace {exc}") from exc
    active_primitives = set(payload["adopter_compatibility_observation"]["primitives"])
    active_primitives.add(payload["bounded_workitem_frontier_contract"]["primitive"])
    if active_primitives - populations["primitives"]:
        raise CIStateMatrixError("machine-readable backtrace has an undeclared active primitive reference")
    for exclusion in payload["exclusions"]:
        if "invariant" in exclusion and exclusion["invariant"] not in populations["invariants"]:
            raise CIStateMatrixError("machine-readable backtrace exclusion has an undeclared invariant reference")


def _validate_machine_backtrace(repo_root: Path) -> dict[str, int]:
    path = repo_root / BACKTRACE_PATH
    if not path.is_file():
        raise CIStateMatrixError("machine-readable CI state backtrace is unavailable")
    try:
        payload = load_yaml_path(path)
    except (OSError, GraphYAMLError) as exc:
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
        edge_id = edge.get("id")
        if not isinstance(edge_id, str) or not edge_id:
            raise CIStateMatrixError("machine-readable adopter edge lacks an id")
        if edge_id in edge_ids:
            raise CIStateMatrixError(f"duplicate machine-readable adopter edge: {edge_id}")
        edge_ids.add(edge_id)
        for field in ("required", "identity_binding", "reject"):
            if not isinstance(edge.get(field), list) or not edge[field]:
                raise CIStateMatrixError(f"machine-readable adopter edge {edge_id} has empty {field}")
        if edge.get("authority_effect") == "":
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
    schema_path = repo_root / "schemas/release-train-backtrace.schema.json"
    try:
        if schema_path.is_symlink():
            raise ValueError("schema must be a regular nonsymlink file")
        schema = json.loads(schema_path.read_text(encoding="utf-8"))
        if not isinstance(schema, dict):
            raise ValueError("schema must be a mapping")
        Draft202012Validator.check_schema(schema)
    except (OSError, ValueError, SchemaError) as exc:
        raise CIStateMatrixError(f"machine-readable backtrace schema is unavailable or invalid: {exc}") from exc
    error = next(Draft202012Validator(schema).iter_errors(payload), None)
    if error is not None:
        raise CIStateMatrixError(f"machine-readable backtrace schema violation: {error.message}")
    _validate_backtrace_references(payload)
    return {"edges": len(edges), "transitions": len(transitions)}


def validate_ci_state_matrix(repo_root: Path, *, authored_only: bool = False) -> dict[str, Any]:
    """Require state/DAG coverage in every candidate changing CI semantics."""

    path = repo_root / MATRIX_PATH
    self_governance = (repo_root / "governance/self-governance-policy.yml").is_file()
    if not path.is_file() and not self_governance:
        return {
            "status": "not_applicable_to_adopter",
            "comparison_base": None,
            "changed_contracts": [],
        }
    if authored_only:
        return {
            "status": "authored_structurally_valid", "authority": False,
            "execution_qualified": False,
            "machine_backtrace": _validate_machine_backtrace(repo_root),
        }
    base = _comparison_base(repo_root)
    try:
        text = path.read_text(encoding="utf-8")
    except OSError as exc:
        raise CIStateMatrixError(f"CI state matrix is unavailable: {exc}") from exc
    missing = [marker for marker in REQUIRED_MARKERS if marker not in text]
    if missing:
        raise CIStateMatrixError("CI state matrix lacks required coverage: " + ", ".join(missing))
    machine = _validate_machine_backtrace(repo_root)
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
