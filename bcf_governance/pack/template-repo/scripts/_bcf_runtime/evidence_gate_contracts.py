"""Resolve executable evidence contracts from their canonical semantic owner."""

from __future__ import annotations

from pathlib import Path
from typing import Any

import yaml  # type: ignore[import-untyped]

from .evidence_execution import EvidenceError


TEST_POLICIES = {
    "automated_tests",
    "contract_tests",
    "architecture_tests",
    "architecture_module_size",
    "architecture_layer_membership",
    "architecture_context_membership",
    "architecture_import_boundaries",
    "architecture_cqrs_side",
    "architecture_router_thinness",
    "architecture_duplication",
}


def _load_yaml(path: Path) -> dict[str, Any]:
    if not path.exists():
        raise EvidenceError(f"missing required path {path}")
    payload = yaml.safe_load(path.read_text(encoding="utf-8"))
    if not isinstance(payload, dict):
        raise EvidenceError(f"{path} must deserialize to a mapping")
    return payload


def _profile_gate(repo_root: Path, gate_id: str) -> tuple[str, dict[str, Any]]:
    profile = _load_yaml(repo_root / "governance-profile.yml")
    release_profile = profile.get("release_gate_profile")
    gates = release_profile.get("gates") if isinstance(release_profile, dict) else None
    if not isinstance(gates, dict):
        raise EvidenceError("governance-profile.yml must define release_gate_profile.gates")
    for configured_id, value in gates.items():
        if not isinstance(value, dict):
            continue
        target = value.get("target")
        if gate_id in {configured_id, target}:
            if not isinstance(target, str) or not target:
                raise EvidenceError(f"gate {configured_id} has no target")
            return str(configured_id), value
    raise EvidenceError(f"unknown governance gate {gate_id!r}")


def _gate_contract(repo_root: Path, gate_id: str) -> dict[str, Any]:
    configured_id, gate = _profile_gate(repo_root, gate_id)
    profile = _load_yaml(repo_root / "governance-profile.yml")
    policy = _load_yaml(repo_root / "governance/evidence-policy.yml")
    overrides = policy.get("gate_overrides")
    override: dict[str, Any] = {}
    if isinstance(overrides, dict):
        candidate = overrides.get(gate.get("target"), overrides.get(configured_id, {}))
        if isinstance(candidate, dict):
            override = candidate
    registry = _load_yaml(repo_root / "governance/gate-contracts.yml")
    registry_gates = registry.get("gates")
    if gate.get("status") != "required":
        raise EvidenceError(f"gate {gate_id!r} is not applicable to the selected profile")
    if not isinstance(registry_gates, dict) or str(gate["target"]) not in registry_gates:
        raise EvidenceError(f"gate {gate_id!r} has no canonical argv contract")
    executable = registry_gates[str(gate["target"])]
    if not isinstance(executable, dict) or not isinstance(executable.get("invocation"), dict):
        raise EvidenceError(f"gate {gate_id!r} invocation contract is invalid")
    contract_v2 = str(profile.get("profile_contract_version", "1.0")) == "2.0"
    evidence = executable.get("evidence", {})
    if not isinstance(evidence, dict):
        raise EvidenceError(f"gate {gate_id!r} evidence contract is invalid")
    if contract_v2 and override:
        raise EvidenceError(
            "profile-v2 evidence semantics must be owned only by governance/gate-contracts.yml"
        )
    command_policy = str(gate.get("command_policy", ""))
    default_kind = (
        "test_suite"
        if command_policy in TEST_POLICIES
        else "security_review"
        if command_policy == "security_review"
        else "runtime_health"
        if command_policy == "runtime_smoke"
        else "gate"
    )
    if contract_v2:
        kind = str(evidence.get("kind") or default_kind)
        controls = executable.get("negative_controls", [])
        test_contract = evidence.get("test_contract", {})
        environment = evidence.get("environment_assertions", [])
        outputs = evidence.get("output_requirements", [])
        freshness = evidence.get("freshness_limit_seconds")
    else:
        kind = str(override.get("evidence_kind") or default_kind)
        controls = override.get("negative_controls", [])
        test_contract = {
            **evidence.get("test_contract", {}),
            **override.get("test_contract", {}),
        }
        environment = override.get("environment_assertions", [])
        outputs = override.get("output_requirements", [])
        freshness = override.get("freshness_limit_seconds")
    return {
        "id": configured_id,
        "target": str(gate["target"]),
        "status": str(gate.get("status", "required")),
        "command_policy": command_policy,
        "evidence_kind": kind,
        "negative_controls": controls,
        "test_contract": test_contract,
        "environment_assertions": environment,
        "output_requirements": outputs,
        "freshness_limit_seconds": freshness,
        "invocation": executable["invocation"],
    }


def expected_evidence_kinds(repo_root: Path) -> dict[str, str]:
    """Return the contract-derived evidence kind for each required gate target."""
    profile = _load_yaml(repo_root / "governance-profile.yml")
    release_profile = profile.get("release_gate_profile")
    gates = release_profile.get("gates") if isinstance(release_profile, dict) else {}
    if not isinstance(gates, dict):
        return {}
    return {
        str(gate["target"]): str(
            _gate_contract(repo_root, str(gate["target"]))["evidence_kind"]
        )
        for gate in gates.values()
        if isinstance(gate, dict)
        and gate.get("status") == "required"
        and isinstance(gate.get("target"), str)
    }


def expected_invocations(repo_root: Path) -> dict[str, dict[str, Any]]:
    """Return canonical invocations for exact receipt revalidation."""
    registry = _load_yaml(repo_root / "governance/gate-contracts.yml")
    gates = registry.get("gates")
    if not isinstance(gates, dict):
        return {}
    return {
        str(target): dict(value["invocation"])
        for target, value in gates.items()
        if isinstance(value, dict) and isinstance(value.get("invocation"), dict)
    }
