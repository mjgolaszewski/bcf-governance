"""Canonical interpreter custody projection for Python-backed gate registries."""

from __future__ import annotations

from pathlib import Path
from typing import Any, Mapping

from .interpreter_environment_plan import InterpreterEnvironmentError
from .interpreter_locked_project import normalize_locked_project_contract


DEFAULT_DEPENDENCY_SOURCE = "requirements-governance.txt"


class InterpreterContractProjectionError(ValueError):
    """Raised when interpreter custody cannot be projected without invention."""


def project_profile_interpreter_contract(
    gates: Mapping[str, Any], declared: object, contract_version: str,
) -> dict[str, Any] | None:
    """Project interpreter custody for one exact profile contract version."""

    if contract_version == "1.0":
        if declared is not None:
            raise InterpreterContractProjectionError(
                "interpreter_contract requires profile contract 2.0 or 3.0"
            )
        return None
    return project_interpreter_contract(gates, declared, default_if_required=True)


def python_gate_consumers(gates: Mapping[str, Any]) -> list[str]:
    """Return every gate whose direct invocation consumes a Python runtime."""

    consumers: list[str] = []
    for gate_id, raw in gates.items():
        invocation = raw.get("invocation") if isinstance(raw, dict) else None
        argv = invocation.get("argv") if isinstance(invocation, dict) else None
        if (
            isinstance(argv, list)
            and argv
            and isinstance(argv[0], str)
            and Path(argv[0]).name.lower().startswith("python")
        ):
            consumers.append(str(gate_id))
    return sorted(consumers)


def _relative(value: object, *, field: str) -> str:
    if not isinstance(value, str) or not value:
        raise InterpreterContractProjectionError(f"{field} must be a non-empty path")
    path = Path(value)
    if path.is_absolute() or ".." in path.parts:
        raise InterpreterContractProjectionError(f"{field} must stay inside the repository")
    return path.as_posix()


def project_interpreter_contract(
    gates: Mapping[str, Any], declared: object, *, default_if_required: bool,
) -> dict[str, Any] | None:
    """Normalize explicit custody or derive its sole pack-owned default."""

    consumers = python_gate_consumers(gates)
    if declared is None:
        if not consumers:
            return None
        if not default_if_required:
            raise InterpreterContractProjectionError(
                "profile-v2/v3 Python gates require interpreter_contract: "
                + ", ".join(consumers)
            )
        return {"dependency_source": DEFAULT_DEPENDENCY_SOURCE}
    if not isinstance(declared, dict):
        raise InterpreterContractProjectionError("interpreter_contract must be a mapping")
    if "locked_project" in declared:
        if set(declared) != {"locked_project"}:
            raise InterpreterContractProjectionError("locked-project interpreter contract is ambiguous")
        try:
            return {"locked_project": normalize_locked_project_contract(declared["locked_project"])}
        except InterpreterEnvironmentError as exc:
            raise InterpreterContractProjectionError(str(exc)) from exc
    if "dependency_source" in declared:
        if set(declared) != {"dependency_source"}:
            raise InterpreterContractProjectionError(
                "dependency-source interpreter_contract has ambiguous fields"
            )
        return {
            "dependency_source": _relative(
                declared["dependency_source"], field="interpreter_contract.dependency_source"
            )
        }
    allowed = {
        "project_dependencies", "build_system_requirements",
        "requirements_projection", "optional_dependency_groups", "gate_requirements",
    }
    if set(declared) - allowed or declared.get("project_dependencies") is not True:
        raise InterpreterContractProjectionError("project interpreter_contract is invalid")
    groups = declared.get("optional_dependency_groups")
    requirements = declared.get("gate_requirements")
    if (
        not isinstance(groups, list)
        or len(groups) != len(set(groups))
        or any(not isinstance(group, str) or not group for group in groups)
        or not isinstance(requirements, dict)
    ):
        raise InterpreterContractProjectionError("project interpreter_contract is invalid")
    unknown = sorted(set(requirements) - set(gates))
    if unknown:
        raise InterpreterContractProjectionError(
            "interpreter requirements name unknown gates: " + ", ".join(unknown)
        )
    normalized_requirements: dict[str, list[str]] = {}
    for gate_id, values in requirements.items():
        if (
            not isinstance(values, list)
            or not values
            or len(values) != len(set(values))
            or any(not isinstance(value, str) or not value for value in values)
        ):
            raise InterpreterContractProjectionError(
                f"interpreter requirements for {gate_id} are invalid"
            )
        normalized_requirements[str(gate_id)] = list(values)
    result: dict[str, Any] = {
        "project_dependencies": True,
        "optional_dependency_groups": list(groups),
        "gate_requirements": normalized_requirements,
    }
    if "build_system_requirements" in declared:
        if declared["build_system_requirements"] is not True:
            raise InterpreterContractProjectionError(
                "interpreter build-system custody is invalid"
            )
        result["build_system_requirements"] = True
    if "requirements_projection" in declared:
        result["requirements_projection"] = _relative(
            declared["requirements_projection"],
            field="interpreter_contract.requirements_projection",
        )
    return result
