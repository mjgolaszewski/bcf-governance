"""Compile and materialize the selected-interpreter dependency contract."""

from __future__ import annotations

import argparse
import re
import tomllib
from dataclasses import dataclass
from pathlib import Path
from typing import Any

import yaml  # type: ignore[import-untyped]


class InterpreterEnvironmentError(ValueError):
    """Raised when the governed interpreter environment cannot be compiled."""


@dataclass(frozen=True)
class InterpreterEnvironmentPlan:
    """One canonical projection of every selected-interpreter requirement."""

    requirements: tuple[str, ...]
    requires_python: str
    projection_path: Path | None

    @property
    def distribution_names(self) -> frozenset[str]:
        return frozenset(_normalized_name(value) for value in self.requirements)

    def rendered_requirements(self) -> str:
        return "".join(f"{value}\n" for value in self.requirements)


def _dependency_name(value: object) -> str:
    if not isinstance(value, str):
        raise InterpreterEnvironmentError("dependency declaration is not a string")
    match = re.match(r"^\s*([A-Za-z0-9][A-Za-z0-9._-]*)", value)
    if match is None:
        raise InterpreterEnvironmentError("dependency declaration has no distribution name")
    return match.group(1)


def _normalized_name(value: object) -> str:
    return re.sub(r"[-_.]+", "-", _dependency_name(value)).lower()


def _mapping(value: object, message: str) -> dict[str, Any]:
    if not isinstance(value, dict):
        raise InterpreterEnvironmentError(message)
    return value


def _requirements(value: object, message: str) -> list[str]:
    if not isinstance(value, list) or not all(isinstance(item, str) for item in value):
        raise InterpreterEnvironmentError(message)
    return list(value)


def _safe_projection(repo_root: Path, value: object) -> Path | None:
    if value is None:
        return None
    if not isinstance(value, str) or not value:
        raise InterpreterEnvironmentError("interpreter requirement projection is invalid")
    relative = Path(value)
    if relative.is_absolute() or ".." in relative.parts:
        raise InterpreterEnvironmentError(
            "interpreter requirement projection must stay inside the repository"
        )
    path = repo_root / relative
    if not path.parent.resolve().is_relative_to(repo_root.resolve()):
        raise InterpreterEnvironmentError(
            "interpreter requirement projection escapes the repository"
        )
    return path


def derive_interpreter_environment(
    repo_root: Path,
) -> InterpreterEnvironmentPlan | None:
    """Derive one dependency plan from governed source declarations."""

    root = repo_root.resolve()
    registry_path = root / "governance/gate-contracts.yml"
    if not registry_path.is_file():
        return None
    registry = yaml.safe_load(registry_path.read_text(encoding="utf-8"))
    registry = _mapping(registry, "gate contract registry is invalid")
    contract = registry.get("interpreter_contract")
    if contract is None:
        return None
    contract = _mapping(contract, "interpreter contract is invalid")
    if contract.get("project_dependencies") is not True:
        raise InterpreterEnvironmentError("interpreter contract is invalid")
    try:
        project = tomllib.loads((root / "pyproject.toml").read_text(encoding="utf-8"))
    except (OSError, UnicodeError, tomllib.TOMLDecodeError) as exc:
        raise InterpreterEnvironmentError(
            "interpreter project dependency source is invalid"
        ) from exc
    metadata = _mapping(project.get("project"), "interpreter project metadata is missing")
    requirements = _requirements(
        metadata.get("dependencies"), "project dependency inventory is missing"
    )
    include_build_system = contract.get("build_system_requirements", False)
    if not isinstance(include_build_system, bool):
        raise InterpreterEnvironmentError(
            "interpreter build-system dependency contract is invalid"
        )
    if include_build_system:
        build_system = _mapping(
            project.get("build-system"), "build-system dependency inventory is missing"
        )
        build_requirements = _requirements(
            build_system.get("requires"), "build-system dependency inventory is missing"
        )
        if not build_requirements:
            raise InterpreterEnvironmentError(
                "build-system dependency inventory is missing"
            )
        requirements.extend(build_requirements)
    optional = _mapping(
        metadata.get("optional-dependencies", {}),
        "interpreter optional dependency contract is invalid",
    )
    groups = contract.get("optional_dependency_groups")
    if not isinstance(groups, list) or not all(isinstance(group, str) for group in groups):
        raise InterpreterEnvironmentError(
            "interpreter optional dependency contract is invalid"
        )
    for group in groups:
        requirements.extend(
            _requirements(
                optional.get(group), "interpreter optional dependency group is missing"
            )
        )
    gates = _mapping(registry.get("gates"), "interpreter gate inventory is invalid")
    additions = _mapping(
        contract.get("gate_requirements"),
        "interpreter gate requirement contract is invalid",
    )
    if set(additions) - set(gates):
        raise InterpreterEnvironmentError("interpreter requirements name unknown gates")
    for values in additions.values():
        requirements.extend(
            _requirements(values, "interpreter gate requirements must be lists")
        )
    normalized = [_normalized_name(value) for value in requirements]
    if len(set(normalized)) != len(requirements):
        raise InterpreterEnvironmentError(
            "interpreter dependency declarations must have unique names"
        )
    requires_python = metadata.get("requires-python")
    if not isinstance(requires_python, str) or not requires_python:
        raise InterpreterEnvironmentError("project requires-python contract is missing")
    return InterpreterEnvironmentPlan(
        requirements=tuple(
            value
            for _, value in sorted(
                zip(normalized, requirements, strict=True), key=lambda item: item[0]
            )
        ),
        requires_python=requires_python,
        projection_path=_safe_projection(root, contract.get("requirements_projection")),
    )


def verify_interpreter_environment_projection(
    plan: InterpreterEnvironmentPlan,
) -> None:
    """Reject a stale hand-maintained bootstrap dependency surface."""

    path = plan.projection_path
    if path is None:
        return
    if path.is_symlink() or not path.is_file():
        raise InterpreterEnvironmentError(
            "interpreter requirement projection is missing or unsafe"
        )
    if path.read_text(encoding="utf-8") != plan.rendered_requirements():
        raise InterpreterEnvironmentError(
            "interpreter requirement projection drift; run `bcf environment apply`"
        )


def apply_interpreter_environment_projection(
    plan: InterpreterEnvironmentPlan,
) -> Path:
    """Materialize the canonical dependency plan for fresh-environment bootstrap."""

    path = plan.projection_path
    if path is None:
        raise InterpreterEnvironmentError(
            "interpreter contract declares no requirement projection"
        )
    if path.is_symlink():
        raise InterpreterEnvironmentError(
            "interpreter requirement projection is missing or unsafe"
        )
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(plan.rendered_requirements(), encoding="utf-8")
    return path


def main(argv: list[str] | None = None) -> None:
    parser = argparse.ArgumentParser(
        description="Check or apply the governed interpreter dependency projection."
    )
    parser.add_argument("operation", choices=("check", "apply"))
    parser.add_argument("--repo-root", type=Path, default=Path.cwd())
    args = parser.parse_args(argv)
    try:
        plan = derive_interpreter_environment(args.repo_root)
        if plan is None:
            raise InterpreterEnvironmentError("repository declares no interpreter contract")
        if args.operation == "check":
            verify_interpreter_environment_projection(plan)
            path = plan.projection_path
        else:
            path = apply_interpreter_environment_projection(plan)
    except (OSError, UnicodeError, ValueError) as exc:
        raise SystemExit(str(exc)) from exc
    print(path if path is not None else "interpreter-environment-ok")


if __name__ == "__main__":
    main()
