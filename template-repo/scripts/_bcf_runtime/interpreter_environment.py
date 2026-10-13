"""Compile and materialize the selected-interpreter dependency contract."""

from __future__ import annotations

import argparse
import ast
import base64
import fcntl
import hashlib
import json
import os
import re
import shutil
import subprocess
import sys
import tomllib
from dataclasses import dataclass
from pathlib import Path
from typing import Any

import yaml  # type: ignore[import-untyped]
from packaging.requirements import InvalidRequirement, Requirement

from .runtime_capacity import (
    RuntimeCapacityError,
    allocate_execution_state,
    load_runtime_contract,
)


class InterpreterEnvironmentError(ValueError):
    """Raised when the governed interpreter environment cannot be compiled."""


PROJECT_ENVIRONMENT_INSTALLER_REQUIREMENT = "pip==26.2.1"


def validate_runtime_import_dependencies(repo_root: Path) -> None:
    """Fail before evidence if self runtime imports undeclared distributions."""

    tooling_root = repo_root / "bcf_governance/tooling"
    if not tooling_root.is_dir():
        return  # An adopter owns the installed pack, not BCF's source package.
    try:
        project = tomllib.loads((repo_root / "pyproject.toml").read_text(encoding="utf-8"))
        declared = {
            _normalized_name(requirement)
            for requirement in project["project"]["dependencies"]
        }
    except (OSError, UnicodeError, tomllib.TOMLDecodeError, KeyError, TypeError) as exc:
        raise InterpreterEnvironmentError("runtime package dependencies are invalid") from exc
    paths = sorted(tooling_root.rglob("*.py"))
    internal = {path.stem for path in paths if path.name != "__init__.py"}
    internal.update(path.name for path in tooling_root.iterdir() if path.is_dir())
    imported: set[str] = set()
    for path in paths:
        try:
            tree = ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
        except (OSError, UnicodeError, SyntaxError) as exc:
            raise InterpreterEnvironmentError("runtime source import inventory is invalid") from exc
        for node in ast.walk(tree):
            if isinstance(node, ast.Import):
                imported.update(alias.name.split(".", 1)[0] for alias in node.names)
            elif isinstance(node, ast.ImportFrom) and node.level == 0 and node.module:
                imported.add(node.module.split(".", 1)[0])
    aliases = {"yaml": "pyyaml"}
    missing = sorted({
        aliases.get(name, name)
        for name in imported
        if name not in sys.stdlib_module_names
        and name != "bcf_governance"
        and name not in internal
    } - declared)
    if missing:
        raise InterpreterEnvironmentError(
            "runtime imports undeclared package dependencies: " + ", ".join(missing)
        )


@dataclass(frozen=True)
class InterpreterEnvironmentPlan:
    """One canonical projection of every selected-interpreter requirement."""

    requirements: tuple[str, ...]
    requires_python: str | None
    projection_path: Path | None
    source_kind: str = "project_metadata_projection"
    source_path: Path | None = None
    source_sha256: str | None = None

    @property
    def distribution_names(self) -> frozenset[str]:
        return frozenset(_normalized_name(value) for value in self.requirements)

    def rendered_requirements(self) -> str:
        return "".join(f"{value}\n" for value in self.requirements)

    def identity(self, base_python: Path) -> str:
        """Bind one derived environment to its source plan and base runtime."""

        executable = base_python.resolve(strict=True)
        digest = hashlib.sha256()
        digest.update(self.rendered_requirements().encode("utf-8"))
        digest.update(b"\0")
        digest.update((self.requires_python or "").encode("utf-8"))
        digest.update(b"\0")
        digest.update(self.source_kind.encode("utf-8"))
        digest.update(b"\0")
        digest.update((self.source_sha256 or "").encode("ascii"))
        digest.update(b"\0")
        with executable.open("rb") as stream:
            for chunk in iter(lambda: stream.read(1024 * 1024), b""):
                digest.update(chunk)
        return digest.hexdigest()

    @property
    def installation_path(self) -> Path | None:
        """Return the authenticated dependency input consumed by pip."""

        return self.projection_path or self.source_path

    def pip_arguments(self) -> tuple[str, ...]:
        """Bind installation to the already-derived dependency proposition."""

        if self.source_kind == "legacy_governance_requirements":
            return self.requirements
        if self.projection_path is None:
            raise InterpreterEnvironmentError(
                "interpreter dependency projection is unavailable"
            )
        return ("--requirement", str(self.projection_path))


def _dependency_name(value: object) -> str:
    if not isinstance(value, str):
        raise InterpreterEnvironmentError("dependency declaration is not a string")
    try:
        requirement = Requirement(value)
    except InvalidRequirement as exc:
        raise InterpreterEnvironmentError(
            "dependency declaration is not a bounded package requirement"
        ) from exc
    if requirement.url or requirement.marker or requirement.extras:
        raise InterpreterEnvironmentError(
            "dependency declaration must not use URLs, markers, or extras"
        )
    return requirement.name


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


def _legacy_interpreter_environment(
    root: Path, registry: dict[str, Any]
) -> InterpreterEnvironmentPlan | None:
    """Compile the closed profile-v1 dependency/runtime contract."""

    if str(registry.get("profile_contract_version", "1.0")) != "1.0":
        return None
    requirements_path = root / "requirements-governance.txt"
    if requirements_path.is_symlink() or not requirements_path.is_file():
        raise InterpreterEnvironmentError(
            "legacy interpreter dependency source is missing or unsafe"
        )
    try:
        source_bytes = requirements_path.read_bytes()
        source_text = source_bytes.decode("utf-8")
    except (OSError, UnicodeError) as exc:
        raise InterpreterEnvironmentError(
            "legacy interpreter dependency source is unreadable"
        ) from exc
    requirements = [
        line.strip()
        for line in source_text.splitlines()
        if line.strip() and not line.lstrip().startswith("#")
    ]
    if not requirements:
        raise InterpreterEnvironmentError(
            "legacy interpreter dependency source is empty"
        )
    normalized = [_normalized_name(value) for value in requirements]
    if len(set(normalized)) != len(requirements):
        raise InterpreterEnvironmentError(
            "interpreter dependency declarations must have unique names"
        )
    installer_name = _normalized_name(PROJECT_ENVIRONMENT_INSTALLER_REQUIREMENT)
    installer_requirements = [
        value
        for value in requirements
        if _normalized_name(value) == installer_name
    ]
    if not installer_requirements:
        requirements.append(PROJECT_ENVIRONMENT_INSTALLER_REQUIREMENT)
    elif installer_requirements != [PROJECT_ENVIRONMENT_INSTALLER_REQUIREMENT]:
        raise InterpreterEnvironmentError(
            "project environment installer requirement must equal "
            + PROJECT_ENVIRONMENT_INSTALLER_REQUIREMENT
        )
    graph_path = root / "governance/ci-graph.yml"
    python_minor: str | None = None
    if graph_path.is_symlink():
        raise InterpreterEnvironmentError(
            "legacy interpreter graph contract is unavailable"
        )
    if graph_path.exists():
        try:
            graph = yaml.safe_load(graph_path.read_text(encoding="utf-8"))
            graph = _mapping(graph, "legacy interpreter graph contract is invalid")
            if str(graph.get("profile_contract_version", "1.0")) != "1.0":
                raise InterpreterEnvironmentError(
                    "legacy interpreter graph contract version is invalid"
                )
            resources = _mapping(
                graph.get("resource_classes"),
                "legacy interpreter graph resources are invalid",
            )
            python_minors = {
                str(resource["python_version"])
                for resource in resources.values()
                if isinstance(resource, dict) and "python_version" in resource
            }
        except (OSError, UnicodeError, yaml.YAMLError, KeyError, TypeError) as exc:
            raise InterpreterEnvironmentError(
                "legacy interpreter graph contract is unavailable"
            ) from exc
        if len(python_minors) != 1 or any(
            re.fullmatch(r"3\.[0-9]+", value) is None for value in python_minors
        ):
            raise InterpreterEnvironmentError(
                "legacy interpreter graph must declare one Python minor"
            )
        python_minor = next(iter(python_minors))
    return InterpreterEnvironmentPlan(
        requirements=tuple(requirements),
        requires_python=f"=={python_minor}.*" if python_minor is not None else None,
        projection_path=None,
        source_kind="legacy_governance_requirements",
        source_path=requirements_path,
        source_sha256=hashlib.sha256(source_bytes).hexdigest(),
    )


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
        return _legacy_interpreter_environment(root, registry)
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
    installer_name = _normalized_name(PROJECT_ENVIRONMENT_INSTALLER_REQUIREMENT)
    installer_requirements = [
        value for value in requirements if _normalized_name(value) == installer_name
    ]
    if not installer_requirements:
        requirements.append(PROJECT_ENVIRONMENT_INSTALLER_REQUIREMENT)
    elif installer_requirements != [PROJECT_ENVIRONMENT_INSTALLER_REQUIREMENT]:
        raise InterpreterEnvironmentError(
            "project environment installer requirement must equal "
            + PROJECT_ENVIRONMENT_INSTALLER_REQUIREMENT
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
        if (
            plan.source_kind == "project_metadata_projection"
            and plan.source_path is None
            and plan.source_sha256 is None
        ):
            return
        if (
            plan.source_kind != "legacy_governance_requirements"
            or plan.source_path is None
            or plan.source_sha256 is None
            or plan.source_path.is_symlink()
            or not plan.source_path.is_file()
        ):
            raise InterpreterEnvironmentError(
                "interpreter dependency source is missing or unsafe"
            )
        try:
            observed_source_sha256 = hashlib.sha256(
                plan.source_path.read_bytes()
            ).hexdigest()
        except OSError as exc:
            raise InterpreterEnvironmentError(
                "interpreter dependency source is unreadable"
            ) from exc
        if observed_source_sha256 != plan.source_sha256:
            raise InterpreterEnvironmentError(
                "interpreter dependency source changed after derivation"
            )
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


def reconcile_interpreter_environment(
    repo_root: Path, *, apply: bool
) -> Path | None:
    """Check or materialize the exact governed bootstrap dependency surface."""

    plan = derive_interpreter_environment(repo_root)
    if plan is None or plan.projection_path is None:
        return None
    if apply:
        return apply_interpreter_environment_projection(plan)
    verify_interpreter_environment_projection(plan)
    return plan.projection_path


def materialize_interpreter_environment(
    repo_root: Path, base_python: Path
) -> Path:
    """Materialize or reuse one content-addressed project interpreter."""

    root = repo_root.resolve()
    plan = derive_interpreter_environment(root)
    if plan is None or plan.installation_path is None:
        raise InterpreterEnvironmentError(
            "project interpreter cannot be derived without an authenticated dependency source"
        )
    if plan.requires_python is None:
        raise InterpreterEnvironmentError(
            "project interpreter cannot be materialized without an authenticated Python runtime source"
        )
    verify_interpreter_environment_projection(plan)
    try:
        plan_identity = plan.identity(base_python)
    except OSError as exc:
        raise InterpreterEnvironmentError(
            "project interpreter base runtime is unavailable"
        ) from exc
    try:
        runtime_contract = load_runtime_contract(root / "governance/ci-runtime.yml")
        namespace = "bcfenv-" + base64.b32encode(
            bytes.fromhex(plan_identity)
        ).decode("ascii").lower().rstrip("=")
        lease = allocate_execution_state(
            root,
            runtime_contract,
            session_id=plan_identity,
            workload_id="project-environment",
            execution_id=plan_identity,
            invocation={
                "state": {
                    "lifecycle": "persistent_shared",
                    "namespace": namespace,
                }
            },
        )
        parent = lease.root / "project-environments"
    except RuntimeCapacityError as exc:
        raise InterpreterEnvironmentError(
            "project interpreter cache contract is invalid"
        ) from exc
    lock_path = parent / ".materialize.lock"
    parent.mkdir(parents=True, exist_ok=True)
    with lock_path.open("a+b") as lock:
        fcntl.flock(lock.fileno(), fcntl.LOCK_EX)
        cached = _matching_cached_environment(parent, plan_identity)
        if cached is not None:
            target, payload = cached
            python = target / "venv/bin/python"
            inventory = _installed_inventory(python, root)
            if payload["inventory_sha256"] != _sha256_text(inventory):
                raise InterpreterEnvironmentError(
                    "derived project interpreter inventory is stale"
                )
            return python
        temporary = parent / f".{plan_identity}.building-{os.getpid()}"
        if temporary.exists() or temporary.is_symlink():
            raise InterpreterEnvironmentError(
                "derived project interpreter has unexplained pre-existing build state"
            )
        try:
            created = subprocess.run(
                [
                    str(base_python.resolve(strict=True)),
                    "-m",
                    "venv",
                    "--without-pip",
                    str(temporary / "venv"),
                ],
                cwd=root,
                capture_output=True,
                text=True,
                check=False,
            )
            if created.returncode != 0:
                detail = created.stderr.strip() or created.stdout.strip() or "venv creation failed"
                raise InterpreterEnvironmentError(
                    "derived project interpreter creation failed: " + detail
                )
            candidate = temporary / "venv/bin/python"
            install_command = [
                str(base_python.resolve(strict=True)),
                "-m",
                "pip",
                "--python",
                str(candidate),
                "install",
                "--disable-pip-version-check",
                *plan.pip_arguments(),
            ]
            installed = subprocess.run(
                install_command,
                cwd=root,
                capture_output=True,
                text=True,
                check=False,
            )
            if installed.returncode != 0:
                detail = installed.stderr.strip() or installed.stdout.strip() or "dependency installation failed"
                raise InterpreterEnvironmentError(
                    "derived project interpreter installation failed: " + detail
                )
            inventory = _installed_inventory(candidate, root)
            inventory_sha256 = _sha256_text(inventory)
            identity = _sha256_text(plan_identity + "\0" + inventory_sha256)
            target = parent / identity
            if target.exists() or target.is_symlink():
                raise InterpreterEnvironmentError(
                    "derived project interpreter target has unexplained state"
                )
            temporary.mkdir(parents=True, exist_ok=True)
            (temporary / "environment.json").write_text(
                json.dumps(
                    {
                        "schema_version": "1.0",
                        "plan_identity": plan_identity,
                        "identity": identity,
                        "inventory_sha256": inventory_sha256,
                    },
                    sort_keys=True,
                    separators=(",", ":"),
                )
                + "\n",
                encoding="utf-8",
            )
            temporary.replace(target)
        finally:
            if temporary.exists():
                shutil.rmtree(temporary)
    return target / "venv/bin/python"


def _matching_cached_environment(
    parent: Path, plan_identity: str
) -> tuple[Path, dict[str, str]] | None:
    matches: list[tuple[Path, dict[str, str]]] = []
    for target in sorted(parent.iterdir()):
        if target.name == ".materialize.lock":
            continue
        if target.name.startswith(".") or target.is_symlink() or not target.is_dir():
            raise InterpreterEnvironmentError(
                "derived project interpreter cache has unexplained state"
            )
        python = target / "venv/bin/python"
        manifest = target / "environment.json"
        if not python.is_file() or not os.access(python, os.X_OK):
            raise InterpreterEnvironmentError(
                "derived project interpreter cache is incomplete or unsafe"
            )
        try:
            payload = json.loads(manifest.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError) as exc:
            raise InterpreterEnvironmentError(
                "derived project interpreter manifest is unavailable"
            ) from exc
        if (
            not isinstance(payload, dict)
            or set(payload)
            != {"schema_version", "plan_identity", "identity", "inventory_sha256"}
            or payload.get("schema_version") != "1.0"
            or payload.get("identity") != target.name
            or not all(
                isinstance(payload.get(name), str)
                and re.fullmatch(r"[a-f0-9]{64}", payload[name]) is not None
                for name in ("plan_identity", "identity", "inventory_sha256")
            )
            or payload.get("identity")
            != _sha256_text(
                str(payload.get("plan_identity"))
                + "\0"
                + str(payload.get("inventory_sha256"))
            )
        ):
            raise InterpreterEnvironmentError(
                "derived project interpreter identity is stale"
            )
        if payload["plan_identity"] != plan_identity:
            raise InterpreterEnvironmentError(
                "derived project interpreter namespace identity is stale"
            )
        matches.append((target, payload))
    if len(matches) > 1:
        raise InterpreterEnvironmentError(
            "derived project interpreter identity is ambiguous"
        )
    return matches[0] if matches else None


def _installed_inventory(python: Path, repo_root: Path) -> str:
    result = subprocess.run(
        [str(python), "-m", "pip", "freeze", "--all"],
        cwd=repo_root,
        capture_output=True,
        text=True,
        check=False,
    )
    if result.returncode != 0:
        detail = result.stderr.strip() or result.stdout.strip() or "inventory failed"
        raise InterpreterEnvironmentError(
            "derived project interpreter inventory failed: " + detail
        )
    return "\n".join(sorted(line.strip() for line in result.stdout.splitlines() if line.strip())) + "\n"


def _sha256_text(value: str) -> str:
    return hashlib.sha256(value.encode("utf-8")).hexdigest()


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
