"""Compile a closed governed pip-requirements graph."""

from __future__ import annotations

import hashlib
import re
from dataclasses import dataclass
from pathlib import Path

import yaml
from packaging.requirements import InvalidRequirement, Requirement


class InterpreterDependencySourceError(ValueError):
    """The governed dependency source is unsafe or ambiguous."""


@dataclass(frozen=True)
class GovernedDependencySource:
    requirements: tuple[str, ...]
    requires_python: str
    path: Path
    sha256: str


def _normalized_name(value: str) -> str:
    try:
        requirement = Requirement(value)
    except InvalidRequirement as exc:
        raise InterpreterDependencySourceError(
            "dependency declaration is not a bounded package requirement"
        ) from exc
    if requirement.url or requirement.marker or requirement.extras:
        raise InterpreterDependencySourceError(
            "dependency declaration must not use URLs, markers, or extras"
        )
    return re.sub(r"[-_.]+", "-", requirement.name).lower()


def close_installer_requirement(
    requirements: list[str], installer_requirement: str,
) -> list[str]:
    """Close authored compatible constraints to one canonical exact installer."""

    installer_name = _normalized_name(installer_requirement)
    selected = Requirement(installer_requirement)
    pins = list(selected.specifier)
    if (
        installer_name != "pip" or len(pins) != 1
        or pins[0].operator != "==" or "*" in pins[0].version
    ):
        raise InterpreterDependencySourceError("canonical installer must be an exact pip pin")
    authored = [item for item in requirements if _normalized_name(item) == installer_name]
    if len(authored) > 1:
        raise InterpreterDependencySourceError("project installer declarations are ambiguous")
    if authored and not Requirement(authored[0]).specifier.contains(
        pins[0].version, prereleases=True,
    ):
        raise InterpreterDependencySourceError(
            "project installer requirement is incompatible with " + installer_requirement
        )
    if not authored:
        return [*requirements, installer_requirement]
    return [installer_requirement if item == authored[0] else item for item in requirements]


def compile_governed_dependency_source(
    repo_root: Path,
    value: object,
    *,
    installer_requirement: str,
) -> GovernedDependencySource:
    """Compile exact recursive requirements beneath one authenticated source root."""

    if not isinstance(value, str) or not value:
        raise InterpreterDependencySourceError(
            "interpreter dependency source is invalid"
        )
    relative_source = Path(value)
    if relative_source.is_absolute() or ".." in relative_source.parts:
        raise InterpreterDependencySourceError(
            "interpreter dependency source must stay inside the repository"
        )
    source = repo_root.resolve() / relative_source
    dependency_root = source.parent.resolve()
    visited: set[Path] = set()
    requirements: list[str] = []
    digest = hashlib.sha256()

    def visit(path: Path) -> None:
        try:
            relative = path.resolve(strict=True).relative_to(dependency_root)
        except (OSError, ValueError) as exc:
            raise InterpreterDependencySourceError(
                "interpreter dependency source escapes the repository"
            ) from exc
        if path.is_symlink() or not path.is_file():
            raise InterpreterDependencySourceError(
                "interpreter dependency source is missing or unsafe"
            )
        resolved = path.resolve()
        if resolved in visited:
            raise InterpreterDependencySourceError(
                "interpreter dependency source contains an include cycle"
            )
        visited.add(resolved)
        try:
            source_bytes = path.read_bytes()
            lines = source_bytes.decode("utf-8").splitlines()
        except (OSError, UnicodeError) as exc:
            raise InterpreterDependencySourceError(
                "interpreter dependency source is unreadable"
            ) from exc
        digest.update(relative.as_posix().encode("utf-8"))
        digest.update(b"\0")
        digest.update(source_bytes)
        digest.update(b"\0")
        for raw in lines:
            line = raw.strip()
            if not line or line.startswith("#"):
                continue
            include: str | None = None
            if line.startswith("-r "):
                include = line[3:].strip()
            elif line.startswith("--requirement "):
                include = line[len("--requirement "):].strip()
            if include is not None:
                relative_include = Path(include)
                if (
                    not include
                    or relative_include.is_absolute()
                    or ".." in relative_include.parts
                ):
                    raise InterpreterDependencySourceError(
                        "interpreter dependency include is unsafe"
                    )
                visit(path.parent / relative_include)
                continue
            if line.startswith("-"):
                raise InterpreterDependencySourceError(
                    "interpreter dependency source contains an unsupported option"
                )
            _normalized_name(line)
            requirements.append(line)
        visited.remove(resolved)

    visit(source)
    if not requirements:
        raise InterpreterDependencySourceError(
            "interpreter dependency source is empty"
        )
    normalized = [_normalized_name(item) for item in requirements]
    if len(set(normalized)) != len(requirements):
        raise InterpreterDependencySourceError(
            "interpreter dependency declarations must have unique names"
        )
    requirements = close_installer_requirement(requirements, installer_requirement)
    graph_path = repo_root.resolve() / "governance/ci-graph.yml"
    if graph_path.is_symlink() or not graph_path.is_file():
        raise InterpreterDependencySourceError(
            "interpreter graph runtime contract is unavailable"
        )
    try:
        graph = yaml.safe_load(graph_path.read_text(encoding="utf-8"))
        resources = graph["resource_classes"]
        python_minors = {
            str(resource["python_version"])
            for resource in resources.values()
            if isinstance(resource, dict) and "python_version" in resource
        }
    except (OSError, UnicodeError, yaml.YAMLError, KeyError, TypeError) as exc:
        raise InterpreterDependencySourceError(
            "interpreter graph runtime contract is unavailable"
        ) from exc
    if len(python_minors) != 1 or any(
        re.fullmatch(r"3\.[0-9]+", value) is None for value in python_minors
    ):
        raise InterpreterDependencySourceError(
            "interpreter graph must declare one Python minor"
        )
    python_minor = next(iter(python_minors))
    return GovernedDependencySource(
        requirements=tuple(requirements),
        requires_python=f"=={python_minor}.*",
        path=source,
        sha256=digest.hexdigest(),
    )
