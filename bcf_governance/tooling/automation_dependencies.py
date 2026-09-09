"""Deterministically derive dependency version transitions from manifest bytes."""

from __future__ import annotations

from dataclasses import dataclass
import json
from pathlib import PurePosixPath
import re
import tomllib
from typing import Any, Callable

from packaging.requirements import InvalidRequirement, Requirement
from packaging.utils import canonicalize_name
import yaml

from .automation_contracts import AutomationContractError


@dataclass(frozen=True)
class DependencyTransition:
    dependency: str
    previous_version: str
    new_version: str
    paths: tuple[str, ...]


def _safe_text(value: object, *, field: str) -> str:
    text = str(value).strip()
    if not text or len(text) > 240 or any(token in text for token in ("`", "\n", "\r")):
        raise AutomationContractError(f"dependency {field} is unsafe or empty")
    return text


def _requirement_version(requirement: Requirement) -> str:
    if requirement.url:
        return _safe_text(requirement.url, field="URL")
    specifier = str(requirement.specifier)
    return _safe_text(specifier or "unversioned", field="version")


def _requirement_identity(requirement: Requirement) -> str:
    identity = canonicalize_name(requirement.name)
    if requirement.marker is not None:
        identity += f"; {requirement.marker}"
    return _safe_text(identity, field="identity")


def _record(result: dict[str, str], requirement: Requirement) -> None:
    identity = _requirement_identity(requirement)
    version = _requirement_version(requirement)
    prior = result.get(identity)
    if prior is not None and prior != version:
        raise AutomationContractError(
            f"dependency manifest declares conflicting versions for {identity}"
        )
    result[identity] = version


def _requirements(content: bytes) -> dict[str, str]:
    try:
        text = content.decode("utf-8")
    except UnicodeDecodeError as exc:
        raise AutomationContractError("dependency manifest must be UTF-8") from exc
    result: dict[str, str] = {}
    for raw in text.splitlines():
        line = raw.strip()
        if not line or line.startswith(("#", "--hash", "-r", "--requirement")):
            continue
        line = line.removesuffix("\\").strip()
        if " #" in line:
            line = line.split(" #", 1)[0].rstrip()
        try:
            _record(result, Requirement(line))
        except InvalidRequirement as exc:
            raise AutomationContractError(
                f"unsupported requirement declaration: {raw.strip()}"
            ) from exc
    return result


def _pyproject(content: bytes) -> dict[str, str]:
    try:
        payload = tomllib.loads(content.decode("utf-8"))
    except (UnicodeDecodeError, tomllib.TOMLDecodeError) as exc:
        raise AutomationContractError("pyproject dependency manifest is invalid") from exc
    values: list[object] = []
    build = payload.get("build-system", {})
    project = payload.get("project", {})
    if isinstance(build, dict):
        values.extend(build.get("requires", []) if isinstance(build.get("requires"), list) else [])
    if isinstance(project, dict):
        values.extend(
            project.get("dependencies", [])
            if isinstance(project.get("dependencies"), list)
            else []
        )
        optional = project.get("optional-dependencies", {})
        if isinstance(optional, dict):
            for group in sorted(optional):
                members = optional[group]
                if isinstance(members, list):
                    values.extend(members)
    result: dict[str, str] = {}
    for raw in values:
        try:
            _record(result, Requirement(str(raw)))
        except InvalidRequirement as exc:
            raise AutomationContractError(
                f"unsupported pyproject dependency declaration: {raw!r}"
            ) from exc
    return result


def _json(content: bytes, *, description: str) -> dict[str, Any]:
    try:
        payload = json.loads(content)
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise AutomationContractError(f"{description} is invalid") from exc
    if not isinstance(payload, dict):
        raise AutomationContractError(f"{description} must be an object")
    return payload


def _npm_package(content: bytes) -> dict[str, str]:
    payload = _json(content, description="package.json dependency manifest")
    result: dict[str, str] = {}
    for section in ("dependencies", "devDependencies", "optionalDependencies", "peerDependencies"):
        values = payload.get(section, {})
        if not isinstance(values, dict):
            raise AutomationContractError(f"package.json {section} must be an object")
        for name, version in values.items():
            identity = _safe_text(canonicalize_name(str(name)), field="identity")
            normalized = _safe_text(version, field="version")
            if identity in result and result[identity] != normalized:
                raise AutomationContractError(
                    f"package.json declares conflicting versions for {identity}"
                )
            result[identity] = normalized
    return result


def _npm_lock(content: bytes) -> dict[str, str]:
    payload = _json(content, description="npm lockfile")
    packages = payload.get("packages")
    if not isinstance(packages, dict):
        raise AutomationContractError("npm lockfile lacks the packages inventory")
    result: dict[str, str] = {}
    for raw_path, value in packages.items():
        if not raw_path or not isinstance(value, dict) or "version" not in value:
            continue
        marker = "node_modules/"
        name = str(raw_path).rsplit(marker, 1)[-1]
        result[_safe_text(canonicalize_name(name), field="identity")] = _safe_text(
            value["version"], field="version"
        )
    return result


def _toml_lock(content: bytes) -> dict[str, str]:
    try:
        payload = tomllib.loads(content.decode("utf-8"))
    except (UnicodeDecodeError, tomllib.TOMLDecodeError) as exc:
        raise AutomationContractError("Python lockfile is invalid") from exc
    packages = payload.get("package")
    if not isinstance(packages, list):
        raise AutomationContractError("Python lockfile lacks a package inventory")
    result: dict[str, str] = {}
    for package in packages:
        if not isinstance(package, dict) or "name" not in package or "version" not in package:
            raise AutomationContractError("Python lockfile package identity is incomplete")
        identity = _safe_text(canonicalize_name(str(package["name"])), field="identity")
        version = _safe_text(package["version"], field="version")
        prior = result.get(identity)
        if prior is not None and prior != version:
            raise AutomationContractError(
                f"Python lockfile declares conflicting versions for {identity}"
            )
        result[identity] = version
    return result


def _pipfile_lock(content: bytes) -> dict[str, str]:
    payload = _json(content, description="Pipfile.lock")
    result: dict[str, str] = {}
    for section in ("default", "develop"):
        values = payload.get(section, {})
        if not isinstance(values, dict):
            raise AutomationContractError(f"Pipfile.lock {section} must be an object")
        for name, declaration in values.items():
            if not isinstance(declaration, dict) or "version" not in declaration:
                raise AutomationContractError("Pipfile.lock dependency version is missing")
            result[_safe_text(canonicalize_name(str(name)), field="identity")] = _safe_text(
                declaration["version"], field="version"
            )
    return result


def _github_actions(content: bytes) -> dict[str, str]:
    try:
        payload = yaml.safe_load(content.decode("utf-8"))
    except (UnicodeDecodeError, yaml.YAMLError) as exc:
        raise AutomationContractError("GitHub Actions dependency manifest is invalid") from exc
    result: dict[str, str] = {}

    def visit(value: object) -> None:
        if isinstance(value, dict):
            for key, nested in value.items():
                if key == "uses" and isinstance(nested, str) and not nested.startswith(("./", "docker://")):
                    if nested.count("@") != 1:
                        raise AutomationContractError("GitHub Action reference must contain one pin")
                    name, version = nested.rsplit("@", 1)
                    result[_safe_text(name, field="identity")] = _safe_text(
                        version, field="version"
                    )
                else:
                    visit(nested)
        elif isinstance(value, list):
            for nested in value:
                visit(nested)

    visit(payload)
    return result


def _dockerfile(content: bytes) -> dict[str, str]:
    try:
        text = content.decode("utf-8")
    except UnicodeDecodeError as exc:
        raise AutomationContractError("Dockerfile dependency manifest must be UTF-8") from exc
    result: dict[str, str] = {}
    for line in text.splitlines():
        match = re.match(r"\s*FROM\s+(?:--platform=\S+\s+)?(\S+)", line, re.IGNORECASE)
        if not match:
            continue
        reference = match.group(1)
        if reference.startswith("${"):
            raise AutomationContractError("variable Docker base-image references are unsupported")
        name, separator, version = reference.partition("@")
        if not separator:
            slash = name.rfind("/")
            colon = name.rfind(":")
            if colon > slash:
                name, version = name[:colon], name[colon + 1 :]
            else:
                version = "latest"
        result[_safe_text(name, field="identity")] = _safe_text(version, field="version")
    return result


PARSERS: dict[str, Callable[[bytes], dict[str, str]]] = {
    "python-requirements": _requirements,
    "python-pyproject": _pyproject,
    "python-lock": _toml_lock,
    "python-pipfile-lock": _pipfile_lock,
    "npm-package": _npm_package,
    "npm-lock": _npm_lock,
    "github-actions": _github_actions,
    "dockerfile": _dockerfile,
}


def dependency_source_kind(path: str) -> str:
    """Derive a supported version extractor from one exact dependency path."""

    pure = PurePosixPath(path)
    name = pure.name
    if name == "pyproject.toml":
        return "python-pyproject"
    if name.startswith("requirements") and name.endswith(".txt"):
        return "python-requirements"
    if name in {"uv.lock", "poetry.lock"}:
        return "python-lock"
    if name == "Pipfile.lock":
        return "python-pipfile-lock"
    if name == "package.json":
        return "npm-package"
    if name in {"package-lock.json", "npm-shrinkwrap.json"}:
        return "npm-lock"
    if path.startswith(".github/") and name in {"action.yml", "action.yaml"}:
        return "github-actions"
    if path.startswith(".github/workflows/") and pure.suffix in {".yml", ".yaml"}:
        return "github-actions"
    if name.startswith("Dockerfile"):
        return "dockerfile"
    raise AutomationContractError(
        f"dependency path has no deterministic version extractor: {path}"
    )


def derive_dependency_transitions(
    sources: tuple[dict[str, str], ...],
    *,
    content: Callable[[str, str], bytes | None],
    base_ref: str,
    head_ref: str,
) -> tuple[DependencyTransition, ...]:
    """Compare exact base/head manifest bytes and merge identical transitions."""

    merged: dict[tuple[str, str, str], set[str]] = {}
    seen_paths: set[str] = set()
    for source in sorted(sources, key=lambda item: item["path"]):
        path = source["path"]
        kind = source["kind"]
        if path in seen_paths or kind not in PARSERS:
            raise AutomationContractError("dependency version-source contract is ambiguous")
        seen_paths.add(path)
        before_content = content(path, base_ref)
        after_content = content(path, head_ref)
        before = {} if before_content is None else PARSERS[kind](before_content)
        after = {} if after_content is None else PARSERS[kind](after_content)
        changes = {
            dependency: (before.get(dependency, "absent"), after.get(dependency, "absent"))
            for dependency in sorted(set(before) | set(after))
            if before.get(dependency) != after.get(dependency)
        }
        if not changes:
            raise AutomationContractError(
                f"changed dependency manifest has no version transition: {path}"
            )
        for dependency, (previous, new) in changes.items():
            merged.setdefault((dependency, previous, new), set()).add(path)
    by_dependency: dict[str, set[tuple[str, str]]] = {}
    for dependency, previous, new in merged:
        by_dependency.setdefault(dependency, set()).add((previous, new))
    conflicts = sorted(name for name, values in by_dependency.items() if len(values) > 1)
    if conflicts:
        raise AutomationContractError(
            "dependency manifests disagree on version transitions: " + ", ".join(conflicts)
        )
    return tuple(
        DependencyTransition(dependency, previous, new, tuple(sorted(paths)))
        for (dependency, previous, new), paths in sorted(merged.items())
    )
