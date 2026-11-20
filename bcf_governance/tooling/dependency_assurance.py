"""Exact installed dependency inventory and advisory-result primitives."""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timezone
import hashlib
from importlib import metadata
import json
from pathlib import Path
import tomllib
from typing import Any

from packaging.requirements import Requirement
from packaging.utils import InvalidName, canonicalize_name


class DependencyAssuranceError(ValueError):
    """Raised when exact dependency assurance cannot be constructed."""


@dataclass(frozen=True)
class InstalledDependencyInventory:
    roots: tuple[str, ...]
    components: tuple[dict[str, Any], ...]
    dependencies: tuple[dict[str, Any], ...]
    sha256: str

    def payload(self) -> dict[str, Any]:
        return {
            "roots": list(self.roots),
            "components": list(self.components),
            "dependencies": list(self.dependencies),
        }


def _declared_requirements(repo_root: Path) -> list[Requirement]:
    project = tomllib.loads((repo_root / "pyproject.toml").read_text(encoding="utf-8"))
    values: list[str] = []
    values.extend(project.get("build-system", {}).get("requires", []))
    values.extend(project.get("project", {}).get("dependencies", []))
    for requirements in project.get("project", {}).get("optional-dependencies", {}).values():
        values.extend(requirements)
    for raw in (repo_root / "requirements-governance.txt").read_text(encoding="utf-8").splitlines():
        stripped = raw.strip()
        if stripped and not stripped.startswith("#"):
            values.append(stripped)
    try:
        return [Requirement(value) for value in values]
    except Exception as exc:
        raise DependencyAssuranceError(f"declared dependency is malformed: {exc}") from exc


def _installed() -> dict[str, metadata.Distribution]:
    result: dict[str, metadata.Distribution] = {}
    for distribution in metadata.distributions():
        name = distribution.metadata.get("Name")
        if isinstance(name, str) and name:
            result[canonicalize_name(name)] = distribution
    return result


def _requirement_applies(requirement: Requirement, active_extras: set[str]) -> bool:
    if requirement.marker is None:
        return True
    return any(
        requirement.marker.evaluate({"extra": extra})
        for extra in ({""} | active_extras)
    )


def collect_installed_inventory(repo_root: Path) -> InstalledDependencyInventory:
    """Derive the exact installed closure of every declared build/runtime root."""

    installed = _installed()
    queue: list[tuple[str, set[str]]] = []
    roots: set[str] = set()
    for requirement in _declared_requirements(repo_root):
        name = canonicalize_name(requirement.name)
        roots.add(name)
        queue.append((name, set(requirement.extras)))
    selected: dict[str, metadata.Distribution] = {}
    extras_by_name: dict[str, set[str]] = {}
    edges: dict[str, set[str]] = {}
    while queue:
        name, extras = queue.pop()
        previous = extras_by_name.setdefault(name, set())
        if name in selected and extras <= previous:
            continue
        previous.update(extras)
        distribution = installed.get(name)
        if distribution is None:
            raise DependencyAssuranceError(f"declared dependency is not installed: {name}")
        selected[name] = distribution
        required: set[str] = set()
        for raw in distribution.requires or []:
            requirement = Requirement(raw)
            if not _requirement_applies(requirement, previous):
                continue
            dependency = canonicalize_name(requirement.name)
            required.add(dependency)
            queue.append((dependency, set(requirement.extras)))
        edges[name] = required
    components = tuple(
        {
            "type": "library",
            "name": name,
            "version": distribution.version,
            "bom-ref": f"pkg:pypi/{name}@{distribution.version}",
        }
        for name, distribution in sorted(selected.items())
    )
    dependencies = tuple(
        {
            "ref": f"pkg:pypi/{name}@{selected[name].version}",
            "dependsOn": [
                f"pkg:pypi/{dependency}@{selected[dependency].version}"
                for dependency in sorted(required)
                if dependency in selected
            ],
        }
        for name, required in sorted(edges.items())
    )
    payload = {
        "roots": sorted(roots),
        "components": components,
        "dependencies": dependencies,
    }
    digest = hashlib.sha256(
        json.dumps(payload, sort_keys=True, separators=(",", ":")).encode()
    ).hexdigest()
    return InstalledDependencyInventory(
        roots=tuple(sorted(roots)),
        components=components,
        dependencies=dependencies,
        sha256=digest,
    )


def write_frozen_requirements(
    inventory: InstalledDependencyInventory, output: Path
) -> None:
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text(
        "".join(
            f"{component['name']}=={component['version']}\n"
            for component in inventory.components
        ),
        encoding="utf-8",
    )


def _scanner_dependency_identity(item: Any) -> tuple[str, str] | None:
    """Identify one selected or scanned distribution without accepting missing fields."""
    if not isinstance(item, dict):
        return None
    name, version = item.get("name"), item.get("version")
    if not isinstance(name, str) or not isinstance(version, str) or not version.strip():
        return None
    if version != version.strip():
        return None
    try:
        return canonicalize_name(name, validate=True), version
    except InvalidName:
        return None


def audit_envelope(
    *,
    inventory: InstalledDependencyInventory,
    scanner_version: str,
    service: str,
    returncode: int,
    raw: dict[str, Any] | None,
    diagnostic: str,
) -> dict[str, Any]:
    """Classify one complete scanner result; ambiguity never becomes clean."""

    dependencies = raw.get("dependencies") if isinstance(raw, dict) else None
    findings = [
        {"name": item.get("name"), "version": item.get("version"), "vulnerabilities": vulns}
        for item in dependencies if isinstance(item, dict)
        and isinstance((vulns := item.get("vulns")), list) and vulns
    ] if isinstance(dependencies, list) else []
    selected = [_scanner_dependency_identity(item) for item in inventory.components]
    complete = (all(identity is not None for identity in selected)
                and len(set(selected)) == len(selected)
                and isinstance(dependencies, list))
    observed: set[tuple[str, str]] = set()
    if isinstance(dependencies, list):
        for item in dependencies:
            identity = _scanner_dependency_identity(item)
            if identity is None or identity in observed or not isinstance(item, dict):
                complete = False
                continue
            observed.add(identity)
            vulnerabilities = item.get("vulns")
            if "skip_reason" in item or not isinstance(vulnerabilities, list):
                complete = False
                continue
            if any(not isinstance(row, dict) or not isinstance(row.get("id"), str)
                   or not row["id"].strip() for row in vulnerabilities):
                complete = False
    complete = complete and observed == set(selected)
    if isinstance(raw, dict) and "fixes" in raw and raw["fixes"] != []:
        complete = False
    if type(returncode) is not int or returncode not in {0, 1} or not complete:
        status = "scanner_failure"
        diagnostic = diagnostic or "scanner result does not account for the exact selected inventory"
    elif returncode == 0 and not findings:
        status = "clean"
    elif returncode == 1 and findings:
        status = "vulnerable"
    else:
        status = "scanner_failure"
        diagnostic = diagnostic or "scanner exit and vulnerability population contradict each other"
    raw_digest = hashlib.sha256(
        json.dumps(raw, sort_keys=True, separators=(",", ":")).encode()
        if raw is not None
        else b""
    ).hexdigest()
    return {
        "kind": "dependency_advisory_observation",
        "schema_version": "1.0",
        "status": status,
        "scanner": {"name": "pip-audit", "version": scanner_version},
        "advisory_source": {"service": service, "observed_at": datetime.now(timezone.utc).isoformat()},
        "inventory_sha256": inventory.sha256,
        "inventory_component_count": len(inventory.components),
        "raw_result_sha256": raw_digest,
        "raw_result": raw,
        "findings": findings,
        "diagnostic": diagnostic,
    }


def cyclonedx_sbom(inventory: InstalledDependencyInventory) -> dict[str, Any]:
    return {
        "bomFormat": "CycloneDX",
        "specVersion": "1.5",
        "version": 1,
        "metadata": {"properties": [{"name": "bcf:inventory_sha256", "value": inventory.sha256}]},
        "components": list(inventory.components),
        "dependencies": list(inventory.dependencies),
    }
