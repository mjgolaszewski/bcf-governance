"""Compose source-first Python and declared TypeScript project inventories."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from .semantic_ownership_inventory import (
    SemanticInventoryError, discover_python_source, resolve_python_imports, tracked_python_files,
)
from .semantic_ownership_registry import Registry, load_registry
from .semantic_ownership_typescript import (
    TypeScriptContract, TypeScriptDiscoveryError, contract_from_mapping,
    discover_typescript_source, tracked_typescript_files,
)
from .semantic_yaml import SemanticYAMLError, load_unique_mapping


FACT_LISTS = (
    "files", "types", "functions", "constructors", "codecs", "translations",
    "normalizations", "sinks", "unresolved", "fetches", "endpoint_calls",
    "decoder_calls", "endpoint_contracts", "public_exports", "typescript_inputs",
)


def discover_optional_python_source(repo_root: Path) -> dict[str, Any]:
    """Permit an empty language view only for the combined source discovery."""
    return discover_python_source(repo_root, files=tracked_python_files(repo_root, allow_empty=True))


def resolve_optional_python_imports(repo_root: Path, inventory: dict[str, Any], roots: tuple[str, ...]) -> dict[str, Any]:
    return resolve_python_imports(repo_root, inventory, roots) if inventory.get("files") else inventory


def compiler_contracts(repo_root: Path, registry: Registry) -> tuple[TypeScriptContract, ...]:
    """Include registry and population projects, coalescing identical compilers."""
    contracts = []
    engine = registry.raw.get("source_authority", {}).get("typescript_engine")
    if isinstance(engine, dict):
        contracts.append(contract_from_mapping(engine))
    operations_path = repo_root / "governance/application-operations.yml"
    if operations_path.exists():
        try:
            operations = load_unique_mapping(operations_path)
        except SemanticYAMLError as exc:
            raise TypeScriptDiscoveryError(f"cannot discover compiler projects: {exc}") from exc
        populations = operations.get("populations", [])
        if not isinstance(populations, list) or any(not isinstance(row, dict) for row in populations):
            raise TypeScriptDiscoveryError("compiler project populations must be object rows")
        for population in populations:
            if population.get("adapter") != "typescript_exports":
                continue
            contracts.append(contract_from_mapping({
                "node_executable": population.get("node_executable"),
                "tsconfig": population.get("tsconfig"),
                "package_lock": population.get("package_lock"),
                "source_roots": [population.get("source")],
                "browser_contract_roots": [],
            }))
    grouped: dict[tuple[str, str, str], TypeScriptContract] = {}
    for contract in contracts:
        key = (contract.node_executable, contract.tsconfig, contract.package_lock)
        previous = grouped.get(key)
        grouped[key] = TypeScriptContract(
            *key,
            source_roots=tuple(sorted(set(contract.source_roots) | set(previous.source_roots if previous else ()))),
            browser_contract_roots=tuple(sorted(set(contract.browser_contract_roots) | set(previous.browser_contract_roots if previous else ()))),
        )
    return tuple(grouped[key] for key in sorted(grouped))


def merge_inventories(inventories: list[dict[str, Any]]) -> dict[str, Any]:
    """Deduplicate shared project facts, rejecting conflicting declaration facts."""
    result: dict[str, Any] = {}
    for key in FACT_LISTS:
        rows: dict[str, Any] = {}
        for inventory in inventories:
            for row in inventory.get(key, []):
                identity = json.dumps(row, sort_keys=True)
                if key in {"files", "typescript_inputs"}:
                    identity = str(row["path"])
                elif key == "functions":
                    identity = str(row["symbol"])
                if identity in rows and rows[identity] != row:
                    raise TypeScriptDiscoveryError(f"compiler projects disagree on {key}: {identity}")
                rows[identity] = row
        result[key] = [rows[key] for key in sorted(rows)]
    return result


def discover_source(
    repo_root: Path, *, python_inventory: dict[str, Any] | None = None,
    typescript_files: list[Path] | None = None, registry: Registry | None = None,
    resolve_imports: bool = True,
) -> tuple[dict[str, Any], dict[str, Any], dict[str, Any], Registry]:
    """Discover tracked sources before loading declarations; return both language views."""
    python = discover_optional_python_source(repo_root) if python_inventory is None else python_inventory
    tracked = tracked_typescript_files(repo_root) if typescript_files is None else typescript_files
    registry = load_registry(repo_root) if registry is None else registry
    if resolve_imports:
        python = resolve_optional_python_imports(repo_root, python, registry.python_import_roots)
    projects = [
        discover_typescript_source(repo_root, contract, tracked)
        for contract in compiler_contracts(repo_root, registry)
    ]
    typescript = merge_inventories(projects)
    typescript["language"] = "typescript"
    typescript["projects"] = projects
    if len(projects) == 1:
        typescript.update({key: projects[0].get(key) for key in ("compiler_version", "toolchain")})
    combined = merge_inventories([python, typescript]) if projects else python
    if not combined.get("files"):
        raise SemanticInventoryError("tracked source discovery returned zero analyzed files; declare a compiler for TypeScript sources")
    return combined, python, typescript, registry
