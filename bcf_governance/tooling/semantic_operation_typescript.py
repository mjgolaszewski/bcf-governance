"""Locked TypeScript export discovery for application-operation populations.

Copyright 2026 Michael Golaszewski.
Licensed under the MIT License.
"""

from __future__ import annotations

import json
import re
from pathlib import Path
from typing import Any

from .semantic_ownership_typescript import (
    TypeScriptContract,
    TypeScriptDiscoveryError,
    discover_typescript_source,
)


class TypeScriptOperationPopulationError(ValueError):
    """Raised when a locked TypeScript population cannot be enumerated."""


def _safe_file(repo_root: Path, value: object, *, context: str) -> Path:
    if not isinstance(value, str) or not value:
        raise TypeScriptOperationPopulationError(f"{context} must be a repository path")
    relative = Path(value)
    if relative.is_absolute() or ".." in relative.parts:
        raise TypeScriptOperationPopulationError(f"{context} escapes the repository")
    target = repo_root / relative
    try:
        resolved = target.resolve(strict=True)
    except OSError as exc:
        raise TypeScriptOperationPopulationError(f"{context} is unreadable: {exc}") from exc
    if target.is_symlink() or not resolved.is_relative_to(repo_root.resolve()) or not target.is_file():
        raise TypeScriptOperationPopulationError(f"{context} must be a safe regular file")
    return target


def discover_typescript_population(
    repo_root: Path, population: dict[str, Any]
) -> dict[str, str]:
    """Use the declared local compiler and exact lock to enumerate exports."""
    source = _safe_file(
        repo_root, population["source"], context=f"population {population['id']} source"
    )
    _safe_file(
        repo_root,
        population["tsconfig"],
        context=f"population {population['id']} tsconfig",
    )
    lock_path = _safe_file(
        repo_root,
        population["package_lock"],
        context=f"population {population['id']} package_lock",
    )
    try:
        lock = json.loads(lock_path.read_text(encoding="utf-8"))
    except (OSError, UnicodeError, json.JSONDecodeError) as exc:
        raise TypeScriptOperationPopulationError(
            f"population {population['id']} package lock is malformed"
        ) from exc
    packages = lock.get("packages", {}) if isinstance(lock, dict) else {}
    typescript = packages.get("node_modules/typescript", {}) if isinstance(packages, dict) else {}
    version = typescript.get("version") if isinstance(typescript, dict) else None
    if not isinstance(version, str) or not re.fullmatch(r"[0-9]+\.[0-9]+\.[0-9]+", version):
        raise TypeScriptOperationPopulationError(
            f"population {population['id']} requires an exact locked TypeScript package"
        )
    try:
        inventory = discover_typescript_source(
            repo_root,
            TypeScriptContract(
                node_executable=str(population["node_executable"]),
                tsconfig=str(population["tsconfig"]),
                package_lock=str(population["package_lock"]),
                source_roots=(Path(str(population["source"])).as_posix(),),
                browser_contract_roots=(),
            ),
            [source],
        )
    except TypeScriptDiscoveryError as exc:
        raise TypeScriptOperationPopulationError(
            f"population {population['id']} TypeScript compiler inventory failed: {exc}"
        ) from exc
    exports = inventory.get("public_exports")
    if not isinstance(exports, list):
        raise TypeScriptOperationPopulationError(
            f"population {population['id']} TypeScript inventory omitted public exports"
        )
    result: dict[str, str] = {}
    for row in exports:
        if not isinstance(row, dict) or not isinstance(row.get("name"), str) or not isinstance(row.get("symbol"), str):
            continue
        name = str(row["name"])
        if population["public_only"] and name.startswith("_"):
            continue
        if name in result:
            raise TypeScriptOperationPopulationError(
                f"population {population['id']} duplicates {name}"
            )
        result[name] = str(row["symbol"])
    return result
