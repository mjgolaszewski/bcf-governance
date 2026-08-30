"""Consumer-owned TypeScript Compiler API discovery for SOIP.

Copyright 2026 Michael Golaszewski.
Licensed under the MIT License.
"""

from __future__ import annotations

import hashlib
import json
import shutil
import subprocess
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Iterable


class TypeScriptDiscoveryError(RuntimeError):
    """Raised when the declared compiler environment cannot produce facts."""


@dataclass(frozen=True)
class TypeScriptContract:
    node_executable: str
    tsconfig: str
    package_lock: str
    source_roots: tuple[str, ...]
    browser_contract_roots: tuple[str, ...]


def _safe_relative(value: object, *, field: str) -> str:
    if not isinstance(value, str) or not value:
        raise TypeScriptDiscoveryError(f"{field} must be a non-empty path")
    path = Path(value)
    if path.is_absolute() or ".." in path.parts:
        raise TypeScriptDiscoveryError(f"{field} must stay inside the repository")
    return path.as_posix()


def contract_from_mapping(payload: object) -> TypeScriptContract:
    """Decode the closed consumer compiler contract."""
    if not isinstance(payload, dict):
        raise TypeScriptDiscoveryError("typescript_engine must be an object")
    expected = {
        "node_executable",
        "tsconfig",
        "package_lock",
        "source_roots",
        "browser_contract_roots",
    }
    if set(payload) != expected:
        raise TypeScriptDiscoveryError("typescript_engine has unknown or missing fields")
    roots = payload["source_roots"]
    browser_roots = payload["browser_contract_roots"]
    if not isinstance(roots, list) or not roots:
        raise TypeScriptDiscoveryError("typescript_engine.source_roots must be non-empty")
    if not isinstance(browser_roots, list):
        raise TypeScriptDiscoveryError(
            "typescript_engine.browser_contract_roots must be a list"
        )
    node = payload["node_executable"]
    if not isinstance(node, str) or not node or any(value in node for value in ("/", "\\")):
        raise TypeScriptDiscoveryError(
            "typescript_engine.node_executable must be a command name"
        )
    return TypeScriptContract(
        node_executable=node,
        tsconfig=_safe_relative(payload["tsconfig"], field="typescript_engine.tsconfig"),
        package_lock=_safe_relative(
            payload["package_lock"], field="typescript_engine.package_lock"
        ),
        source_roots=tuple(
            sorted(
                {
                    _safe_relative(value, field="typescript_engine.source_roots")
                    for value in roots
                }
            )
        ),
        browser_contract_roots=tuple(
            sorted(
                {
                    _safe_relative(
                        value, field="typescript_engine.browser_contract_roots"
                    )
                    for value in browser_roots
                }
            )
        ),
    )


def tracked_typescript_files(repo_root: Path) -> list[Path]:
    """Discover the complete tracked TypeScript population before declarations."""
    result = subprocess.run(
        ["git", "ls-files", "-z", "--", "*.ts", "*.tsx"],
        cwd=repo_root,
        capture_output=True,
        check=False,
    )
    if result.returncode != 0:
        raise TypeScriptDiscoveryError("tracked TypeScript discovery requires Git")
    paths: list[Path] = []
    for raw in result.stdout.split(b"\0"):
        if not raw:
            continue
        try:
            relative = Path(raw.decode("utf-8"))
        except UnicodeDecodeError as exc:
            raise TypeScriptDiscoveryError("tracked TypeScript path is not UTF-8") from exc
        path = repo_root / relative
        if relative.is_absolute() or ".." in relative.parts:
            raise TypeScriptDiscoveryError("tracked TypeScript path escapes the repository")
        if path.is_symlink() or not path.is_file():
            raise TypeScriptDiscoveryError(
                f"tracked TypeScript source must be a regular file: {relative.as_posix()}"
            )
        paths.append(path)
    return sorted(paths)


def _inside(relative: str, roots: tuple[str, ...]) -> bool:
    return any(relative == root or relative.startswith(root.rstrip("/") + "/") for root in roots)


def _json_object(path: Path, *, label: str) -> dict[str, Any]:
    if path.is_symlink() or not path.is_file():
        raise TypeScriptDiscoveryError(f"{label} must be a regular file")
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeError, json.JSONDecodeError) as exc:
        raise TypeScriptDiscoveryError(f"cannot read {label}: {exc}") from exc
    if not isinstance(value, dict):
        raise TypeScriptDiscoveryError(f"{label} must contain an object")
    return value


def _compiler_version(repo_root: Path, contract: TypeScriptContract) -> str:
    lock = _json_object(repo_root / contract.package_lock, label="TypeScript package lock")
    package = _json_object(
        repo_root / "node_modules/typescript/package.json",
        label="installed TypeScript package",
    )
    packages = lock.get("packages")
    locked = packages.get("node_modules/typescript") if isinstance(packages, dict) else None
    locked_version = locked.get("version") if isinstance(locked, dict) else None
    installed_version = package.get("version")
    if not isinstance(locked_version, str) or not locked_version:
        raise TypeScriptDiscoveryError("package lock does not pin node_modules/typescript")
    if installed_version != locked_version:
        raise TypeScriptDiscoveryError(
            "installed TypeScript version does not match the package lock"
        )
    return locked_version


def discover_typescript_source(
    repo_root: Path,
    contract: TypeScriptContract,
    discovered_files: Iterable[Path],
    *,
    timeout_seconds: int = 300,
) -> dict[str, Any]:
    """Analyze only the pre-discovered files using the declared local toolchain."""
    repo_root = repo_root.resolve()
    node = shutil.which(contract.node_executable)
    if node is None:
        raise TypeScriptDiscoveryError(
            f"declared Node executable is unavailable: {contract.node_executable}"
        )
    node_path = Path(node)
    if not node_path.is_file():
        raise TypeScriptDiscoveryError("declared Node executable is not a file")
    tsconfig = repo_root / contract.tsconfig
    if tsconfig.is_symlink() or not tsconfig.is_file():
        raise TypeScriptDiscoveryError("declared tsconfig must be a regular file")
    locked_version = _compiler_version(repo_root, contract)
    selected = []
    for path in discovered_files:
        resolved = path.resolve()
        try:
            relative = resolved.relative_to(repo_root).as_posix()
        except ValueError as exc:
            raise TypeScriptDiscoveryError("TypeScript source escapes repository") from exc
        if _inside(relative, contract.source_roots):
            selected.append(resolved)
    if not selected:
        raise TypeScriptDiscoveryError("declared TypeScript roots select zero tracked files")
    analyzer = Path(__file__).with_name("semantic_ownership_typescript.mjs")
    try:
        result = subprocess.run(
            [
                str(node_path),
                str(analyzer),
                "--repo-root",
                str(repo_root),
                "--tsconfig",
                contract.tsconfig,
                "--files",
                *(str(path) for path in selected),
            ],
            cwd=repo_root,
            capture_output=True,
            text=True,
            check=False,
            timeout=timeout_seconds,
        )
    except (OSError, subprocess.TimeoutExpired) as exc:
        raise TypeScriptDiscoveryError(
            f"TypeScript Compiler API discovery could not execute: {exc}"
        ) from exc
    if result.returncode != 0:
        diagnostic = result.stderr.strip() or result.stdout.strip()
        raise TypeScriptDiscoveryError(
            f"TypeScript Compiler API discovery failed: {diagnostic}"
        )
    try:
        payload = json.loads(result.stdout)
    except json.JSONDecodeError as exc:
        raise TypeScriptDiscoveryError(
            "TypeScript Compiler API discovery emitted malformed JSON"
        ) from exc
    if not isinstance(payload, dict) or payload.get("language") != "typescript":
        raise TypeScriptDiscoveryError("TypeScript discovery emitted an invalid inventory")
    if payload.get("compiler_version") != locked_version:
        raise TypeScriptDiscoveryError("TypeScript analyzer did not use the locked compiler")
    payload["files"] = [
        {
            "path": path.relative_to(repo_root).as_posix(),
            "sha256": hashlib.sha256(path.read_bytes()).hexdigest(),
        }
        for path in selected
    ]
    payload["toolchain"] = {
        "node_executable_sha256": hashlib.sha256(node_path.read_bytes()).hexdigest(),
        "node_version": payload.get("node_version"),
        "typescript_version": locked_version,
        "tsconfig": contract.tsconfig,
        "package_lock": contract.package_lock,
    }
    return payload
