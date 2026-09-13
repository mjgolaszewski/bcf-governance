"""Preserve a consumer's installed compiler closure during semantic adoption.

Only disposable shadows receive dependency files. No installation or dependency
promotion is performed, and the original closure must survive adoption unchanged.
"""

from __future__ import annotations

import hashlib
import json
import os
import shutil
import stat
from dataclasses import dataclass
from pathlib import Path
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from .semantic_ownership_typescript import TypeScriptContract


class SemanticDependencyError(ValueError):
    """The declared installed compiler closure cannot be safely snapshotted."""


def _regular_bytes(path: Path) -> bytes:
    try:
        descriptor = os.open(path, os.O_RDONLY | os.O_NONBLOCK | os.O_NOFOLLOW)
        with os.fdopen(descriptor, "rb") as stream:
            before = os.fstat(stream.fileno())
            if not stat.S_ISREG(before.st_mode):
                raise SemanticDependencyError(f"dependency must be a regular file: {path}")
            result = stream.read()
            after = os.fstat(stream.fileno())
        if (before.st_ino, before.st_size, before.st_mtime_ns, before.st_ctime_ns) != (
            after.st_ino, after.st_size, after.st_mtime_ns, after.st_ctime_ns
        ):
            raise SemanticDependencyError(f"dependency changed while reading: {path}")
        return result
    except OSError as exc:
        raise SemanticDependencyError(f"cannot read installed dependency {path}: {exc}") from exc


def _plain_path(root: Path, relative: Path) -> Path:
    if relative.is_absolute() or ".." in relative.parts or not relative.parts:
        raise SemanticDependencyError("dependency path must stay inside the repository")
    current = root
    for component in relative.parts:
        current /= component
        if current.is_symlink():
            raise SemanticDependencyError(f"dependency path crosses a symlink: {current}")
    return current


def _resolve_internal(root: Path, relative: Path) -> Path:
    current = root
    pending = list(relative.parts)
    followed = 0
    while pending:
        component = pending.pop(0)
        if component == "..":
            if current == root:
                raise SemanticDependencyError(f"escaping dependency symlink: {relative}")
            current = current.parent
            continue
        path = current / component
        try:
            mode = path.lstat().st_mode
        except OSError as exc:
            raise SemanticDependencyError(f"missing dependency symlink target or file: {path}") from exc
        if stat.S_ISLNK(mode):
            followed += 1
            if followed > 40:
                raise SemanticDependencyError(f"cyclic or excessive dependency symlink chain: {relative}")
            target = Path(os.readlink(path))
            if target.is_absolute():
                raise SemanticDependencyError(f"absolute dependency symlink: {path}")
            pending = list(target.parts) + pending
        else:
            if pending and not stat.S_ISDIR(mode):
                raise SemanticDependencyError(f"dependency symlink traverses a non-directory: {path}")
            current = path
    return current


def resolve_dependency_file(repo_root: Path, node_modules: Path, path: Path) -> Path:
    """Resolve a compiler input only through relative links inside its closure."""
    root = repo_root.resolve()
    try:
        modules = _plain_path(root, node_modules.relative_to(root))
        relative = path.relative_to(modules)
    except ValueError as exc:
        raise SemanticDependencyError("compiler input must remain inside declared node_modules") from exc
    if not modules.is_dir() or modules.name != "node_modules":
        raise SemanticDependencyError("installed node_modules directory is missing or invalid")
    resolved = _resolve_internal(modules, relative)
    if not resolved.is_file():
        raise SemanticDependencyError(f"compiler input must be a regular file: {path}")
    return resolved


def _tree_entries(root: Path) -> tuple[tuple[str, str, int, str], ...]:
    if root.is_symlink() or not root.is_dir():
        raise SemanticDependencyError(f"installed node_modules directory is missing or linked: {root}")
    entries: list[tuple[str, str, int, str]] = []
    pending = [root]
    while pending:
        path = pending.pop()
        info = path.lstat()
        relative = path.relative_to(root).as_posix()
        mode = stat.S_IMODE(info.st_mode)
        if stat.S_ISLNK(info.st_mode):
            target = os.readlink(path)
            _resolve_internal(root, Path(relative))
            entries.append((relative, "link", mode, target))
        elif stat.S_ISDIR(info.st_mode):
            entries.append((relative, "directory", mode, ""))
            pending.extend(sorted(path.iterdir(), reverse=True))
        elif stat.S_ISREG(info.st_mode):
            entries.append((relative, "file", mode, hashlib.sha256(_regular_bytes(path)).hexdigest()))
        else:
            raise SemanticDependencyError(f"unsupported installed dependency entry: {path}")
    return tuple(sorted(entries))


def _compiler_lock(root: Path, relative: Path) -> str:
    lock_path = _plain_path(root, relative)
    modules = root / relative.parent / "node_modules"
    compiler_path = resolve_dependency_file(root, modules, modules / "typescript/package.json")
    lock_bytes = _regular_bytes(lock_path)
    try:
        lock = json.loads(lock_bytes)
        compiler = json.loads(_regular_bytes(compiler_path))
    except (ValueError, UnicodeError) as exc:
        raise SemanticDependencyError(f"invalid compiler or lock JSON: {relative}") from exc
    packages = lock.get("packages") if isinstance(lock, dict) else None
    locked = packages.get("node_modules/typescript") if isinstance(packages, dict) else None
    version = locked.get("version") if isinstance(locked, dict) else None
    if not isinstance(version, str) or not version:
        raise SemanticDependencyError(f"package lock must pin node_modules/typescript: {relative}")
    if not isinstance(compiler, dict) or compiler.get("version") != version:
        raise SemanticDependencyError(f"installed TypeScript compiler and package lock differ: {relative}")
    _regular_bytes(resolve_dependency_file(root, modules, modules / "typescript/lib/typescript.js"))
    return hashlib.sha256(lock_bytes).hexdigest()


@dataclass(frozen=True)
class DependencySnapshot:
    """Internal adoption receipt retaining the original and shadow identities."""

    repo_root: Path
    shadow_root: Path
    locks: tuple[tuple[Path, str], ...]
    trees: tuple[tuple[Path, tuple[tuple[str, str, int, str], ...]], ...]

    def validate_unchanged(self) -> None:
        """Reject dependency drift before any managed contract is promoted."""
        for root in (self.repo_root, self.shadow_root):
            for relative, expected in self.locks:
                if _compiler_lock(root, relative) != expected:
                    raise SemanticDependencyError(f"package lock changed during adoption: {relative}")
            for relative, expected_tree in self.trees:
                if _tree_entries(_plain_path(root, relative)) != expected_tree:
                    raise SemanticDependencyError(f"installed dependencies changed during adoption: {relative}")


def snapshot_adoption_dependencies(
    repo_root: Path, shadow_root: Path, contracts: tuple[TypeScriptContract, ...]
) -> DependencySnapshot:
    """Copy each declared, complete installed closure into its disposable shadow."""
    repo_root = repo_root.resolve(strict=True)
    shadow_root = shadow_root.resolve(strict=True)
    if shadow_root == repo_root or shadow_root.is_relative_to(repo_root):
        raise SemanticDependencyError("dependency shadow must be outside the original repository")
    lock_paths = sorted({Path(contract.package_lock) for contract in contracts})
    try:
        locks = tuple((relative, _compiler_lock(repo_root, relative)) for relative in lock_paths)
        roots = sorted({relative.parent / "node_modules" for relative in lock_paths})
        trees = tuple((relative, _tree_entries(_plain_path(repo_root, relative))) for relative in roots)
        for relative, _ in trees:
            destination = _plain_path(shadow_root, relative)
            if destination.exists():
                raise SemanticDependencyError(f"dependency shadow destination already exists: {relative}")
        for relative, _ in trees:
            shutil.copytree(_plain_path(repo_root, relative), shadow_root / relative, symlinks=True)
        snapshot = DependencySnapshot(repo_root, shadow_root, locks, trees)
        snapshot.validate_unchanged()
        return snapshot
    except OSError as exc:
        raise SemanticDependencyError(f"cannot snapshot installed dependencies: {exc}") from exc
