"""Rollback-safe file transactions for governance installation and promotion."""

from __future__ import annotations

import os
import shutil
import tempfile
from pathlib import Path
from typing import Callable


IGNORED_SHADOW_NAMES = {
    ".git",
    ".artifacts",
    ".mypy_cache",
    ".pytest_cache",
    ".ruff_cache",
    ".tox",
    ".venv",
    "__pycache__",
    "node_modules",
    "venv",
}


def _safe_relative(value: str) -> Path:
    path = Path(value)
    if path.is_absolute() or not path.parts or ".." in path.parts:
        raise ValueError(f"unsafe transaction path: {value}")
    return path


def _reject_symlink_chain(root: Path, relative: Path) -> None:
    current = root
    for part in relative.parts:
        current = current / part
        if current.is_symlink():
            raise ValueError(f"transaction path traverses a symlink: {relative.as_posix()}")


def _copy_shadow(source: Path, destination: Path) -> None:
    shutil.copytree(
        source,
        destination,
        symlinks=True,
        ignore=shutil.ignore_patterns(*IGNORED_SHADOW_NAMES),
    )


def _managed_files(root: Path, managed: tuple[Path, ...]) -> set[Path]:
    files: set[Path] = set()
    for relative in managed:
        path = root / relative
        if path.is_symlink():
            raise ValueError(f"managed path is a symlink: {relative.as_posix()}")
        if path.is_file():
            files.add(relative)
        elif path.is_dir():
            for child in path.rglob("*"):
                child_relative = child.relative_to(root)
                if child.is_symlink():
                    raise ValueError(f"managed path contains a symlink: {child_relative.as_posix()}")
                if child.is_file():
                    files.add(child_relative)
    return files


def _atomic_write(path: Path, data: bytes, mode: int) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with tempfile.NamedTemporaryFile(dir=path.parent, delete=False) as handle:
        handle.write(data)
        staged = Path(handle.name)
    try:
        os.chmod(staged, mode)
        staged.replace(path)
    finally:
        if staged.exists():
            staged.unlink()


def apply_transaction(
    repo_root: Path,
    *,
    managed_paths: tuple[str, ...],
    mutate_shadow: Callable[[Path], None],
) -> None:
    """Mutate and validate a shadow, then atomically transfer only managed files."""
    repo_root = repo_root.resolve()
    managed = tuple(_safe_relative(value) for value in managed_paths)
    for relative in managed:
        _reject_symlink_chain(repo_root, relative)
    with tempfile.TemporaryDirectory(prefix="bcf-transaction-") as temporary:
        shadow = Path(temporary) / "repo"
        _copy_shadow(repo_root, shadow)
        mutate_shadow(shadow)
        before_files = _managed_files(repo_root, managed)
        after_files = _managed_files(shadow, managed)
        def content(root: Path, relative: Path, files: set[Path]) -> bytes | None:
            return (root / relative).read_bytes() if relative in files else None

        changed = sorted(
            relative
            for relative in before_files | after_files
            if content(repo_root, relative, before_files)
            != content(shadow, relative, after_files)
            or (
                relative in before_files
                and relative in after_files
                and (repo_root / relative).stat().st_mode
                != (shadow / relative).stat().st_mode
            )
        )
        snapshots = {
            relative: (
                (repo_root / relative).read_bytes(),
                (repo_root / relative).stat().st_mode,
            )
            if relative in before_files
            else None
            for relative in changed
        }
        applied: list[Path] = []
        try:
            for relative in changed:
                destination = repo_root / relative
                _reject_symlink_chain(repo_root, relative)
                if relative not in after_files:
                    destination.unlink()
                else:
                    source = shadow / relative
                    _atomic_write(destination, source.read_bytes(), source.stat().st_mode)
                applied.append(relative)
        except BaseException:
            for relative in reversed(applied):
                destination = repo_root / relative
                snapshot = snapshots[relative]
                if snapshot is None:
                    if destination.exists():
                        destination.unlink()
                else:
                    _atomic_write(destination, snapshot[0], snapshot[1])
            raise
