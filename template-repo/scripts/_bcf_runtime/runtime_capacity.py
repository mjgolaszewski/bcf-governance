"""Fail-fast repository runtime and capacity contracts."""

from __future__ import annotations

from dataclasses import asdict, dataclass
from pathlib import Path
import shutil
from typing import Callable

import yaml


class RuntimeCapacityError(ValueError):
    """Raised before expensive work when runtime custody is unsafe or insufficient."""


@dataclass(frozen=True)
class RuntimeCapacityReport:
    status: str
    runtime_root: str
    database_root: str
    available_bytes: int
    minimum_free_bytes: int
    owned_containers: int
    maximum_owned_containers: int

    def as_dict(self) -> dict[str, object]:
        return asdict(self)


DiskUsage = Callable[[Path], shutil._ntuple_diskusage]


def _safe_repo_path(repo_root: Path, value: str, *, field: str) -> Path:
    relative = Path(value)
    if relative.is_absolute() or not relative.parts or ".." in relative.parts:
        raise RuntimeCapacityError(f"{field} must be a safe repository-relative path")
    current = repo_root
    for part in relative.parts:
        current = current / part
        if current.is_symlink():
            raise RuntimeCapacityError(f"{field} traverses a symlink")
    resolved = current.resolve(strict=False)
    try:
        resolved.relative_to(repo_root.resolve())
    except ValueError as exc:
        raise RuntimeCapacityError(f"{field} escapes the repository") from exc
    return resolved


def load_runtime_contract(path: Path) -> dict[str, object]:
    if not path.is_file() or path.is_symlink():
        raise RuntimeCapacityError("runtime contract must be a regular file")
    payload = yaml.safe_load(path.read_text(encoding="utf-8"))
    if not isinstance(payload, dict):
        raise RuntimeCapacityError("runtime contract must contain a mapping")
    expected = {
        "schema_version",
        "runtime_root",
        "minimum_free_bytes",
        "maximum_owned_containers",
        "database",
        "cleanup",
    }
    if set(payload) != expected or payload.get("schema_version") != "1.0":
        raise RuntimeCapacityError("runtime contract fields or version are invalid")
    return payload


def check_runtime_capacity(
    repo_root: Path,
    contract: dict[str, object],
    *,
    owned_containers: int,
    disk_usage: DiskUsage = shutil.disk_usage,
) -> RuntimeCapacityReport:
    """Validate safe bind roots and capacity before database-heavy execution."""

    if owned_containers < 0:
        raise RuntimeCapacityError("owned container count cannot be negative")
    runtime_root = _safe_repo_path(
        repo_root, str(contract.get("runtime_root", "")), field="runtime_root"
    )
    database = contract.get("database")
    if not isinstance(database, dict) or set(database) != {"storage", "relative_path"}:
        raise RuntimeCapacityError("database contract fields are invalid")
    if database.get("storage") != "repository_bind_mount":
        raise RuntimeCapacityError("database storage must use a repository-owned bind mount")
    database_root = _safe_repo_path(
        repo_root, str(database.get("relative_path", "")), field="database.relative_path"
    )
    if runtime_root not in database_root.parents:
        raise RuntimeCapacityError("database bind root must be beneath runtime_root")
    cleanup = contract.get("cleanup")
    if not isinstance(cleanup, dict) or cleanup != {
        "caller_globs": False,
        "daemon_global_prune": False,
        "exact_owner_revalidation": True,
        "remove_anonymous_volumes": True,
    }:
        raise RuntimeCapacityError("cleanup contract must be exact, scoped, and fail-closed")
    minimum = contract.get("minimum_free_bytes")
    maximum = contract.get("maximum_owned_containers")
    if isinstance(minimum, bool) or not isinstance(minimum, int) or minimum < 1:
        raise RuntimeCapacityError("minimum_free_bytes must be a positive integer")
    if isinstance(maximum, bool) or not isinstance(maximum, int) or maximum < 1:
        raise RuntimeCapacityError("maximum_owned_containers must be a positive integer")
    available = disk_usage(repo_root).free
    if available < minimum:
        raise RuntimeCapacityError("insufficient disk capacity before expensive work")
    if owned_containers >= maximum:
        raise RuntimeCapacityError("owned container capacity exhausted before expensive work")
    return RuntimeCapacityReport(
        status="ready",
        runtime_root=runtime_root.relative_to(repo_root.resolve()).as_posix(),
        database_root=database_root.relative_to(repo_root.resolve()).as_posix(),
        available_bytes=available,
        minimum_free_bytes=minimum,
        owned_containers=owned_containers,
        maximum_owned_containers=maximum,
    )
