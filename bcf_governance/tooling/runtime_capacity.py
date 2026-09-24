"""Fail-fast repository runtime and capacity contracts."""

from __future__ import annotations

from dataclasses import asdict, dataclass
import hashlib
import json
from pathlib import Path
import re
import shutil
from typing import Any, Callable

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


@dataclass(frozen=True)
class ExecutionStateLease:
    namespace: str
    lifecycle: str
    root: Path
    database_root: Path
    binding_sha256: str
    preexisting: bool

    def environment(self) -> dict[str, str]:
        home = self.root / "home"
        temporary = self.root / "tmp"
        return {
            "BCF_EXECUTION_STATE_NAMESPACE": self.namespace,
            "BCF_EXECUTION_STATE_ROOT": str(self.root),
            "BCF_EXECUTION_DATABASE_ROOT": str(self.database_root),
            "HOME": str(home),
            "PYTHONUSERBASE": str(self.root / "python-userbase"),
            "TMPDIR": str(temporary),
            "TMP": str(temporary),
            "TEMP": str(temporary),
            "XDG_CACHE_HOME": str(self.root / "cache"),
            "XDG_STATE_HOME": str(self.root / "state"),
        }


DiskUsage = Callable[[Path], shutil._ntuple_diskusage]
Remover = Callable[[Path], None]
STATE_MANIFEST = ".bcf-execution-state.json"
STATE_NAMESPACE = re.compile(r"^[a-z0-9][a-z0-9-]{5,63}$")
EXECUTION_STATE_POLICY = {
    "default_lifecycle": "ephemeral",
    "namespace_binding": ["session_id", "workload_id", "execution_id"],
    "unexplained_preexisting": "reject",
    "persistent_requires_workload_declaration": True,
    "terminal_cleanup": "exact_owned_namespace",
    "verify_removal": True,
}


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
        "execution_state",
    }
    if set(payload) != expected or payload.get("schema_version") != "1.1":
        raise RuntimeCapacityError("runtime contract fields or version are invalid")
    if payload.get("execution_state") != EXECUTION_STATE_POLICY:
        raise RuntimeCapacityError("execution-state policy must be exact and fail-closed")
    return payload


def _identity(value: str, *, field: str) -> str:
    if not value or "\0" in value or "\n" in value or "\r" in value:
        raise RuntimeCapacityError(f"{field} is invalid")
    return value


def _canonical_digest(payload: dict[str, str]) -> str:
    encoded = json.dumps(payload, sort_keys=True, separators=(",", ":")).encode()
    return hashlib.sha256(encoded).hexdigest()


def _workload_state(invocation: dict[str, Any]) -> tuple[str, str | None]:
    raw = invocation.get("state")
    if raw is None:
        return "ephemeral", None
    if not isinstance(raw, dict) or set(raw) - {"lifecycle", "namespace"}:
        raise RuntimeCapacityError("workload state declaration is invalid")
    lifecycle = raw.get("lifecycle")
    namespace = raw.get("namespace")
    if lifecycle == "ephemeral" and namespace is None:
        return lifecycle, None
    if (
        lifecycle == "persistent_shared"
        and isinstance(namespace, str)
        and STATE_NAMESPACE.fullmatch(namespace)
    ):
        return lifecycle, namespace
    raise RuntimeCapacityError(
        "persistent/shared state requires an explicit safe workload namespace"
    )


def _read_state_manifest(root: Path) -> dict[str, Any]:
    manifest = root / STATE_MANIFEST
    if root.is_symlink() or not root.is_dir() or manifest.is_symlink() or not manifest.is_file():
        raise RuntimeCapacityError("execution-state namespace has unexplained pre-existing state")
    try:
        payload = json.loads(manifest.read_text(encoding="utf-8"))
    except (OSError, UnicodeError, json.JSONDecodeError) as exc:
        raise RuntimeCapacityError(
            "execution-state namespace ownership is unreadable"
        ) from exc
    expected = {"schema_version", "namespace", "lifecycle", "workload_id", "binding_sha256"}
    if set(payload) != expected or payload.get("schema_version") != "1.0":
        raise RuntimeCapacityError("execution-state namespace ownership is invalid")
    return payload


def _validate_existing_state(base: Path, target: Path, lifecycle: str) -> None:
    for entry in base.iterdir():
        _read_state_manifest(entry)
        exact_target = entry == target
        if exact_target and lifecycle != "persistent_shared":
            raise RuntimeCapacityError(
                "execution-state namespace has unexplained pre-existing state"
            )


def allocate_execution_state(
    repo_root: Path,
    contract: dict[str, object],
    *,
    session_id: str,
    workload_id: str,
    execution_id: str,
    invocation: dict[str, Any],
) -> ExecutionStateLease:
    """Allocate one exact workload namespace before isolated execution."""

    if contract.get("execution_state") != EXECUTION_STATE_POLICY:
        raise RuntimeCapacityError("execution-state policy must be exact and fail-closed")
    database = contract.get("database")
    if not isinstance(database, dict) or database.get("storage") != "repository_bind_mount":
        raise RuntimeCapacityError("database storage must use a repository-owned bind mount")
    base = _safe_repo_path(
        repo_root,
        str(database.get("relative_path", "")),
        field="database.relative_path",
    )
    session = _identity(session_id, field="session_id")
    workload = _identity(workload_id, field="workload_id")
    execution = _identity(execution_id, field="execution_id")
    lifecycle, declared_namespace = _workload_state(invocation)
    binding = (
        {"lifecycle": lifecycle, "namespace": str(declared_namespace), "workload_id": workload}
        if lifecycle == "persistent_shared"
        else {
            "execution_id": execution,
            "lifecycle": lifecycle,
            "session_id": session,
            "workload_id": workload,
        }
    )
    binding_sha256 = _canonical_digest(binding)
    namespace = declared_namespace or f"bcf-{binding_sha256[:32]}"
    if not STATE_NAMESPACE.fullmatch(namespace):
        raise RuntimeCapacityError("derived execution-state namespace is unsafe")
    base.mkdir(parents=True, exist_ok=True)
    root = base / namespace
    _validate_existing_state(base, root, lifecycle)
    expected_manifest = {
        "schema_version": "1.0",
        "namespace": namespace,
        "lifecycle": lifecycle,
        "workload_id": workload,
        "binding_sha256": binding_sha256,
    }
    if root.exists() or root.is_symlink():
        actual = _read_state_manifest(root)
        if lifecycle != "persistent_shared" or actual != expected_manifest:
            raise RuntimeCapacityError(
                "execution-state namespace has unexplained pre-existing state"
            )
        preexisting = True
    else:
        root.mkdir(mode=0o700)
        manifest = root / STATE_MANIFEST
        manifest.write_text(
            json.dumps(expected_manifest, sort_keys=True, separators=(",", ":")) + "\n",
            encoding="utf-8",
        )
        manifest.chmod(0o400)
        preexisting = False
    database_root = root / "database"
    for path in (
        database_root,
        root / "home",
        root / "python-userbase",
        root / "tmp",
        root / "cache",
        root / "state",
    ):
        path.mkdir(mode=0o700, exist_ok=True)
    return ExecutionStateLease(
        namespace=namespace,
        lifecycle=lifecycle,
        root=root,
        database_root=database_root,
        binding_sha256=binding_sha256,
        preexisting=preexisting,
    )


def retire_execution_state(
    lease: ExecutionStateLease,
    *,
    remover: Remover = shutil.rmtree,
) -> dict[str, object]:
    """Retire only the exact owned ephemeral namespace and verify removal."""

    actual = _read_state_manifest(lease.root)
    if (
        actual.get("namespace") != lease.namespace
        or actual.get("lifecycle") != lease.lifecycle
        or actual.get("binding_sha256") != lease.binding_sha256
    ):
        raise RuntimeCapacityError("execution-state ownership changed before retirement")
    if lease.lifecycle == "persistent_shared":
        return {
            "namespace": lease.namespace,
            "lifecycle": lease.lifecycle,
            "binding_sha256": lease.binding_sha256,
            "preexisting": lease.preexisting,
            "retired": False,
            "removal_verified": False,
        }
    remover(lease.root)
    if lease.root.exists() or lease.root.is_symlink():
        raise RuntimeCapacityError("execution-state namespace retirement was incomplete")
    try:
        lease.root.parent.rmdir()
    except OSError:
        pass
    return {
        "namespace": lease.namespace,
        "lifecycle": lease.lifecycle,
        "binding_sha256": lease.binding_sha256,
        "preexisting": lease.preexisting,
        "retired": True,
        "removal_verified": True,
    }


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
    if contract.get("execution_state") != EXECUTION_STATE_POLICY:
        raise RuntimeCapacityError("execution-state policy must be exact and fail-closed")
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
