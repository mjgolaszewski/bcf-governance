"""Deterministic toolchain and single-host admission before expensive local gates."""

from __future__ import annotations

import fcntl
import json
import os
import re
import stat
import subprocess
import sys
from collections.abc import Iterator, Mapping
from contextlib import contextmanager
from dataclasses import dataclass
from pathlib import Path
from typing import Any

import yaml

from .bootstrap.contracts import CustodySettings, ScopedExecutionEnvironment
from .bootstrap.environment import custody_settings as _default_custody_settings
from .bootstrap.environment import (
    scoped_execution_environment as _default_scoped_execution_environment,
)
from .exception_messages import native_exception_message
from .interpreter_environment import (
    InterpreterEnvironmentError,
    InterpreterEnvironmentPlan,
    derive_interpreter_environment,
    materialize_interpreter_environment,
    probe_interpreter_environment,
)
from .runtime_capacity import (
    RuntimeCapacityError,
    authenticated_execution_state_namespace,
)


class LocalExecutionAdmissionError(ValueError):
    """The local gate is mechanically unready or already owns the host slot."""


def _supported_python_minors(repo_root: Path) -> set[str]:
    """Load the canonical self or adopter authority for project interpreters."""

    path = repo_root / "governance/public-contracts.yml"
    if not path.is_file():
        from .ci_graph_contracts import CIGraphError, validate_ci_graph

        try:
            resources = validate_ci_graph(repo_root).graph["resource_classes"]
            values = sorted(
                {
                    str(resource["python_version"])
                    for resource in resources.values()
                    if isinstance(resource, dict) and "python_version" in resource
                }
            )
        except (CIGraphError, KeyError, TypeError, ValueError) as exc:
            raise LocalExecutionAdmissionError(
                "adopter Python runtime authority is unavailable"
            ) from exc
        if not values:
            raise LocalExecutionAdmissionError(
                "adopter Python runtime authority declares no Python minor"
            )
        return set(values)
    try:
        payload = yaml.safe_load(path.read_text(encoding="utf-8"))
        values = payload["package"]["python_minors"]
    except (OSError, TypeError, KeyError, yaml.YAMLError) as exc:
        raise LocalExecutionAdmissionError(
            "public Python runtime contract is unavailable"
        ) from exc
    if (
        not isinstance(values, list)
        or not values
        or any(not isinstance(value, str) or re.fullmatch(r"3\.[0-9]+", value) is None for value in values)
        or len(values) != len(set(values))
    ):
        raise LocalExecutionAdmissionError("public Python runtime contract is malformed")
    return set(values)


def _virtual_environment_root(executable: Path) -> Path | None:
    absolute = executable.absolute()
    root = absolute.parent.parent
    return root if absolute.parent.name == "bin" and (root / "pyvenv.cfg").is_file() else None


def _shares_interpreter_custody(project: Path, controller: Path) -> bool:
    """Distinguish environment custody even when venvs share one base binary."""

    project_absolute = project.absolute()
    controller_absolute = controller.absolute()
    if project_absolute == controller_absolute:
        return True
    project_root = _virtual_environment_root(project_absolute)
    controller_root = _virtual_environment_root(controller_absolute)
    if project_root is not None and controller_root is not None:
        return project_root == controller_root
    return project_absolute.resolve() == controller_absolute.resolve()


def resolve_local_project_python(
    repo_root: Path,
    controller_python: Path,
    *,
    requested: Path | None = None,
) -> Path:
    """Select one project interpreter without conflating it with the BCF controller."""

    local = (
        requested.absolute()
        if requested is not None
        else repo_root.resolve() / ".venv/bin/python"
    )
    if local.exists() or local.is_symlink():
        if not local.is_file() or not os.access(local, os.X_OK):
            raise LocalExecutionAdmissionError(
                "selected project Python is unavailable or non-executable"
            )
        try:
            local.resolve(strict=True)
        except OSError as exc:
            raise LocalExecutionAdmissionError(
                "selected project Python cannot be resolved"
            ) from exc
        if _shares_interpreter_custody(local, controller_python):
            raise LocalExecutionAdmissionError(
                "controller interpreter cannot serve as project Python"
            )
        return local
    raise LocalExecutionAdmissionError(
        "repository project Python is absent and must be derived"
    )


def ensure_local_project_python(
    repo_root: Path,
    controller_python: Path,
    *,
    requested: Path | None = None,
) -> Path:
    """Derive the project interpreter without an operator setup procedure."""

    def dependency_plan() -> InterpreterEnvironmentPlan:
        try:
            plan = derive_interpreter_environment(repo_root)
            if plan is None:
                raise InterpreterEnvironmentError(
                    "repository declares no interpreter dependency contract"
                )
            return plan
        except InterpreterEnvironmentError as exc:
            raise LocalExecutionAdmissionError(native_exception_message(exc)) from exc

    if requested is not None:
        project_python = resolve_local_project_python(
            repo_root, controller_python, requested=requested
        )
        plan = dependency_plan()
        try:
            probe_interpreter_environment(plan, project_python)
        except InterpreterEnvironmentError as exc:
            raise LocalExecutionAdmissionError(native_exception_message(exc)) from exc
        return project_python
    local = repo_root.resolve() / ".venv/bin/python"
    if local.exists() or local.is_symlink() or local.parent.parent.exists():
        try:
            project_python = resolve_local_project_python(repo_root, controller_python)
            plan = dependency_plan()
            probe_interpreter_environment(plan, project_python)
            return project_python
        except (InterpreterEnvironmentError, LocalExecutionAdmissionError):
            pass
    plan = dependency_plan()
    try:
        project_python = materialize_interpreter_environment(
            repo_root, controller_python
        )
        probe_interpreter_environment(plan, project_python)
    except InterpreterEnvironmentError as exc:
        raise LocalExecutionAdmissionError(native_exception_message(exc)) from exc
    return project_python


def project_python_environment(
    repo_root: Path,
    project_python: Path,
    source: Mapping[str, str],
) -> dict[str, str]:
    """Project a project-owned Python environment without controller leakage."""

    environment = dict(source)
    for name in ("PYTHONHOME", "PYTHONPATH", "VIRTUAL_ENV"):
        environment.pop(name, None)
    executable = project_python.absolute()
    bin_directory = executable.parent
    prefix = bin_directory.parent
    if bin_directory.name == "bin" and (prefix / "pyvenv.cfg").is_file():
        environment["VIRTUAL_ENV"] = str(prefix)
    previous_path = environment.get("PATH")
    environment["PATH"] = str(bin_directory) + (
        os.pathsep + previous_path if previous_path else ""
    )
    return environment


@dataclass(frozen=True)
class LocalExecutionAdmission:
    status: str
    execution_id: str
    python_executable: str
    python_version: str
    toolchain_scope: str
    node_version: str | None
    node_executable: str | None
    typescript_version: str | None

    def as_dict(self) -> dict[str, str | None]:
        return {
            "status": self.status,
            "execution_id": self.execution_id,
            "python_executable": self.python_executable,
            "python_version": self.python_version,
            "toolchain_scope": self.toolchain_scope,
            "node_version": self.node_version,
            "node_executable": self.node_executable,
            "typescript_version": self.typescript_version,
        }


def validate_local_toolchain(
    repo_root: Path,
    python_executable: Path,
    *,
    toolchain_command: Mapping[str, Any] | None,
) -> LocalExecutionAdmission:
    """Validate the selected interpreter and only graph-declared setup bytes."""

    executable = python_executable.resolve()
    if not executable.is_file():
        raise LocalExecutionAdmissionError("selected project Python is unavailable")
    version = subprocess.run(
        [str(executable), "--version"], capture_output=True, text=True, check=False
    )
    observed_python = (version.stdout or version.stderr).strip()
    match = re.fullmatch(r"Python ((3\.[0-9]+)\.[0-9]+)", observed_python)
    if version.returncode or match is None:
        raise LocalExecutionAdmissionError(
            f"selected project Python is outside the governed runtime: {observed_python}"
        )
    if match.group(2) not in _supported_python_minors(repo_root):
        raise LocalExecutionAdmissionError(
            f"selected project Python {match.group(2)} is absent from the public runtime contract"
        )
    if toolchain_command is None:
        return LocalExecutionAdmission(
            status="ready",
            execution_id="toolchain-only",
            python_executable=str(executable),
            python_version=match.group(1),
            toolchain_scope="python_only",
            node_version=None,
            node_executable=None,
            typescript_version=None,
        )
    argv = toolchain_command.get("argv")
    cwd = toolchain_command.get("cwd")
    environment = toolchain_command.get("environment")
    if (
        not isinstance(argv, list)
        or not argv
        or any(not isinstance(value, str) or not value for value in argv)
        or cwd != "."
        or environment != {}
    ):
        raise LocalExecutionAdmissionError(
            "declared local toolchain command is malformed"
        )
    command = [sys.executable if value == "{python}" else value for value in argv]
    checked = subprocess.run(
        command,
        cwd=repo_root,
        capture_output=True,
        text=True,
        check=False,
    )
    if checked.returncode:
        detail = checked.stderr.strip() or checked.stdout.strip() or "toolchain check failed"
        raise LocalExecutionAdmissionError(detail)
    try:
        payload = json.loads(checked.stdout)
    except json.JSONDecodeError as exc:
        raise LocalExecutionAdmissionError("toolchain check emitted invalid JSON") from exc
    if payload.get("status") != "test_toolchain_ready":
        raise LocalExecutionAdmissionError("toolchain check did not prove installed custody")
    return LocalExecutionAdmission(
        status="ready",
        execution_id="toolchain-only",
        python_executable=str(executable),
        python_version=match.group(1),
        toolchain_scope="python_node_typescript",
        node_version=str(payload["node_version"]),
        node_executable=str(payload["node_executable"]),
        typescript_version=str(payload["typescript_version"]),
    )


@contextmanager
def selected_toolchain_environment(
    admission: LocalExecutionAdmission,
    *,
    scoped_environment: ScopedExecutionEnvironment | None=None,
) -> Iterator[None]:
    """Project the mechanically selected Node binary for all downstream tools."""
    scoped_environment = _default_scoped_execution_environment() if scoped_environment is None else scoped_environment

    if admission.node_executable is None:
        yield
        return
    with scoped_environment.toolchain_path(admission.node_executable):
        yield


def _gate_leaf_identity(value: os.stat_result) -> tuple[int, int]:
    if (not stat.S_ISREG(value.st_mode) or value.st_uid != os.getuid()
            or value.st_nlink != 1 or value.st_size > 4096):
        raise LocalExecutionAdmissionError("local gate lock leaf is unsafe")
    return value.st_dev, value.st_ino


@contextmanager
def local_gate_lease(
    execution_id: str,
    *,
    custody_settings: CustodySettings | None=None,
) -> Iterator[None]:
    """Own one safe host-local gate inode or return typed busy/deferred."""
    custody_settings = _default_custody_settings() if custody_settings is None else custody_settings
    if re.fullmatch(r"[a-f0-9]{40}", execution_id) is None:
        raise LocalExecutionAdmissionError("local gate execution identity is invalid")
    try:
        namespace = authenticated_execution_state_namespace(custody_settings.execution_inputs())
    except RuntimeCapacityError as exc:
        raise LocalExecutionAdmissionError(native_exception_message(exc)) from exc
    suffix = f"-{namespace}" if namespace is not None else ""
    # A fixed shared-host inode is the coordination contract, not a temporary
    # output file. O_EXCL/O_NOFOLLOW plus uid, nlink and inode checks below
    # reject precreated aliases; moving the path would split the execution fence.
    path = Path(f"/tmp/bcf-local-gate-{os.getuid()}{suffix}.lock")  # nosec B108
    try:
        try:
            before = _gate_leaf_identity(path.lstat())
        except FileNotFoundError:
            before = None
        flags = os.O_RDWR | os.O_NOFOLLOW | os.O_NONBLOCK
        if before is None:
            flags |= os.O_CREAT | os.O_EXCL
        raw = os.open(path, flags, 0o600)
    except OSError as exc:
        raise LocalExecutionAdmissionError("local gate lock leaf is unsafe") from exc
    try:
        opened = _gate_leaf_identity(os.fstat(raw))
        if (before is not None and opened != before) or _gate_leaf_identity(path.lstat()) != opened:
            raise LocalExecutionAdmissionError("local gate lock inode changed before admission")
        descriptor = os.fdopen(raw, "r+", encoding="utf-8")
    except OSError as exc:
        os.close(raw)
        raise LocalExecutionAdmissionError("local gate lock inode changed before admission") from exc
    except BaseException:
        os.close(raw)
        raise
    acquired = False
    try:
        try:
            fcntl.flock(descriptor.fileno(), fcntl.LOCK_EX | fcntl.LOCK_NB)
            acquired = True
        except BlockingIOError as exc:
            descriptor.seek(0)
            try:
                owner = descriptor.read(4096).strip() or "unknown"
            except UnicodeError:
                owner = "unreadable"
            raise LocalExecutionAdmissionError(
                f"local_execution_busy_deferred: active={owner}"
            ) from exc
        try:
            unchanged = (_gate_leaf_identity(os.fstat(descriptor.fileno())) == opened
                         and _gate_leaf_identity(path.lstat()) == opened)
        except OSError as exc:
            raise LocalExecutionAdmissionError("local gate lock inode changed before write") from exc
        if not unchanged:
            raise LocalExecutionAdmissionError("local gate lock inode changed before write")
        descriptor.seek(0)
        descriptor.truncate()
        descriptor.write(execution_id + "\n")
        descriptor.flush()
        yield
    finally:
        try:
            if acquired:
                fcntl.flock(descriptor.fileno(), fcntl.LOCK_UN)
        finally:
            descriptor.close()
