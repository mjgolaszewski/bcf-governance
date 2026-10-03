"""Deterministic toolchain and single-host admission before expensive local gates."""

from __future__ import annotations

from contextlib import contextmanager
from dataclasses import dataclass
import fcntl
import json
import os
from pathlib import Path
import re
import subprocess
import sys
from typing import Iterator, Mapping

from .runtime_capacity import (
    RuntimeCapacityError,
    authenticated_execution_state_namespace,
)


class LocalExecutionAdmissionError(ValueError):
    """The local gate is mechanically unready or already owns the host slot."""


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
        return local
    controller = controller_python.absolute()
    try:
        resolved_controller = controller.resolve(strict=True)
    except OSError as exc:
        raise LocalExecutionAdmissionError("selected project Python is unavailable") from exc
    if not resolved_controller.is_file() or not os.access(controller, os.X_OK):
        raise LocalExecutionAdmissionError("selected project Python is unavailable")
    return controller


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
    if bin_directory.name == "bin" and prefix.name == ".venv":
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
    node_version: str
    node_executable: str
    typescript_version: str

    def as_dict(self) -> dict[str, str]:
        return {
            "status": self.status,
            "execution_id": self.execution_id,
            "python_executable": self.python_executable,
            "python_version": self.python_version,
            "node_version": self.node_version,
            "node_executable": self.node_executable,
            "typescript_version": self.typescript_version,
        }


def validate_local_toolchain(
    repo_root: Path, python_executable: Path
) -> LocalExecutionAdmission:
    """Validate the selected interpreter and locked Node/TypeScript bytes once."""

    executable = python_executable.resolve()
    if not executable.is_file():
        raise LocalExecutionAdmissionError("selected project Python is unavailable")
    version = subprocess.run(
        [str(executable), "--version"], capture_output=True, text=True, check=False
    )
    observed_python = (version.stdout or version.stderr).strip()
    match = re.fullmatch(r"Python (3\.(?:12|13)\.[0-9]+)", observed_python)
    if version.returncode or match is None:
        raise LocalExecutionAdmissionError(
            f"selected project Python is outside the governed runtime: {observed_python}"
        )
    bootstrap = repo_root / ".github/scripts/bootstrap_test_toolchain.py"
    checked = subprocess.run(
        [sys.executable, str(bootstrap), "--repo-root", str(repo_root)],
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
        node_version=str(payload["node_version"]),
        node_executable=str(payload["node_executable"]),
        typescript_version=str(payload["typescript_version"]),
    )


@contextmanager
def selected_toolchain_environment(
    admission: LocalExecutionAdmission,
) -> Iterator[None]:
    """Project the mechanically selected Node binary for all downstream tools."""

    previous = os.environ.get("PATH")
    node_directory = str(Path(admission.node_executable).parent)
    os.environ["PATH"] = node_directory + (os.pathsep + previous if previous else "")
    try:
        yield
    finally:
        if previous is None:
            os.environ.pop("PATH", None)
        else:
            os.environ["PATH"] = previous


@contextmanager
def local_gate_lease(execution_id: str) -> Iterator[None]:
    """Own one host-local expensive gate slot or return typed busy/deferred."""

    if re.fullmatch(r"[a-f0-9]{40}", execution_id) is None:
        raise LocalExecutionAdmissionError("local gate execution identity is invalid")
    try:
        namespace = authenticated_execution_state_namespace(os.environ)
    except RuntimeCapacityError as exc:
        raise LocalExecutionAdmissionError(str(exc)) from exc
    suffix = f"-{namespace}" if namespace is not None else ""
    path = Path(f"/tmp/bcf-local-gate-{os.getuid()}{suffix}.lock")
    descriptor = path.open("a+", encoding="utf-8")
    try:
        try:
            fcntl.flock(descriptor.fileno(), fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError as exc:
            descriptor.seek(0)
            owner = descriptor.read().strip() or "unknown"
            raise LocalExecutionAdmissionError(
                f"local_execution_busy_deferred: active={owner}"
            ) from exc
        descriptor.seek(0)
        descriptor.truncate()
        descriptor.write(execution_id + "\n")
        descriptor.flush()
        yield
    finally:
        try:
            fcntl.flock(descriptor.fileno(), fcntl.LOCK_UN)
        finally:
            descriptor.close()
