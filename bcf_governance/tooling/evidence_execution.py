"""Prepare isolated evidence commands under the caller-selected Python runtime."""

from __future__ import annotations

import hashlib
import json
import os
import shutil
import site
import subprocess
import sys
from pathlib import Path
from typing import Any

from .runtime_capacity import (
    EXECUTION_STATE_ENVIRONMENT,
    allocate_execution_state,
    load_runtime_contract,
    retire_execution_state,
)

PYTHON_COMMANDS = {"python", "python3"}
LOADER_ENVIRONMENT = ("LD_LIBRARY_PATH", "DYLD_LIBRARY_PATH")
STATE_ENVIRONMENT = frozenset(EXECUTION_STATE_ENVIRONMENT)


class EvidenceError(ValueError):
    """Raised when evidence cannot be captured safely."""


def _sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _selected_python(value: str | Path | None = None) -> Path:
    raw = os.fspath(value) if value is not None else sys.executable
    if not raw or "\0" in raw or "\n" in raw:
        raise EvidenceError("selected Python executable is invalid")
    candidate = Path(raw)
    if not candidate.is_absolute():
        discovered = shutil.which(raw)
        if discovered is None:
            raise EvidenceError(f"selected Python executable is missing: {raw}")
        candidate = Path(discovered)
    candidate = Path(os.path.abspath(candidate))
    if not candidate.is_file() or not os.access(candidate, os.X_OK):
        raise EvidenceError(f"selected Python executable is not executable: {candidate.name}")
    return candidate


def _command(contract: dict[str, Any]) -> list[str]:
    invocation = contract.get("invocation")
    argv = invocation.get("argv") if isinstance(invocation, dict) else None
    if not isinstance(argv, list) or not argv or not all(isinstance(value, str) for value in argv):
        raise EvidenceError(f"gate {contract.get('target')} has no valid argv")
    for value in argv:
        argument = Path(value)
        if argument.is_absolute() or ".." in argument.parts:
            raise EvidenceError("gate argv must not reference an out-of-tree path")
    return list(argv)


def _runtime_command(command: list[str], python_executable: Path) -> list[str]:
    if command[0] in PYTHON_COMMANDS:
        return [str(python_executable), *command[1:]]
    return list(command)


def _run(
    command: list[str],
    *,
    cwd: Path,
    env: dict[str, str] | None = None,
    timeout_seconds: int,
) -> subprocess.CompletedProcess[str]:
    try:
        return subprocess.run(
            command,
            cwd=cwd,
            env=env,
            capture_output=True,
            text=True,
            timeout=timeout_seconds,
        )
    except (OSError, subprocess.TimeoutExpired) as exc:
        return subprocess.CompletedProcess(
            command, 126, "", f"bcf execution infrastructure failure: {exc}"
        )


def _execution_cwd(worktree: Path, contract: dict[str, Any]) -> Path:
    invocation = contract["invocation"]
    relative = Path(str(invocation.get("cwd", ".")))
    if relative.is_absolute() or ".." in relative.parts:
        raise EvidenceError("gate cwd must stay inside the governed tree")
    cwd = (worktree / relative).resolve()
    if not cwd.is_relative_to(worktree.resolve()) or not cwd.is_dir():
        raise EvidenceError("gate cwd does not resolve to a directory inside the governed tree")
    return cwd


def _interpreter_metadata(
    python_executable: Path, runtime_env: dict[str, str]
) -> dict[str, str]:
    try:
        version = subprocess.run(
            [str(python_executable), "-c", "import platform; print(platform.python_version())"],
            env=runtime_env,
            capture_output=True,
            text=True,
            timeout=30,
            check=False,
        )
    except (OSError, subprocess.TimeoutExpired) as exc:
        raise EvidenceError(f"selected Python executable is not runnable: {exc}") from exc
    if version.returncode != 0:
        diagnostic = version.stderr.strip() or f"exit {version.returncode}"
        raise EvidenceError(f"selected Python executable is not runnable: {diagnostic}")
    loader = {
        name: runtime_env[name]
        for name in LOADER_ENVIRONMENT
        if runtime_env.get(name)
    }
    environment_material = json.dumps(
        {"executable_directory": str(python_executable.parent), "loader": loader},
        sort_keys=True,
    ).encode("utf-8")
    return {
        "role": "project_python",
        "version": version.stdout.strip(),
        "executable_name": python_executable.name,
        "binary_sha256": _sha256(python_executable),
        "lexical_path_sha256": hashlib.sha256(
            str(python_executable).encode("utf-8")
        ).hexdigest(),
        "runtime_environment_sha256": hashlib.sha256(environment_material).hexdigest(),
    }


def _execution_env(
    worktree: Path,
    contract: dict[str, Any],
    python_executable: Path,
    *,
    state_environment: dict[str, str] | None = None,
) -> tuple[dict[str, str], dict[str, Any]]:
    invocation = contract["invocation"]
    configured = invocation.get("env", {})
    required = invocation.get("required_env", [])
    if not isinstance(configured, dict) or not isinstance(required, list):
        raise EvidenceError("gate environment contract is invalid")
    conflicts = sorted(
        STATE_ENVIRONMENT.intersection(str(value) for value in configured)
        | STATE_ENVIRONMENT.intersection(str(value) for value in required)
    )
    if conflicts:
        raise EvidenceError(
            "gate cannot override execution-state environment: " + ", ".join(conflicts)
        )
    missing = sorted(name for name in required if not isinstance(name, str) or name not in os.environ)
    if missing:
        raise EvidenceError("required gate environment is missing: " + ", ".join(missing))
    runtime_home = worktree.parent / ".bcf-home"
    runtime_home.mkdir(exist_ok=True)
    caller_path = os.environ.get("PATH", "")
    executable_directory = str(python_executable.parent)
    path_entries = [
        executable_directory,
        *(entry for entry in caller_path.split(os.pathsep) if entry != executable_directory),
    ]
    env = {
        "PATH": os.pathsep.join(entry for entry in path_entries if entry),
        "HOME": str(runtime_home),
        "LANG": "C.UTF-8",
        "LC_ALL": "C.UTF-8",
        "PYTHONDONTWRITEBYTECODE": "1",
        "PYTHONUSERBASE": site.getuserbase(),
        **{
            name: os.environ[name]
            for name in LOADER_ENVIRONMENT
            if os.environ.get(name)
        },
        **{str(key): str(value) for key, value in configured.items()},
        **{str(name): os.environ[str(name)] for name in required},
        **(state_environment or {}),
    }
    return env, {
        "declared": dict(sorted((str(key), str(value)) for key, value in configured.items())),
        "required_present": sorted(str(name) for name in required),
        "selected_interpreter": _interpreter_metadata(python_executable, env),
    }


def _run_with_execution_state(
    repo_root: Path,
    worktree: Path,
    contract: dict[str, Any],
    command: list[str],
    python_executable: Path,
    *,
    session_id: str,
    execution_id: str,
    require_state: bool,
) -> tuple[
    subprocess.CompletedProcess[str],
    dict[str, str],
    dict[str, Any],
    dict[str, object] | None,
]:
    """Run once with exact execution-state allocation and terminal retirement."""

    if not require_state:
        env, metadata = _execution_env(worktree, contract, python_executable)
        return (
            _run(
                command,
                cwd=_execution_cwd(worktree, contract),
                env=env,
                timeout_seconds=contract["execution_timeout_seconds"],
            ),
            env,
            metadata,
            None,
        )
    runtime_contract = load_runtime_contract(repo_root / "governance/ci-runtime.yml")
    lease = allocate_execution_state(
        repo_root,
        runtime_contract,
        session_id=session_id,
        workload_id=str(contract["target"]),
        execution_id=execution_id,
        invocation=contract["invocation"],
    )
    try:
        env, metadata = _execution_env(
            worktree,
            contract,
            python_executable,
            state_environment=lease.environment(),
        )
        result = _run(
            command,
            cwd=_execution_cwd(worktree, contract),
            env=env,
            timeout_seconds=contract["execution_timeout_seconds"],
        )
    finally:
        state_report = retire_execution_state(lease)
    return result, env, metadata, state_report
