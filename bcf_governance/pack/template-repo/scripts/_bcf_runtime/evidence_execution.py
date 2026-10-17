"""Prepare isolated evidence commands under the caller-selected Python runtime."""

from __future__ import annotations

import hashlib
import json
import os
import shutil
import selectors
import signal
import site
import subprocess
import sys
import time
from pathlib import Path
from typing import Any

from .ci_graph_errors import CIGraphError
from .ci_graph_timeouts import INTERPRETER_PROBE_TIMEOUT_SECONDS, LEGACY_GATE_CLEANUP_SECONDS, bounded_execution_seconds

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


class EvidenceProcessCleanupError(EvidenceError):
    """Command process custody is unresolved; its namespace must be retained."""


def _execution_deadline(timeout_seconds: object, cleanup_seconds: object) -> tuple[int, int]:
    try:
        execution = bounded_execution_seconds(timeout_seconds, field='gate execution timeout')
        cleanup = bounded_execution_seconds(cleanup_seconds, field='gate cleanup timeout')
    except CIGraphError as exc:
        raise EvidenceError(str(exc)) from exc
    if os.name != 'posix' or not all(hasattr(os, name) for name in ('waitid', 'WNOWAIT', 'WEXITED', 'WNOHANG')):
        raise EvidenceError('evidence command containment requires POSIX wait-without-reap support')
    if sys.platform != 'linux' or not Path('/proc/self/stat').is_file():
        raise EvidenceError('evidence command process-group inventory requires qualified Linux procfs')
    if signal.getsignal(signal.SIGCHLD) != signal.SIG_DFL:
        raise EvidenceError('evidence command custody requires default SIGCHLD ownership')
    try:
        raw = Path('/proc/self/stat').read_text()
        fields = raw[raw.rfind(')') + 2:].split()
        if (int(raw.split(' ', 1)[0]) != os.getpid() or int(fields[2]) != os.getpgrp()
                or int(fields[3]) != os.getsid(0)):
            raise EvidenceError('Linux procfs does not identify this execution namespace')
    except (OSError, ValueError, IndexError) as exc:
        raise EvidenceError('Linux execution namespace inventory is unavailable') from exc
    return execution, cleanup


def _process_group_snapshot(group):
    """Capture PID incarnations and every task in the ordinary owned group."""
    root = Path('/proc')
    try:
        (root / 'self/stat').read_text()
        pids = {path.name for path in root.iterdir() if path.name.isdigit()}
        identities, tasks = {}, {}
        for pid in pids:
            path = root / pid
            try:
                raw = (path / 'stat').read_text()
                fields = raw[raw.rfind(')') + 2:].split()
                identities[pid] = fields[19]
                if int(fields[2]) != group:
                    continue
                population = {task.name for task in (path / 'task').iterdir() if task.name.isdigit()}
                if not population:
                    return None
                for tid in population:
                    raw = (path / 'task' / tid / 'stat').read_text()
                    fields = raw[raw.rfind(')') + 2:].split()
                    if int(fields[2]) != group:
                        return None
                    tasks[(pid, tid)] = (fields[19], fields[0])
                if population != {task.name for task in (path / 'task').iterdir() if task.name.isdigit()}:
                    return None
            except FileNotFoundError:
                return None
        if pids != {path.name for path in root.iterdir() if path.name.isdigit()}:
            return None
        return identities, tasks
    except (OSError, ValueError, IndexError) as exc:
        raise EvidenceProcessCleanupError('process-group inventory is unavailable') from exc


def _live_process_group(group: int) -> bool | None:
    """Changing populations are unknown, never evidence of group quiescence."""
    first = _process_group_snapshot(group)
    second = _process_group_snapshot(group)
    if first is None or second is None:
        return None
    anchor = (str(group), str(group))
    if any(str(group) not in snapshot[0] or anchor not in snapshot[1]
           or snapshot[1][anchor][1] not in {'Z', 'X'} for snapshot in (first, second)):
        return None
    if (first[0] != second[0]
            or {key: value[0] for key, value in first[1].items()}
               != {key: value[0] for key, value in second[1].items()}):
        return None
    return any(value[1] not in {'Z', 'X'} for value in (*first[1].values(), *second[1].values()))


def _capture_process(process, selector, buffers, deadline, *, wait_for_quiescence=False):
    """Keep the leader unreaped so its group identifier cannot be recycled."""
    while True:
        terminal = os.waitid(os.P_PID, process.pid, os.WEXITED | os.WNOHANG | os.WNOWAIT)
        if terminal is not None:
            live = _live_process_group(process.pid)
            if live is True and not wait_for_quiescence:
                return False
            if live is False and not selector.get_map():
                if time.monotonic() > deadline:
                    raise subprocess.TimeoutExpired(process.args, 0)
                return True
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            raise subprocess.TimeoutExpired(process.args, 0)
        for key, _events in selector.select(min(0.05, remaining)):
            chunk = os.read(key.fd, 65536)
            if chunk:
                buffers[key.data].append(chunk)
            else:
                selector.unregister(key.fileobj)


def _terminate_process_group(process, selector, buffers, cleanup_seconds):
    """Terminate an anchored group, then bound drain, verification and reap."""
    deadline = time.monotonic() + cleanup_seconds
    try:
        # No signal is authorized after another waiter has consumed the leader.
        os.waitid(os.P_PID, process.pid, os.WEXITED | os.WNOHANG | os.WNOWAIT)
        try:
            os.killpg(process.pid, signal.SIGKILL)
        except ProcessLookupError:
            pass
        _capture_process(process, selector, buffers, deadline, wait_for_quiescence=True)
        process.wait(timeout=max(0.0, deadline - time.monotonic()))
    except BaseException as exc:
        raise EvidenceProcessCleanupError('process-group cleanup could not be authenticated') from exc


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
    cleanup_timeout_seconds: int = LEGACY_GATE_CLEANUP_SECONDS,
) -> subprocess.CompletedProcess[str]:
    timeout_seconds, cleanup_timeout_seconds = _execution_deadline(timeout_seconds, cleanup_timeout_seconds)
    selector = selectors.DefaultSelector()
    try:
        process = subprocess.Popen(command, cwd=cwd, env=env, stdout=subprocess.PIPE,
                                   stderr=subprocess.PIPE, text=True, start_new_session=True)
    except OSError as exc:
        selector.close()
        return subprocess.CompletedProcess(command, 126, '', f'bcf execution infrastructure failure: {exc}')
    buffers = {'stdout': [], 'stderr': []}
    try:
        with selector:
            try:
                for name in buffers:
                    selector.register(getattr(process, name), selectors.EVENT_READ, name)
                complete = _capture_process(process, selector, buffers, time.monotonic() + timeout_seconds)
            except subprocess.TimeoutExpired:
                _terminate_process_group(process, selector, buffers, cleanup_timeout_seconds)
                return subprocess.CompletedProcess(command, 126, '',
                    'bcf execution infrastructure failure: command timed out')
            except BaseException:
                _terminate_process_group(process, selector, buffers, cleanup_timeout_seconds)
                raise
            if not complete:
                _terminate_process_group(process, selector, buffers, cleanup_timeout_seconds)
                return subprocess.CompletedProcess(command, 126, '',
                    'bcf execution infrastructure failure: command left live process-group descendants')
            try:
                # Decode before consuming the leader's terminal identity.
                values = [b''.join(buffers[name]).decode(getattr(process, name).encoding,
                    getattr(process, name).errors).replace('\r\n', '\n').replace('\r', '\n')
                    for name in ('stdout', 'stderr')]
            except BaseException:
                _terminate_process_group(process, selector, buffers, cleanup_timeout_seconds)
                raise
            return subprocess.CompletedProcess(command, process.wait(timeout=0), *values)
    finally:
        for stream in (process.stdout, process.stderr):
            if stream is not None:
                stream.close()


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
    python_executable: Path, runtime_env: dict[str, str],
    cleanup_timeout_seconds: int = LEGACY_GATE_CLEANUP_SECONDS,
) -> dict[str, str]:
    try:
        version = _run(
            [str(python_executable), "-c", "import platform; print(platform.python_version())"],
            cwd=Path.cwd(), env=runtime_env,
            timeout_seconds=INTERPRETER_PROBE_TIMEOUT_SECONDS,
            cleanup_timeout_seconds=cleanup_timeout_seconds,
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
    job_environment: dict[str, str] | None = None,
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
    projected = os.environ
    unsupported: list[str] = []
    if job_environment is not None:
        projected = dict(job_environment)
        unsupported = sorted(
            name
            for name, value in projected.items()
            if "${{" in value
            or "}}" in value
            or "\0" in value
            or "\n" in value
            or "\r" in value
        )
    if unsupported:
        raise EvidenceError(
            "unsupported local graph environment: " + ", ".join(unsupported)
        )
    missing = sorted(name for name in required if not isinstance(name, str) or name not in projected)
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
        **{str(name): projected[str(name)] for name in required},
        **(state_environment or {}),
    }
    return env, {
        "declared": dict(sorted((str(key), str(value)) for key, value in configured.items())),
        "required_present": sorted(str(name) for name in required),
        "selected_interpreter": _interpreter_metadata(python_executable, env,
            contract.get("execution_cleanup_timeout_seconds", LEGACY_GATE_CLEANUP_SECONDS)),
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
    job_environment: dict[str, str] | None = None,
) -> tuple[
    subprocess.CompletedProcess[str],
    dict[str, str],
    dict[str, Any],
    dict[str, object] | None,
]:
    """Run once with exact execution-state allocation and terminal retirement."""

    _execution, cleanup_seconds = _execution_deadline(
        contract['execution_timeout_seconds'],
        contract.get('execution_cleanup_timeout_seconds', LEGACY_GATE_CLEANUP_SECONDS),
    )

    if not require_state:
        env, metadata = _execution_env(
            worktree, contract, python_executable, job_environment=job_environment
        )
        return (
            _run(
                command,
                cwd=_execution_cwd(worktree, contract),
                env=env,
                timeout_seconds=contract["execution_timeout_seconds"],
                cleanup_timeout_seconds=cleanup_seconds,
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
    cleanup_unproven = False
    try:
        env, metadata = _execution_env(
            worktree,
            contract,
            python_executable,
            state_environment=lease.environment(),
            job_environment=job_environment,
        )
        result = _run(
            command,
            cwd=_execution_cwd(worktree, contract),
            env=env,
            timeout_seconds=contract["execution_timeout_seconds"],
            cleanup_timeout_seconds=cleanup_seconds,
        )
    except EvidenceProcessCleanupError:
        cleanup_unproven = True
        raise
    finally:
        if not cleanup_unproven:
            state_report = retire_execution_state(lease)
    return result, env, metadata, state_report
