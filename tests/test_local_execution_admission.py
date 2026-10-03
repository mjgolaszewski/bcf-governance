from __future__ import annotations

from contextlib import ExitStack
from pathlib import Path
import sys

import pytest

from bcf_governance.tooling.local_execution_admission import (
    LocalExecutionAdmissionError,
    local_gate_lease,
    project_python_environment,
    resolve_local_project_python,
    selected_toolchain_environment,
    validate_local_toolchain,
)
from bcf_governance.tooling.runtime_capacity import (
    EXECUTION_STATE_ENVIRONMENT,
    EXECUTION_STATE_POLICY,
    allocate_execution_state,
    retire_execution_state,
)


def _runtime_contract() -> dict[str, object]:
    return {
        "runtime_root": ".artifacts/runtime",
        "database": {
            "storage": "repository_bind_mount",
            "relative_path": ".artifacts/runtime/database",
        },
        "execution_state": EXECUTION_STATE_POLICY,
    }


def test_competing_local_gate_fails_busy_before_work() -> None:
    first = "a" * 40
    second = "b" * 40
    with ExitStack() as stack:
        stack.enter_context(local_gate_lease(first))
        with pytest.raises(LocalExecutionAdmissionError, match="busy_deferred"):
            stack.enter_context(local_gate_lease(second))


def test_local_gate_requires_exact_execution_identity() -> None:
    with pytest.raises(LocalExecutionAdmissionError, match="identity"):
        with local_gate_lease("branch-name"):
            pass


def test_local_gate_uses_authenticated_execution_state_namespace(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    first = allocate_execution_state(
        tmp_path,
        _runtime_contract(),
        session_id="session-one",
        workload_id="test",
        execution_id="positive",
        invocation={},
    )
    second = allocate_execution_state(
        tmp_path,
        _runtime_contract(),
        session_id="session-two",
        workload_id="test",
        execution_id="positive",
        invocation={},
    )
    try:
        for name, value in first.environment().items():
            monkeypatch.setenv(name, value)
        with local_gate_lease("a" * 40):
            for name, value in second.environment().items():
                monkeypatch.setenv(name, value)
            with local_gate_lease("b" * 40):
                with pytest.raises(LocalExecutionAdmissionError, match="busy_deferred"):
                    with local_gate_lease("c" * 40):
                        pass
    finally:
        retire_execution_state(first)
        retire_execution_state(second)


def test_local_gate_rejects_partial_execution_state_environment(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    for name in EXECUTION_STATE_ENVIRONMENT:
        monkeypatch.delenv(name, raising=False)
    monkeypatch.setenv("BCF_EXECUTION_STATE_NAMESPACE", "bcf-forged-state")
    with pytest.raises(LocalExecutionAdmissionError, match="incomplete"):
        with local_gate_lease("a" * 40):
            pass


def test_project_python_is_distinct_from_controller_python(tmp_path: Path) -> None:
    project = tmp_path / ".venv/bin/python"
    project.parent.mkdir(parents=True)
    project.write_text("#!/bin/sh\n", encoding="utf-8")
    project.chmod(0o755)

    assert resolve_local_project_python(tmp_path, Path(sys.executable)) == project


def test_broken_repository_project_python_never_falls_back(tmp_path: Path) -> None:
    project = tmp_path / ".venv/bin/python"
    project.parent.mkdir(parents=True)
    project.symlink_to("missing-python")

    with pytest.raises(LocalExecutionAdmissionError, match="unavailable"):
        resolve_local_project_python(tmp_path, Path(sys.executable))


def test_project_python_environment_removes_controller_paths(tmp_path: Path) -> None:
    project = tmp_path / ".venv/bin/python"
    environment = project_python_environment(
        tmp_path,
        project,
        {
            "PATH": "/controller/bin:/usr/bin",
            "PYTHONPATH": "/controller/source",
            "PYTHONHOME": "/controller/home",
            "VIRTUAL_ENV": "/controller/.venv",
            "KEPT": "exact",
        },
    )

    assert environment == {
        "PATH": f"{project.parent}:/controller/bin:/usr/bin",
        "VIRTUAL_ENV": str(tmp_path / ".venv"),
        "KEPT": "exact",
    }


def test_python_only_graph_does_not_invoke_self_toolchain_bootstrap(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    executable = tmp_path / "python"
    executable.write_text("", encoding="utf-8")
    calls: list[list[str]] = []

    def run(argv: list[str], **_kwargs: object) -> object:
        calls.append(argv)
        return type("Result", (), {"returncode": 0, "stdout": "Python 3.12.9\n", "stderr": ""})()

    monkeypatch.setattr("subprocess.run", run)
    admission = validate_local_toolchain(
        tmp_path, executable, toolchain_command=None
    )

    assert calls == [[str(executable), "--version"]]
    assert admission.toolchain_scope == "python_only"
    assert admission.node_executable is None
    with selected_toolchain_environment(admission):
        pass


def test_declared_toolchain_command_is_the_only_bootstrap_authority(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    executable = tmp_path / "python"
    executable.write_text("", encoding="utf-8")
    calls: list[list[str]] = []

    def run(argv: list[str], **_kwargs: object) -> object:
        calls.append(argv)
        if len(calls) == 1:
            stdout = "Python 3.12.9\n"
        else:
            stdout = (
                '{"status":"test_toolchain_ready","node_version":"v22.23.2",'
                '"node_executable":"/tool/node","typescript_version":"6.0.3"}'
            )
        return type("Result", (), {"returncode": 0, "stdout": stdout, "stderr": ""})()

    monkeypatch.setattr("subprocess.run", run)
    admission = validate_local_toolchain(
        tmp_path,
        executable,
        toolchain_command={
            "argv": ["{python}", "tools/owned_bootstrap.py", "--repo-root", "."],
            "cwd": ".",
            "environment": {},
        },
    )

    assert calls[1] == [
        sys.executable,
        "tools/owned_bootstrap.py",
        "--repo-root",
        ".",
    ]
    assert admission.toolchain_scope == "python_node_typescript"
