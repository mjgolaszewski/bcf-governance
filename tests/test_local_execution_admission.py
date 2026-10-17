from __future__ import annotations

from contextlib import ExitStack
from pathlib import Path
import sys

import pytest

from bcf_governance.tooling.interpreter_environment import InterpreterEnvironmentError
from bcf_governance.tooling.local_execution_admission import (
    ensure_local_project_python,
    LocalExecutionAdmissionError,
    local_gate_lease,
    project_python_environment,
    resolve_local_project_python,
    selected_toolchain_environment,
    validate_local_toolchain,
)
from bcf_governance.tooling.local_cli_receipt import (
    LocalCLIReceiptError,
    project_local_cli_receipt,
    resolve_local_cli,
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


def _public_python_contract(repo: Path, *minors: str) -> None:
    path = repo / "governance/public-contracts.yml"
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(
        "package:\n  python_minors: [" + ", ".join(repr(value) for value in minors) + "]\n",
        encoding="utf-8",
    )


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


def test_adopter_cannot_select_controller_as_project_python(tmp_path: Path) -> None:
    with pytest.raises(
        LocalExecutionAdmissionError,
        match="controller interpreter cannot serve as project Python",
    ):
        ensure_local_project_python(
            tmp_path, Path(sys.executable), requested=Path(sys.executable)
        )


def test_directory_alias_cannot_disguise_controller_environment(tmp_path: Path) -> None:
    import venv
    controller_root = tmp_path / 'controller'
    venv.create(controller_root, with_pip=False, symlinks=True)
    alias = tmp_path / 'project-alias'
    alias.symlink_to(controller_root, target_is_directory=True)
    with pytest.raises(LocalExecutionAdmissionError, match='controller interpreter cannot serve as project Python'):
        resolve_local_project_python(tmp_path, controller_root / 'bin/python', requested=alias / 'bin/python')


def test_materialized_controller_environment_cannot_bypass_custody_guard(tmp_path: Path, monkeypatch) -> None:
    import venv
    controller_root = tmp_path / 'controller'
    venv.create(controller_root, with_pip=False, symlinks=True)
    controller = controller_root / 'bin/python'
    monkeypatch.setattr('bcf_governance.tooling.local_execution_admission.derive_interpreter_environment', lambda _root: object())
    monkeypatch.setattr('bcf_governance.tooling.local_execution_admission.materialize_interpreter_environment', lambda *_args: controller)
    monkeypatch.setattr('bcf_governance.tooling.local_execution_admission.probe_interpreter_environment', lambda *_args: pytest.fail('controller reached project dependency probe'))
    with pytest.raises(LocalExecutionAdmissionError, match='controller interpreter cannot serve as project Python'):
        ensure_local_project_python(tmp_path, controller)


def test_local_cli_receipt_binds_one_safe_executable_after_install(tmp_path: Path) -> None:
    executable = tmp_path / "candidate/bin/bcf"
    executable.parent.mkdir(parents=True)
    executable.write_text("#!/bin/sh\n", encoding="utf-8")
    executable.chmod(0o755)

    receipt = project_local_cli_receipt(tmp_path, executable)

    assert receipt.read_text(encoding="utf-8") == (
        f"BCF := {executable.absolute()} -m bcf_governance.cli\n"
    )


def test_local_cli_receipt_preserves_virtual_environment_entrypoint(tmp_path: Path) -> None:
    base = tmp_path / "runtime/python"
    base.parent.mkdir(parents=True)
    base.write_text("runtime", encoding="utf-8")
    base.chmod(0o755)
    executable = tmp_path / "candidate/bin/python"
    executable.parent.mkdir(parents=True)
    executable.symlink_to(base)

    receipt = project_local_cli_receipt(tmp_path, executable)

    assert receipt.read_text(encoding="utf-8") == (
        f"BCF := {executable.absolute()} -m bcf_governance.cli\n"
    )


@pytest.mark.parametrize("value", ["bcf", "/tmp/bcf path", "/tmp/bcf#unsafe"])
def test_local_cli_receipt_rejects_ambiguous_or_unsafe_paths(value: str) -> None:
    with pytest.raises(LocalCLIReceiptError):
        resolve_local_cli(value)


def test_implicit_repository_alias_is_replaced_not_used_as_project_python(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    project = tmp_path / ".venv/bin/python"
    project.parent.mkdir(parents=True)
    project.symlink_to(Path(sys.executable).resolve())
    derived = tmp_path / ".artifacts/project/bin/python"
    monkeypatch.setattr(
        "bcf_governance.tooling.local_execution_admission.derive_interpreter_environment",
        lambda _root: object(),
    )
    monkeypatch.setattr(
        "bcf_governance.tooling.local_execution_admission.materialize_interpreter_environment",
        lambda _root, _controller: derived,
    )
    monkeypatch.setattr(
        "bcf_governance.tooling.local_execution_admission.probe_interpreter_environment",
        lambda _plan, selected: {} if selected == derived else pytest.fail("alias used"),
    )

    assert ensure_local_project_python(tmp_path, Path(sys.executable)) == derived


def test_distinct_virtual_environments_may_share_base_python(tmp_path: Path) -> None:
    controller = tmp_path / "controller/bin/python"
    project = tmp_path / "project/.venv/bin/python"
    for executable in (controller, project):
        executable.parent.mkdir(parents=True)
        executable.symlink_to(Path(sys.executable).resolve())
        (executable.parent.parent / "pyvenv.cfg").write_text(
            "home = /usr/local/bin\n", encoding="utf-8"
        )

    assert resolve_local_project_python(
        tmp_path / "project", controller
    ) == project


def test_adopter_without_environment_derives_project_python(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    _public_python_contract(
        tmp_path, f"{sys.version_info.major}.{sys.version_info.minor}"
    )
    derived = tmp_path / ".artifacts/runtime/project-environments/exact/venv/bin/python"
    calls: list[tuple[Path, Path]] = []

    def materialize(repo_root: Path, base_python: Path) -> Path:
        calls.append((repo_root, base_python))
        return derived

    monkeypatch.setattr(
        "bcf_governance.tooling.local_execution_admission.materialize_interpreter_environment",
        materialize,
    )
    monkeypatch.setattr(
        "bcf_governance.tooling.local_execution_admission.derive_interpreter_environment",
        lambda _root: object(),
    )
    monkeypatch.setattr(
        "bcf_governance.tooling.local_execution_admission.probe_interpreter_environment",
        lambda _plan, _python: {},
    )

    assert ensure_local_project_python(tmp_path, Path(sys.executable)) == derived
    assert calls == [(tmp_path, Path(sys.executable))]


def test_incomplete_implicit_project_environment_is_mechanically_replaced_before_reconcile(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    controller = tmp_path / "controller/bin/python"
    project = tmp_path / ".venv/bin/python"
    for executable in (controller, project):
        executable.parent.mkdir(parents=True)
        executable.write_text("#!/bin/sh\nexit 0\n", encoding="utf-8")
        executable.chmod(0o755)
        (executable.parent.parent / "pyvenv.cfg").write_text(
            "home = exact\n", encoding="utf-8"
        )
    monkeypatch.setattr(
        "bcf_governance.tooling.local_execution_admission.derive_interpreter_environment",
        lambda _root: object(),
    )

    derived = tmp_path / ".artifacts/project/bin/python"
    observations: list[Path] = []

    def probe(_plan: object, selected: Path) -> dict[str, str]:
        observations.append(selected)
        if selected == project:
            raise InterpreterEnvironmentError(
                "selected interpreter dependency contract failed: build missing"
            )
        assert selected == derived
        return {"build": "1.6.1"}

    monkeypatch.setattr(
        "bcf_governance.tooling.local_execution_admission.probe_interpreter_environment",
        probe,
    )
    monkeypatch.setattr(
        "bcf_governance.tooling.local_execution_admission.validate_local_toolchain",
        lambda *_args, **_kwargs: None,
    )
    monkeypatch.setattr(
        "bcf_governance.tooling.local_execution_admission.materialize_interpreter_environment",
        lambda _root, _controller: derived,
    )

    assert ensure_local_project_python(tmp_path, controller) == derived
    assert observations == [project, derived]


def test_incomplete_explicit_project_environment_rejects_without_replacement(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    controller = tmp_path / "controller/bin/python"
    project = tmp_path / "project/bin/python"
    for executable in (controller, project):
        executable.parent.mkdir(parents=True)
        executable.write_text("#!/bin/sh\nexit 0\n", encoding="utf-8")
        executable.chmod(0o755)
    monkeypatch.setattr(
        "bcf_governance.tooling.local_execution_admission.derive_interpreter_environment",
        lambda _root: object(),
    )
    monkeypatch.setattr(
        "bcf_governance.tooling.local_execution_admission.probe_interpreter_environment",
        lambda _plan, _selected: (_ for _ in ()).throw(
            InterpreterEnvironmentError("build missing")
        ),
    )
    monkeypatch.setattr(
        "bcf_governance.tooling.local_execution_admission.materialize_interpreter_environment",
        lambda *_args: pytest.fail("explicit interpreter was silently replaced"),
    )

    with pytest.raises(LocalExecutionAdmissionError, match="build missing"):
        ensure_local_project_python(tmp_path, controller, requested=project)


def test_adopter_environment_derives_graph_python_when_controller_minor_differs(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    _public_python_contract(tmp_path, "3.99")
    derived = tmp_path / ".artifacts/project/bin/python"
    calls: list[tuple[Path, Path]] = []

    def materialize(repo_root: Path, base_python: Path) -> Path:
        calls.append((repo_root, base_python))
        return derived

    monkeypatch.setattr(
        "bcf_governance.tooling.local_execution_admission.materialize_interpreter_environment",
        materialize,
    )
    monkeypatch.setattr(
        "bcf_governance.tooling.local_execution_admission.derive_interpreter_environment",
        lambda _root: object(),
    )
    monkeypatch.setattr(
        "bcf_governance.tooling.local_execution_admission.probe_interpreter_environment",
        lambda _plan, _python: {},
    )

    assert ensure_local_project_python(tmp_path, Path(sys.executable)) == derived
    assert calls == [(tmp_path, Path(sys.executable))]


def test_project_python_environment_removes_controller_paths(tmp_path: Path) -> None:
    project = tmp_path / ".venv/bin/python"
    (project.parent.parent / "pyvenv.cfg").parent.mkdir(parents=True)
    (project.parent.parent / "pyvenv.cfg").write_text("home = exact\n", encoding="utf-8")
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


def test_derived_project_python_environment_owns_virtual_environment(
    tmp_path: Path,
) -> None:
    prefix = tmp_path / ".artifacts/runtime/project-environments/exact/venv"
    project = prefix / "bin/python"
    prefix.mkdir(parents=True)
    (prefix / "pyvenv.cfg").write_text("home = exact\n", encoding="utf-8")

    environment = project_python_environment(tmp_path, project, {})

    assert environment == {"PATH": str(project.parent), "VIRTUAL_ENV": str(prefix)}


def test_python_only_graph_does_not_invoke_self_toolchain_bootstrap(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    executable = tmp_path / "python"
    executable.write_text("", encoding="utf-8")
    _public_python_contract(tmp_path, "3.12")
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
    _public_python_contract(tmp_path, "3.12")
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


def test_local_python_admission_derives_every_supported_minor(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    executable = tmp_path / "python"
    executable.write_text("", encoding="utf-8")
    _public_python_contract(tmp_path, "3.11", "3.12", "3.13", "3.14")
    monkeypatch.setattr(
        "subprocess.run",
        lambda *_args, **_kwargs: type(
            "Result", (), {"returncode": 0, "stdout": "Python 3.14.5\n", "stderr": ""}
        )(),
    )
    assert validate_local_toolchain(
        tmp_path, executable, toolchain_command=None
    ).python_version == "3.14.5"


def test_local_python_admission_rejects_minor_absent_from_public_contract(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    executable = tmp_path / "python"
    executable.write_text("", encoding="utf-8")
    _public_python_contract(tmp_path, "3.12", "3.13")
    monkeypatch.setattr(
        "subprocess.run",
        lambda *_args, **_kwargs: type(
            "Result", (), {"returncode": 0, "stdout": "Python 3.14.5\n", "stderr": ""}
        )(),
    )
    with pytest.raises(LocalExecutionAdmissionError, match="absent from the public"):
        validate_local_toolchain(tmp_path, executable, toolchain_command=None)


def test_adopter_python_admission_derives_generated_graph_runtime(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    executable = tmp_path / "python"
    executable.write_text("", encoding="utf-8")
    compiled = type(
        "Compiled",
        (),
        {"graph": {"resource_classes": {"hosted": {"python_version": "3.12"}}}},
    )()
    monkeypatch.setattr(
        "bcf_governance.tooling.ci_graph_contracts.validate_ci_graph",
        lambda _repo: compiled,
    )
    monkeypatch.setattr(
        "subprocess.run",
        lambda *_args, **_kwargs: type(
            "Result", (), {"returncode": 0, "stdout": "Python 3.12.11\n", "stderr": ""}
        )(),
    )
    assert validate_local_toolchain(
        tmp_path, executable, toolchain_command=None
    ).python_version == "3.12.11"
