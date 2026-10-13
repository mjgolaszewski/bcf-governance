from __future__ import annotations

import json
from pathlib import Path
import subprocess
import sys

import pytest
import yaml

from bcf_governance.tooling.interpreter_environment import (
    InterpreterEnvironmentError,
    apply_interpreter_environment_projection,
    derive_interpreter_environment,
    main,
    materialize_interpreter_environment,
    reconcile_interpreter_environment,
    validate_runtime_import_dependencies,
    verify_interpreter_environment_projection,
)
from bcf_governance.tooling.runtime_capacity import EXECUTION_STATE_POLICY


REPO_ROOT = Path(__file__).resolve().parents[1]


def _fixture(repo: Path, *, projected: str = "") -> None:
    (repo / "governance").mkdir(parents=True)
    (repo / "governance/gate-contracts.yml").write_text(
        "interpreter_contract: {project_dependencies: true, "
        "build_system_requirements: true, requirements_projection: "
        "requirements-governance.txt, optional_dependency_groups: [dev], "
        "gate_requirements: {test: [pip==26.2.1]}}\n"
        "gates: {test: {}}\n",
        encoding="utf-8",
    )
    runtime_contract = {
        "schema_version": "1.1",
        "runtime_root": ".artifacts/runtime",
        "minimum_free_bytes": 1,
        "maximum_owned_containers": 1,
        "database": {
            "storage": "repository_bind_mount",
            "relative_path": ".artifacts/runtime/database",
        },
        "cleanup": {
            "caller_globs": False,
            "daemon_global_prune": False,
            "exact_owner_revalidation": True,
            "remove_anonymous_volumes": True,
        },
        "execution_state": EXECUTION_STATE_POLICY,
    }
    (repo / "governance/ci-runtime.yml").write_text(
        yaml.safe_dump(runtime_contract, sort_keys=False), encoding="utf-8"
    )
    (repo / "pyproject.toml").write_text(
        "[build-system]\nrequires=['setuptools>=69', 'wheel']\n"
        "build-backend='setuptools.build_meta'\n"
        "[project]\nname='fixture'\nversion='1.0.0'\n"
        "requires-python='>=3.11'\ndependencies=['PyYAML>=6,<7']\n"
        "[project.optional-dependencies]\ndev=['pytest==9.0.3']\n",
        encoding="utf-8",
    )
    (repo / "requirements-governance.txt").write_text(projected, encoding="utf-8")


def _legacy_fixture(repo: Path, *, profile_version: str = "1.0") -> None:
    (repo / "governance").mkdir(parents=True)
    (repo / "governance/gate-contracts.yml").write_text(
        f"profile_contract_version: '{profile_version}'\n"
        "gates: {governance-validate: {}}\n",
        encoding="utf-8",
    )
    (repo / "governance/ci-graph.yml").write_text(
        f"profile_contract_version: '{profile_version}'\n"
        "resource_classes:\n"
        "  candidate-python: {python_version: '3.12'}\n"
        "  trusted-control: {python_version: '3.12'}\n",
        encoding="utf-8",
    )
    (repo / "requirements-governance.txt").write_text(
        "PyYAML>=6,<7\npytest==9.0.3\n", encoding="utf-8"
    )
    runtime_contract = {
        "schema_version": "1.1",
        "runtime_root": ".artifacts/runtime",
        "minimum_free_bytes": 1,
        "maximum_owned_containers": 1,
        "database": {
            "storage": "repository_bind_mount",
            "relative_path": ".artifacts/runtime/database",
        },
        "cleanup": {
            "caller_globs": False,
            "daemon_global_prune": False,
            "exact_owner_revalidation": True,
            "remove_anonymous_volumes": True,
        },
        "execution_state": EXECUTION_STATE_POLICY,
    }
    (repo / "governance/ci-runtime.yml").write_text(
        yaml.safe_dump(runtime_contract, sort_keys=False), encoding="utf-8"
    )


def test_profile_v1_derives_isolated_environment_from_authenticated_legacy_inputs(
    tmp_path: Path,
) -> None:
    _legacy_fixture(tmp_path)

    plan = derive_interpreter_environment(tmp_path)

    assert plan is not None
    assert plan.source_kind == "legacy_governance_requirements"
    assert plan.requirements == (
        "PyYAML>=6,<7",
        "pytest==9.0.3",
        "pip==26.2.1",
    )
    assert plan.requires_python == "==3.12.*"
    assert plan.projection_path is None
    assert plan.installation_path == tmp_path / "requirements-governance.txt"
    assert plan.pip_arguments() == (
        "PyYAML>=6,<7",
        "pytest==9.0.3",
        "pip==26.2.1",
    )
    verify_interpreter_environment_projection(plan)


def test_legacy_environment_rejects_changed_dependency_source(tmp_path: Path) -> None:
    _legacy_fixture(tmp_path)
    plan = derive_interpreter_environment(tmp_path)
    assert plan is not None
    (tmp_path / "requirements-governance.txt").write_text(
        "PyYAML>=6,<7\npytest==9.1.1\n", encoding="utf-8"
    )

    with pytest.raises(InterpreterEnvironmentError, match="changed after derivation"):
        verify_interpreter_environment_projection(plan)


def test_missing_profile_v2_interpreter_contract_remains_fail_closed(
    tmp_path: Path,
) -> None:
    _legacy_fixture(tmp_path, profile_version="2.0")

    assert derive_interpreter_environment(tmp_path) is None
    with pytest.raises(
        InterpreterEnvironmentError,
        match="cannot be derived without an authenticated dependency source",
    ):
        materialize_interpreter_environment(tmp_path, Path(sys.executable))


def test_legacy_environment_rejects_ambiguous_graph_python_runtime(
    tmp_path: Path,
) -> None:
    _legacy_fixture(tmp_path)
    graph = tmp_path / "governance/ci-graph.yml"
    graph.write_text(
        graph.read_text(encoding="utf-8").replace(
            "trusted-control: {python_version: '3.12'}",
            "trusted-control: {python_version: '3.13'}",
        ),
        encoding="utf-8",
    )

    with pytest.raises(InterpreterEnvironmentError, match="one Python minor"):
        derive_interpreter_environment(tmp_path)


def test_legacy_environment_materialization_installs_only_derived_requirements(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    _legacy_fixture(tmp_path)
    commands: list[list[str]] = []

    def run(argv: list[str], **_: object) -> subprocess.CompletedProcess[str]:
        commands.append(argv)
        if argv[1:3] == ["-m", "venv"]:
            environment = Path(argv[-1])
            (environment / "bin").mkdir(parents=True)
            (environment / "bin/python").symlink_to(sys.executable)
            (environment / "pyvenv.cfg").write_text("home = exact\n", encoding="utf-8")
        stdout = (
            "pip==26.2.1\npytest==9.0.3\nPyYAML==6.0.3\n"
            if argv[-2:] == ["freeze", "--all"]
            else ""
        )
        return subprocess.CompletedProcess(argv, 0, stdout, "")

    monkeypatch.setattr(subprocess, "run", run)

    python = materialize_interpreter_environment(tmp_path, Path(sys.executable))

    assert python.is_file()
    assert commands[1][5:] == [
        "install",
        "--disable-pip-version-check",
        "PyYAML>=6,<7",
        "pytest==9.0.3",
        "pip==26.2.1",
    ]
    assert "requirements-governance.txt" not in commands[1]


def test_repository_bootstrap_requirements_are_a_mechanical_projection() -> None:
    plan = derive_interpreter_environment(REPO_ROOT)

    assert plan is not None
    verify_interpreter_environment_projection(plan)
    assert plan.projection_path == REPO_ROOT / "requirements-governance.txt"
    assert plan.distribution_names == {
        "build",
        "jsonschema",
        "packaging",
        "pip",
        "pip-audit",
        "pytest",
        "pyyaml",
        "setuptools",
        "urllib3",
        "wheel",
    }


def test_runtime_imports_must_be_declared_before_evidence(tmp_path: Path) -> None:
    _fixture(tmp_path)
    tooling = tmp_path / "bcf_governance/tooling"
    tooling.mkdir(parents=True)
    (tooling / "owner.py").write_text("import yaml\n", encoding="utf-8")
    validate_runtime_import_dependencies(tmp_path)

    (tooling / "owner.py").write_text("import referencing\n", encoding="utf-8")
    with pytest.raises(
        InterpreterEnvironmentError,
        match="runtime imports undeclared package dependencies: referencing",
    ):
        validate_runtime_import_dependencies(tmp_path)


def test_environment_cli_checks_the_governed_projection(capsys: pytest.CaptureFixture[str]) -> None:
    main(["check", "--repo-root", str(REPO_ROOT)])

    assert capsys.readouterr().out.strip() == str(
        REPO_ROOT / "requirements-governance.txt"
    )


def test_stale_bootstrap_requirements_fail_before_environment_probe(
    tmp_path: Path,
) -> None:
    _fixture(tmp_path, projected="PyYAML>=6,<7\n")
    plan = derive_interpreter_environment(tmp_path)

    assert plan is not None
    with pytest.raises(InterpreterEnvironmentError, match="projection drift"):
        verify_interpreter_environment_projection(plan)


def test_apply_materializes_the_exact_derived_dependency_plan(tmp_path: Path) -> None:
    _fixture(tmp_path)
    plan = derive_interpreter_environment(tmp_path)

    assert plan is not None
    path = apply_interpreter_environment_projection(plan)
    assert path.read_text(encoding="utf-8") == (
        "pip==26.2.1\n"
        "pytest==9.0.3\n"
        "PyYAML>=6,<7\n"
        "setuptools>=69\n"
        "wheel\n"
    )
    verify_interpreter_environment_projection(plan)


def test_fixed_point_reconcile_owns_environment_projection(tmp_path: Path) -> None:
    _fixture(tmp_path, projected="stale\n")

    with pytest.raises(InterpreterEnvironmentError, match="projection drift"):
        reconcile_interpreter_environment(tmp_path, apply=False)
    path = reconcile_interpreter_environment(tmp_path, apply=True)

    assert path == tmp_path / "requirements-governance.txt"
    reconcile_interpreter_environment(tmp_path, apply=False)


def test_gate_requirement_pin_is_compiled_by_the_same_requirement_primitive(
    tmp_path: Path,
) -> None:
    _fixture(tmp_path)

    plan = derive_interpreter_environment(tmp_path)

    assert plan is not None
    assert "pip==26.2.1" in plan.requirements


def test_exact_installer_is_added_when_the_project_declares_no_pip(
    tmp_path: Path,
) -> None:
    _fixture(tmp_path)
    gate_contract = tmp_path / "governance/gate-contracts.yml"
    gate_contract.write_text(
        gate_contract.read_text(encoding="utf-8").replace(
            "gate_requirements: {test: [pip==26.2.1]}",
            "gate_requirements: {}",
        ),
        encoding="utf-8",
    )

    plan = derive_interpreter_environment(tmp_path)

    assert plan is not None
    assert "pip==26.2.1" in plan.requirements


def test_different_project_environment_installer_is_rejected(tmp_path: Path) -> None:
    _fixture(tmp_path)
    gate_contract = tmp_path / "governance/gate-contracts.yml"
    gate_contract.write_text(
        gate_contract.read_text(encoding="utf-8").replace(
            "pip==26.2.1", "pip==25.0.1"
        ),
        encoding="utf-8",
    )

    with pytest.raises(
        InterpreterEnvironmentError,
        match="installer requirement must equal pip==26.2.1",
    ):
        derive_interpreter_environment(tmp_path)


@pytest.mark.parametrize("requirement", ["pkg[extra]", "pkg; python_version>'3.11'", "pkg @ https://example.invalid/pkg.whl"])
def test_gate_requirement_rejects_unbounded_alternate_resolution(
    tmp_path: Path, requirement: str
) -> None:
    _fixture(tmp_path)
    gate_contract = tmp_path / "governance/gate-contracts.yml"
    gate_contract.write_text(
        gate_contract.read_text(encoding="utf-8").replace(
            "gate_requirements: {test: [pip==26.2.1]}",
            f"gate_requirements: {{test: [{requirement!r}]}}",
        ),
        encoding="utf-8",
    )

    with pytest.raises(InterpreterEnvironmentError, match="URLs, markers, or extras"):
        derive_interpreter_environment(tmp_path)


def test_normalized_duplicate_dependencies_are_rejected(tmp_path: Path) -> None:
    _fixture(tmp_path)
    pyproject = tmp_path / "pyproject.toml"
    pyproject.write_text(
        pyproject.read_text(encoding="utf-8").replace(
            "dependencies=['PyYAML>=6,<7']",
            "dependencies=['example_name', 'example-name']",
        ),
        encoding="utf-8",
    )

    with pytest.raises(InterpreterEnvironmentError, match="unique names"):
        derive_interpreter_environment(tmp_path)


def test_apply_rejects_a_symlinked_projection(tmp_path: Path) -> None:
    _fixture(tmp_path)
    projection = tmp_path / "requirements-governance.txt"
    projection.unlink()
    projection.symlink_to(tmp_path / "outside.txt")
    plan = derive_interpreter_environment(tmp_path)

    assert plan is not None
    with pytest.raises(InterpreterEnvironmentError, match="unsafe"):
        apply_interpreter_environment_projection(plan)


def test_missing_project_environment_is_materialized_once_from_exact_plan(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    _fixture(tmp_path)
    apply_interpreter_environment_projection(derive_interpreter_environment(tmp_path))  # type: ignore[arg-type]
    commands: list[list[str]] = []

    def run(argv: list[str], **_: object) -> subprocess.CompletedProcess[str]:
        commands.append(argv)
        if argv[1:3] == ["-m", "venv"]:
            environment = Path(argv[-1])
            (environment / "bin").mkdir(parents=True)
            (environment / "bin/python").symlink_to(sys.executable)
            (environment / "pyvenv.cfg").write_text("home = exact\n", encoding="utf-8")
        stdout = "pip==26.2.1\nPyYAML==6.0.3\n" if argv[-2:] == ["freeze", "--all"] else ""
        return subprocess.CompletedProcess(argv, 0, stdout, "")

    monkeypatch.setattr(subprocess, "run", run)

    first = materialize_interpreter_environment(tmp_path, Path(sys.executable))
    second = materialize_interpreter_environment(tmp_path, Path(sys.executable))

    assert first == second
    assert first.is_file()
    assert len(commands) == 4
    assert commands[0][1:4] == ["-m", "venv", "--without-pip"]
    assert commands[1][1:4] == ["-m", "pip", "--python"]
    assert Path(commands[1][4]).parts[-3:] == ("venv", "bin", "python")
    assert commands[1][5] == "install"
    assert commands[2][1:] == ["-m", "pip", "freeze", "--all"]
    assert commands[3][1:] == ["-m", "pip", "freeze", "--all"]
    assert first.is_relative_to(tmp_path / ".artifacts/runtime/execution-state")
    cache_entry = first.parent.parent.parent
    manifest = json.loads(
        (cache_entry / "environment.json").read_text(encoding="utf-8")
    )
    plan = derive_interpreter_environment(tmp_path)
    assert plan is not None
    assert manifest["plan_identity"] == plan.identity(Path(sys.executable))
    assert manifest["identity"] == cache_entry.name


def test_failed_project_environment_materialization_leaves_no_cache(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    _fixture(tmp_path)
    apply_interpreter_environment_projection(derive_interpreter_environment(tmp_path))  # type: ignore[arg-type]

    monkeypatch.setattr(
        subprocess,
        "run",
        lambda argv, **_: subprocess.CompletedProcess(argv, 1, "", "offline"),
    )

    with pytest.raises(InterpreterEnvironmentError, match="creation failed: offline"):
        materialize_interpreter_environment(tmp_path, Path(sys.executable))
    parents = list(
        (tmp_path / ".artifacts/runtime/execution-state").glob(
            "*/project-environments"
        )
    )
    assert len(parents) == 1
    roots = list(parents[0].iterdir())
    assert all(path.name == ".materialize.lock" for path in roots)


def test_cached_project_environment_rejects_changed_inventory(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    _fixture(tmp_path)
    plan = derive_interpreter_environment(tmp_path)
    assert plan is not None
    apply_interpreter_environment_projection(plan)
    freeze_calls = 0

    def run(argv: list[str], **_: object) -> subprocess.CompletedProcess[str]:
        nonlocal freeze_calls
        if argv[1:3] == ["-m", "venv"]:
            environment = Path(argv[-1])
            (environment / "bin").mkdir(parents=True)
            (environment / "bin/python").symlink_to(sys.executable)
            (environment / "pyvenv.cfg").write_text("home = exact\n", encoding="utf-8")
        if argv[-2:] == ["freeze", "--all"]:
            freeze_calls += 1
            value = "PyYAML==6.0.3\n" if freeze_calls == 1 else "PyYAML==6.0.4\n"
            return subprocess.CompletedProcess(argv, 0, value, "")
        return subprocess.CompletedProcess(argv, 0, "", "")

    monkeypatch.setattr(subprocess, "run", run)
    materialize_interpreter_environment(tmp_path, Path(sys.executable))

    with pytest.raises(InterpreterEnvironmentError, match="inventory is stale"):
        materialize_interpreter_environment(tmp_path, Path(sys.executable))


def test_cached_project_environment_rejects_changed_plan_identity(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    _fixture(tmp_path)
    plan = derive_interpreter_environment(tmp_path)
    assert plan is not None
    apply_interpreter_environment_projection(plan)

    def run(argv: list[str], **_: object) -> subprocess.CompletedProcess[str]:
        if argv[1:3] == ["-m", "venv"]:
            environment = Path(argv[-1])
            (environment / "bin").mkdir(parents=True)
            (environment / "bin/python").symlink_to(sys.executable)
            (environment / "pyvenv.cfg").write_text("home = exact\n", encoding="utf-8")
        output = "PyYAML==6.0.3\n" if argv[-2:] == ["freeze", "--all"] else ""
        return subprocess.CompletedProcess(argv, 0, output, "")

    monkeypatch.setattr(subprocess, "run", run)
    python = materialize_interpreter_environment(tmp_path, Path(sys.executable))
    manifest_path = python.parent.parent.parent / "environment.json"
    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    manifest["plan_identity"] = "f" * 64
    manifest_path.write_text(json.dumps(manifest), encoding="utf-8")

    with pytest.raises(InterpreterEnvironmentError, match="identity is stale"):
        materialize_interpreter_environment(tmp_path, Path(sys.executable))


def test_project_environment_requires_canonical_execution_state_contract(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    _fixture(tmp_path)
    plan = derive_interpreter_environment(tmp_path)
    assert plan is not None
    apply_interpreter_environment_projection(plan)
    runtime_path = tmp_path / "governance/ci-runtime.yml"
    runtime = yaml.safe_load(runtime_path.read_text(encoding="utf-8"))
    runtime["execution_state"]["persistent_requires_workload_declaration"] = False
    runtime_path.write_text(yaml.safe_dump(runtime, sort_keys=False), encoding="utf-8")
    called = False

    def run(*_args: object, **_kwargs: object) -> subprocess.CompletedProcess[str]:
        nonlocal called
        called = True
        raise AssertionError("invalid persistence must reject before subprocess")

    monkeypatch.setattr(subprocess, "run", run)

    with pytest.raises(InterpreterEnvironmentError, match="cache contract is invalid"):
        materialize_interpreter_environment(tmp_path, Path(sys.executable))
    assert called is False
