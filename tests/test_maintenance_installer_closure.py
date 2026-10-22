"""Release-based controls for compatible secure installer declarations."""

from pathlib import Path

import pytest

from bcf_governance.tooling.interpreter_environment import (
    InterpreterEnvironmentError,
    derive_interpreter_environment,
    materialize_interpreter_environment,
    verify_interpreter_environment_projection,
)


def _source(root: Path, mode: str, declaration: str | None) -> None:
    (root / "governance").mkdir()
    contract = {
        "legacy": "profile_contract_version: '1.0'\n",
        "governed": "interpreter_contract: {dependency_source: requirements-governance.txt}\n",
        "project": (
            "interpreter_contract: {project_dependencies: true, "
            "optional_dependency_groups: [], gate_requirements: {}}\n"
        ),
    }[mode]
    (root / "governance/gate-contracts.yml").write_text(contract + "gates: {}\n")
    (root / "governance/ci-graph.yml").write_text(
        "resource_classes: {candidate: {python_version: '3.12'}}\n"
    )
    requirements = ["PyYAML>=6,<7", *([declaration] if declaration else [])]
    (root / "requirements-governance.txt").write_text("\n".join(requirements) + "\n")
    (root / "pyproject.toml").write_text(
        "[project]\nname='fixture'\nversion='1.0'\nrequires-python='>=3.12'\n"
        f"dependencies={requirements!r}\n"
    )


@pytest.mark.parametrize("mode", ["legacy", "governed", "project"])
@pytest.mark.parametrize("declaration", [None, "pip>=26.2.2,<27", "pip==26.2.2"])
def test_secure_compatible_installer_closes_to_exact_pin(
    tmp_path: Path, mode: str, declaration: str | None,
) -> None:
    _source(tmp_path, mode, declaration)
    plan = derive_interpreter_environment(tmp_path)
    assert plan is not None
    assert "pip==26.2.2" in plan.requirements
    assert sum(item.lower().startswith("pip") for item in plan.requirements) == 1
    verify_interpreter_environment_projection(plan)


@pytest.mark.parametrize("mode", ["legacy", "governed", "project"])
@pytest.mark.parametrize("declaration", ["pip==26.2.1", "pip<26.2.2"])
def test_incompatible_installer_blocks_before_materialization(
    tmp_path: Path, mode: str, declaration: str,
) -> None:
    _source(tmp_path, mode, declaration)
    with pytest.raises(InterpreterEnvironmentError, match="installer.*incompatible"):
        derive_interpreter_environment(tmp_path)


@pytest.mark.parametrize("mode", ["legacy", "governed", "project"])
def test_authored_compatible_constraint_changes_environment_identity(
    tmp_path: Path, mode: str,
) -> None:
    _source(tmp_path, mode, "pip>=26.2.2,<27")
    first = derive_interpreter_environment(tmp_path)
    assert first is not None
    source = tmp_path / ("pyproject.toml" if mode == "project" else "requirements-governance.txt")
    source.write_text(source.read_text().replace("pip>=26.2.2,<27", "pip>=26.2.2,<26.3"))
    second = derive_interpreter_environment(tmp_path)
    assert second is not None
    assert first.requirements == second.requirements
    assert first.source_sha256 != second.source_sha256


@pytest.mark.parametrize("mode", ["legacy", "governed", "project"])
@pytest.mark.parametrize("declaration", [
    "pip @ https://example.invalid/pip.whl", "pip[unsafe]>=26.2.2",
    "pip>=26.2.2; python_version < '3.0'", "pip!=26.2.2", "pip>=27",
])
def test_unsafe_or_excluding_installer_stays_rejected(
    tmp_path: Path, mode: str, declaration: str,
) -> None:
    _source(tmp_path, mode, declaration)
    with pytest.raises(InterpreterEnvironmentError):
        derive_interpreter_environment(tmp_path)


def test_project_source_change_is_rejected_after_derivation(tmp_path: Path) -> None:
    _source(tmp_path, "project", "pip>=26.2.2,<27")
    plan = derive_interpreter_environment(tmp_path)
    assert plan is not None
    path = tmp_path / "pyproject.toml"
    path.write_text(path.read_text() + "\n# authored change\n")
    with pytest.raises(InterpreterEnvironmentError, match="changed after derivation"):
        verify_interpreter_environment_projection(plan)


def test_project_registry_change_is_rejected_after_derivation(tmp_path: Path) -> None:
    _source(tmp_path, "project", "pip>=26.2.2,<27")
    plan = derive_interpreter_environment(tmp_path)
    assert plan is not None
    path = tmp_path / "governance/gate-contracts.yml"
    path.write_text(path.read_text() + "\n# authored change\n")
    with pytest.raises(InterpreterEnvironmentError, match="changed after derivation"):
        verify_interpreter_environment_projection(plan)


def test_metadata_identity_is_not_an_installation_input(tmp_path: Path) -> None:
    _source(tmp_path, "project", "pip>=26.2.2,<27")
    plan = derive_interpreter_environment(tmp_path)
    assert plan is not None
    assert plan.source_path == tmp_path / "pyproject.toml"
    assert plan.source_sha256 is not None
    verify_interpreter_environment_projection(plan)
    assert plan.installation_path is None
    assert not (tmp_path / ".artifacts").exists()


def test_missing_projection_blocks_before_selection_or_allocation(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
) -> None:
    from bcf_governance.tooling import interpreter_environment as owner

    _source(tmp_path, "project", "pip>=26.2.2,<27")

    def forbidden(*args: object, **kwargs: object) -> None:
        pytest.fail("missing installation input reached selection/allocation/subprocess")

    for name in ("select_materialization_base", "allocate_execution_state", "_matching_cached_environment"):
        monkeypatch.setattr(owner, name, forbidden)
    monkeypatch.setattr(owner.subprocess, "run", forbidden)
    with pytest.raises(InterpreterEnvironmentError, match="authenticated dependency source"):
        materialize_interpreter_environment(tmp_path, Path("/unselected/python"))
    assert not (tmp_path / ".artifacts").exists()


@pytest.mark.parametrize("mode", ["legacy", "governed"])
def test_requirement_source_remains_a_valid_installation_input(
    tmp_path: Path, mode: str,
) -> None:
    _source(tmp_path, mode, "pip>=26.2.2,<27")
    plan = derive_interpreter_environment(tmp_path)
    assert plan is not None
    verify_interpreter_environment_projection(plan)
    assert plan.installation_path == tmp_path / "requirements-governance.txt"
    assert plan.pip_arguments() == plan.requirements
    assert not (tmp_path / ".artifacts").exists()
