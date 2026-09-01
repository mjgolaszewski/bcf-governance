from __future__ import annotations

from pathlib import Path

import pytest

from bcf_governance.tooling.interpreter_environment import (
    InterpreterEnvironmentError,
    apply_interpreter_environment_projection,
    derive_interpreter_environment,
    main,
    verify_interpreter_environment_projection,
)


REPO_ROOT = Path(__file__).resolve().parents[1]


def _fixture(repo: Path, *, projected: str = "") -> None:
    (repo / "governance").mkdir(parents=True)
    (repo / "governance/gate-contracts.yml").write_text(
        "interpreter_contract: {project_dependencies: true, "
        "build_system_requirements: true, requirements_projection: "
        "requirements-governance.txt, optional_dependency_groups: [dev], "
        "gate_requirements: {test: [pip]}}\n"
        "gates: {test: {}}\n",
        encoding="utf-8",
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
        "pytest",
        "pyyaml",
        "setuptools",
        "wheel",
    }


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
        "pip\n"
        "pytest==9.0.3\n"
        "PyYAML>=6,<7\n"
        "setuptools>=69\n"
        "wheel\n"
    )
    verify_interpreter_environment_projection(plan)


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
