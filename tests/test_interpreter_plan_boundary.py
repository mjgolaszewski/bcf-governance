"""Immutable dependency plans retain their import contract without owning effects."""
from __future__ import annotations

import ast
from pathlib import Path


def test_extracted_plan_preserves_original_type_and_error_imports():
    from bcf_governance.tooling import interpreter_environment as commands
    from bcf_governance.tooling import interpreter_environment_plan as plans

    assert commands.InterpreterEnvironmentPlan is plans.InterpreterEnvironmentPlan
    assert commands.InterpreterEnvironmentError is plans.InterpreterEnvironmentError
    assert commands._normalized_name is plans._normalized_name


def test_immutable_plan_does_not_own_environment_mutations():
    from bcf_governance.tooling import interpreter_environment_plan as plans

    tree = ast.parse(Path(plans.__file__).read_text())
    effects = {"write_text", "write_bytes", "mkdir", "unlink", "replace", "Popen", "run"}
    assert not [node for node in ast.walk(tree)
                if isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute)
                and node.func.attr in effects]
    assert not [node for node in ast.walk(tree)
                if isinstance(node, ast.Import)
                and any(alias.name in {"subprocess", "shutil", "socket"} for alias in node.names)]


def test_plan_keeps_closed_requirements_when_projection_bytes_move(tmp_path):
    from bcf_governance.tooling.interpreter_environment import InterpreterEnvironmentPlan

    projection = tmp_path / "requirements.txt"
    projection.write_text("PyYAML==6.0.3\n")
    plan = InterpreterEnvironmentPlan(("PyYAML==6.0.3",), ">=3.11", projection)
    projection.write_text("foreign-dependency==9\n")
    assert plan.pip_arguments() == ("PyYAML==6.0.3",)
    assert plan.rendered_requirements() == "PyYAML==6.0.3\n"
    assert plan.distribution_names == frozenset({"pyyaml"})
