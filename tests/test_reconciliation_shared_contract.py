"""Characterize the existing reconciliation value before sharing its definition."""
from __future__ import annotations

import ast
from dataclasses import FrozenInstanceError
from pathlib import Path

import pytest

from test_managed_runtime_quality import _portable_ast_sha256


ROOT = Path(__file__).resolve().parents[1]


def test_reconcile_step_class_remains_exact_and_compatibly_bound() -> None:
    from bcf_governance.tooling.reconcile_contracts import ReconcileStep
    from bcf_governance.tooling.scaffold_governance_artifacts import ReconcileStep as LegacyStep

    assert ReconcileStep is LegacyStep
    tree = ast.parse((ROOT / "bcf_governance/tooling/reconcile_contracts.py").read_text())
    node = next(n for n in tree.body if isinstance(n, ast.ClassDef) and n.name == "ReconcileStep")
    assert _portable_ast_sha256(node) == "37224ba309011d4ba6179c9e4fb12f56bf737020ca0a67d46428b568c384139e"
    calls = []

    def check() -> object:
        calls.append("check")
        return {"drift": True}

    def apply() -> object:
        calls.append("apply")
        return 7

    step = LegacyStep("projection", check, apply)
    assert step.apply_verifies is False and step.watch_paths is None
    assert step.check() == {"drift": True}
    assert step.apply() == 7 and calls == ["check", "apply"]
    with pytest.raises(FrozenInstanceError):
        setattr(step, "step_id", "changed")


def test_managed_runtime_retains_python_311_source_compatibility() -> None:
    root = ROOT / "bcf_governance/tooling"
    for path in sorted(root.rglob("*.py")):
        ast.parse(path.read_text(), filename=str(path), feature_version=(3, 11))
    with pytest.raises(SyntaxError):
        ast.parse("def newer[T](value: T) -> T:\n    return value\n", feature_version=(3, 11))
