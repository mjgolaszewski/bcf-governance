from __future__ import annotations

from pathlib import Path
import sys

import pytest

from bcf_governance.cli import COMMANDS
from bcf_governance.tooling.scaffold_governance_artifacts import (
    ReconcileError,
    ReconcileStep,
    converge,
    reconcile_steps,
)


def test_reconcile_is_the_canonical_cli_surface() -> None:
    assert "reconcile" in COMMANDS


def test_reconcile_declares_one_closed_dependency_order() -> None:
    root = Path(__file__).resolve().parents[1]
    ids = [step.step_id for step in reconcile_steps(root, Path(sys.executable))]
    assert ids[:3] == ["structural-limits", "pack-projection", "semantic-lock"]
    assert ids.index("ci-graph-lock") < ids.index("ci-graph-render")
    assert ids[-1] == "editorial-audit"


def test_reconcile_runs_declared_order_to_a_fixed_point(tmp_path: Path) -> None:
    state = tmp_path / "state"
    calls: list[str] = []

    def first() -> None:
        calls.append("first")
        if not state.exists():
            state.write_text("stable", encoding="utf-8")

    def second() -> None:
        calls.append("second")

    checks: list[str] = []
    steps = (
        ReconcileStep("first", lambda: checks.append("first"), first),
        ReconcileStep("second", lambda: checks.append("second"), second),
    )
    rounds = converge(
        steps,
        lambda: state.read_text(encoding="utf-8") if state.exists() else "absent",
    )
    assert rounds == 2
    assert calls == ["first", "second", "first", "second"]
    assert checks == ["first", "second"]


def test_reconcile_rejects_non_convergence(tmp_path: Path) -> None:
    state = tmp_path / "state"

    def oscillate() -> None:
        current = state.read_text(encoding="utf-8") if state.exists() else "a"
        state.write_text("b" if current == "a" else "a", encoding="utf-8")

    with pytest.raises(ReconcileError, match="did not converge after 3 rounds"):
        converge(
            (ReconcileStep("oscillating-owner", lambda: None, oscillate),),
            lambda: state.read_text(encoding="utf-8") if state.exists() else "absent",
            max_rounds=3,
        )
