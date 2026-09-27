from __future__ import annotations

from pathlib import Path
import sys

import pytest
import yaml

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
    assert ids[:4] == [
        "structural-limits",
        "ci-graph-post-merge-scope",
        "pack-projection",
        "semantic-lock",
    ]
    assert ids.index("ci-graph-lock") < ids.index("ci-graph-render")
    assert ids[-1] == "editorial-audit"


def test_reconcile_omits_semantic_lock_for_closed_disabled_capabilities(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path,
) -> None:
    (tmp_path / "governance-profile.yml").write_text(
        yaml.safe_dump(
            {
                "semantic_capabilities": {
                    "semantic_family_completeness": "disabled",
                    "application_operation_inventory": "disabled",
                    "representation_provenance": "disabled",
                }
            }
        ),
        encoding="utf-8",
    )
    governance = tmp_path / "governance"
    governance.mkdir()
    (governance / "canonical-representations.yml").write_text("representations: []\n", encoding="utf-8")
    monkeypatch.setattr(
        "bcf_governance.tooling.scaffold_governance_artifacts.declared_test_gates",
        lambda _root: (),
    )

    ids = [step.step_id for step in reconcile_steps(tmp_path, Path(sys.executable))]

    assert "semantic-lock" not in ids


def test_reconcile_rejects_disabled_capabilities_with_partial_semantic_runtime(
    tmp_path: Path,
) -> None:
    (tmp_path / "governance-profile.yml").write_text(
        "semantic_capabilities: {}\n", encoding="utf-8"
    )
    governance = tmp_path / "governance"
    governance.mkdir()
    (governance / "semantic-families.yml").write_text("families: []\n", encoding="utf-8")

    with pytest.raises(ReconcileError, match="without an enabled semantic capability"):
        reconcile_steps(tmp_path, Path(sys.executable))


def test_reconcile_separates_tool_runtime_from_selected_project_python(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path,
) -> None:
    (tmp_path / "governance-profile.yml").write_text(
        "semantic_capabilities: {}\n", encoding="utf-8"
    )
    selected = tmp_path / "venv/bin/python"
    selected.parent.mkdir(parents=True)
    selected.symlink_to(sys.executable)
    observed: list[list[str]] = []
    monkeypatch.setattr(
        "bcf_governance.tooling.scaffold_governance_artifacts._run_reconcile_command",
        lambda command, **_kwargs: observed.append(command),
    )
    monkeypatch.setattr(
        "bcf_governance.tooling.scaffold_governance_artifacts.declared_test_gates",
        lambda _root: ("test",),
    )

    steps = reconcile_steps(tmp_path, selected)
    graph_lock = next(step for step in steps if step.step_id == "ci-graph-lock")
    graph_lock.check()
    manifest = next(step for step in steps if step.step_id == "test-manifests")
    manifest.check()

    assert observed[0][0] == str(Path(sys.executable).absolute())
    assert observed[0][0] != str(selected.absolute())
    assert observed[1][0] == str(Path(sys.executable).absolute())
    assert "--all" in observed[1]
    assert observed[1][observed[1].index("--python") + 1] == str(selected.absolute())


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


def test_reconcile_does_not_repeat_checks_already_proven_by_apply(
    tmp_path: Path,
) -> None:
    checks: list[str] = []
    applications: list[str] = []
    steps = (
        ReconcileStep(
            "self-verifying",
            lambda: checks.append("self-verifying"),
            lambda: applications.append("self-verifying"),
            apply_verifies=True,
        ),
        ReconcileStep(
            "independent-check",
            lambda: checks.append("independent-check"),
            lambda: applications.append("independent-check"),
        ),
    )

    rounds = converge(steps, lambda: "stable")

    assert rounds == 1
    assert applications == ["self-verifying", "independent-check"]
    assert checks == ["independent-check"]


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
