from __future__ import annotations

from pathlib import Path

import pytest

from bcf_governance.tooling.evidence_scheduling import (
    compile_test_splinter_plan,
    validate_test_splinter_plan,
    validate_test_splinter_results,
)
from bcf_governance.tooling.runtime_capacity import (
    EXECUTION_STATE_POLICY,
    allocate_child_execution_state,
    allocate_execution_state,
    retire_execution_state,
)


IDENTITY = {
    "subject_commit": "a" * 40,
    "subject_tree": "b" * 40,
    "session": "session-1",
    "policy_sha256": "c" * 64,
    "producer": "test",
}


def _nodes() -> dict[str, str]:
    return {
        "tests.one::test_a": "tests/one.py::test_a",
        "tests.one::test_b": "tests/one.py::test_b",
        "tests.two::test_c": "tests/two.py::test_c",
        "tests.two::test_d": "tests/two.py::test_d",
    }


def test_splinter_plan_is_stable_exact_and_duration_aware() -> None:
    durations = {
        "tests.one::test_a": 40,
        "tests.one::test_b": 30,
        "tests.two::test_c": 20,
        "tests.two::test_d": 10,
    }
    first = compile_test_splinter_plan(
        _nodes(), durations, max_splinters=2, identity=IDENTITY
    )
    second = compile_test_splinter_plan(
        dict(reversed(list(_nodes().items()))),
        dict(reversed(list(durations.items()))),
        max_splinters=2,
        identity=IDENTITY,
    )
    assert first == second
    assert first["duration_source"] == "exact_observations"
    assert [item["estimated_duration_ms"] for item in first["splinters"]] == [50, 50]
    validate_test_splinter_plan(first)
    validate_test_splinter_results(
        first, {item["id"]: item["nodes"] for item in first["splinters"]}
    )


def test_bad_metrics_and_incompatible_resources_fall_back_monolithically() -> None:
    partial = compile_test_splinter_plan(
        _nodes(),
        {"tests.one::test_a": 1},
        max_splinters=4,
        identity=IDENTITY,
    )
    assert partial["duration_source"] == "partial_observations"
    assert partial["fallback_reason"] is None
    assert len(partial["splinters"]) == 4
    validate_test_splinter_plan(partial)
    invalid = compile_test_splinter_plan(
        _nodes(),
        {"tests.unknown::test_nope": 1},
        max_splinters=4,
        identity=IDENTITY,
    )
    assert invalid["fallback_reason"] == "duration_observations_invalid"
    assert len(invalid["splinters"]) == 1
    incompatible = compile_test_splinter_plan(
        _nodes(), {}, max_splinters=4, identity=IDENTITY, resources_compatible=False
    )
    assert incompatible["fallback_reason"] == "resources_incompatible"
    assert len(incompatible["splinters"]) == 1


@pytest.mark.parametrize("defect", ["overlap", "missing", "extra", "digest"])
def test_splinter_validation_rejects_incomplete_or_mutated_closure(defect: str) -> None:
    plan = compile_test_splinter_plan(
        _nodes(), {}, max_splinters=2, identity=IDENTITY
    )
    observed = {item["id"]: list(item["nodes"]) for item in plan["splinters"]}
    if defect == "overlap":
        observed["splinter-1"].append(observed["splinter-0"][0])
    elif defect == "missing":
        observed["splinter-0"].pop()
    elif defect == "extra":
        observed["splinter-0"].append("tests.extra::test_nope")
    else:
        plan["partition_sha256"] = "0" * 64
        with pytest.raises(ValueError, match="digest"):
            validate_test_splinter_plan(plan)
        return
    with pytest.raises(ValueError, match="overlap|exact node inventory"):
        validate_test_splinter_results(plan, observed)


def test_splinters_receive_unique_owned_state_and_retire_exactly(tmp_path: Path) -> None:
    contract = {
        "execution_state": EXECUTION_STATE_POLICY,
        "runtime_root": ".artifacts/runtime",
        "database": {"storage": "repository_bind_mount"},
    }
    parent = allocate_execution_state(
        tmp_path,
        contract,
        session_id="session-1",
        workload_id="test",
        execution_id="positive",
        invocation={},
    )
    first = allocate_child_execution_state(
        parent.environment(), execution_id="test:splinter-0"
    )
    second = allocate_child_execution_state(
        parent.environment(), execution_id="test:splinter-1"
    )
    assert first is not None and second is not None
    assert first.namespace != second.namespace != parent.namespace
    assert retire_execution_state(first)["removal_verified"] is True
    assert second.root.is_dir()
    assert retire_execution_state(second)["removal_verified"] is True
    assert retire_execution_state(parent)["removal_verified"] is True


def test_self_test_splinters_use_distinct_worktrees_and_locked_toolchains() -> None:
    source = (
        Path(__file__).resolve().parents[1]
        / ".github/scripts/run_self_governance_gate.py"
    ).read_text(encoding="utf-8")
    assert '"worktree", "add", "--quiet",' in source
    assert 'cwd=worktree,' in source
    assert 'Path(temporary.name) / f"pytest-{splinter_id}"' in source
    assert '".github/scripts/bootstrap_test_toolchain.py"' in source
    assert '"worktree", "remove", "--force",' in source
