from __future__ import annotations

import json
from pathlib import Path

from bcf_governance.tooling.truth_reporting import failure_envelope


def _plan() -> dict:
    return {
        "session_id": "session-1",
        "required_claims": ["app-valid"],
        "reused_evidence": [],
        "invalidated_evidence": [{"claim_id": "app-valid", "reasons": ["subject_dependency_changed"]}],
        "execution_dag": {"nodes": [{"id": "app-tests", "claims": ["app-valid"]}], "edges": []},
    }


def test_failure_envelope_groups_roots_and_keeps_raw_result_references(tmp_path: Path) -> None:
    result = failure_envelope(
        tmp_path,
        {"commit_sha": "a" * 40, "tree_sha": "b" * 40},
        _plan(),
        ["evidence_receipt_invalid:test:evidence-1", "required_claim_app-valid_not_declared"],
        [{
            "result": "invalid",
            "evidence_id": "evidence-1",
            "gate_id": "test",
            "artifact_sha256": "c" * 64,
            "issues": ["receipt_schema:broken"],
        }],
    )
    roots = {root["root_cause_id"]: root for root in result["root_causes"]}
    assert set(roots) == {
        "evidence_receipt_invalid:test:evidence-1",
        "required_claim_app-valid_not_declared",
    }
    assert roots["evidence_receipt_invalid:test:evidence-1"]["raw_result_refs"][0]["artifact_sha256"] == "c" * 64
    assert result["required_next_action"]["nodes"][0]["id"] == "app-tests"


def test_identical_causal_result_reports_no_new_information(tmp_path: Path) -> None:
    current = {"commit_sha": "a" * 40, "tree_sha": "b" * 40}
    first = failure_envelope(tmp_path, current, _plan(), ["phase_effective_state_active"])
    (tmp_path / "prior-truth-report.json").write_text(
        json.dumps({"failure_envelope": first}), encoding="utf-8"
    )
    second = failure_envelope(tmp_path, current, _plan(), ["phase_effective_state_active"])
    assert second["no_new_information"] is True


def test_advisory_metrics_cannot_change_causal_identity(tmp_path: Path) -> None:
    current = {"commit_sha": "a" * 40, "tree_sha": "b" * 40}
    left = _plan()
    right = _plan()
    left["advisory_metrics"] = {"estimated_cost": 1}
    right["advisory_metrics"] = {"estimated_cost": 999999}
    first = failure_envelope(tmp_path, current, left, ["phase_effective_state_active"])
    second = failure_envelope(tmp_path, current, right, ["phase_effective_state_active"])
    assert first["causal_result_fingerprint"] == second["causal_result_fingerprint"]


def test_independent_receipts_with_same_diagnostic_class_remain_distinct(tmp_path: Path) -> None:
    result = failure_envelope(
        tmp_path,
        {"commit_sha": "a" * 40, "tree_sha": "b" * 40},
        _plan(),
        [
            "evidence_receipt_invalid:test:evidence-1",
            "evidence_receipt_invalid:test:evidence-2",
        ],
        [
            {"result": "invalid", "evidence_id": evidence_id, "gate_id": "test",
             "artifact_sha256": character * 64, "issues": ["same diagnostic"]}
            for evidence_id, character in (("evidence-1", "c"), ("evidence-2", "d"))
        ],
    )
    assert [root["root_cause_id"] for root in result["root_causes"]] == [
        "evidence_receipt_invalid:test:evidence-1",
        "evidence_receipt_invalid:test:evidence-2",
    ]
    assert len(result["raw_failures"]) == 2


def test_invalidated_selection_changes_no_new_information_fingerprint(tmp_path: Path) -> None:
    current = {"commit_sha": "a" * 40, "tree_sha": "b" * 40}
    first = failure_envelope(tmp_path, current, _plan(), ["phase_effective_state_active"])
    changed = _plan()
    changed["invalidated_evidence"] = [{"claim_id": "other", "reasons": ["freshness_expired"]}]
    second = failure_envelope(tmp_path, current, changed, ["phase_effective_state_active"])
    assert first["causal_result_fingerprint"] != second["causal_result_fingerprint"]
