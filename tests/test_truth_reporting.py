from __future__ import annotations

import json
import hashlib
from pathlib import Path

import pytest

from bcf_governance.tooling.truth_reporting import (
    exact_session_binding,
    eligible_claim_receipts,
    eligible_receipts,
    failure_envelope,
)


def test_reuse_truth_binds_exact_consumed_session_bytes(tmp_path: Path) -> None:
    subject = {"commit_sha": "a" * 40, "tree_sha": "b" * 40}
    plan = {"session_id": "c" * 32, "subject": subject, "reused_evidence": []}
    encoded = (json.dumps(plan, sort_keys=True) + "\n").encode()
    for name in ("first", "same-copy"):
        directory = tmp_path / name
        directory.mkdir()
        (directory / "evidence-session.json").write_bytes(encoded)
    assert exact_session_binding(tmp_path, subject, plan) == {
        "session_id": "c" * 32,
        "manifest_sha256": hashlib.sha256(encoded).hexdigest(),
    }
    (tmp_path / "same-copy/evidence-session.json").write_bytes(
        json.dumps(plan, indent=2).encode()
    )
    with pytest.raises(ValueError, match="ambiguous evidence-session bytes"):
        exact_session_binding(tmp_path, subject, plan)


def _plan() -> dict:
    return {
        "session_id": "session-1",
        "required_claims": ["app-valid"],
        "reused_evidence": [],
        "invalidated_evidence": [{"claim_id": "app-valid", "reasons": ["subject_dependency_changed"]}],
        "execution_dag": {"nodes": [{"id": "app-tests", "claims": ["app-valid"]}], "edges": []},
    }


def test_eligible_receipts_are_version_aware_and_preflight_is_optional() -> None:
    model = {
        "claims": {
            "contract-claim": {
                "legacy_gate": "contract-test",
                "execution_group": "python-tests",
            },
        },
        "execution_groups": {
            "python-tests": {"producer": "test", "claims": ["contract-claim"]}
        },
    }
    grouped = {
        "test": [
            {
                "gate_id": "test",
                "result": "verified",
                "receipt": {
                    "schema_version": "3.0",
                    "claims": ["contract-claim"],
                },
            }
        ]
    }
    assert list(eligible_receipts(grouped, model, "contract-test", set())) == grouped["test"]
    grouped["test"][0]["receipt"].pop("claims")
    assert list(eligible_receipts(grouped, model, "contract-test", set())) == []

    legacy = {
        "contract-test": [
            {
                "gate_id": "contract-test",
                "result": "verified",
                "receipt": {
                    "schema_version": "2.0",
                    "subject": {"binding": "exact_tree"},
                },
            }
        ]
    }
    assert list(eligible_receipts(legacy, model, "contract-test", set())) == legacy["contract-test"]
    assert list(
        eligible_receipts({}, model, "contract-test", {"contract-claim"})
    )[0]["source"] == "evidence-session-v2"
    assert list(
        eligible_receipts(
            {}, model, "contract-test", {"contract-claim"}, include_preflight=False
        )
    ) == []


def test_provisional_reuse_resolves_only_its_exact_claim() -> None:
    model = {
        "claims": {
            "contract-claim": {
                "legacy_gate": "contract-test", "execution_group": "python-tests",
            },
            "other-claim": {
                "legacy_gate": "other-test", "execution_group": "other-tests",
            },
        },
        "execution_groups": {
            "python-tests": {"producer": "test", "claims": ["contract-claim"]},
            "other-tests": {"producer": "other-test", "claims": ["other-claim"]},
        },
    }
    attestation = {
        "claim": {
            "claim_id": "contract-claim", "execution_group_id": "python-tests",
        },
        "source_receipt": {"evidence_id": "source-1"},
        "attestation_id": "a" * 64,
        "decision": "reuse_admitted",
    }
    attestations = {"contract-claim": attestation}
    selected = list(eligible_receipts(
        {}, model, "contract-test", set(), reuse_attestations=attestations,
    ))
    assert len(selected) == 1
    assert selected[0]["source"] == "provisional_reuse_v1"
    assert selected[0]["claim_id"] == "contract-claim"
    assert list(eligible_receipts(
        {}, model, "other-test", set(), reuse_attestations=attestations,
    )) == []
    attestation["claim"]["execution_group_id"] = "other-tests"
    assert list(eligible_receipts(
        {}, model, "contract-test", set(), reuse_attestations=attestations,
    )) == []


def test_grouped_claim_resolver_rejects_unrelated_producer_laundering() -> None:
    model = {
        "claims": {
            "test-claim": {"legacy_gate": "test", "execution_group": "tests"},
            "security-claim": {
                "legacy_gate": "security-review",
                "execution_group": "security",
            },
        },
        "execution_groups": {
            "tests": {"producer": "test", "claims": ["test-claim"]},
            "security": {
                "producer": "security-review",
                "claims": ["security-claim"],
            },
        },
    }
    receipt = {
        "gate_id": "test",
        "result": "verified",
        "receipt": {"schema_version": "3.0", "claims": ["security-claim"]},
    }

    assert list(
        eligible_claim_receipts(
            {"test": [receipt]}, model, "security-claim", set()
        )
    ) == []


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


def test_failure_envelope_removes_successfully_resolved_grouped_claims(
    tmp_path: Path,
) -> None:
    plan = _plan()
    plan["required_claims"].append("security-valid")
    plan["invalidated_evidence"].append(
        {"claim_id": "security-valid", "reasons": ["dependency_closure_ambiguous"]}
    )
    plan["execution_dag"] = {
        "nodes": [
            {"id": "grouped", "claims": ["app-valid", "security-valid"]}
        ],
        "edges": [],
    }

    result = failure_envelope(
        tmp_path,
        {"commit_sha": "a" * 40, "tree_sha": "b" * 40},
        plan,
        ["phase_effective_state_active"],
        resolved_claims={"app-valid", "security-valid"},
    )

    assert result["required_next_action"] == {"nodes": [], "edges": []}
    assert result["invalidated_evidence"] == []


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
