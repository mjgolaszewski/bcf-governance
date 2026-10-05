from __future__ import annotations

import json
import hashlib
from pathlib import Path

import pytest
import yaml

from bcf_governance.tooling.evidence_session_schema import (
    EvidenceSessionSchemaError,
    active_planned_session_version,
    evidence_session_schema_path,
    is_planned_session,
    load_evidence_session_schema,
)
from bcf_governance.tooling.truth_sessions import _manifest_issues


REPO_ROOT = Path(__file__).resolve().parents[1]


def test_current_session_versions_select_active_v3_without_rewriting_legacy() -> None:
    legacy = REPO_ROOT / "schemas/evidence-session.schema.json"
    active = REPO_ROOT / "schemas/evidence-session-v3.schema.json"
    assert evidence_session_schema_path(REPO_ROOT, "1.0") == legacy
    assert evidence_session_schema_path(REPO_ROOT, "2.0") == legacy
    assert evidence_session_schema_path(REPO_ROOT, "3.0") == active
    assert active_planned_session_version(REPO_ROOT) == "3.0"


def test_adopter_session_activation_is_derived_from_claim_capability(
    tmp_path: Path,
) -> None:
    gate_path = tmp_path / "governance/gate-contracts.yml"
    gate_path.parent.mkdir()
    gate_path.write_text(
        yaml.safe_dump({"claim_model": {"version": "1.0"}}), encoding="utf-8"
    )
    assert active_planned_session_version(tmp_path) == "2.0"

    gate_path.write_text(yaml.safe_dump({
        "claim_model": {"version": "1.0", "non_proof_dependencies": []},
    }), encoding="utf-8")
    assert active_planned_session_version(tmp_path) == "3.0"

    public_path = tmp_path / "governance/public-contracts.yml"
    public_path.write_text(yaml.safe_dump({
        "contracts": {"evidence_session": {"active_version": "2.0"}},
    }), encoding="utf-8")
    with pytest.raises(EvidenceSessionSchemaError, match="differs"):
        active_planned_session_version(tmp_path)


def test_dormant_v3_session_uses_the_exact_successor_schema() -> None:
    path = evidence_session_schema_path(REPO_ROOT, "3.0")
    schema = load_evidence_session_schema(REPO_ROOT, {"schema_version": "3.0"})

    assert path == REPO_ROOT / "schemas/evidence-session-v3.schema.json"
    assert schema["properties"]["schema_version"] == {
        "enum": ["1.0", "2.0", "3.0"]
    }
    required = schema["allOf"][1]["then"]["required"]
    assert "affected_proof_set" in required
    assert "affected_proof_set" not in json.loads(
        (REPO_ROOT / "schemas/evidence-session.schema.json").read_text(encoding="utf-8")
    )["properties"]


def test_planned_session_versions_are_closed_and_include_dormant_v3() -> None:
    assert is_planned_session({"schema_version": "2.0"}) is True
    assert is_planned_session({"schema_version": "3.0"}) is True
    assert is_planned_session({"schema_version": "1.0"}) is False
    assert is_planned_session({"schema_version": "4.0"}) is False


def test_dormant_v3_uses_planned_inventory_semantics(tmp_path: Path) -> None:
    subject = {"commit_sha": "a" * 40, "tree_sha": "b" * 40}
    manifest = {
        "schema_version": "3.0",
        "session_id": "c" * 32,
        "subject": subject,
        "profile": "standard",
        "profile_contract_version": "3.0",
        "producer": {"provider": "github", "run_id": "1", "run_attempt": "1"},
        "expected_gate_inventory": ["test"],
        "expected_producer_inventory": ["evidence"],
        "required_claims": ["app-valid"],
        "execution_dag": {"nodes": [{"producer": "test"}], "edges": []},
    }
    manifest_path = tmp_path / "evidence-session.json"
    manifest_path.write_text(json.dumps(manifest), encoding="utf-8")
    digest = hashlib.sha256(manifest_path.read_bytes()).hexdigest()
    receipt_path = tmp_path / "test.evidence.json"
    receipt = {
        "gate_id": "test",
        "artifacts": [{
            "path": "evidence-session.json",
            "media_type": "application/vnd.bcf.evidence-session+json",
            "sha256": digest,
        }],
        "observations": {"evidence_session": {
            "session_id": manifest["session_id"], "manifest_sha256": digest,
        }},
        "invocation": {"workflow": {
            "provider": "github", "run_id": "1", "run_attempt": "1", "job": "evidence",
        }},
        "subject": subject,
    }
    receipt_path.write_text(json.dumps(receipt), encoding="utf-8")

    issues, selected, _ = _manifest_issues(
        REPO_ROOT,
        {"receipt": receipt, "receipt_path": str(receipt_path)},
        current=subject,
        selected_profile="standard",
        contract_version="3.0",
        expected_gates={"legacy-would-differ"},
        schema={},
    )

    assert selected == manifest
    assert "evidence_session_gate_inventory_mismatch" not in issues
    assert "evidence_session_required_claims_missing" not in issues


@pytest.mark.parametrize("version", [None, "", "4.0", 3])
def test_unknown_session_schema_version_fails_closed(version: object) -> None:
    with pytest.raises(EvidenceSessionSchemaError, match="schema_version"):
        evidence_session_schema_path(REPO_ROOT, version)
