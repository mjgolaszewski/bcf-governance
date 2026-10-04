from __future__ import annotations

import json
from pathlib import Path

import pytest

from bcf_governance.tooling.evidence_session_schema import (
    EvidenceSessionSchemaError,
    evidence_session_schema_path,
    load_evidence_session_schema,
)


REPO_ROOT = Path(__file__).resolve().parents[1]


def test_current_session_versions_keep_the_active_schema() -> None:
    active = REPO_ROOT / "schemas/evidence-session.schema.json"
    assert evidence_session_schema_path(REPO_ROOT, "1.0") == active
    assert evidence_session_schema_path(REPO_ROOT, "2.0") == active


def test_dormant_v3_session_uses_the_exact_successor_schema() -> None:
    path = evidence_session_schema_path(REPO_ROOT, "3.0")
    schema = load_evidence_session_schema(REPO_ROOT, {"schema_version": "3.0"})

    assert path == REPO_ROOT / "schemas/evidence-session-v3.schema.json"
    assert schema["properties"]["schema_version"] == {"enum": ["3.0"]}
    required = schema["allOf"][0]["then"]["required"]
    assert "affected_proof_set" in required
    assert "affected_proof_set" not in json.loads(
        (REPO_ROOT / "schemas/evidence-session.schema.json").read_text(encoding="utf-8")
    )["properties"]


@pytest.mark.parametrize("version", [None, "", "4.0", 3])
def test_unknown_session_schema_version_fails_closed(version: object) -> None:
    with pytest.raises(EvidenceSessionSchemaError, match="schema_version"):
        evidence_session_schema_path(REPO_ROOT, version)
