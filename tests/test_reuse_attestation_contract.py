from __future__ import annotations

import copy
import json
from pathlib import Path

import jsonschema
import pytest
import yaml


ROOT = Path(__file__).resolve().parents[1]


def _schema() -> dict:
    return json.loads(
        (ROOT / "schemas/reuse-attestation.schema.json").read_text(encoding="utf-8")
    )


def _attestation() -> dict:
    digest = "a" * 64
    subject = {"commit_sha": "b" * 40, "tree_sha": "c" * 40}
    main = {"commit_sha": "d" * 40, "tree_sha": "e" * 40}
    return {
        "schema_version": "1.0",
        "kind": "reuse_attestation",
        "attestation_id": "f" * 64,
        "claim": {"claim_id": "test-passes", "execution_group_id": "test"},
        "source_receipt": {
            "evidence_id": "test-source",
            "receipt_sha256": digest,
            "artifact_sha256": "1" * 64,
            "immutable_reference": "github-actions://artifact/123/file/test.evidence.json",
        },
        "source_subject": subject,
        "main_subject": main,
        "dependency_closure": {
            "source_sha256": "2" * 64,
            "main_sha256": "2" * 64,
            "equivalent": True,
        },
        "qualification": {
            "source_sha256": "3" * 64,
            "main_sha256": "3" * 64,
            "equivalent": True,
        },
        "provider_custody": {
            "provider": "github",
            "repository_id": "1207503211",
            "pull_request_number": 214,
            "candidate": subject,
            "merge_commit_sha": "4" * 40,
            "main": main,
            "producer": {
                "run_id": "35247833166",
                "run_attempt": 1,
                "workflow": {
                    "path": ".github/workflows/governance.yml",
                    "workflow_id": "334490532",
                    "definition_commit": "5" * 40,
                    "definition_sha256": "6" * 64,
                },
            },
            "artifact": {"artifact_id": "10509152893", "artifact_sha256": "7" * 64},
            "authority": {
                "controller_commit_sha": "8" * 40,
                "controller_bundle_sha256": "9" * 64,
            },
            "protection_sha256": "0" * 64,
            "authenticated_at": "2026-09-18T00:00:00Z",
        },
        "decision": "reuse_admitted",
        "rejection_reasons": [],
        "emitted_at": "2026-09-18T00:00:01Z",
    }


def test_reuse_attestation_is_closed_and_admits_exact_equivalence() -> None:
    jsonschema.Draft202012Validator(_schema()).validate(_attestation())


@pytest.mark.parametrize(
    "mutation",
    [
        lambda value: value["source_receipt"].update({"receipt": {"mutable": True}}),
        lambda value: value["source_receipt"].pop("receipt_sha256"),
        lambda value: value["dependency_closure"].update({"equivalent": False}),
        lambda value: value["qualification"].update({"equivalent": False}),
        lambda value: value["rejection_reasons"].append("replay_detected"),
    ],
)
def test_reuse_admission_rejects_mutable_incomplete_or_nonequivalent_proof(
    mutation,
) -> None:
    value = copy.deepcopy(_attestation())
    mutation(value)
    with pytest.raises(jsonschema.ValidationError):
        jsonschema.Draft202012Validator(_schema()).validate(value)


def test_execution_fallback_requires_a_closed_reason() -> None:
    value = _attestation()
    value["decision"] = "canonical_execution_required"
    with pytest.raises(jsonschema.ValidationError):
        jsonschema.Draft202012Validator(_schema()).validate(value)
    value["rejection_reasons"] = ["authority_ambiguous"]
    jsonschema.Draft202012Validator(_schema()).validate(value)


def test_foundation_inventory_has_exactly_one_owner_for_every_required_primitive() -> None:
    audit = yaml.safe_load(
        (ROOT / "audits/bcf-2.1-p26-invariant-ownership.yml").read_text(
            encoding="utf-8"
        )
    )
    expected = {
        "SubjectIdentity", "TreeIdentity", "ClaimIdentity", "ExecutionGroupIdentity",
        "ExecutionProvenance", "AuthorityIdentity", "DependencyClosure", "Qualification",
        "EvidenceReceipt", "EvidenceReference", "ApplicabilityDecision",
        "InvalidationReason", "ReuseAttestation", "LifecycleState", "RecoveryAuthority",
    }
    primitives = audit["primitives"]
    assert {item["id"] for item in primitives} == expected
    assert len(primitives) == len(expected)
    assert audit["registry_rule"].endswith("governance/gate-contracts.yml")
