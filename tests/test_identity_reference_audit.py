from __future__ import annotations

import importlib.util
import io
import json
from pathlib import Path
import zipfile

import pytest


REPO_ROOT = Path(__file__).resolve().parents[1]
MODULE_PATH = REPO_ROOT / ".github/scripts/import_identity_reference_proof.py"
spec = importlib.util.spec_from_file_location("identity_reference_audit", MODULE_PATH)
if spec is None or spec.loader is None:
    raise RuntimeError("unable to load Identity reference audit compiler")
compiler = importlib.util.module_from_spec(spec)
spec.loader.exec_module(compiler)


def _inputs() -> tuple[dict, dict, dict, dict, dict[str, str]]:
    contract = {
        "subject": {
            "repository": "owner/identity",
            "commit_sha": "a" * 40,
            "tree_sha": "b" * 40,
            "expected_representations": 62,
        },
        "benchmark": {
            "measured_runs": 10,
            "median_ceiling_seconds": 30,
            "p95_ceiling_seconds": 36,
            "compact_report_ceiling_bytes": 1048576,
        },
    }
    validation = {
        "document": {
            "kind": "bcf_hosted_identity_reference_validation",
            "version": "1.0.0",
        },
        "status": "hosted_pass",
        "provider": {
            "repository_id": "123",
            "run_id": "456",
            "run_attempt": "1",
            "workflow_definition_commit": "c" * 40,
        },
        "subject": {
            "repository": "owner/identity",
            "commit_sha": "a" * 40,
            "tree_sha": "b" * 40,
            "clean": True,
        },
        "reference": {
            "verdict": "conformant",
            "consumer_report": {"representation_count": 62, "unresolved_escape_count": 0},
            "generalized_inventory": {"uncovered_required_trace_count": 0},
        },
        "benchmark": {
            "verdict": "pass",
            "measured_run_count": 10,
            "median_seconds": 8.8,
            "p95_seconds": 10.3,
            "compact_proof_bytes": 1004,
        },
    }
    run = {
        "id": 456,
        "run_attempt": 1,
        "status": "completed",
        "conclusion": "success",
        "event": "workflow_dispatch",
        "path": ".github/workflows/governance.yml",
        "head_branch": "audit/proof",
        "head_sha": "c" * 40,
        "workflow_id": 789,
        "repository": {"id": 123, "full_name": "owner/identity"},
    }
    artifact = {
        "id": 999,
        "name": "bcf-p13-identity-reference-456-1",
        "digest": "sha256:" + "d" * 64,
        "size_in_bytes": 100,
        "expired": False,
        "workflow_run": {"id": 456, "head_sha": "c" * 40, "repository_id": 123},
    }
    return contract, validation, run, artifact, {"hosted-validation.json": "f" * 64}


def test_identity_reference_importer_binds_provider_artifact() -> None:
    audit = compiler.compile_audit(*_inputs())
    assert audit["document"]["status"] == "hosted_pass"
    assert audit["provider_custody"] == {
        "repository": "owner/identity",
        "repository_id": "123",
        "workflow_id": "789",
        "workflow_path": ".github/workflows/governance.yml",
        "run_id": "456",
        "run_attempt": "1",
        "event": "workflow_dispatch",
        "head_branch": "audit/proof",
        "head_sha": "c" * 40,
        "artifact_id": "999",
        "artifact_name": "bcf-p13-identity-reference-456-1",
        "artifact_provider_digest": "sha256:" + "d" * 64,
        "artifact_size_bytes": 100,
        "artifact_members": {"hosted-validation.json": "f" * 64},
    }


def test_identity_reference_importer_rejects_provider_artifact_mismatch() -> None:
    contract, validation, run, artifact, members = _inputs()
    artifact["workflow_run"]["id"] = 455
    with pytest.raises(ValueError, match="different run"):
        compiler.compile_audit(contract, validation, run, artifact, members)


def _proof_zip(validation: dict) -> bytes:
    result_members = {
        "benchmark.json": b'{"value":"benchmark"}',
        "consumer-report.json": b'{"value":"consumer"}',
        "generalized-reference.json": b'{"value":"reference"}',
    }
    validation["benchmark"]["artifact_sha256"] = compiler._sha256(result_members["benchmark.json"])
    validation["reference"]["artifact_sha256"] = compiler._sha256(result_members["generalized-reference.json"])
    validation["reference"]["consumer_report"]["sha256"] = compiler._sha256(result_members["consumer-report.json"])
    output = io.BytesIO()
    with zipfile.ZipFile(output, "w") as archive:
        archive.writestr("hosted-validation.json", json.dumps(validation))
        for name, payload in result_members.items():
            archive.writestr(name, payload)
    return output.getvalue()


def test_identity_reference_importer_authenticates_archive_bytes() -> None:
    _, validation, _, artifact, _ = _inputs()
    payload = _proof_zip(validation)
    artifact["digest"] = f"sha256:{compiler._sha256(payload)}"

    decoded, members = compiler.load_proof_archive(payload, artifact)

    assert decoded["status"] == "hosted_pass"
    assert set(members) == {
        "benchmark.json", "consumer-report.json", "generalized-reference.json",
        "hosted-validation.json",
    }
    with pytest.raises(ValueError, match="provider digest"):
        compiler.load_proof_archive(payload + b"tampered", artifact)


def test_authenticated_hosted_audit_replaces_only_provisional_benchmark() -> None:
    audit = compiler.compile_audit(*_inputs())
    audit["validation"]["benchmark"]["environment"] = {
        "architecture": "x86_64",
        "vcpus": 2,
        "python_version": "3.14.5",
        "node_version": "v24.20.0",
        "typescript_version": "6.0.3",
    }
    audit["validation"]["benchmark"].update({
        "warmup_count": 1,
        "median_ceiling_seconds": 30,
        "p95_ceiling_seconds": 36,
        "artifact_sha256": "e" * 64,
    })
    audit["validation"]["reference"].update({
        "artifact_sha256": "f" * 64,
    })
    audit["validation"]["reference"]["consumer_report"]["sha256"] = "1" * 64
    audit["validation"]["reference"]["generalized_inventory"].update({
        "python_file_count": 906,
        "typescript_file_count": 168,
        "cross_language_trace_count": 221,
        "required_browser_trace_count": 220,
    })
    legacy = {
        "document": {"status": "provisional_local_pass"},
        "subject": audit["validation"]["subject"],
        "limitations": [
            "Python 3.14.7 remains unavailable",
            "disposable candidate VM image proof remains required",
        ],
    }

    promoted = compiler.promote_legacy_validation(legacy, audit)

    assert promoted["document"]["status"] == "hosted_pass"
    assert promoted["benchmark"]["substrate"] == "github_hosted_ubuntu_24_04"
    assert promoted["limitations"] == ["Python 3.14.7 remains unavailable"]
