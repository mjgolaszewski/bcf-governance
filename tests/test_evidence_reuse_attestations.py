"""Main-side reuse decisions are exact, partial, and schema-closed."""

from __future__ import annotations

import hashlib
import json
from pathlib import Path
import subprocess

import pytest
import yaml

from bcf_governance.tooling.ci_github_artifacts import ProviderArtifact
from bcf_governance.tooling.ci_github_identity import MainIdentity
from bcf_governance.tooling.ci_prior_evidence_auth import AuthenticatedPriorTransport
from bcf_governance.tooling.evidence_claims import qualification_equivalence
from bcf_governance.tooling.evidence_reuse_attestations import compose_reuse_attestations
from tests.test_evidence_planning import _commit, _receipt, _repo


def _fixture(tmp_path: Path):
    root = _repo(tmp_path)
    receipt = _receipt(root, ["app-valid"])
    receipt.pop("artifact_sha256")
    qualified = receipt["qualifications"]["app-valid"]
    qualified["control_ids"] = []
    qualified["fingerprint"] = qualification_equivalence(
        root, receipt, "app-valid"
    )["main_sha256"]
    raw = json.dumps(receipt).encode()
    commit = subprocess.check_output(["git", "rev-parse", "HEAD"], cwd=root, text=True).strip()
    tree = subprocess.check_output(["git", "rev-parse", "HEAD^{tree}"], cwd=root, text=True).strip()
    main = MainIdentity("123", "main", commit, tree)
    reference = {
        "artifact_id": "901", "artifact_name": "source-evidence",
        "evidence_id": receipt["evidence_id"], "path": "test/app.evidence.json",
        "receipt_sha256": hashlib.sha256(raw).hexdigest(),
        "immutable_reference": "github-actions://owner/repo/runs/900/attempts/1/artifacts/901/test/app.evidence.json",
    }
    manifest = {
        "main": {"commit_sha": commit, "tree_sha": tree},
        "candidate": {"commit_sha": commit, "tree_sha": tree},
        "repository": {"repository_id": "123"}, "pull_request": 42,
        "merge": {"commit_sha": commit},
        "producer": {"run_id": "900", "run_attempt": 1,
                     "workflow": {"path": ".github/workflows/governance.yml", "workflow_id": "902",
                                  "definition_commit": commit, "definition_sha256": "a" * 64}},
        "authority": {"controller_commit_sha": commit, "controller_bundle_sha256": "b" * 64},
        "protection": {"declaration_sha256": "c" * 64},
        "authenticated_at": "2026-09-22T00:00:00Z",
        "artifacts": [{"artifact_id": "901", "archive_sha256": "d" * 64}],
        "receipts": [reference],
    }
    artifact = ProviderArtifact("1234", 1, "905", "transport", "sha256:" + "e" * 64, {})
    transport = AuthenticatedPriorTransport(
        artifact, manifest, {"expanded/901/test/app.evidence.json": raw},
    )
    contract = yaml.safe_load((root / "governance/gate-contracts.yml").read_text())
    entries = tuple(
        (line.split("\t", 1)[1], line.split("\t", 1)[0].split()[2])
        for line in subprocess.check_output(
            ["git", "ls-tree", "-r", "--full-tree", "HEAD"], cwd=root, text=True,
        ).splitlines()
    )
    return root, transport, main, contract, entries


def test_reuse_attestations_admit_only_exact_applicable_claim(tmp_path: Path) -> None:
    root, transport, main, contract, entries = _fixture(tmp_path)
    decisions, fallback = compose_reuse_attestations(
        root, transport, main, contract, entries, ["app-valid", "other-valid"],
        emitted_at="2026-09-22T00:01:00Z",
    )
    assert fallback == ["other-valid"]
    assert len(decisions) == 1
    assert decisions[0]["decision"] == "reuse_admitted"
    assert decisions[0]["rejection_reasons"] == []
    assert decisions[0]["claim"] == {
        "claim_id": "app-valid", "execution_group_id": "app-tests",
    }


def test_reuse_attestation_rejects_wrong_producer(tmp_path: Path) -> None:
    root, transport, main, contract, entries = _fixture(tmp_path)
    raw_path = "expanded/901/test/app.evidence.json"
    receipt = json.loads(transport.files[raw_path])
    receipt["gate_id"] = "other-test"
    transport.files[raw_path] = json.dumps(receipt).encode()
    decisions, fallback = compose_reuse_attestations(
        root, transport, main, contract, entries, ["app-valid"],
        emitted_at="2026-09-22T00:01:00Z",
    )
    assert fallback == ["app-valid"]
    assert decisions[0]["decision"] == "canonical_execution_required"
    assert "authority_ambiguous" in decisions[0]["rejection_reasons"]


def test_failed_source_receipt_requires_canonical_execution(tmp_path: Path) -> None:
    root, transport, main, contract, entries = _fixture(tmp_path)
    raw_path = "expanded/901/test/app.evidence.json"
    receipt = json.loads(transport.files[raw_path])
    receipt["result"] = "failed"
    transport.files[raw_path] = json.dumps(receipt).encode()
    decisions, fallback = compose_reuse_attestations(
        root, transport, main, contract, entries, ["app-valid"],
        emitted_at="2026-09-22T00:01:00Z",
    )
    assert fallback == ["app-valid"]
    assert decisions[0]["decision"] == "canonical_execution_required"
    assert "authority_ambiguous" in decisions[0]["rejection_reasons"]


def test_reuse_attestation_rejects_changed_main_dependency(tmp_path: Path) -> None:
    root, transport, main, contract, _ = _fixture(tmp_path)
    _commit(root, "app.py", "VALUE = 2\n")
    new_main = MainIdentity(
        main.repository_id, main.default_branch,
        subprocess.check_output(["git", "rev-parse", "HEAD"], cwd=root, text=True).strip(),
        subprocess.check_output(["git", "rev-parse", "HEAD^{tree}"], cwd=root, text=True).strip(),
    )
    transport.manifest["main"] = {
        "commit_sha": new_main.checkout_sha, "tree_sha": new_main.tree_sha,
    }
    lines = subprocess.check_output(
        ["git", "ls-tree", "-r", "--full-tree", "HEAD"], cwd=root, text=True,
    ).splitlines()
    entries = tuple((line.split("\t", 1)[1], line.split("\t", 1)[0].split()[2]) for line in lines)
    decisions, fallback = compose_reuse_attestations(
        root, transport, new_main, contract, entries, ["app-valid"],
        emitted_at="2026-09-22T00:01:00Z",
    )
    assert fallback == ["app-valid"]
    assert decisions[0]["decision"] == "canonical_execution_required"
    assert "dependency_closure_mismatch" in decisions[0]["rejection_reasons"]


def test_reuse_attestation_rejects_candidate_subject_substitution(tmp_path: Path) -> None:
    root, transport, main, contract, entries = _fixture(tmp_path)
    wrong = MainIdentity(main.repository_id, main.default_branch, "0" * 40, main.tree_sha)
    with pytest.raises(ValueError, match="main subject is not exact"):
        compose_reuse_attestations(
            root, transport, wrong, contract, entries, ["app-valid"],
            emitted_at="2026-09-22T00:01:00Z",
        )
