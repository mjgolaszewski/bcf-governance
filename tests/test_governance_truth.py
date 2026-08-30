from __future__ import annotations

import hashlib
import importlib.util
import json
import os
import shutil
import subprocess
import sys
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

import pytest
import yaml

from scripts.governance_evidence import attest_bundle

REPO_ROOT = Path(__file__).resolve().parents[1]
TRUTH_MODULE_PATH = Path(
    os.environ.get(
        "BCF_TRUTH_MODULE_PATH", str(REPO_ROOT / "scripts/governance_truth.py")
    )
).resolve()


def _load_truth_module() -> Any:
    spec = importlib.util.spec_from_file_location("governance_truth_under_test", TRUTH_MODULE_PATH)
    if spec is None or spec.loader is None:
        raise RuntimeError(f"unable to load truth module from {TRUTH_MODULE_PATH}")
    module = importlib.util.module_from_spec(spec)
    sys.path.insert(0, str(TRUTH_MODULE_PATH.parent))
    try:
        spec.loader.exec_module(module)
    finally:
        sys.path.pop(0)
    return module


TRUTH_MODULE = _load_truth_module()
TruthfulnessError = TRUTH_MODULE.TruthfulnessError
derive_truth = TRUTH_MODULE.derive_truth


def _write_yaml(path: Path, payload: dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(yaml.safe_dump(payload, sort_keys=False), encoding="utf-8")


def _git(repo: Path, *args: str) -> str:
    result = subprocess.run(
        ["git", *args], cwd=repo, check=True, capture_output=True, text=True
    )
    return result.stdout.strip()


def _commit(repo: Path, message: str) -> None:
    _git(repo, "add", ".")
    _git(repo, "commit", "-m", message)


def _actor(actor_id: str) -> dict[str, str]:
    return {"kind": "human", "id": actor_id}


def _make_repo(
    tmp_path: Path,
    *,
    finding_disposition: str | None = None,
    false_zero_summary: bool = False,
) -> Path:
    repo = tmp_path / "repo"
    (repo / ".github/workflows").mkdir(parents=True)
    (repo / "schemas").mkdir()
    (repo / "plans").mkdir()
    (repo / "phases").mkdir()
    (repo / "governance").mkdir()
    (repo / "audits").mkdir()
    (repo / ".gitignore").write_text(".artifacts/\n", encoding="utf-8")
    (repo / "schemas/evidence-receipt.schema.json").write_bytes(
        (REPO_ROOT / "template-repo/schemas/evidence-receipt.schema.json").read_bytes()
    )
    (repo / "schemas/evidence-session.schema.json").write_bytes(
        (REPO_ROOT / "template-repo/schemas/evidence-session.schema.json").read_bytes()
    )
    _write_yaml(
        repo / "governance-profile.yml",
        {
            "profile": {"selected": "standard"},
            "release_gate_profile": {
                "gates": {
                    "test": {
                        "target": "test",
                        "status": "required",
                        "command_policy": "automated_tests",
                    },
                    "security_review": {
                        "target": "security-review",
                        "status": "required",
                        "command_policy": "security_vulnerability_scan",
                    },
                    "reconcile": {
                        "target": "reconcile",
                        "status": "required",
                        "command_policy": "governance_validation",
                    },
                }
            },
        },
    )
    _write_yaml(
        repo / "governance/gate-contracts.yml",
        {
            "document": {
                "kind": "gate_contract_registry",
                "version": "1.0",
                "path": "governance/gate-contracts.yml",
            },
            "schema_version": "1.0",
            "target_profile": "standard",
            "gates": {
                gate: {
                    "invocation": {
                        "argv": ["python3", "gate.py", gate],
                        "cwd": ".",
                        "env": {},
                        "required_env": [],
                    },
                    "evidence": {},
                    "negative_controls": [],
                }
                for gate in ("test", "security-review", "reconcile")
            },
            "provenance": {},
        },
    )
    _write_yaml(
        repo / "governance/evidence-policy.yml",
        {
            "settings": {
                "require_negative_control_for_required_gates": True,
                "tree_independent_allowlist": [],
            },
            "claim_dependencies": {
                "workitems_closed": ["source", "test", "governance"],
                "required_suites_green": ["source", "test", "workflow"],
                "architecture_gates_green": ["source", "test", "workflow"],
                "health_checks_green": ["source", "config", "workflow"],
                "security_review_complete": [
                    "source",
                    "test",
                    "workflow",
                    "audit",
                    "governance",
                    "security_impact",
                ],
                "findings_resolved": ["source", "test", "audit", "governance"],
            },
            "workflow_contract": {
                "paths": [".github/workflows/governance.yml"],
                "required_events": ["pull_request", "push"],
            },
            "provenance": {
                "standard_same_actor_policy": "warn",
                "regulated_requires_attestation": True,
                "trusted_verifier_keys": {},
                "permitted_risk_authorities": [],
            },
        },
    )
    (repo / ".github/workflows/governance.yml").write_text(
        """name: governance
on:
  pull_request:
  push:
jobs:
  evidence:
    strategy:
      matrix:
        gate: [test, security-review, reconcile]
    steps:
      - run: python scripts/governance_evidence.py --repo-root . run --gate ${{ matrix.gate }} --output .artifacts/bcf
""",
        encoding="utf-8",
    )
    _write_yaml(
        repo / "plans/phase-ledger.yml",
        {
            "active_phase": {
                "id": "P01",
                "log": "phases/phase-01-log.yml",
                "workitems": "plans/phase-01-workitems.yml",
                "lifecycle_status": "completed",
            }
        },
    )
    _write_yaml(
        repo / "plans/phase-01-workitems.yml",
        {"workitems": [{"id": "P01-W01", "status": "DONE"}]},
    )
    claims = {
        "workitems_closed": {"required_evidence": ["test"]},
        "required_suites_green": {"required_evidence": ["test"]},
        "architecture_gates_green": {"required_evidence": ["test"]},
        "health_checks_green": {"required_evidence": ["security-review"]},
        "security_review_complete": {"required_evidence": ["security-review"]},
        "findings_resolved": {"required_evidence": ["security-review"]},
    }
    _write_yaml(
        repo / "phases/phase-01-log.yml",
        {
            "document": {"status": "completed"},
            "phase": {"id": "P01"},
            "closeout_requirements": {
                "claims": claims,
                "reconciliation": {"required_evidence": ["reconcile"]},
                "finding_registry": "governance/findings.yml",
            },
        },
    )
    findings: list[dict[str, Any]] = []
    reviews: list[dict[str, Any]] = []
    if finding_disposition is not None:
        source = repo / "audits/security-review.md"
        source.write_text("# Review\n\nOne authentication correction.\n", encoding="utf-8")
        finding = {
            "id": "SEC-001",
            "review_id": "REV-001",
            "severity": "high",
            "disposition": finding_disposition,
            "provenance": {
                "producers": [_actor("author")],
                "reviewer": _actor("reviewer"),
                "remediators": [_actor("remediator")],
                "verifier": _actor("verifier"),
            },
            "proofs": [],
        }
        if finding_disposition == "remediation_completed":
            finding["proofs"] = [
                {
                    "kind": "test_node",
                    "gate_id": "test",
                    "node_id": "tests/test_security.py::test_auth",
                    "negative_control_id": "assertion-removed",
                }
            ]
        findings.append(finding)
        reviews.append(
            {
                "id": "REV-001",
                "source_path": "audits/security-review.md",
                "source_sha256": hashlib.sha256(source.read_bytes()).hexdigest(),
                "reviewer": _actor("reviewer"),
                "finding_ids": ["SEC-001"],
                "summary": {
                    "findings_total": 0 if false_zero_summary else 1,
                    "open_count": 0 if false_zero_summary else int(finding_disposition == "open"),
                },
            }
        )
    _write_yaml(
        repo / "governance/findings.yml",
        {"reviews": reviews, "findings": findings},
    )
    _git(repo, "init")
    _git(repo, "config", "user.email", "truth@example.test")
    _git(repo, "config", "user.name", "Truth Test")
    _commit(repo, "governed tree")
    return repo


def _write_receipt(
    repo: Path,
    gate_id: str,
    *,
    skipped: bool = False,
    probe_exit: int = 1,
    include_node: bool = True,
    environment_ok: bool = True,
) -> Path:
    evidence_dir = repo / ".artifacts/bcf"
    evidence_dir.mkdir(parents=True, exist_ok=True)
    artifact = evidence_dir / f"{gate_id}.stdout.txt"
    is_test = gate_id == "test"
    artifact.write_text(
        "collected 2 items\n2 skipped\n" if is_test and skipped else
        "collected 2 items\n2 passed\n" if is_test else "gate output\n",
        encoding="utf-8",
    )
    probe_stdout = evidence_dir / f"{gate_id}.probe.stdout.txt"
    probe_stderr = evidence_dir / f"{gate_id}.probe.stderr.txt"
    probe_stdout.write_text("expected mutation failure\n", encoding="utf-8")
    probe_stderr.write_text("", encoding="utf-8")
    probe_junit = evidence_dir / f"{gate_id}.probe.junit.xml"
    if is_test:
        probe_junit.write_text(
            '<testsuite tests="1" failures="1"><testcase classname="tests/test_security.py" name="test_auth"><failure>mutated</failure></testcase></testsuite>',
            encoding="utf-8",
        )
    observations: dict[str, Any] = {
        "exit_code": 0,
        "environment_assertions": [
            {
                "name": "BCF_ENV",
                "operator": "equals",
                "expected": "production",
                "actual": "production" if environment_ok else "development",
                "satisfied": environment_ok,
            }
        ],
    }
    if is_test:
        observations.update(
            {
                "test_counts": {
                    "collected": 2,
                    "executed": 0 if skipped else 2,
                    "passed": 0 if skipped else 2,
                    "failed": 0,
                    "errors": 0,
                    "skipped": 2 if skipped else 0,
                    "xfailed": 0,
                    "xpassed": 0,
                },
                "test_thresholds": {
                    "min_collected": 1,
                    "min_executed": 1,
                    "max_skipped": 0,
                },
                "test_node_ids": (
                    ["tests/test_security.py::test_auth"] if include_node else []
                ),
                "expected_test_node_ids": ["tests/test_security.py::test_auth"],
                "expected_nodes_mode": "contains",
            }
        )
    timestamp = datetime.now(UTC).isoformat().replace("+00:00", "Z")
    receipt = {
        "schema_version": "2.0",
        "kind": "test_suite" if is_test else "gate",
        "evidence_id": f"{gate_id}-evidence",
        "gate_id": gate_id,
        "producer": {"kind": "workflow", "id": "test-ci"},
        "invocation": {
            "argv": ["python3", "gate.py", gate_id],
            "cwd": ".",
            "environment": {"declared": {}, "required_present": []},
            "workflow": {
                "provider": "test",
                "path": ".github/workflows/governance.yml",
                "job": "evidence",
                "run_id": "1",
                "run_attempt": "1",
                "matrix": {"gate": gate_id},
            },
        },
        "subject": {
            "commit_sha": _git(repo, "rev-parse", "HEAD"),
            "tree_sha": _git(repo, "rev-parse", "HEAD^{tree}"),
            "execution_tree_sha": _git(repo, "rev-parse", "HEAD^{tree}"),
            "binding": "exact_tree",
            "tracked_clean": True,
            "untracked_clean": True,
            "status_porcelain_sha256": hashlib.sha256(b"").hexdigest(),
        },
        "artifacts": [
            {
                "path": artifact.name,
                "media_type": "text/plain",
                "sha256": hashlib.sha256(artifact.read_bytes()).hexdigest(),
            },
            {
                "path": probe_stdout.name,
                "media_type": "text/plain",
                "sha256": hashlib.sha256(probe_stdout.read_bytes()).hexdigest(),
            },
            {
                "path": probe_stderr.name,
                "media_type": "text/plain",
                "sha256": hashlib.sha256(probe_stderr.read_bytes()).hexdigest(),
            },
            *(
                [
                    {
                        "path": probe_junit.name,
                        "media_type": "application/junit+xml",
                        "sha256": hashlib.sha256(probe_junit.read_bytes()).hexdigest(),
                    }
                ]
                if is_test
                else []
            ),
        ],
        "observations": {
            **observations,
            "execution_tree_clean": True,
            "output_requirements": [],
        },
        "behavioral_probes": [
            {
                "id": "assertion-removed" if is_test else "gate-broken",
                "mutation_applied": True,
                "observed_exit_code": probe_exit,
                "oracle": (
                    {
                        "kind": "test_node_failure",
                        "node_ids": ["tests/test_security.py::test_auth"],
                    }
                    if is_test
                    else {
                        "kind": "diagnostic",
                        "exit_codes": [1],
                        "stream": "stdout",
                        "regex": "expected mutation failure",
                    }
                ),
                "oracle_observation": {"satisfied": probe_exit == 1},
                "baseline_test_nodes_passed": True,
                "unexpected_worktree_changes": [],
                "raw_artifacts": {
                    "stdout": probe_stdout.name,
                    "stderr": probe_stderr.name,
                    **({"junit": probe_junit.name} if is_test else {}),
                },
            }
        ],
        "result": "passed",
        "started_at": timestamp,
        "timestamp": timestamp,
    }
    path = evidence_dir / f"{gate_id}.evidence.json"
    path.write_text(json.dumps(receipt, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    return path


def _write_complete_bundle(repo: Path) -> Path:
    _write_receipt(repo, "test")
    _write_receipt(repo, "security-review")
    _write_receipt(repo, "reconcile")
    return repo / ".artifacts/bcf"


def _enable_v2_session(repo: Path) -> Path:
    profile_path = repo / "governance-profile.yml"
    profile = yaml.safe_load(profile_path.read_text(encoding="utf-8"))
    profile["profile_contract_version"] = "2.0"
    _write_yaml(profile_path, profile)
    _commit(repo, "enable profile v2")
    evidence_dir = _write_complete_bundle(repo)
    session_id = "a" * 32
    manifest = {
        "schema_version": "1.0",
        "session_id": session_id,
        "subject": {
            "commit_sha": _git(repo, "rev-parse", "HEAD"),
            "tree_sha": _git(repo, "rev-parse", "HEAD^{tree}"),
        },
        "profile": "standard",
        "profile_contract_version": "2.0",
        "producer": {
            "kind": "workflow",
            "provider": "test",
            "repository": "example/repo",
            "repository_id": "42",
            "run_id": "1",
            "run_attempt": "1",
            "producer_id": "evidence",
        },
        "expected_gate_inventory": ["reconcile", "security-review", "test"],
        "expected_producer_inventory": ["evidence"],
        "created_at": datetime.now(UTC).isoformat().replace("+00:00", "Z"),
        "session_root_policy": {
            "mode": "0700",
            "root_kind": "ignored_repository",
            "immutable_manifest": True,
        },
    }
    manifest_path = evidence_dir / "evidence-session.json"
    manifest_path.write_text(
        json.dumps(manifest, indent=2, sort_keys=True) + "\n", encoding="utf-8"
    )
    digest = hashlib.sha256(manifest_path.read_bytes()).hexdigest()
    for receipt_path in evidence_dir.glob("*.evidence.json"):
        receipt = json.loads(receipt_path.read_text(encoding="utf-8"))
        receipt["artifacts"].append(
            {
                "path": "evidence-session.json",
                "media_type": "application/vnd.bcf.evidence-session+json",
                "sha256": digest,
            }
        )
        receipt["observations"]["evidence_session"] = {
            "session_id": session_id,
            "manifest_sha256": digest,
        }
        receipt_path.write_text(
            json.dumps(receipt, indent=2, sort_keys=True) + "\n", encoding="utf-8"
        )
    return evidence_dir


def _rewrite_session_bundle(evidence_dir: Path, transform: Any) -> None:
    manifest_path = evidence_dir / "evidence-session.json"
    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    transform(manifest)
    manifest_path.write_text(
        json.dumps(manifest, indent=2, sort_keys=True) + "\n", encoding="utf-8"
    )
    digest = hashlib.sha256(manifest_path.read_bytes()).hexdigest()
    for receipt_path in evidence_dir.glob("*.evidence.json"):
        receipt = json.loads(receipt_path.read_text(encoding="utf-8"))
        session = receipt["observations"]["evidence_session"]
        session.update(
            {"session_id": manifest["session_id"], "manifest_sha256": digest}
        )
        artifact = next(
            value
            for value in receipt["artifacts"]
            if value["path"] == "evidence-session.json"
        )
        artifact["sha256"] = digest
        receipt_path.write_text(
            json.dumps(receipt, indent=2, sort_keys=True) + "\n", encoding="utf-8"
        )


def _rewrite_receipt(path: Path, transform: Any) -> None:
    receipt = json.loads(path.read_text(encoding="utf-8"))
    transform(receipt)
    path.write_text(json.dumps(receipt, indent=2, sort_keys=True) + "\n", encoding="utf-8")


def test_completed_without_evidence_remains_completed_and_truth_fails(tmp_path: Path) -> None:
    repo = _make_repo(tmp_path)
    evidence_dir = repo / ".artifacts/bcf"
    evidence_dir.mkdir(parents=True)

    report = derive_truth(repo, evidence_dir)

    assert report["effective_state"] == "completed"
    assert report["status"] == "fail"
    assert report["failure_class"] == "truthfulness"


def test_current_evidence_and_reconciliation_compute_closed(tmp_path: Path) -> None:
    repo = _make_repo(tmp_path)

    report = derive_truth(repo, _write_complete_bundle(repo))

    assert report["authored_state"] == "completed"
    assert report["effective_state"] == "closed"
    assert report["release_readiness"]["effective_state"] == "closed"
    assert report["status"] == "pass"


def test_truth_integrates_independently_verified_ci_certification(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    repo = _make_repo(tmp_path)
    monkeypatch.setitem(
        derive_truth.__globals__,
        "verify_ci_certification",
        lambda *args, **kwargs: type(
            "Verification",
            (),
            {
                "as_dict": lambda self: {
                    "status": "pass",
                    "computed_state": "certified",
                    "admission_ordinal": 7,
                    "selected_attempts": [
                        {"producer_id": "test", "run_attempt": 1}
                    ],
                    "reasons": [],
                }
            },
        )(),
    )

    report = derive_truth(
        repo,
        _write_complete_bundle(repo),
        ci_authority_path=repo / "ci-authority.json",
        ci_certification_path=repo / "ci-certification.json",
        ci_session_manifest_path=repo / "evidence-session.json",
    )

    assert report["status"] == "pass"
    assert report["checks"]["ci_certification"] == "pass"
    assert report["ci_certification"]["computed_state"] == "certified"


def test_truth_fails_closed_for_incomplete_or_invalid_ci_inputs(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    repo = _make_repo(tmp_path)
    evidence = _write_complete_bundle(repo)

    incomplete = derive_truth(
        repo,
        evidence,
        ci_authority_path=repo / "ci-authority.json",
    )
    assert incomplete["status"] == "fail"
    assert "ci_certification_inputs_incomplete" in incomplete["issues"]

    monkeypatch.setitem(
        derive_truth.__globals__,
        "verify_ci_certification",
        lambda *args, **kwargs: (_ for _ in ()).throw(
            TRUTH_MODULE.CICertificationError("snapshot digest mismatch")
        ),
    )
    invalid = derive_truth(
        repo,
        evidence,
        ci_authority_path=repo / "ci-authority.json",
        ci_certification_path=repo / "ci-certification.json",
        ci_session_manifest_path=repo / "evidence-session.json",
    )
    assert invalid["status"] == "fail"
    assert invalid["checks"]["ci_certification"] == "fail"
    assert invalid["ci_certification"]["reasons"] == ["snapshot digest mismatch"]


def test_profile_v2_requires_one_valid_evidence_session(tmp_path: Path) -> None:
    repo = _make_repo(tmp_path)
    profile_path = repo / "governance-profile.yml"
    profile = yaml.safe_load(profile_path.read_text(encoding="utf-8"))
    profile["profile_contract_version"] = "2.0"
    _write_yaml(profile_path, profile)
    _commit(repo, "enable profile v2 without session")

    report = derive_truth(repo, _write_complete_bundle(repo))

    assert report["status"] == "fail"
    refs = report["claims"]["required_suites_green"]["evidence_refs"]
    assert any("evidence_session_manifest_artifact_missing" in ref["issues"] for ref in refs)


def test_profile_v2_session_computes_closed(tmp_path: Path) -> None:
    repo = _make_repo(tmp_path)

    report = derive_truth(repo, _enable_v2_session(repo))

    assert report["status"] == "pass"
    assert report["effective_state"] == "closed"


@pytest.mark.parametrize(
    ("mutant", "expected_issue"),
    [
        (
            lambda receipt: receipt["observations"]["evidence_session"].update(
                {"manifest_sha256": "0" * 64}
            ),
            "evidence_session_observed_digest_mismatch",
        ),
        (
            lambda receipt: receipt["invocation"]["workflow"].update(
                {"run_attempt": "2"}
            ),
            "evidence_session_run_attempt_mismatch",
        ),
        (
            lambda receipt: receipt["invocation"]["workflow"].update(
                {"job": "different-producer"}
            ),
            "evidence_session_producer_id_mismatch",
        ),
    ],
)
def test_profile_v2_session_mutants_fail_for_declared_cause(
    tmp_path: Path, mutant: Any, expected_issue: str
) -> None:
    repo = _make_repo(tmp_path)
    evidence_dir = _enable_v2_session(repo)
    receipt_path = evidence_dir / "test.evidence.json"
    _rewrite_receipt(receipt_path, mutant)

    report = derive_truth(repo, evidence_dir)

    refs = report["claims"]["required_suites_green"]["evidence_refs"]
    assert report["status"] == "fail"
    assert any(expected_issue in ref["issues"] for ref in refs)


def test_profile_v2_rejects_session_inventory_drift(tmp_path: Path) -> None:
    repo = _make_repo(tmp_path)
    evidence_dir = _enable_v2_session(repo)
    _rewrite_session_bundle(
        evidence_dir,
        lambda manifest: manifest["expected_gate_inventory"].remove("reconcile"),
    )

    report = derive_truth(repo, evidence_dir)

    refs = report["claims"]["required_suites_green"]["evidence_refs"]
    assert report["status"] == "fail"
    assert any("evidence_session_gate_inventory_mismatch" in ref["issues"] for ref in refs)


def test_profile_v2_rejects_stale_receipts_from_another_session(tmp_path: Path) -> None:
    repo = _make_repo(tmp_path)
    evidence_dir = _enable_v2_session(repo)
    stale_dir = evidence_dir / "stale"
    stale_dir.mkdir()
    for source in [value for value in evidence_dir.iterdir() if value.is_file()]:
        shutil.copy2(source, stale_dir / source.name)
    _rewrite_session_bundle(
        stale_dir,
        lambda manifest: manifest.update({"session_id": "b" * 32}),
    )

    report = derive_truth(repo, evidence_dir)

    refs = report["claims"]["required_suites_green"]["evidence_refs"]
    assert report["status"] == "fail"
    assert any("evidence_session_mixed_bundle" in ref["issues"] for ref in refs)


def test_missing_direct_claim_declarations_cannot_promote_completed_phase(
    tmp_path: Path,
) -> None:
    repo = _make_repo(tmp_path)
    log_path = repo / "phases/phase-01-log.yml"
    log = yaml.safe_load(log_path.read_text(encoding="utf-8"))
    del log["closeout_requirements"]["claims"]["security_review_complete"]
    _write_yaml(log_path, log)
    _commit(repo, "remove required claim")

    report = derive_truth(repo, _write_complete_bundle(repo))

    assert report["effective_state"] == "completed"
    assert "required_claim_security_review_complete_not_declared" in report["issues"]


def test_active_phase_hotfix_closure_is_computed_and_blocks_release(tmp_path: Path) -> None:
    repo = _make_repo(tmp_path)
    hotfix_path = repo / "phases/phase-01-hotfix01.yml"
    hotfix = {
        "document": {"status": "completed"},
        "hotfix": {"id": "HF-001", "related_phase_id": "P01"},
        "closeout_requirements": {
            "claims": {
                "required_suites_green": {"required_evidence": ["test"]},
                "security_review_complete": {"required_evidence": ["security-review"]},
            },
            "reconciliation": {"required_evidence": ["reconcile"]},
        },
    }
    _write_yaml(hotfix_path, hotfix)
    _commit(repo, "completed hotfix")

    closed = derive_truth(repo, _write_complete_bundle(repo))
    assert closed["hotfixes"][0]["effective_state"] == "closed"
    assert closed["release_readiness"]["effective_state"] == "closed"

    hotfix["document"]["status"] = "planned"
    _write_yaml(hotfix_path, hotfix)
    _commit(repo, "reopen hotfix")
    blocked = derive_truth(repo, _write_complete_bundle(repo))
    assert blocked["effective_state"] == "closed"
    assert blocked["hotfixes"][0]["effective_state"] == "planned"
    assert blocked["release_readiness"]["effective_state"] == "completed"
    assert "hotfix_HF-001_effective_state_planned" in blocked["issues"]


def test_missing_reconciliation_holds_verified_without_closing(tmp_path: Path) -> None:
    repo = _make_repo(tmp_path)
    _write_receipt(repo, "test")
    _write_receipt(repo, "security-review")

    report = derive_truth(repo, repo / ".artifacts/bcf")

    assert report["effective_state"] == "verified"
    assert report["reconciliation"]["effective_state"] == "completed"
    assert report["status"] == "fail"


def test_workitems_closed_is_measured_from_current_ledger(tmp_path: Path) -> None:
    repo = _make_repo(tmp_path)
    evidence_dir = _write_complete_bundle(repo)
    workitems_path = repo / "plans/phase-01-workitems.yml"
    payload = yaml.safe_load(workitems_path.read_text(encoding="utf-8"))
    payload["workitems"][0]["status"] = "TODO"
    _write_yaml(workitems_path, payload)
    _commit(repo, "reopen workitem")
    # Recapture all gates on the new tree; repository measurement must still refuse verification.
    evidence_dir = _write_complete_bundle(repo)

    report = derive_truth(repo, evidence_dir)

    claim = report["claims"]["workitems_closed"]
    assert claim["effective_state"] == "completed"
    assert claim["repository_observation"]["open_ids"] == ["P01-W01"]
    assert report["effective_state"] == "completed"


def test_open_blocking_finding_holds_verified(tmp_path: Path) -> None:
    repo = _make_repo(tmp_path, finding_disposition="open")

    report = derive_truth(repo, _write_complete_bundle(repo))

    assert report["effective_state"] == "verified"
    assert report["findings"]["findings_total"] == 1
    assert report["findings"]["open_count"] == 1
    assert report["claims"]["findings_resolved"]["effective_state"] == "completed"


def test_remediated_finding_counts_as_finding_and_closes_with_node_proof(tmp_path: Path) -> None:
    repo = _make_repo(tmp_path, finding_disposition="remediation_completed")

    report = derive_truth(repo, _write_complete_bundle(repo))

    assert report["effective_state"] == "closed"
    assert report["findings"]["findings_total"] == 1
    assert report["findings"]["open_count"] == 0


@pytest.mark.parametrize(
    ("mutant_id", "mutate", "expected_issue"),
    [
        (
            "gate-replaced-with-true",
            lambda receipt: receipt["behavioral_probes"][0].update(
                {"observed_exit_code": 0}
            ),
            "oracle_not_satisfied",
        ),
        (
            "all-required-tests-skipped",
            lambda receipt: receipt["observations"].update(
                {
                    "test_counts": {
                        "collected": 2,
                        "executed": 0,
                        "passed": 0,
                        "failed": 0,
                        "errors": 0,
                        "skipped": 2,
                        "xfailed": 0,
                        "xpassed": 0,
                    }
                }
            ),
            "test_min_executed_not_met",
        ),
        (
            "referenced-assertion-removed",
            lambda receipt: receipt["observations"].update({"test_node_ids": []}),
            "expected_test_nodes_missing",
        ),
        (
            "development-preflight-for-production",
            lambda receipt: receipt["observations"]["environment_assertions"][0].update(
                {"actual": "development", "satisfied": False}
            ),
            "environment_assertion_BCF_ENV_failed",
        ),
    ],
)
def test_semantic_receipt_mutants_die(
    tmp_path: Path, mutant_id: str, mutate: Any, expected_issue: str
) -> None:
    repo = _make_repo(tmp_path)
    evidence_dir = _write_complete_bundle(repo)
    _rewrite_receipt(evidence_dir / "test.evidence.json", mutate)

    report = derive_truth(repo, evidence_dir)

    assert report["status"] == "fail", mutant_id
    issues = report["claims"]["required_suites_green"]["evidence_refs"][0]["issues"]
    assert any(expected_issue in issue for issue in issues), mutant_id
    assert report["effective_state"] == "completed"


def test_required_test_gate_cannot_disguise_itself_as_generic_evidence(
    tmp_path: Path,
) -> None:
    repo = _make_repo(tmp_path)
    evidence_dir = _write_complete_bundle(repo)
    _rewrite_receipt(
        evidence_dir / "test.evidence.json",
        lambda receipt: receipt.update({"kind": "gate"}),
    )

    report = derive_truth(repo, evidence_dir)

    issues = report["claims"]["required_suites_green"]["evidence_refs"][0]["issues"]
    assert "evidence_kind_must_be_test_suite" in issues
    assert report["checks"]["test_execution"] == "fail"


def test_head_change_stales_internally_consistent_old_tree_bundle(tmp_path: Path) -> None:
    repo = _make_repo(tmp_path)
    evidence_dir = _write_complete_bundle(repo)
    (repo / "auth").mkdir()
    (repo / "auth/token.py").write_text(
        "AUTH_TOKEN_POLICY = 'rotated'\n", encoding="utf-8"
    )
    _commit(repo, "change authentication")

    report = derive_truth(repo, evidence_dir)

    assert report["effective_state"] == "completed"
    assert report["checks"]["exact_tree"] == "fail"
    assert "security_impact" in report["invalidation"]["categories"]
    assert "security_review_complete" in report["invalidation"]["affected_claims"]


def test_commit_identity_mismatch_alone_invalidates_receipt(tmp_path: Path) -> None:
    repo = _make_repo(tmp_path)
    evidence_dir = _write_complete_bundle(repo)
    for path in evidence_dir.glob("*.evidence.json"):
        _rewrite_receipt(
            path, lambda receipt: receipt["subject"].update({"commit_sha": "d" * 40})
        )

    report = derive_truth(repo, evidence_dir)

    assert report["effective_state"] == "completed"
    assert report["checks"]["exact_tree"] == "fail"


def test_legacy_0_5_receipt_is_rejected_with_distinct_classification(tmp_path: Path) -> None:
    repo = _make_repo(tmp_path)
    evidence_dir = _write_complete_bundle(repo)
    _rewrite_receipt(
        evidence_dir / "test.evidence.json",
        lambda receipt: receipt.update({"schema_version": "1.0"}),
    )

    report = derive_truth(repo, evidence_dir)

    assert "test:unsupported_schema_version" in report["issues"]
    assert report["claims"]["required_suites_green"]["effective_state"] == "completed"


def test_tree_identity_mismatch_alone_invalidates_receipt(tmp_path: Path) -> None:
    repo = _make_repo(tmp_path)
    evidence_dir = _write_complete_bundle(repo)
    for path in evidence_dir.glob("*.evidence.json"):
        _rewrite_receipt(
            path, lambda receipt: receipt["subject"].update({"tree_sha": "e" * 40})
        )

    report = derive_truth(repo, evidence_dir)

    assert report["effective_state"] == "completed"
    assert report["checks"]["exact_tree"] == "fail"


def test_finding_closure_requires_node_even_without_suite_manifest(tmp_path: Path) -> None:
    repo = _make_repo(tmp_path, finding_disposition="remediation_completed")
    evidence_dir = _write_complete_bundle(repo)
    _rewrite_receipt(
        evidence_dir / "test.evidence.json",
        lambda receipt: receipt["observations"].update(
            {"test_node_ids": [], "expected_test_node_ids": []}
        ),
    )

    report = derive_truth(repo, evidence_dir)

    assert report["effective_state"] == "completed"
    assert "finding_SEC-001_behavioral_proof_missing" in report["issues"]


def test_finding_proof_rejects_unexecuted_node_id(tmp_path: Path) -> None:
    repo = _make_repo(tmp_path, finding_disposition="remediation_completed")
    registry_path = repo / "governance/findings.yml"
    registry = yaml.safe_load(registry_path.read_text(encoding="utf-8"))
    registry["findings"][0]["proofs"][0]["node_id"] = (
        "tests/test_security.py::test_nonexistent"
    )
    _write_yaml(registry_path, registry)
    _commit(repo, "bind finding to an unexecuted test node")

    report = derive_truth(repo, _write_complete_bundle(repo))

    assert "finding_SEC-001_behavioral_proof_missing" in report["issues"]
    assert report["effective_state"] == "verified"


def test_terminal_claims_never_accept_allowlisted_tree_independent_evidence(
    tmp_path: Path,
) -> None:
    repo = _make_repo(tmp_path)
    evidence_dir = _write_complete_bundle(repo)
    policy_path = repo / "governance/evidence-policy.yml"
    policy = yaml.safe_load(policy_path.read_text(encoding="utf-8"))
    policy["settings"]["tree_independent_allowlist"] = [
        "test",
        "security-review",
        "reconcile",
    ]
    _write_yaml(policy_path, policy)
    for path in evidence_dir.glob("*.evidence.json"):
        _rewrite_receipt(
            path,
            lambda receipt: receipt["subject"].update({"binding": "tree_independent"}),
        )

    report = derive_truth(repo, evidence_dir)

    assert report["effective_state"] == "completed"
    assert report["status"] == "fail"


def test_dynamic_mandatory_workflow_matrix_fails_closed(tmp_path: Path) -> None:
    repo = _make_repo(tmp_path)
    workflow = repo / ".github/workflows/governance.yml"
    workflow.write_text(
        """name: governance
on:
  pull_request:
  push:
jobs:
  evidence:
    strategy:
      matrix:
        gate: "${{ fromJSON(needs.plan.outputs.gates) }}"
    steps:
      - run: python scripts/governance_evidence.py --repo-root . run --gate "${{ matrix.gate }}" --output .artifacts/bcf
""",
        encoding="utf-8",
    )
    _commit(repo, "dynamic workflow")
    evidence_dir = _write_complete_bundle(repo)

    report = derive_truth(repo, evidence_dir)

    assert report["status"] == "fail"
    assert any("matrix_dynamic" in issue for issue in report["issues"])
    assert any("workflow_gate_test_unresolved" == issue for issue in report["issues"])


def _configure_contract_shards(repo: Path, *, shards: str, shard_count: int) -> None:
    script = repo / ".github/scripts/capture.py"
    script.parent.mkdir(parents=True, exist_ok=True)
    script.write_text("# governed canonical-contract shard runner\n", encoding="utf-8")
    policy_path = repo / "governance/evidence-policy.yml"
    policy = yaml.safe_load(policy_path.read_text(encoding="utf-8"))
    policy["workflow_contract"]["gate_resolvers"] = [
        {
            "id": "fixture-shards",
            "kind": "canonical_contract_shards",
            "workflow_path": ".github/workflows/governance.yml",
            "job_id": "evidence",
            "matrix_key": "shard",
            "script_path": ".github/scripts/capture.py",
            "gate_contract_path": "governance/gate-contracts.yml",
            "profile_path": "governance-profile.yml",
        }
    ]
    _write_yaml(policy_path, policy)
    (repo / ".github/workflows/governance.yml").write_text(
        f"""name: governance
on:
  pull_request:
  push:
jobs:
  evidence:
    strategy:
      matrix:
        shard: {shards}
    steps:
      - run: python .github/scripts/capture.py --shard-index "${{{{ matrix.shard }}}}" --shard-count {shard_count} --output-root .artifacts/bcf
""",
        encoding="utf-8",
    )


def test_canonical_contract_shards_resolve_every_required_gate(tmp_path: Path) -> None:
    repo = _make_repo(tmp_path)
    _configure_contract_shards(repo, shards="[0, 1, 2, 3]", shard_count=4)
    _commit(repo, "use canonical contract shards")

    report = derive_truth(repo, _write_complete_bundle(repo))

    assert report["effective_state"] == "closed"
    assert report["checks"]["workflow_execution"] == "pass"


@pytest.mark.parametrize(
    ("shards", "shard_count", "issue"),
    [
        ("[0, 2, 3]", 3, "workflow_gate_resolver_fixture-shards_invalid"),
        ("[0, 1, 2, 3]", 3, "workflow_gate_resolver_fixture-shards_invocation_invalid"),
        ('"${{ fromJSON(needs.plan.outputs.shards) }}"', 4, "workflow_gate_resolver_fixture-shards_invalid"),
    ],
)
def test_canonical_contract_shards_fail_closed_on_ambiguous_coverage(
    tmp_path: Path, shards: str, shard_count: int, issue: str
) -> None:
    repo = _make_repo(tmp_path)
    _configure_contract_shards(repo, shards=shards, shard_count=shard_count)
    _commit(repo, "break canonical contract shards")

    report = derive_truth(repo, _write_complete_bundle(repo))

    assert report["status"] == "fail"
    assert issue in report["issues"]


def test_local_reusable_workflow_is_resolved(tmp_path: Path) -> None:
    repo = _make_repo(tmp_path)
    (repo / ".github/workflows/governance.yml").write_text(
        """name: governance
on:
  pull_request:
  push:
jobs:
  evidence:
    uses: ./.github/workflows/evidence.yml
""",
        encoding="utf-8",
    )
    (repo / ".github/workflows/evidence.yml").write_text(
        """name: evidence
on:
  workflow_call:
jobs:
  gates:
    strategy:
      matrix:
        gate: [test, security-review, reconcile]
    steps:
      - run: python scripts/governance_evidence.py --repo-root . run --gate "${{ matrix.gate }}" --output .artifacts/bcf
""",
        encoding="utf-8",
    )
    _commit(repo, "local reusable workflow")
    evidence_dir = _write_complete_bundle(repo)

    report = derive_truth(repo, evidence_dir)

    assert report["effective_state"] == "closed"
    assert report["checks"]["workflow_execution"] == "pass"


def test_regulated_profile_requires_and_accepts_dsse_ed25519_attestation(
    tmp_path: Path,
) -> None:
    repo = _make_repo(tmp_path)
    profile_path = repo / "governance-profile.yml"
    profile = yaml.safe_load(profile_path.read_text(encoding="utf-8"))
    profile["profile"]["selected"] = "regulated"
    _write_yaml(profile_path, profile)
    private_key = tmp_path / "verifier-private.pem"
    public_key = repo / "governance/trusted-verifier.pem"
    subprocess.run(
        ["openssl", "genpkey", "-algorithm", "Ed25519", "-out", str(private_key)],
        check=True,
        capture_output=True,
    )
    subprocess.run(
        [
            "openssl",
            "pkey",
            "-in",
            str(private_key),
            "-pubout",
            "-out",
            str(public_key),
        ],
        check=True,
        capture_output=True,
    )
    policy_path = repo / "governance/evidence-policy.yml"
    policy = yaml.safe_load(policy_path.read_text(encoding="utf-8"))
    policy["provenance"]["trusted_verifier_keys"] = {
        "release-verifier": "governance/trusted-verifier.pem"
    }
    _write_yaml(policy_path, policy)
    _commit(repo, "configure regulated verifier")
    evidence_dir = _write_complete_bundle(repo)

    unsigned = derive_truth(repo, evidence_dir)
    assert unsigned["effective_state"] == "verified"
    assert "regulated_attestation_required" in unsigned["issues"]

    attestation_path = evidence_dir / "release.attestation.json"
    attest_bundle(
        repo,
        evidence_dir,
        private_key,
        "release-verifier",
        "independent-reviewer",
        attestation_path,
        "human",
    )
    envelope = json.loads(attestation_path.read_text(encoding="utf-8"))
    assert envelope["payloadType"].endswith("+json")
    assert envelope["signatures"][0]["keyid"] == "release-verifier"

    signed = derive_truth(repo, evidence_dir)
    assert signed["effective_state"] == "closed"
    assert signed["status"] == "pass"


@pytest.mark.parametrize(
    ("relative_path", "expected_category"),
    [
        ("src/service.py", "source"),
        ("tests/test_service.py", "test"),
        (".github/workflows/extra.yml", "workflow"),
        ("audits/follow-up.md", "audit"),
        ("governance/change-note.yml", "governance"),
    ],
)
def test_governed_category_mutations_invalidate_current_evidence(
    tmp_path: Path, relative_path: str, expected_category: str
) -> None:
    repo = _make_repo(tmp_path)
    evidence_dir = _write_complete_bundle(repo)
    path = repo / relative_path
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text("changed: true\n", encoding="utf-8")
    _commit(repo, f"mutate {expected_category}")

    report = derive_truth(repo, evidence_dir)

    assert report["effective_state"] == "completed"
    assert expected_category in report["invalidation"]["categories"]
    assert report["invalidation"]["affected_phase"] == "P01"
    assert report["invalidation"]["affected_release"] is True


def test_correction_with_zero_finding_summary_fails_accounting(tmp_path: Path) -> None:
    repo = _make_repo(
        tmp_path,
        finding_disposition="remediation_completed",
        false_zero_summary=True,
    )

    report = derive_truth(repo, _write_complete_bundle(repo))

    assert report["findings"]["findings_total"] == 1
    assert "review_REV-001_findings_total_mismatch" in report["issues"]
    assert report["status"] == "fail"


def test_review_finding_ids_and_actor_provenance_must_reconcile(tmp_path: Path) -> None:
    repo = _make_repo(tmp_path, finding_disposition="remediation_completed")
    registry_path = repo / "governance/findings.yml"
    registry = yaml.safe_load(registry_path.read_text(encoding="utf-8"))
    registry["reviews"][0]["finding_ids"] = []
    registry["reviews"][0]["reviewer"] = _actor("different-reviewer")
    _write_yaml(registry_path, registry)
    _commit(repo, "break finding reconciliation")

    report = derive_truth(repo, _write_complete_bundle(repo))

    assert "review_REV-001_finding_ids_mismatch" in report["issues"]
    assert "review_REV-001_reviewer_provenance_mismatch" in report["issues"]


def test_authored_verified_cannot_be_promoted_by_consistent_yaml(tmp_path: Path) -> None:
    repo = _make_repo(tmp_path)
    evidence_dir = _write_complete_bundle(repo)
    path = repo / "phases/phase-01-log.yml"
    payload = yaml.safe_load(path.read_text(encoding="utf-8"))
    payload["document"]["status"] = "verified"
    _write_yaml(path, payload)

    with pytest.raises(TruthfulnessError, match="verified and closed are computed"):
        derive_truth(repo, evidence_dir)
