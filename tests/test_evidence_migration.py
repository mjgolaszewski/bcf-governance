from __future__ import annotations

import hashlib
from pathlib import Path
from typing import Any

import yaml

from scripts.migrate_governance_evidence import migration_plan


def _write_yaml(path: Path, payload: dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(yaml.safe_dump(payload, sort_keys=False), encoding="utf-8")


def _seed_legacy_repo(tmp_path: Path) -> Path:
    repo = tmp_path / "repo"
    _write_yaml(
        repo / "governance-profile.yml",
        {
            "release_gate_profile": {
                "gates": {
                    "test": {"target": "test", "status": "required", "command_policy": "automated_tests"},
                    "runtime": {"target": "runtime-smoke", "status": "required", "command_policy": "runtime_smoke"},
                    "security": {"target": "security-review", "status": "required", "command_policy": "security_vulnerability_scan"},
                }
            }
        },
    )
    _write_yaml(
        repo / "phases/phase-01-log.yml",
        {
            "document": {"kind": "phase_execution_log", "status": "closed"},
            "required_suites_green": ["make test"],
            "health_checks_green": True,
            "security_review_complete": True,
            "zero_findings": True,
        },
    )
    _write_yaml(
        repo / "phases/phase-01-hotfix01.yml",
        {
            "document": {"kind": "hotfix_execution_log", "status": "closed"},
            "reconciliation": {
                "required_before_closeout": ["record hotfix in active ledger"]
            },
        },
    )
    _write_yaml(
        repo / "plans/phase-01-workitems.yml",
        {"workitems": [{"id": "P01-W01", "status": "DONE"}]},
    )
    _write_yaml(
        repo / "plans/phase-ledger.yml",
        {
            "active_phase": {"lifecycle_status": "verified"},
            "release_trains": {"release_1": {"status": "release_ready"}},
            "release_readiness": {"status": "release_ready", "validating_command": "make release-check"},
        },
    )
    _write_yaml(
        repo / "plans/phase-history.yml",
        {
            "entries": [
                {
                    "phase_id": "P00",
                    "status": "closed",
                    "archived_artifacts": [],
                }
            ]
        },
    )
    return repo


def test_migration_downgrades_self_attestation_without_inventing_evidence(tmp_path: Path) -> None:
    repo = _seed_legacy_repo(tmp_path)
    source = repo / "phases/phase-01-log.yml"
    source_digest = hashlib.sha256(source.read_bytes()).hexdigest()

    report = migration_plan(repo, apply=True)

    log = yaml.safe_load(source.read_text(encoding="utf-8"))
    assert log["document"]["status"] == "completed"
    assert "required_suites_green" not in log
    assert "health_checks_green" not in log
    assert "security_review_complete" not in log
    assert "zero_findings" not in log
    assert log["closeout_requirements"]["claims"]["required_suites_green"] == {
        "required_evidence": ["test"]
    }
    assert log["closeout_requirements"]["claims"]["workitems_closed"] == {
        "required_evidence": ["governance-validate"]
    }
    hotfix = yaml.safe_load(
        (repo / "phases/phase-01-hotfix01.yml").read_text(encoding="utf-8")
    )
    assert hotfix["document"]["status"] == "completed"
    assert "reconciliation" not in hotfix
    assert hotfix["closeout_requirements"]["reconciliation"] == {
        "required_evidence": ["governance-validate", "governance-exposure-scan"]
    }
    ledger = yaml.safe_load((repo / "plans/phase-ledger.yml").read_text(encoding="utf-8"))
    assert ledger["active_phase"]["lifecycle_status"] == "completed"
    assert ledger["release_trains"]["release_1"]["status"] == "completed"
    assert "status" not in ledger["release_readiness"]
    assert ledger["release_readiness"]["computed_by"] == "bcf truth"
    history = yaml.safe_load((repo / "plans/phase-history.yml").read_text(encoding="utf-8"))
    assert history["entries"][0]["status"] == "completed"
    assert history["entries"][0]["legacy_terminal_status"] == "closed"
    migration = yaml.safe_load(
        (repo / "governance/migrations/evidence-integrity-v1.yml").read_text(encoding="utf-8")
    )
    legacy = {entry["path"]: entry for entry in migration["legacy_records"]}
    assert legacy["phases/phase-01-log.yml"]["source_sha256"] == source_digest
    assert legacy["phases/phase-01-log.yml"]["authoritative"] is False
    assert "phases/phase-01-log.yml" in report["changed_paths"]


def test_migration_is_idempotent_and_previewable(tmp_path: Path) -> None:
    repo = _seed_legacy_repo(tmp_path)

    preview = migration_plan(repo, apply=False)
    assert preview["changed_paths"]
    assert yaml.safe_load((repo / "phases/phase-01-log.yml").read_text(encoding="utf-8"))[
        "document"
    ]["status"] == "closed"

    migration_plan(repo, apply=True)
    second = migration_plan(repo, apply=True)

    assert second["changed_paths"] == []


def test_migration_preserves_valid_historical_computation_as_derived_state(
    tmp_path: Path,
) -> None:
    repo = _seed_legacy_repo(tmp_path)
    history_path = repo / "plans/phase-history.yml"
    history = yaml.safe_load(history_path.read_text(encoding="utf-8"))
    history["entries"][0]["verification_snapshot"] = {
        "commit_sha": "a" * 40,
        "tree_sha": "b" * 40,
        "truth_report_sha256": "c" * 64,
        "evidence_bundle_sha256": "d" * 64,
        "durable_ref": "ci-artifact://bcf/P00",
        "verifier": {"kind": "workflow", "id": "release-verifier"},
    }
    _write_yaml(history_path, history)

    migration_plan(repo, apply=True)

    migrated = yaml.safe_load(history_path.read_text(encoding="utf-8"))["entries"][0]
    assert migrated["status"] == "completed"
    assert migrated["derived_state_at_capture"] == "closed"
    assert "legacy_terminal_status" not in migrated
