from __future__ import annotations

from copy import deepcopy
import hashlib
import json
from pathlib import Path

import pytest

from bcf_governance.tooling.ci_authority_certification import (
    CICertificationError,
    normalize_ci_certification,
    verify_ci_certification,
)


REPO_ROOT = Path(__file__).resolve().parents[1]
SHA_A = "a" * 40
SHA_B = "b" * 40
TREE_A = "c" * 40
TREE_B = "d" * 40
WORKFLOW_DIGEST = "e" * 64
SESSION_ID = "f" * 32
CAPTURED_AT = "2026-08-30T00:00:00Z"


def _authority() -> dict[str, object]:
    return {
        "schema_version": "1.0",
        "repository": {"provider": "github", "repository_id": "42"},
        "producers": [
            {
                "producer_id": producer_id,
                "workflow": {
                    "workflow_id": workflow_id,
                    "active_path": f".github/workflows/{producer_id}.yml",
                    "trusted_workflow_blob_oid": SHA_A,
                    "trusted_workflow_sha256": WORKFLOW_DIGEST,
                    "trusted_workflow_definition_commit": SHA_A,
                    "allowed_events": ["workflow_dispatch", "repository_dispatch"],
                },
                "expected_jobs": [
                    {"job_id": "test", "matrix": {"python": "3.12"}}
                ],
            }
            for producer_id, workflow_id in (("unit", "101"), ("pack", "102"))
        ],
        "trusted_external_inputs": [],
    }


def _admission(
    producer_id: str,
    *,
    ordinal: int,
    conclusion: str = "success",
    checkout_sha: str = SHA_A,
    tree_sha: str = TREE_A,
    event: str = "workflow_dispatch",
) -> dict[str, object]:
    workflow_id = "101" if producer_id == "unit" else "102"
    return {
        "admission_ordinal": str(ordinal),
        "control_plane_run_id": f"control-{ordinal}",
        "control_plane_run_attempt": 1,
        "dispatch_sequence": ordinal,
        "candidate": {"checkout_sha": checkout_sha, "tree_sha": tree_sha},
        "collection_complete": True,
        "producer_run": {
            "producer_id": producer_id,
            "run_id": f"run-{ordinal}-{producer_id}",
            "workflow": {
                "provider": "github",
                "repository_id": "42",
                "workflow_id": workflow_id,
                "active_path": f".github/workflows/{producer_id}.yml",
                "trusted_workflow_blob_oid": SHA_A,
                "trusted_workflow_sha256": WORKFLOW_DIGEST,
                "trusted_workflow_definition_commit": SHA_A,
                "event": event,
            },
            "attempts": [
                {
                    "run_attempt": 1,
                    "status": "completed",
                    "conclusion": conclusion,
                    "jobs": [
                        {
                            "job_id": "test",
                            "matrix": {"python": "3.12"},
                            "status": "completed",
                            "conclusion": conclusion,
                        }
                    ],
                }
            ],
        },
    }


def _snapshot(
    producer_id: str,
    *,
    conclusions: tuple[str, ...] = ("success",),
    current_sha: str = SHA_A,
    current_tree: str = TREE_A,
    admitted_sha: str = SHA_A,
    admitted_tree: str = TREE_A,
    event: str = "workflow_dispatch",
) -> dict[str, object]:
    return {
        "schema_version": "1.0",
        "producer_id": producer_id,
        "repository": {"provider": "github", "repository_id": "42"},
        "authentication": {
            "collector_id": "trusted-collector",
            "provider_api_verified": True,
            "captured_at": CAPTURED_AT,
        },
        "current_default_main": {
            "checkout_sha": current_sha,
            "tree_sha": current_tree,
        },
        "admissions": [
            _admission(
                producer_id,
                ordinal=index,
                conclusion=conclusion,
                checkout_sha=admitted_sha,
                tree_sha=admitted_tree,
                event=event,
            )
            for index, conclusion in enumerate(conclusions, start=1)
        ],
    }


def _write_json(path: Path, payload: dict[str, object]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n", encoding="utf-8")


def _digest(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def _material(
    tmp_path: Path,
    *,
    snapshots: dict[str, dict[str, object]] | None = None,
) -> tuple[Path, Path, Path, dict[str, object]]:
    root = tmp_path / "certification"
    authority_path = root / "ci-authority.json"
    certification_path = root / "ci-certification.json"
    session_path = root / "evidence-session.json"
    authority = _authority()
    _write_json(authority_path, authority)
    snapshots = snapshots or {
        producer_id: _snapshot(producer_id) for producer_id in ("unit", "pack")
    }
    descriptors: list[dict[str, object]] = []
    for producer_id, snapshot in sorted(snapshots.items()):
        path = root / "raw" / f"{producer_id}.json"
        _write_json(path, snapshot)
        descriptors.append(
            {
                "producer_id": producer_id,
                "artifact_path": f"raw/{producer_id}.json",
                "sha256": _digest(path),
                "authenticated_at": CAPTURED_AT,
            }
        )
    highest = max(
        int(value["admission_ordinal"])
        for value in next(iter(snapshots.values()))["admissions"]  # type: ignore[index]
    )
    session = {
        "schema_version": "1.0",
        "session_id": SESSION_ID,
        "subject": {"commit_sha": SHA_A, "tree_sha": TREE_A},
        "profile": "standard",
        "profile_contract_version": "2.0",
        "producer": {
            "kind": "workflow",
            "provider": "github",
            "repository": "mjgolaszewski/bcf-governance",
            "repository_id": "42",
            "run_id": f"control-{highest}",
            "run_attempt": "1",
            "producer_id": "trusted-control-plane",
        },
        "expected_gate_inventory": ["ci-certification"],
        "expected_producer_inventory": ["pack", "unit"],
        "created_at": CAPTURED_AT,
        "session_root_policy": {
            "mode": "0700",
            "root_kind": "external",
            "immutable_manifest": True,
        },
    }
    _write_json(session_path, session)
    evidence_session = {
        "session_id": SESSION_ID,
        "manifest_sha256": _digest(session_path),
        "run_id": f"control-{highest}",
        "run_attempt": 1,
    }
    certification = normalize_ci_certification(
        REPO_ROOT,
        authority=authority,
        snapshots=snapshots.values(),
        raw_snapshot_descriptors=descriptors,
        evidence_session=evidence_session,
        generated_at=CAPTURED_AT,
    )
    _write_json(certification_path, certification)
    return authority_path, certification_path, session_path, certification


def test_authenticated_snapshots_normalize_and_truth_recomputes_certified(
    tmp_path: Path,
) -> None:
    authority, certification, session, report = _material(tmp_path)

    verified = verify_ci_certification(
        REPO_ROOT,
        authority_path=authority,
        certification_path=certification,
        session_manifest_path=session,
    )

    assert report["state"] == "active"
    assert verified.status == "pass"
    assert verified.computed_state == "certified"
    assert verified.selected_attempts == (("pack", 1), ("unit", 1))


def test_later_admitted_failure_revokes_earlier_success(tmp_path: Path) -> None:
    snapshots = {
        producer_id: _snapshot(producer_id, conclusions=("success", "failure"))
        for producer_id in ("unit", "pack")
    }
    authority, certification, session, report = _material(
        tmp_path, snapshots=snapshots
    )

    verified = verify_ci_certification(
        REPO_ROOT,
        authority_path=authority,
        certification_path=certification,
        session_manifest_path=session,
    )

    assert report["state"] == "failed"
    assert verified.status == "fail"
    assert verified.computed_state == "failed"
    assert any("attempt_failure" in reason for reason in verified.reasons)


@pytest.mark.parametrize(
    ("current_sha", "current_tree", "admitted_sha", "admitted_tree"),
    [
        (SHA_B, TREE_A, SHA_A, TREE_A),
        (SHA_A, TREE_B, SHA_A, TREE_A),
    ],
)
def test_moved_commit_or_tree_is_obsolete(
    tmp_path: Path,
    current_sha: str,
    current_tree: str,
    admitted_sha: str,
    admitted_tree: str,
) -> None:
    snapshots = {
        producer_id: _snapshot(
            producer_id,
            current_sha=current_sha,
            current_tree=current_tree,
            admitted_sha=admitted_sha,
            admitted_tree=admitted_tree,
        )
        for producer_id in ("unit", "pack")
    }
    _, _, _, report = _material(tmp_path, snapshots=snapshots)

    assert report["state"] == "obsolete"
    assert report["evaluation"]["reasons"] == ["default_main_moved"]


def test_snapshot_bytes_are_hash_bound(tmp_path: Path) -> None:
    authority, certification, session, _ = _material(tmp_path)
    snapshot_path = certification.parent / "raw/unit.json"
    snapshot = json.loads(snapshot_path.read_text(encoding="utf-8"))
    snapshot["authentication"]["collector_id"] = "forged"
    _write_json(snapshot_path, snapshot)

    with pytest.raises(CICertificationError, match="digest mismatch"):
        verify_ci_certification(
            REPO_ROOT,
            authority_path=authority,
            certification_path=certification,
            session_manifest_path=session,
        )


def test_normalized_report_cannot_diverge_from_provider_state(tmp_path: Path) -> None:
    authority, certification, session, _ = _material(tmp_path)
    report = json.loads(certification.read_text(encoding="utf-8"))
    report["evaluation"]["selected_attempts"][0]["run_attempt"] = 2
    _write_json(certification, report)

    with pytest.raises(CICertificationError, match="selected attempts"):
        verify_ci_certification(
            REPO_ROOT,
            authority_path=authority,
            certification_path=certification,
            session_manifest_path=session,
        )


def test_failed_report_reason_is_independently_recomputed(tmp_path: Path) -> None:
    snapshots = {
        producer_id: _snapshot(producer_id, conclusions=("success", "failure"))
        for producer_id in ("unit", "pack")
    }
    authority, certification, session, _ = _material(tmp_path, snapshots=snapshots)
    report = json.loads(certification.read_text(encoding="utf-8"))
    report["evaluation"]["reasons"] = ["forged_failure_reason"]
    _write_json(certification, report)

    with pytest.raises(CICertificationError, match="independently recomputed"):
        verify_ci_certification(
            REPO_ROOT,
            authority_path=authority,
            certification_path=certification,
            session_manifest_path=session,
        )


def test_session_subject_and_producer_inventory_are_bound(tmp_path: Path) -> None:
    authority, certification, session, _ = _material(tmp_path)
    manifest = json.loads(session.read_text(encoding="utf-8"))
    manifest["subject"]["commit_sha"] = SHA_B
    _write_json(session, manifest)
    report = json.loads(certification.read_text(encoding="utf-8"))
    report["evidence_session"]["manifest_sha256"] = _digest(session)
    _write_json(certification, report)

    with pytest.raises(CICertificationError, match="session subject"):
        verify_ci_certification(
            REPO_ROOT,
            authority_path=authority,
            certification_path=certification,
            session_manifest_path=session,
        )


def test_snapshots_must_agree_on_admission_authority(tmp_path: Path) -> None:
    snapshots = {
        producer_id: _snapshot(producer_id) for producer_id in ("unit", "pack")
    }
    snapshots["pack"] = deepcopy(snapshots["pack"])
    snapshots["pack"]["admissions"][0]["dispatch_sequence"] = 99  # type: ignore[index]

    with pytest.raises(CICertificationError, match="disagree on admission"):
        _material(tmp_path, snapshots=snapshots)


def test_untrusted_event_cannot_enter_admission_order(tmp_path: Path) -> None:
    snapshots = {
        producer_id: _snapshot(producer_id, event="pull_request_target")
        for producer_id in ("unit", "pack")
    }

    with pytest.raises(CICertificationError, match="not authenticated"):
        _material(tmp_path, snapshots=snapshots)
