from __future__ import annotations

import json
from pathlib import Path

import pytest

from bcf_governance.tooling.release_receipts import (
    ReleaseReceiptError,
    build_release_receipt,
    emit_release_receipt,
)


REPO_ROOT = Path(__file__).resolve().parents[1]
SHA = "a" * 40
TREE = "b" * 40
DIGEST = "c" * 64


def _write(path: Path, value: str) -> Path:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(value, encoding="utf-8")
    return path


def _inputs(tmp_path: Path) -> dict[str, object]:
    evidence_dir = tmp_path / "evidence"
    truth_path = _write(evidence_dir / "truth-report.json", "{}\n")
    certification_path = _write(tmp_path / "ci-certification.json", "{}\n")
    session_path = _write(tmp_path / "evidence-session.json", "{}\n")
    wheel = _write(tmp_path / "bcf-0.7.0.whl", "wheel")
    truth = {
        "status": "pass",
        "release_readiness": {"effective_state": "closed"},
        "subject": {
            "commit_sha": SHA,
            "tree_sha": TREE,
            "tracked_clean": True,
            "untracked_clean": True,
        },
        "bundle_sha256": DIGEST,
    }
    certification = {
        "repository": {"provider": "github", "repository_id": "42"},
        "subject": {
            "checkout_sha": SHA,
            "tree_sha": TREE,
            "current_default_main_sha": SHA,
        },
        "admission": {
            "admission_ordinal": "101",
            "control_plane_run_id": "run-101",
            "control_plane_run_attempt": 2,
        },
        "generated_at": "2026-08-30T00:00:00Z",
    }
    return {
        "evidence_dir": evidence_dir,
        "truth_path": truth_path,
        "certification_path": certification_path,
        "session_path": session_path,
        "wheel": wheel,
        "truth": truth,
        "certification": certification,
        "verification": {"status": "pass", "computed_state": "certified"},
        "output": tmp_path / "release" / "release.evidence.json",
    }


def _build(values: dict[str, object]):
    return build_release_receipt(
        REPO_ROOT,
        truth_report=values["truth"],  # type: ignore[arg-type]
        truth_report_path=values["truth_path"],  # type: ignore[arg-type]
        certification=values["certification"],  # type: ignore[arg-type]
        certification_path=values["certification_path"],  # type: ignore[arg-type]
        certification_verification=values["verification"],  # type: ignore[arg-type]
        session_manifest_path=values["session_path"],  # type: ignore[arg-type]
        evidence_dir=values["evidence_dir"],  # type: ignore[arg-type]
        release_artifacts=[values["wheel"]],  # type: ignore[list-item]
        output_path=values["output"],  # type: ignore[arg-type]
    )


def test_release_receipt_is_output_only_and_binds_exact_artifacts(tmp_path: Path) -> None:
    values = _inputs(tmp_path)
    receipt = _build(values)

    emit_release_receipt(values["output"], receipt)  # type: ignore[arg-type]
    stored = json.loads(values["output"].read_text(encoding="utf-8"))  # type: ignore[union-attr]

    assert stored["kind"] == "release"
    assert stored["behavioral_probes"] == []
    assert stored["observations"]["acyclic_construction"] == {
        "release_receipt_was_truth_input": False,
        "output_outside_evidence_dir": True,
    }
    assert {value["path"] for value in stored["artifacts"]} == {
        "truth-report.json",
        "ci-certification.json",
        "evidence-session.json",
        "bcf-0.7.0.whl",
    }


def test_release_receipt_cannot_be_written_into_truth_inputs(tmp_path: Path) -> None:
    values = _inputs(tmp_path)
    values["output"] = values["evidence_dir"] / "release.evidence.json"  # type: ignore[operator]

    with pytest.raises(ReleaseReceiptError, match="outside truth input"):
        _build(values)


def test_failed_truth_or_uncertified_ci_cannot_emit_release(tmp_path: Path) -> None:
    values = _inputs(tmp_path)
    values["truth"]["status"] = "fail"  # type: ignore[index]
    with pytest.raises(ReleaseReceiptError, match="passing closed truth"):
        _build(values)

    values = _inputs(tmp_path / "second")
    values["verification"] = {"status": "pass", "computed_state": "failed"}
    with pytest.raises(ReleaseReceiptError, match="independently certified"):
        _build(values)


def test_release_subject_must_match_exact_commit_and_tree(tmp_path: Path) -> None:
    values = _inputs(tmp_path)
    values["certification"]["subject"]["checkout_sha"] = "d" * 40  # type: ignore[index]

    with pytest.raises(ReleaseReceiptError, match="subjects must match exactly"):
        _build(values)


def test_release_receipt_publication_is_exclusive(tmp_path: Path) -> None:
    values = _inputs(tmp_path)
    receipt = _build(values)
    emit_release_receipt(values["output"], receipt)  # type: ignore[arg-type]

    with pytest.raises(ReleaseReceiptError, match="already exists"):
        emit_release_receipt(values["output"], receipt)  # type: ignore[arg-type]
