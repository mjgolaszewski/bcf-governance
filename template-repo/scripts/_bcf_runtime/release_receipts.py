"""Construct output-only schema-2 release receipts after truth succeeds."""

from __future__ import annotations

from dataclasses import dataclass
from datetime import UTC, datetime
import hashlib
import json
import os
from pathlib import Path
from typing import Any, Iterable

from jsonschema import Draft202012Validator


class ReleaseReceiptError(ValueError):
    """Raised when release inputs are invalid or construction would be cyclic."""


@dataclass(frozen=True)
class ReleaseReceipt:
    """A validated output-only release receipt payload."""

    payload: dict[str, Any]


EMPTY_SHA256 = hashlib.sha256(b"").hexdigest()


def _sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _regular(path: Path, *, label: str) -> Path:
    if path.is_symlink() or not path.is_file():
        raise ReleaseReceiptError(f"{label} must be a regular file")
    return path


def _artifact(path: Path, *, name: str, media_type: str) -> dict[str, str]:
    _regular(path, label=name)
    return {"path": name, "media_type": media_type, "sha256": _sha256(path)}


def _outside(child: Path, parent: Path) -> bool:
    try:
        child.resolve().relative_to(parent.resolve())
    except ValueError:
        return True
    return False


def _validate_receipt(repo_root: Path, receipt: dict[str, Any]) -> None:
    schema = json.loads(
        (repo_root / "schemas/evidence-receipt.schema.json").read_text(encoding="utf-8")
    )
    errors = sorted(
        Draft202012Validator(schema).iter_errors(receipt),
        key=lambda error: ([str(value) for value in error.absolute_path], error.message),
    )
    if errors:
        first = errors[0]
        location = ".".join(str(value) for value in first.absolute_path)
        raise ReleaseReceiptError(
            f"release receipt {location or '<root>'}: {first.message}"
        )


def build_release_receipt(
    repo_root: Path,
    *,
    truth_report: dict[str, Any],
    truth_report_path: Path,
    certification: dict[str, Any],
    certification_path: Path,
    certification_verification: dict[str, Any],
    session_manifest_path: Path,
    evidence_dir: Path,
    release_artifacts: Iterable[Path],
    output_path: Path,
) -> ReleaseReceipt:
    """Build but do not publish a receipt from already-verified input artifacts."""

    if not _outside(output_path, evidence_dir):
        raise ReleaseReceiptError("release receipt output must be outside truth input evidence")
    if output_path.resolve() in {
        truth_report_path.resolve(),
        certification_path.resolve(),
        session_manifest_path.resolve(),
    }:
        raise ReleaseReceiptError("release receipt cannot overwrite one of its own inputs")
    if truth_report.get("status") != "pass" or truth_report.get(
        "release_readiness", {}
    ).get("effective_state") != "closed":
        raise ReleaseReceiptError("release receipt requires passing closed truth")
    if certification_verification.get("status") != "pass" or certification_verification.get(
        "computed_state"
    ) != "certified":
        raise ReleaseReceiptError("release receipt requires independently certified CI state")
    subject = truth_report.get("subject")
    cert_subject = certification.get("subject")
    if not isinstance(subject, dict) or not isinstance(cert_subject, dict) or (
        subject.get("commit_sha") != cert_subject.get("checkout_sha")
        or subject.get("tree_sha") != cert_subject.get("tree_sha")
    ):
        raise ReleaseReceiptError("truth and CI certification subjects must match exactly")
    release_paths = tuple(release_artifacts)
    if not release_paths:
        raise ReleaseReceiptError("release receipt requires at least one release artifact")
    names = [path.name for path in release_paths]
    reserved = {"truth-report.json", "ci-certification.json", "evidence-session.json"}
    if len(set(names)) != len(names) or set(names).intersection(reserved):
        raise ReleaseReceiptError("release artifact names must be unique and non-reserved")
    artifacts = [
        _artifact(
            truth_report_path,
            name="truth-report.json",
            media_type="application/json",
        ),
        _artifact(
            certification_path,
            name="ci-certification.json",
            media_type="application/json",
        ),
        _artifact(
            session_manifest_path,
            name="evidence-session.json",
            media_type="application/json",
        ),
    ]
    artifacts.extend(
        _artifact(path, name=path.name, media_type="application/octet-stream")
        for path in release_paths
    )
    admission = certification["admission"]
    generated_at = datetime.now(UTC).isoformat().replace("+00:00", "Z")
    receipt = {
        "schema_version": "2.0",
        "kind": "release",
        "evidence_id": f"release-{subject['commit_sha'][:12]}",
        "gate_id": "ci-certification",
        "producer": {"kind": "workflow", "id": "bcf-truth"},
        "invocation": {
            "argv": ["bcf", "truth"],
            "cwd": ".",
            "environment": {},
            "workflow": {
                "provider": str(certification["repository"]["provider"]),
                "path": "trusted-control-plane",
                "job": "truth-finalizer",
                "run_id": str(admission["control_plane_run_id"]),
                "run_attempt": str(admission["control_plane_run_attempt"]),
                "matrix": {},
            },
        },
        "subject": {
            "commit_sha": str(subject["commit_sha"]),
            "tree_sha": str(subject["tree_sha"]),
            "execution_tree_sha": str(subject["tree_sha"]),
            "binding": "exact_tree",
            "tracked_clean": True,
            "untracked_clean": True,
            "status_porcelain_sha256": EMPTY_SHA256,
        },
        "artifacts": artifacts,
        "observations": {
            "truth_report_sha256": artifacts[0]["sha256"],
            "ci_certification_sha256": artifacts[1]["sha256"],
            "session_manifest_sha256": artifacts[2]["sha256"],
            "evidence_bundle_sha256": truth_report["bundle_sha256"],
            "admission_ordinal": str(admission["admission_ordinal"]),
            "ci_computed_state": certification_verification["computed_state"],
            "release_artifacts": artifacts[3:],
            "acyclic_construction": {
                "release_receipt_was_truth_input": False,
                "output_outside_evidence_dir": True,
            },
        },
        "behavioral_probes": [],
        "result": "passed",
        "started_at": str(certification["generated_at"]),
        "timestamp": generated_at,
    }
    _validate_receipt(repo_root, receipt)
    return ReleaseReceipt(receipt)


def emit_release_receipt(output_path: Path, receipt: ReleaseReceipt) -> None:
    """Write a release receipt once; callers must construct it after truth output."""

    output_path.parent.mkdir(parents=True, exist_ok=True)
    encoded = (json.dumps(receipt.payload, indent=2, sort_keys=True) + "\n").encode()
    try:
        descriptor = os.open(output_path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    except FileExistsError as exc:
        raise ReleaseReceiptError("release receipt output already exists") from exc
    with os.fdopen(descriptor, "wb") as stream:
        stream.write(encoded)
        stream.flush()
        os.fsync(stream.fileno())
