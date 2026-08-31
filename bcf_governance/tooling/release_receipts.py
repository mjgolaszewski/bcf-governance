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


def _load_json(path: Path, *, label: str) -> dict[str, Any]:
    _regular(path, label=label)
    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise ReleaseReceiptError(f"{label} is invalid JSON") from exc
    if not isinstance(payload, dict):
        raise ReleaseReceiptError(f"{label} must contain an object")
    return payload


def build_trusted_release_receipt(
    repo_root: Path,
    *,
    certification: dict[str, Any],
    certification_path: Path,
    certification_verification: dict[str, Any],
    session_manifest_path: Path,
    authorization_path: Path,
    build_manifest_path: Path,
    verification_path: Path,
    release_artifacts: Iterable[Path],
    collector_identity: dict[str, str],
    output_path: Path,
) -> ReleaseReceipt:
    """Build the sole v1.1 release receipt from verified, acyclic role outputs."""

    if certification_verification.get("status") != "pass" or (
        certification_verification.get("computed_state") != "certified"
    ):
        raise ReleaseReceiptError("trusted release receipt requires certified exact-main CI")
    if certification.get("authority_contract_version") != "1.1":
        raise ReleaseReceiptError("trusted release receipt requires authority version 1.1")
    authorization = _load_json(authorization_path, label="release authorization")
    build = _load_json(build_manifest_path, label="release build manifest")
    verification = _load_json(verification_path, label="release verification")
    subject = {
        "commit_sha": certification["subject"]["checkout_sha"],
        "tree_sha": certification["subject"]["tree_sha"],
    }
    if authorization.get("subject") != subject or build.get("subject") != subject or (
        verification.get("subject") != subject
    ):
        raise ReleaseReceiptError("release role subjects do not match exact-main certification")
    admission = certification["admission"]
    exact_main = authorization.get("exact_main")
    if not isinstance(exact_main, dict) or exact_main != {
        "admission_ordinal": str(admission["admission_ordinal"]),
        "run_id": str(admission["control_plane_run_id"]),
        "run_attempt": int(admission["control_plane_run_attempt"]),
        "certification_sha256": _sha256(certification_path),
        "session_sha256": _sha256(session_manifest_path),
    }:
        raise ReleaseReceiptError("release authorization is not bound to exact-main authority")
    if build.get("authorization_sha256") != _sha256(authorization_path):
        raise ReleaseReceiptError("release build is not bound to its authorization")
    verified_build = verification.get("build")
    if not isinstance(verified_build, dict) or (
        verified_build.get("manifest_sha256") != _sha256(build_manifest_path)
        or verified_build.get("run_id") != build.get("run_id")
        or verified_build.get("run_attempt") != build.get("run_attempt")
    ):
        raise ReleaseReceiptError("release verification is not bound to the exact build")
    if verification.get("status") != "passed":
        raise ReleaseReceiptError("release verifier did not pass")
    release_paths = tuple(release_artifacts)
    if not release_paths or len({path.name for path in release_paths}) != len(release_paths):
        raise ReleaseReceiptError("trusted release asset inventory is empty or duplicated")
    verified_assets = verification.get("assets")
    actual_assets = {path.name: _sha256(_regular(path, label=path.name)) for path in release_paths}
    if verified_assets != actual_assets:
        raise ReleaseReceiptError("trusted release assets differ from verifier output")
    controller = authorization.get("controller")
    dependency = verification.get("dependency_closure")
    if not isinstance(controller, dict) or not isinstance(dependency, dict):
        raise ReleaseReceiptError("controller or dependency closure identity is missing")
    materials = [
        _artifact(certification_path, name="ci-certification.json", media_type="application/json"),
        _artifact(session_manifest_path, name="evidence-session.json", media_type="application/json"),
        _artifact(authorization_path, name="release-authorization.json", media_type="application/json"),
        _artifact(build_manifest_path, name="release-build-manifest.json", media_type="application/json"),
        _artifact(verification_path, name="release-verification.json", media_type="application/json"),
    ]
    materials.extend(
        _artifact(path, name=path.name, media_type="application/octet-stream")
        for path in release_paths
    )
    timestamp = datetime.now(UTC).isoformat().replace("+00:00", "Z")
    receipt = {
        "schema_version": "2.0",
        "kind": "release",
        "evidence_id": f"release-{subject['commit_sha'][:12]}",
        "gate_id": "ci-certification",
        "producer": {"kind": "workflow", "id": "bcf-trusted-release-collector"},
        "invocation": {
            "argv": ["bcf", "ci-github", "release", "collect"],
            "cwd": ".",
            "environment": {},
            "workflow": {
                "provider": "github",
                "path": collector_identity["workflow_path"],
                "job": "trusted-release-collector",
                "run_id": collector_identity["run_id"],
                "run_attempt": collector_identity["run_attempt"],
                "matrix": {},
            },
        },
        "subject": {
            **subject,
            "execution_tree_sha": subject["tree_sha"],
            "binding": "exact_tree",
            "tracked_clean": True,
            "untracked_clean": True,
            "status_porcelain_sha256": EMPTY_SHA256,
        },
        "artifacts": materials,
        "observations": {
            "authority_contract_version": "1.1",
            "ci_computed_state": "certified",
            "admission_ordinal": str(admission["admission_ordinal"]),
            "exact_main_run": {
                "run_id": str(admission["control_plane_run_id"]),
                "run_attempt": int(admission["control_plane_run_attempt"]),
            },
            "release_run": {
                "run_id": str(build["run_id"]),
                "run_attempt": int(build["run_attempt"]),
            },
            "build_artifact": {
                "id": str(verified_build["artifact_id"]),
                "provider_digest": str(verified_build["provider_digest"]),
            },
            "verifier_run": verification["verifier"],
            "controller": controller,
            "dependency_closure": dependency,
            "release_artifacts": materials[5:],
            "acyclic_construction": {
                "release_receipt_was_truth_input": False,
                "candidate_authored_receipt_accepted": False,
                "collector_executed_release_code": False,
            },
        },
        "behavioral_probes": [],
        "result": "passed",
        "started_at": str(build["started_at"]),
        "timestamp": timestamp,
    }
    _validate_receipt(repo_root, receipt)
    if output_path in {
        certification_path,
        session_manifest_path,
        authorization_path,
        build_manifest_path,
        verification_path,
        *release_paths,
    }:
        raise ReleaseReceiptError("trusted release receipt cannot overwrite an input")
    return ReleaseReceipt(receipt)
