"""Decode immutable prior receipts after caller-authenticated bundle custody.

This boundary verifies transported bytes; it never grants reuse or authority.
"""

from __future__ import annotations

import hashlib
import json
from pathlib import Path, PurePosixPath
import re
from typing import Any, Mapping

import yaml  # type: ignore[import-untyped]

from .ci_github_bundle import canonical_json
from .evidence_execution import EvidenceError


def _digest(raw: bytes) -> str:
    return hashlib.sha256(raw).hexdigest()


def validate_transport_material(
    files: Mapping[str, bytes], manifest: Mapping[str, Any],
    current_subject: Mapping[str, Any] | None,
) -> None:
    """Verify trusted transport's exact path/digest inventory and main binding."""
    if manifest.get("schema_version") != "1.0" or manifest.get("kind") != "prior_evidence_transport":
        raise EvidenceError("prior evidence transport contract is invalid")
    main = manifest.get("main")
    if not isinstance(main, dict) or current_subject is None or any(
        main.get(field) != current_subject.get(field)
        for field in ("commit_sha", "tree_sha")
    ):
        raise EvidenceError("prior evidence transport main subject is not current")
    artifacts = manifest.get("artifacts")
    receipts = manifest.get("receipts")
    if not isinstance(artifacts, list) or not artifacts or not isinstance(receipts, list):
        raise EvidenceError("prior evidence transport inventory is incomplete")
    declared: dict[str, str] = {}
    for artifact in artifacts:
        if not isinstance(artifact, dict):
            raise EvidenceError("prior evidence transport artifact is invalid")
        artifact_id = str(artifact.get("artifact_id", ""))
        if not re.fullmatch(r"[1-9][0-9]*", artifact_id):
            raise EvidenceError("prior evidence transport artifact ID is invalid")
        archive_path = f"archives/{artifact_id}.zip"
        archive_digest = artifact.get("archive_sha256")
        if not isinstance(archive_digest, str) or archive_path in declared:
            raise EvidenceError("prior evidence transport archive is ambiguous")
        declared[archive_path] = archive_digest
        members = artifact.get("files")
        if not isinstance(members, list) or not members:
            raise EvidenceError("prior evidence transport artifact files are missing")
        for member in members:
            if not isinstance(member, dict) or not isinstance(member.get("path"), str):
                raise EvidenceError("prior evidence transport member is invalid")
            source = PurePosixPath(member["path"])
            if source.is_absolute() or ".." in source.parts or source.as_posix() != member["path"]:
                raise EvidenceError("prior evidence transport member path is unsafe")
            relative = f"expanded/{artifact_id}/{source.as_posix()}"
            if relative in declared or not isinstance(member.get("sha256"), str):
                raise EvidenceError("prior evidence transport member is ambiguous")
            declared[relative] = member["sha256"]
            raw = files.get(relative)
            if raw is None or len(raw) != member.get("size"):
                raise EvidenceError("prior evidence transport member size differs")
    actual = {name: _digest(raw) for name, raw in files.items()
              if name != "prior-evidence-transport.json"}
    if actual != declared or _digest(canonical_json(actual)) != manifest.get("bundle_sha256"):
        raise EvidenceError("prior evidence bundle digest mismatch")
    declared_receipts: set[str] = set()
    for receipt in receipts:
        if not isinstance(receipt, dict):
            raise EvidenceError("prior evidence transport receipt is invalid")
        relative = f"expanded/{receipt.get('artifact_id')}/{receipt.get('path')}"
        if (relative in declared_receipts or relative not in actual
            or actual[relative] != receipt.get("receipt_sha256")
            or not relative.endswith(".evidence.json")):
            raise EvidenceError("prior evidence transport receipt inventory differs")
        declared_receipts.add(relative)
    actual_receipts = {name for name in actual if name.endswith(".evidence.json")}
    if declared_receipts != actual_receipts:
        raise EvidenceError("prior evidence transport receipt inventory differs")


def load_prior_receipts(
    repo_root: Path, evidence_dir: Path | None, expected_digest: str | None,
    *, current_subject: Mapping[str, Any] | None,
) -> list[Mapping[str, Any]]:
    """Load only exact, digest-closed prior receipts; applicability is separate."""
    if evidence_dir is None:
        if expected_digest is not None:
            raise EvidenceError("prior evidence digest requires --prior-evidence-dir")
        return []
    if not re.fullmatch(r"[a-f0-9]{64}", expected_digest or ""):
        raise EvidenceError("prior evidence requires an authenticated SHA-256 digest")
    if evidence_dir.is_symlink() or not evidence_dir.is_dir():
        raise EvidenceError("prior evidence directory is unsafe")
    root = evidence_dir.resolve()
    entries = list(root.rglob("*"))
    if any(path.is_symlink() for path in entries):
        raise EvidenceError("prior evidence directory is unsafe")
    files = {path.relative_to(root).as_posix(): path for path in entries if path.is_file()}
    raw_files = {name: path.read_bytes() for name, path in files.items()}
    # The caller-authenticated digest closes the manifest as well as its payload.
    # The transport's internal bundle digest closes payload bytes only.
    material = sorted((name, _digest(raw)) for name, raw in raw_files.items())
    if _digest(json.dumps(material, sort_keys=True, separators=(",", ":")).encode()) != expected_digest:
        raise EvidenceError("prior evidence bundle digest mismatch")
    manifest_path = files.get("prior-evidence-transport.json")
    if manifest_path is not None:
        try:
            manifest = json.loads(raw_files["prior-evidence-transport.json"].decode("utf-8"))
        except (OSError, UnicodeDecodeError, json.JSONDecodeError) as exc:
            raise EvidenceError("prior evidence transport manifest is invalid") from exc
        if not isinstance(manifest, dict):
            raise EvidenceError("prior evidence transport manifest is invalid")
        validate_transport_material(raw_files, manifest, current_subject)
    receipt_files = [path for name, path in files.items() if name.endswith(".evidence.json")]
    if not receipt_files:
        return []
    for path in receipt_files:
        try:
            payload = json.loads(path.read_text(encoding="utf-8"))
        except (OSError, UnicodeDecodeError, json.JSONDecodeError) as exc:
            raise EvidenceError(f"prior evidence receipt is invalid: {path.name}") from exc
        if not isinstance(payload, dict):
            raise EvidenceError(f"prior evidence receipt is not an object: {path.name}")
    from .truth_receipts import ReceiptError, load_receipts

    repo_root = repo_root.resolve()
    contract = yaml.safe_load((repo_root / "governance/gate-contracts.yml").read_text(encoding="utf-8"))
    gates = contract.get("gates") if isinstance(contract, dict) else None
    if not isinstance(gates, dict):
        raise EvidenceError("prior evidence cannot resolve gate contracts")
    expected_kinds = {
        gate_id: str(gate.get("evidence", {}).get("kind", "gate"))
        for gate_id, gate in gates.items() if isinstance(gate, dict)
    }
    invocations = {
        gate_id: gate["invocation"]
        for gate_id, gate in gates.items()
        if isinstance(gate, dict) and isinstance(gate.get("invocation"), dict)
    }
    if current_subject is None:
        raise EvidenceError("prior evidence current subject is missing")
    try:
        validated = load_receipts(
            repo_root, root, dict(current_subject), require_negative_control=False,
            tree_independent_allowlist=set(), expected_kinds=expected_kinds,
            invocations=invocations, contract_version="3.0",
        )
    except (ReceiptError, OSError, ValueError) as exc:
        raise EvidenceError("prior evidence receipt validation failed") from exc
    results = [result for values in validated.values() for result in values]
    structural_issues: set[str] = set()
    for result in results:
        if result.get("result") == "verified":
            continue
        issues = set(result.get("issues", []))
        invalidation = result.get("invalidation")
        applicability = set(invalidation.get("reasons", []) if isinstance(invalidation, dict) else [])
        if "freshness_expired" in applicability:
            applicability.add("evidence_freshness_expired")
        if (result.get("receipt") or {}).get("schema_version") == "2.0":
            applicability.update({"commit_sha_not_current_head", "tree_sha_not_current_tree"})
        structural_issues.update(issues - applicability)
    if structural_issues:
        raise EvidenceError("prior evidence receipt validation failed: " + ", ".join(sorted(structural_issues)))
    receipts: list[Mapping[str, Any]] = []
    for result in results:
        payload = dict(result["receipt"])
        payload["artifact_sha256"] = result["artifact_sha256"]
        receipts.append(payload)
    return receipts
