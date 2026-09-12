"""Construct and verify content-addressed evidence input bundles."""

from __future__ import annotations

from datetime import UTC, datetime
import hashlib
from pathlib import Path
import tempfile
from typing import Any, Iterable

from .evidence_storage_archives import InputSpec, build_archive, materialize_bundle
from .evidence_storage_contracts import (
    CONTRACT_PATH,
    EvidenceStorageError,
    canonical_json,
    load_input_manifest,
    load_storage_contract,
    load_storage_contract_path,
    sha256_bytes,
    validate_freshness,
)


MANIFEST_NAME = "evidence-input-manifest.json"
CONTRACT_NAME = "evidence-storage.yml"


def _file_sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _subject(value: dict[str, Any]) -> dict[str, Any]:
    expected = {"repository_id", "commit_sha", "tree_sha"}
    if set(value) != expected:
        raise EvidenceStorageError("evidence input subject identity is incomplete")
    return dict(value)


def _producer(value: dict[str, Any]) -> dict[str, Any]:
    expected = {
        "kind",
        "workflow_path",
        "workflow_sha256",
        "job_id",
        "job_name",
        "run_id",
        "run_attempt",
    }
    if set(value) != expected:
        raise EvidenceStorageError("evidence input producer identity is incomplete")
    return dict(value)


def build_input_bundle(
    repo_root: Path,
    *,
    namespace: str,
    specs: Iterable[InputSpec],
    output_dir: Path,
    subject: dict[str, Any],
    producer: dict[str, Any],
    created_at: datetime | None = None,
) -> Path:
    """Build one immutable candidate bundle before trusted publication."""

    root = repo_root.resolve()
    contract = load_storage_contract(root)
    if contract["activation"] != "enabled":
        raise EvidenceStorageError("content-addressed evidence storage is not enabled")
    selected = tuple(specs)
    if not selected or len({item.id for item in selected}) != len(selected):
        raise EvidenceStorageError("evidence input specs must be nonempty and uniquely identified")
    destination = output_dir.resolve()
    if destination.exists() or output_dir.is_symlink():
        raise EvidenceStorageError("evidence input bundle output must not already exist")
    destination.parent.mkdir(parents=True, exist_ok=True)
    if destination.parent.is_symlink():
        raise EvidenceStorageError("evidence input bundle parent must not be symlinked")
    safety = {
        **contract["archive_safety"],
        "maximum_asset_bytes": contract["provider"]["max_asset_bytes"],
    }
    with tempfile.TemporaryDirectory(
        prefix="bcf-evidence-bundle-", dir=destination.parent
    ) as temporary_name:
        temporary = Path(temporary_name) / "bundle"
        objects_root = temporary / "objects"
        objects: list[dict[str, Any]] = []
        for spec in sorted(selected, key=lambda item: item.id):
            item, _ = build_archive(root, spec, objects_root, safety)
            objects.append(item)
        unique_sizes = {
            str(item["asset_name"]): int(item["archive_size"]) for item in objects
        }
        payload: dict[str, Any] = {
            "schema_version": "1.0",
            "kind": "governance.evidence-input-manifest.v1",
            "namespace": namespace,
            "storage_contract_sha256": _file_sha256(root / CONTRACT_PATH),
            "subject": _subject(subject),
            "producer": _producer(producer),
            "created_at_utc": (created_at or datetime.now(UTC))
            .astimezone(UTC)
            .isoformat()
            .replace("+00:00", "Z"),
            "objects": objects,
            "total_archive_bytes": sum(unique_sizes.values()),
            "total_expanded_bytes": sum(
                int(item["expanded_size"]) for item in objects
            ),
        }
        if payload["total_archive_bytes"] > min(
            int(contract["budgets"]["maximum_new_bytes_per_run"]),
            int(contract["budgets"]["maximum_actions_bytes"]),
        ):
            raise EvidenceStorageError(
                "evidence input bundle exceeds the preflight storage budget"
            )
        temporary.mkdir(parents=True, exist_ok=True)
        (temporary / CONTRACT_NAME).write_bytes((root / CONTRACT_PATH).read_bytes())
        (temporary / CONTRACT_NAME).chmod(0o600)
        (temporary / MANIFEST_NAME).write_bytes(canonical_json(payload))
        (temporary / MANIFEST_NAME).chmod(0o600)
        verify_input_bundle(root, temporary)
        temporary.replace(destination)
    return destination / MANIFEST_NAME


def verify_input_bundle(repo_root: Path, bundle_dir: Path) -> dict[str, Any]:
    """Verify exact manifest bytes and the closed archive inventory."""

    return verify_input_bundle_contract(
        repo_root.resolve(), bundle_dir, repo_root.resolve() / CONTRACT_PATH
    )[0]


def verify_input_bundle_contract(
    schema_root: Path, bundle_dir: Path, contract_path: Path
) -> tuple[dict[str, Any], dict[str, Any]]:
    """Verify a transported bundle against one separately authenticated contract."""

    if bundle_dir.is_symlink() or not bundle_dir.is_dir():
        raise EvidenceStorageError("evidence input bundle must be a nonsymlink directory")
    manifest = load_input_manifest(schema_root, bundle_dir / MANIFEST_NAME)
    contract = load_storage_contract_path(schema_root, contract_path)
    contract_digest = _file_sha256(contract_path)
    if manifest["storage_contract_sha256"] != contract_digest:
        raise EvidenceStorageError("evidence input bundle uses a different storage contract")
    validate_freshness(contract, manifest)
    objects_root = bundle_dir / "objects"
    if objects_root.is_symlink() or not objects_root.is_dir():
        raise EvidenceStorageError("evidence input bundle object root is missing or symlinked")
    expected = {
        str(item["asset_name"]): (
            str(item["archive_sha256"]),
            int(item["archive_size"]),
        )
        for item in manifest["objects"]
    }
    actual = {
        path.name: path
        for path in objects_root.iterdir()
        if path.is_file() and not path.is_symlink()
    }
    if set(actual) != set(expected) or any(
        path.is_symlink() or not path.is_file() for path in objects_root.iterdir()
    ):
        raise EvidenceStorageError("evidence input bundle archive inventory differs")
    for name, (digest, size) in expected.items():
        path = actual[name]
        if path.stat().st_size != size or _file_sha256(path) != digest:
            raise EvidenceStorageError(f"evidence input archive differs: {name}")
    if len(actual) + 1 > int(contract["provider"]["max_assets_per_release"]):
        raise EvidenceStorageError("evidence input bundle exceeds the provider asset limit")
    with tempfile.TemporaryDirectory(
        prefix="bcf-evidence-verify-", dir=bundle_dir.parent
    ) as temporary_name:
        materialize_bundle(
            manifest,
            objects_root,
            Path(temporary_name) / "materialized",
            contract["archive_safety"],
        )
    return manifest, contract


def manifest_digest(manifest: dict[str, Any]) -> str:
    return sha256_bytes(canonical_json(manifest))
