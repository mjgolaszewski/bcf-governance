"""Verify and project already-resolved durable inputs into detached worktrees."""

from __future__ import annotations

import hashlib
import os
from pathlib import Path, PurePosixPath
import stat
from typing import Any

from .evidence_storage_contracts import (
    EvidenceStorageError,
    load_input_manifest,
    load_input_reference,
    load_storage_contract,
    validate_freshness,
)
from .evidence_storage_manifests import MANIFEST_NAME, manifest_digest


RESOLVED_MANIFEST = ".bcf-evidence-input-manifest.json"


def _sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _observed_members(target: Path, root_kind: str) -> dict[str, dict[str, Any]]:
    if target.is_symlink() or not target.exists():
        raise EvidenceStorageError("resolved evidence input target is missing or symlinked")
    paths = [target]
    if target.is_dir():
        for current, directories, files in os.walk(target, followlinks=False):
            directories.sort()
            files.sort()
            paths.extend(Path(current) / name for name in directories + files)
    expected_kind = "file" if target.is_file() else "directory"
    if root_kind != expected_kind:
        raise EvidenceStorageError("resolved evidence input root kind differs")
    result: dict[str, dict[str, Any]] = {}
    for path in paths:
        if path.is_symlink():
            raise EvidenceStorageError("resolved evidence input contains a symlink")
        relative = path.relative_to(target).as_posix()
        name = "root" if relative == "." else f"root/{relative}"
        metadata = path.lstat()
        kind = "file" if stat.S_ISREG(metadata.st_mode) else (
            "directory" if stat.S_ISDIR(metadata.st_mode) else "unsupported"
        )
        if kind == "unsupported":
            raise EvidenceStorageError("resolved evidence input contains a special file")
        result[name] = {
            "path": name,
            "kind": kind,
            "mode": stat.S_IMODE(metadata.st_mode),
            "size": metadata.st_size if kind == "file" else 0,
            "sha256": _sha256(path) if kind == "file" else None,
        }
    return result


def verify_materialized_inputs(
    repo_root: Path, reference_path: Path, materialization_root: Path
) -> tuple[Path, ...]:
    """Recompute every original member before a governed gate receives the tree."""

    root = repo_root.resolve()
    if (
        reference_path.is_symlink()
        or not reference_path.is_file()
        or not reference_path.resolve().is_relative_to(root)
        or materialization_root.is_symlink()
        or not materialization_root.is_dir()
        or not materialization_root.resolve().is_relative_to(root)
    ):
        raise EvidenceStorageError(
            "resolved evidence reference and materialization must remain inside the repository"
        )
    reference = load_input_reference(repo_root, reference_path)
    manifest_path = materialization_root / RESOLVED_MANIFEST
    manifest = load_input_manifest(repo_root, manifest_path)
    if (
        manifest_digest(manifest) != reference["manifest_sha256"]
        or manifest["subject"] != reference["subject"]
        or manifest["producer"] != reference["producer"]
    ):
        raise EvidenceStorageError("resolved evidence manifest differs from its reference")
    validate_freshness(load_storage_contract(repo_root), manifest)
    targets: list[Path] = []
    for item in manifest["objects"]:
        relative = PurePosixPath(item["target_path"])
        target = materialization_root.joinpath(*relative.parts)
        observed = _observed_members(target, item["root_kind"])
        expected = {member["path"]: member for member in item["members"]}
        if observed != expected:
            raise EvidenceStorageError(
                f"resolved evidence input differs from manifest: {item['id']}"
            )
        targets.append(target)
    return tuple(targets)
