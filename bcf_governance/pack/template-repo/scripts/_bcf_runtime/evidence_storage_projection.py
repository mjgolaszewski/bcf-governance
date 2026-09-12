"""Project authenticated durable inputs into isolated evidence worktrees."""

from __future__ import annotations

import hashlib
import os
from pathlib import Path
import shutil
import subprocess
from typing import Any

from .evidence_execution import EvidenceError
from .evidence_storage_contracts import (
    evidence_input_reference_identity,
    load_input_reference,
)
from .evidence_storage_materialized import verify_materialized_inputs


def _sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _durable_input_bindings() -> tuple[tuple[str, str], ...]:
    raw = os.environ.get("BCF_EVIDENCE_INPUT_BINDINGS", "")
    if not raw:
        return ()
    result: list[tuple[str, str]] = []
    for value in raw.split(";"):
        parts = value.split("|")
        if len(parts) != 2 or not all(parts):
            raise EvidenceError("durable evidence input binding is malformed")
        if any(Path(part).is_absolute() or ".." in Path(part).parts for part in parts):
            raise EvidenceError("durable evidence input binding is unsafe")
        result.append((parts[0], parts[1]))
    if len(set(result)) != len(result):
        raise EvidenceError("durable evidence input bindings are duplicated")
    return tuple(result)


def install_durable_inputs(
    repo_root: Path,
    worktree: Path,
    output_dir: Path | None = None,
) -> tuple[list[dict[str, Any]], list[dict[str, str]]]:
    """Verify and copy each declared input without sharing a mutable tree."""

    observations: list[dict[str, Any]] = []
    artifacts: list[dict[str, str]] = []
    for index, (reference_value, root_value) in enumerate(
        _durable_input_bindings(), start=1
    ):
        reference = repo_root / reference_value
        source = repo_root / root_value
        identity = evidence_input_reference_identity(
            load_input_reference(repo_root, reference)
        )
        verify_materialized_inputs(repo_root, reference, source)
        destination = worktree / root_value
        if destination.exists() or destination.is_symlink():
            raise EvidenceError("detached durable evidence input target already exists")
        destination.parent.mkdir(parents=True, exist_ok=True)
        if not destination.parent.resolve().is_relative_to(worktree.resolve()):
            raise EvidenceError("detached durable evidence input target escapes the worktree")
        copied = subprocess.run(
            ["cp", "-a", "--reflink=auto", f"{source}/.", str(destination)],
            capture_output=True,
            text=True,
            check=False,
        )
        if copied.returncode:
            raise EvidenceError(
                copied.stderr.strip() or "durable evidence input projection failed"
            )
        worktree_reference = worktree / reference_value
        if worktree_reference.exists() or worktree_reference.is_symlink():
            raise EvidenceError("detached durable evidence reference target already exists")
        worktree_reference.parent.mkdir(parents=True, exist_ok=True)
        if not worktree_reference.parent.resolve().is_relative_to(worktree.resolve()):
            raise EvidenceError(
                "detached durable evidence reference target escapes the worktree"
            )
        shutil.copy2(reference, worktree_reference)
        verify_materialized_inputs(worktree, worktree_reference, destination)
        observation = {
            "manifest_sha256": identity.manifest_sha256,
            "repository_id": identity.repository_id,
            "subject_commit": identity.subject_commit,
            "subject_tree": identity.subject_tree,
            "producer_run_id": identity.producer_run_id,
            "producer_run_attempt": identity.producer_run_attempt,
            "release_id": identity.release_id,
            "reference_sha256": _sha256(reference),
            "materialization_root": root_value,
        }
        observations.append(observation)
        if output_dir is not None:
            destination_reference = output_dir / f"durable-input-{index}.json"
            shutil.copy2(reference, destination_reference)
            artifacts.append(
                {
                    "path": destination_reference.name,
                    "media_type": "application/vnd.bcf.evidence-input-reference+json",
                    "sha256": observation["reference_sha256"],
                }
            )
    return observations, artifacts
