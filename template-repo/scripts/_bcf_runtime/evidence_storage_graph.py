"""Project durable evidence declarations from the CI graph into exact bundles."""

from __future__ import annotations

import hashlib
import os
from pathlib import Path
import subprocess
from typing import Any, Mapping

from .ci_graph_contracts import validate_ci_graph
from .evidence_storage_archives import InputSpec
from .evidence_storage_contracts import EvidenceStorageError, parse_utc
from .evidence_storage_manifests import build_input_bundle


def _git(repo_root: Path, *args: str) -> str:
    result = subprocess.run(
        ["git", "-C", str(repo_root), *args],
        capture_output=True,
        text=True,
        check=False,
    )
    value = result.stdout.strip()
    if result.returncode or not value:
        raise EvidenceStorageError(f"cannot resolve Git identity: {' '.join(args)}")
    return value


def _positive_int(value: str | None, *, label: str) -> int:
    if value is None or not value.isdigit() or int(value) < 1:
        raise EvidenceStorageError(f"{label} must be a positive provider ID")
    return int(value)


def _workflow_path(value: str | None, repository: str) -> str:
    prefix = repository + "/"
    if value is None or not value.startswith(prefix) or "@" not in value:
        raise EvidenceStorageError("GITHUB_WORKFLOW_REF is not an exact workflow identity")
    path, ref = value[len(prefix) :].rsplit("@", 1)
    if not path.startswith(".github/workflows/") or not ref:
        raise EvidenceStorageError("GITHUB_WORKFLOW_REF is not an exact workflow identity")
    return path


def _freshness(repo_root: Path, declaration: dict[str, Any]) -> str | None:
    relative = declaration.get("freshness_observed_at_path")
    if relative is None:
        return None
    if not isinstance(relative, str):
        raise EvidenceStorageError("freshness observation path must be a string")
    path = repo_root / relative
    if path.is_symlink() or not path.is_file():
        raise EvidenceStorageError(
            f"freshness observation is missing or symlinked: {relative}"
        )
    value = path.read_text(encoding="utf-8").strip()
    parse_utc(value, label=f"freshness observation {relative}")
    return value


def prepare_graph_artifact(
    repo_root: Path,
    *,
    artifact_id: str,
    output_dir: Path,
    environment: Mapping[str, str] | None = None,
) -> Path:
    """Build one graph-owned handoff from authenticated ambient job identity."""

    root = repo_root.resolve()
    compiled = validate_ci_graph(root)
    artifact = compiled.graph["artifacts"].get(artifact_id)
    if not isinstance(artifact, dict) or artifact.get("kind") != "durable-source":
        raise EvidenceStorageError(f"unknown durable evidence source {artifact_id}")
    producers = [
        (workflow, job)
        for workflow in compiled.workflows
        for job in workflow["jobs"]
        if artifact_id in job["produces"]
    ]
    if len(producers) != 1:
        raise EvidenceStorageError("durable evidence source lacks one graph producer")
    workflow, job = producers[0]
    env = dict(os.environ if environment is None else environment)
    repository = env.get("GITHUB_REPOSITORY", "")
    workflow_path = _workflow_path(env.get("GITHUB_WORKFLOW_REF"), repository)
    if workflow_path != workflow["path"] or env.get("GITHUB_JOB") != job["id"]:
        raise EvidenceStorageError("ambient job identity differs from the graph producer")
    commit = _git(root, "rev-parse", "HEAD")
    tree = _git(root, "rev-parse", "HEAD^{tree}")
    if env.get("GITHUB_SHA") != commit:
        raise EvidenceStorageError("ambient candidate SHA differs from committed HEAD")
    contract = compiled.graph["evidence_storage"]
    storage = compiled.input_sha256
    storage_hash = dict(storage).get(str(contract["path"]))
    if storage_hash is None:
        raise EvidenceStorageError("compiled graph lacks evidence storage custody")
    specs = [
        InputSpec(
            id=item["id"],
            source_path=item["source_path"],
            target_path=item["target_path"],
            freshness_class=item["freshness_class"],
            observed_at_utc=_freshness(root, item),
        )
        for item in artifact["durable_input"]["objects"]
    ]
    return build_input_bundle(
        root,
        namespace=artifact["durable_input"]["namespace"],
        specs=specs,
        output_dir=output_dir,
        subject={
            "repository_id": _positive_int(
                env.get("GITHUB_REPOSITORY_ID"), label="GITHUB_REPOSITORY_ID"
            ),
            "commit_sha": commit,
            "tree_sha": tree,
        },
        producer={
            "kind": "workflow",
            "workflow_path": workflow_path,
            "workflow_sha256": hashlib.sha256(
                (root / workflow_path).read_bytes()
            ).hexdigest(),
            "job_id": job["id"],
            "job_name": job["display_name"],
            "run_id": str(
                _positive_int(env.get("GITHUB_RUN_ID"), label="GITHUB_RUN_ID")
            ),
            "run_attempt": _positive_int(
                env.get("GITHUB_RUN_ATTEMPT"), label="GITHUB_RUN_ATTEMPT"
            ),
        },
    )
