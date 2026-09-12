"""Validate durable evidence-input topology from one graph and storage owner."""

from __future__ import annotations

import hashlib
from pathlib import Path
from typing import Any

from .ci_graph_errors import CIGraphError
from .evidence_storage_contracts import (
    CONTRACT_PATH,
    EvidenceStorageError,
    load_storage_contract_path,
)


def _overlaps(first: str, second: str) -> bool:
    left = Path(first).parts
    right = Path(second).parts
    return left == right[: len(left)] or right == left[: len(right)]


def _publisher_jobs(graph: dict[str, Any]) -> list[dict[str, Any]]:
    return [
        job
        for workflow in graph["workflows"]
        for job in workflow["jobs"]
        if job["executor"]["kind"] == "durable_publish"
    ]


def _validate_artifacts(graph: dict[str, Any], contract: dict[str, Any]) -> None:
    artifacts = graph["artifacts"]
    sources = {
        artifact_id: artifact
        for artifact_id, artifact in artifacts.items()
        if artifact["kind"] == "durable-source"
    }
    references = {
        artifact_id: artifact
        for artifact_id, artifact in artifacts.items()
        if artifact["kind"] == "durable-reference"
    }
    if (sources or references) and contract["activation"] != "enabled":
        raise CIGraphError("durable evidence artifacts require enabled evidence storage")
    handoff_days = contract["transport"]["actions_handoff_retention_days"]
    reference_days = contract["transport"]["reference_retention_days"]
    freshness = set(contract["freshness_classes"])
    targets: list[str] = []
    for artifact_id, artifact in sources.items():
        if artifact["retention_days"] != handoff_days:
            raise CIGraphError(
                f"durable evidence source {artifact_id} retention differs from storage policy"
            )
        declaration = artifact["durable_input"]
        object_ids = [item["id"] for item in declaration["objects"]]
        object_targets = [item["target_path"] for item in declaration["objects"]]
        if len(set(object_ids)) != len(object_ids):
            raise CIGraphError(f"durable evidence source {artifact_id} duplicates object IDs")
        if any(
            _overlaps(left, right)
            for index, left in enumerate(object_targets)
            for right in object_targets[index + 1 :]
        ):
            raise CIGraphError(f"durable evidence source {artifact_id} overlaps targets")
        unknown = sorted(
            {item["freshness_class"] for item in declaration["objects"]} - freshness
        )
        if unknown:
            raise CIGraphError(
                f"durable evidence source {artifact_id} uses unknown freshness classes {unknown}"
            )
    artifact_paths = [artifact["path"] for artifact in artifacts.values()]
    for artifact_id, artifact in references.items():
        source = artifact["durable_source"]
        if source not in sources:
            raise CIGraphError(
                f"durable evidence reference {artifact_id} has unknown source {source}"
            )
        if artifact["retention_days"] != reference_days:
            raise CIGraphError(
                f"durable evidence reference {artifact_id} retention differs from storage policy"
            )
        root = artifact["materialization_root"]
        if not root.startswith(".artifacts/"):
            raise CIGraphError(
                f"durable evidence reference {artifact_id} must materialize under .artifacts/"
            )
        if any(_overlaps(root, existing) for existing in [*targets, *artifact_paths]):
            raise CIGraphError("durable evidence materialization roots overlap")
        targets.append(root)


def _validate_publishers(graph: dict[str, Any], contract: dict[str, Any]) -> None:
    artifacts = graph["artifacts"]
    publishers = _publisher_jobs(graph)
    claimed_sources: set[str] = set()
    claimed_references: set[str] = set()
    for job in publishers:
        executor = job["executor"]
        source = executor["source"]
        reference = executor["reference"]
        publisher_owners = [
            workflow
            for workflow in graph["workflows"]
            if any(candidate is job for candidate in workflow["jobs"])
        ]
        source_producers = [
            (workflow, producer)
            for workflow in graph["workflows"]
            for producer in workflow["jobs"]
            if source in producer["produces"]
        ]
        if len(publisher_owners) != 1 or len(source_producers) != 1:
            raise CIGraphError(
                f"durable publisher {job['id']} lacks exact workflow ownership"
            )
        publisher_workflow = publisher_owners[0]
        source_workflow, _ = source_producers[0]
        expected_event = {
            "type": "workflow_run",
            "workflows": [source_workflow["display_name"]],
            "types": ["completed"],
        }
        if source in claimed_sources or reference in claimed_references:
            raise CIGraphError("durable evidence source or reference has multiple publishers")
        claimed_sources.add(source)
        claimed_references.add(reference)
        if (
            source not in artifacts
            or artifacts[source]["kind"] != "durable-source"
            or reference not in artifacts
            or artifacts[reference]["kind"] != "durable-reference"
            or artifacts[reference]["durable_source"] != source
        ):
            raise CIGraphError(f"durable publisher {job['id']} has inconsistent artifacts")
        if job["consumes"] != [source] or job["produces"] != [reference]:
            raise CIGraphError(
                f"durable publisher {job['id']} must exclusively transform its source into its reference"
            )
        if job["trust"] != "trusted":
            raise CIGraphError(
                f"durable publisher {job['id']} must be trusted control"
            )
        if job["checkout"] is not False or job["components"]:
            raise CIGraphError(
                f"durable publisher {job['id']} must not execute candidate code"
            )
        if job["condition"] != "success" or job["required"] is not True:
            raise CIGraphError(
                f"durable publisher {job['id']} must be required after source success"
            )
        if publisher_workflow is source_workflow:
            raise CIGraphError(
                f"durable publisher {job['id']} must run in a separate trusted workflow"
            )
        if publisher_workflow["events"] != [expected_event]:
            raise CIGraphError(
                f"durable publisher {job['id']} must authenticate the exact completed source workflow"
            )
        if (
            job.get("protected_environment")
            != contract["provider"]["protected_environment"]
        ):
            raise CIGraphError(
                f"durable publisher {job['id']} must use the declared protected environment"
            )
        if any(value == "write" for value in job["permissions"].values()):
            raise CIGraphError(
                f"durable publisher {job['id']} workflow token must remain read-only"
            )
        if any(
            job["permissions"].get(permission) != "read"
            for permission in ("actions", "attestations", "contents")
        ):
            raise CIGraphError(
                f"durable publisher {job['id']} lacks complete read authority"
            )
    sources = {
        artifact_id
        for artifact_id, artifact in artifacts.items()
        if artifact["kind"] == "durable-source"
    }
    references = {
        artifact_id
        for artifact_id, artifact in artifacts.items()
        if artifact["kind"] == "durable-reference"
    }
    if claimed_sources != sources or claimed_references != references:
        raise CIGraphError("every durable evidence source and reference requires one publisher")
    for workflow in graph["workflows"]:
        for job in workflow["jobs"]:
            consumed_references = set(job["consumes"]) & references
            if consumed_references and any(
                job["permissions"].get(permission) != "read"
                for permission in ("actions", "attestations", "contents")
            ):
                raise CIGraphError(
                    f"job {job['id']} lacks read authority for durable evidence resolution"
                )
    for reference in references:
        consumers = [
            job
            for workflow in graph["workflows"]
            for job in workflow["jobs"]
            if reference in job["consumes"]
            and job["executor"]["kind"] != "durable_publish"
        ]
        if not consumers:
            raise CIGraphError(
                f"durable evidence reference {reference} has no verifying consumer"
            )
    for source in sources:
        producers = [
            job
            for workflow in graph["workflows"]
            for job in workflow["jobs"]
            if source in job["produces"]
        ]
        if len(producers) != 1 or "matrix" in producers[0] or "strategy" in producers[0]:
            raise CIGraphError(
                f"durable evidence source {source} requires one non-matrix producer"
            )
    for workflow in graph["workflows"]:
        for job in workflow["jobs"]:
            if job["executor"]["kind"] == "durable_publish":
                continue
            forbidden = set(job["consumes"]) & sources
            if forbidden:
                raise CIGraphError(
                    f"job {job['id']} bypasses the durable evidence reference {sorted(forbidden)}"
                )


def validate_evidence_storage(
    repo_root: Path, graph: dict[str, Any]
) -> tuple[tuple[tuple[str, str], ...], dict[str, Any] | None]:
    """Validate graph storage semantics and return mechanically bound input hashes."""

    reference = graph.get("evidence_storage")
    durable = any(
        artifact["kind"] in {"durable-source", "durable-reference"}
        for artifact in graph["artifacts"].values()
    )
    if reference is None:
        if durable or _publisher_jobs(graph):
            raise CIGraphError("durable evidence topology lacks a storage contract")
        return (), None
    path = repo_root / str(reference["path"])
    if path.is_symlink() or not path.is_file():
        raise CIGraphError("evidence storage contract must be one regular nonsymlink file")
    digest = hashlib.sha256(path.read_bytes()).hexdigest()
    if digest != reference["sha256"]:
        raise CIGraphError("evidence storage contract digest mismatch")
    try:
        contract = load_storage_contract_path(repo_root, path)
    except EvidenceStorageError as exc:
        raise CIGraphError(str(exc)) from exc
    _validate_artifacts(graph, contract)
    _validate_publishers(graph, contract)
    return ((CONTRACT_PATH.as_posix(), digest),), contract
