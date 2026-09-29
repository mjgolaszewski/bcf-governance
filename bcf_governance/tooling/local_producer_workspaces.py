"""Execution-owned provider-job workspaces for local prospective evidence."""

from __future__ import annotations

from contextlib import contextmanager
import hashlib
from pathlib import Path
import tempfile
from typing import Any, Iterator

from .ci_graph_execution import LocalGateProducer


class LocalProducerWorkspaceError(ValueError):
    """Raised when an exact local producer workspace cannot be retired."""


def planned_local_producers(
    nodes: list[dict[str, Any]],
) -> tuple[tuple[str, ...], dict[str, int]]:
    """Preserve canonical plan order and exact provider shard identity."""

    producers: list[str] = []
    shards: dict[str, int] = {}
    for node in nodes:
        producer = node.get("producer") if isinstance(node, dict) else None
        shard = node.get("assigned_shard") if isinstance(node, dict) else None
        if (
            not isinstance(producer, str)
            or not producer
            or producer in shards
            or isinstance(shard, bool)
            or not isinstance(shard, int)
            or shard < 0
        ):
            raise LocalProducerWorkspaceError(
                "planned local producer topology is incomplete or ambiguous"
            )
        producers.append(producer)
        shards[producer] = shard
    return tuple(producers), shards


@contextmanager
def local_producer_environments(
    session_manifest: Path,
    bindings: dict[str, LocalGateProducer],
) -> Iterator[dict[str, dict[str, str]]]:
    """Resolve graph workspace expressions through exact ephemeral job custody."""

    identities = sorted(
        {
            (binding.workflow_id, binding.job_id, binding.instance_id)
            for binding in bindings.values()
        }
    )
    session_digest = hashlib.sha256(session_manifest.read_bytes()).hexdigest()
    workspace_root: Path | None = None
    try:
        with tempfile.TemporaryDirectory(prefix="bcf-local-job-workspaces-") as name:
            workspace_root = Path(name)
            workspaces = {
                identity: workspace_root
                / (
                    "job-"
                    + hashlib.sha256(
                        f"{session_digest}:{identity[0]}:{identity[1]}:{identity[2]}".encode()
                    ).hexdigest()[:32]
                )
                for identity in identities
            }
            for workspace in workspaces.values():
                workspace.mkdir()
            yield {
                producer: {
                    key: value.replace(
                        "${{ github.workspace }}",
                        str(
                            workspaces[
                                (
                                    binding.workflow_id,
                                    binding.job_id,
                                    binding.instance_id,
                                )
                            ]
                        ),
                    )
                    for key, value in binding.environment.items()
                }
                for producer, binding in bindings.items()
            }
    finally:
        if workspace_root is not None and workspace_root.exists():
            raise LocalProducerWorkspaceError(
                "local producer-job workspace retirement was incomplete"
            )
