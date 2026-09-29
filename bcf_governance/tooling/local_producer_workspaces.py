"""Execution-owned provider-job workspaces for local prospective evidence."""

from __future__ import annotations

from contextlib import contextmanager
import hashlib
from pathlib import Path
import tempfile
from typing import Iterator

from .ci_graph_execution import LocalGateProducer


class LocalProducerWorkspaceError(ValueError):
    """Raised when an exact local producer workspace cannot be retired."""


@contextmanager
def local_producer_environments(
    session_manifest: Path,
    bindings: dict[str, LocalGateProducer],
) -> Iterator[dict[str, dict[str, str]]]:
    """Resolve graph workspace expressions through exact ephemeral job custody."""

    identities = sorted(
        {(binding.workflow_id, binding.job_id) for binding in bindings.values()}
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
                        f"{session_digest}:{identity[0]}:{identity[1]}".encode()
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
                        str(workspaces[(binding.workflow_id, binding.job_id)]),
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
