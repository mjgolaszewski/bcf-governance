"""Bind canonical receipt input paths to the already validated capture session."""

from __future__ import annotations

import os
from pathlib import Path
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from .evidence_sessions import EvidenceSession


SESSION_INPUT_NAMESPACE = Path(".artifacts/bcf/sessions")


def bind_current_session_inputs(
    repo_root: Path,
    session: EvidenceSession | None,
    required_environment: list[str],
    job_environment: dict[str, str] | None,
) -> dict[str, str] | None:
    """Resolve only the reserved receipt namespace, without discovering sessions.

    The caller must first bind the immutable manifest, current subject and output.
    Other workspace paths and the authored gate/environment contract stay intact.
    """

    if session is None:
        return job_environment
    projected = (
        {name: os.environ[name] for name in required_environment if name in os.environ}
        if job_environment is None
        else dict(job_environment)
    )
    namespace = repo_root / SESSION_INPUT_NAMESPACE
    for name, value in projected.items():
        if Path(value) in (SESSION_INPUT_NAMESPACE, namespace):
            projected[name] = str(session.root)
    return projected
