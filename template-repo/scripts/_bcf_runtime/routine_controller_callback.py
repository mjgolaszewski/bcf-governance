"""Closed applicability classification for routine-controller callbacks."""

from __future__ import annotations

from typing import Any, Mapping, Sequence

from .ci_github_identity import GitHubControllerError


AUTHORIZE_JOB = "Authorize protected routine controller transition"
RECONCILE_JOB = "Commit the deterministic automation changelog entry"


def classify_callback_topology(
    *,
    expected_jobs: set[str],
    jobs: Sequence[Mapping[str, Any]],
) -> str:
    """Return the sole typed callback lane for one exact job inventory."""

    actual = {str(value.get("name", "")): value for value in jobs}
    if set(actual) != expected_jobs:
        raise GitHubControllerError("rotation callback job inventory is not exact")
    if AUTHORIZE_JOB not in expected_jobs or RECONCILE_JOB not in expected_jobs:
        raise GitHubControllerError("rotation callback authority inventory is invalid")
    if actual[AUTHORIZE_JOB].get("conclusion") != "success":
        raise GitHubControllerError("rotation callback authorization did not succeed")
    if actual[RECONCILE_JOB].get("conclusion") != "skipped":
        raise GitHubControllerError("rotation callback reconcile topology is invalid")
    downstream = expected_jobs - {AUTHORIZE_JOB, RECONCILE_JOB}
    conclusions = {str(actual[name].get("conclusion")) for name in downstream}
    if conclusions == {"skipped"}:
        return "no_transition"
    if conclusions == {"success"}:
        return "active_transition"
    raise GitHubControllerError("rotation callback topology is partial")
