"""Closed rotation-outcome input contract for the asynchronous callback."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any, Mapping

from .ci_github_identity import GitHubControllerError
from .controller_custody import validate_controller_custody
from .routine_controller_rotation import validate_transition


def load_callback_outcome(path: Path) -> dict[str, Any]:
    """Load the sole exact JSON document selected by the provider workflow."""

    files = [path] if path.is_file() else sorted(path.glob("*.json")) if path.is_dir() else []
    if len(files) != 1 or files[0].is_symlink():
        raise GitHubControllerError("rotation callback outcome is not exact")
    try:
        value = json.loads(files[0].read_text(encoding="utf-8"))
    except (OSError, ValueError) as exc:
        raise GitHubControllerError("rotation callback outcome is invalid") from exc
    if not isinstance(value, dict):
        raise GitHubControllerError("rotation callback outcome is not an object")
    return value


def validate_no_transition_outcome(
    value: Mapping[str, Any], *, subject: Mapping[str, str], custody: Mapping[str, Any]
) -> dict[str, Any]:
    """Reject an untyped or authority-bearing no-transition observation."""

    expected = {
        "schema_version", "decision", "transition_class", "applicable",
        "reason", "subject", "admission", "controller_custody",
        "release_authority",
    }
    if (
        set(value) != expected
        or value.get("schema_version") != "1.0"
        or value.get("decision") != "no_transition"
        or value.get("transition_class") != "none"
        or value.get("applicable") is not False
        or value.get("reason") != "controller_current"
        or value.get("subject") != dict(subject)
        or value.get("release_authority") is not False
        or validate_controller_custody(value.get("controller_custody"))
        != validate_controller_custody(custody)
    ):
        raise GitHubControllerError("no-transition callback outcome is not exact")
    return dict(value)


def validate_active_outcome(
    repo_root: Path, value: Mapping[str, Any]
) -> dict[str, Any]:
    """Delegate active receipt validation to its canonical semantic owner."""

    return validate_transition(repo_root, dict(value))
