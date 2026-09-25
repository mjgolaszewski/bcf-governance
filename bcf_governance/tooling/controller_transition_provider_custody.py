"""Narrow provider observations for routine controller transition custody."""

from __future__ import annotations

import io
import json
from typing import Any
import zipfile

from .ci_github_api import GitHubAPI
from .ci_github_identity import GitHubControllerError


TRANSITION_REPORT = "controller-transition.json"


def receipt_from_zip(raw: bytes) -> dict[str, Any]:
    """Decode the one-file immutable transition artifact inventory."""

    try:
        with zipfile.ZipFile(io.BytesIO(raw)) as archive:
            names = archive.namelist()
            if names != [TRANSITION_REPORT]:
                raise GitHubControllerError(
                    "controller transition artifact inventory is not exact"
                )
            value = json.loads(archive.read(TRANSITION_REPORT))
    except (zipfile.BadZipFile, KeyError, json.JSONDecodeError) as exc:
        raise GitHubControllerError("controller transition artifact is unreadable") from exc
    if not isinstance(value, dict):
        raise GitHubControllerError("controller transition report must be an object")
    return value


def github_is_ancestor(
    api: GitHubAPI, repository: str, *, base: str, head: str
) -> bool:
    """Authenticate one exact GitHub ancestry relationship."""

    comparison = api.compare_commits(repository, base=base, head=head)
    base_value = comparison.get("base_commit")
    merge_base = comparison.get("merge_base_commit")
    if not isinstance(base_value, dict) or not isinstance(merge_base, dict):
        raise GitHubControllerError("controller ancestry comparison is incomplete")
    return (
        comparison.get("status") in {"ahead", "identical"}
        and base_value.get("sha") == base
        and merge_base.get("sha") == base
    )
