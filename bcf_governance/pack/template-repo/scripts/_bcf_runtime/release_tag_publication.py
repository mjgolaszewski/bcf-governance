"""Provider-owned construction and authentication of immutable release tags."""

from __future__ import annotations

import re
from typing import Any
from urllib.parse import quote

from .ci_github_api import GitHubAPI, GitHubAPIError, _sha
from .ci_github_identity import GitHubControllerError
from .release_versions import ReleaseVersionError, parse_release_tag


def _optional_reference(
    api: GitHubAPI, repository: str, ref: str
) -> dict[str, Any] | None:
    if not ref or ".." in ref or not re.fullmatch(r"[A-Za-z0-9._/-]+", ref):
        raise GitHubAPIError("Git reference is unsafe")
    value = api._request(  # noqa: SLF001 - typed GitHub API extension
        "GET",
        f"/repos/{api._repository(repository)}/git/ref/{quote(ref)}",  # noqa: SLF001
        not_found_none=True,
    )
    if value is not None and not isinstance(value, dict):
        raise GitHubAPIError("Git reference response must be an object")
    return value


def _create_tag(api: GitHubAPI, repository: str, tag: str, commit_sha: str) -> str:
    try:
        parse_release_tag(tag)
    except ReleaseVersionError as exc:
        raise GitHubAPIError("release tag must be one canonical public version") from exc
    value = api._request(  # noqa: SLF001 - typed GitHub API extension
        "POST",
        f"/repos/{api._repository(repository)}/git/tags",  # noqa: SLF001
        payload={
            "tag": tag,
            "message": f"BCF Governance {tag}",
            "object": _sha(commit_sha, field="release commit SHA"),
            "type": "commit",
        },
    )
    if not isinstance(value, dict):
        raise GitHubAPIError("created annotated tag response must be an object")
    return _sha(value.get("sha"), field="created annotated tag object SHA")


def _create_reference(
    api: GitHubAPI, repository: str, tag: str, tag_object_sha: str
) -> None:
    value = api._request(  # noqa: SLF001 - typed GitHub API extension
        "POST",
        f"/repos/{api._repository(repository)}/git/refs",  # noqa: SLF001
        payload={"ref": f"refs/tags/{tag}", "sha": tag_object_sha},
    )
    if not isinstance(value, dict):
        raise GitHubAPIError("created tag reference response must be an object")


def ensure_release_tag(
    api: GitHubAPI, *, repository: str, tag: str, commit_sha: str
) -> None:
    """Create an absent exact tag, then authenticate the provider result."""

    reference = _optional_reference(api, repository, f"tags/{tag}")
    if reference is None:
        tag_sha = _create_tag(api, repository, tag, commit_sha)
        _create_reference(api, repository, tag, tag_sha)
        reference = api.reference(repository, f"tags/{tag}")
    target = reference.get("object")
    if not isinstance(target, dict) or target.get("type") != "tag":
        raise GitHubControllerError("release publication requires an annotated tag")
    tag_object = api.tag_object(repository, str(target.get("sha")))
    tag_target = tag_object.get("object")
    verification = tag_object.get("verification")
    if tag_object.get("tag") != tag or not isinstance(tag_target, dict) or (
        tag_target.get("type") != "commit" or tag_target.get("sha") != commit_sha
    ):
        raise GitHubControllerError("release publication tag does not match certified commit")
    if not isinstance(verification, dict) or verification.get("verified") is not False or (
        verification.get("reason") != "unsigned"
    ):
        raise GitHubControllerError(
            "release publication requires the annotated unsigned tag policy"
        )
