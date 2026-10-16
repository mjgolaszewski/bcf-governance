"""Exact provider identity validation shared by GitHub transport operations."""

from __future__ import annotations

import re
from typing import Any, Mapping
from urllib.parse import quote, urlparse


class GitHubValueError(ValueError):
    """A provider identity is not exact or safe."""


REPOSITORY_PATTERN = re.compile(r"^[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+$")


def repository(value: object) -> str:
    text = str(value)
    parts = text.split("/")
    if (
        not REPOSITORY_PATTERN.fullmatch(text)
        or len(parts) != 2
        or any(part in {".", ".."} for part in parts)
    ):
        raise GitHubValueError("repository must be exact owner/name identity")
    return text


def remote_repository(value: object) -> str:
    """Decode one exact GitHub Git remote into owner/name identity."""

    text = str(value).strip()
    scp = re.fullmatch(
        r"git@github\.com:(?P<repository>[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+?)(?:\.git)?",
        text,
    )
    if scp is not None:
        return repository(scp.group("repository"))
    parsed = urlparse(text)
    if (
        parsed.scheme not in {"https", "ssh"}
        or parsed.hostname not in {"github.com", "ssh.github.com"}
        or parsed.query
        or parsed.fragment
        or parsed.password is not None
    ):
        raise GitHubValueError("Git remote must identify an exact GitHub repository")
    return repository(parsed.path.removeprefix("/").removesuffix(".git"))


def positive_id(value: object, *, field: str) -> str:
    text = str(value)
    if not text.isdigit() or int(text) < 1:
        raise GitHubValueError(f"{field} must be a positive numeric provider ID")
    return text


def workflow_reference(value: object) -> str:
    text = str(value)
    if text.isdigit():
        return positive_id(text, field="workflow ID")
    if not re.fullmatch(r"[A-Za-z0-9_.-]+\.ya?ml", text):
        raise GitHubValueError(
            "workflow reference must be a numeric ID or exact file name"
        )
    return quote(text, safe="")


def sha(value: object, *, field: str) -> str:
    text = str(value)
    if not re.fullmatch(r"[a-f0-9]{40}", text):
        raise GitHubValueError(
            f"{field} must be an exact 40-character Git SHA"
        )
    return text


def candidate_pull_request_identity(
    value: Mapping[str, Any],
    *,
    repository_id: int,
    branch: str,
    base_ref: str,
    base_sha: str,
    head_sha: str,
) -> dict[str, Any]:
    head = value.get("head")
    base = value.get("base")
    if not isinstance(head, Mapping) or not isinstance(base, Mapping):
        raise GitHubValueError("candidate pull request identity is incomplete")
    head_repo = head.get("repo")
    base_repo = base.get("repo")
    if (
        value.get("state") != "open"
        or not isinstance(value.get("number"), int)
        or isinstance(value.get("number"), bool)
        or int(value["number"]) < 1
        or not re.fullmatch(r"PR_[A-Za-z0-9_-]+", str(value.get("node_id", "")))
        or head.get("ref") != branch
        or head.get("sha") != head_sha
        or base.get("ref") != base_ref
        or base.get("sha") != base_sha
        or not isinstance(head_repo, Mapping)
        or not isinstance(base_repo, Mapping)
        or head_repo.get("id") != repository_id
        or base_repo.get("id") != repository_id
    ):
        raise GitHubValueError(
            "candidate pull request does not bind the exact proved subject"
        )
    return {
        "number": int(value["number"]),
        "node_id": str(value["node_id"]),
        "state": "open",
        "repository_id": repository_id,
        "base_sha": base_sha,
        "head_sha": head_sha,
    }
