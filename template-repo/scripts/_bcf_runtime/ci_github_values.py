"""Exact provider identity validation shared by GitHub transport operations."""

from __future__ import annotations

import re
from urllib.parse import quote


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
