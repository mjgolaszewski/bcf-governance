"""Bounded complete GitHub Actions artifact inventory reads."""

from __future__ import annotations

import re
from typing import Any, Callable
from urllib.parse import urlencode


class ArtifactInventoryError(ValueError):
    """Raised when provider pagination cannot prove one exact inventory."""


class _ArtifactInventoryChanged(ArtifactInventoryError):
    """Raised when one bounded read observes concurrent provider mutation."""


RequestJSON = Callable[[str, str], Any]
_MAX_STABLE_READ_ATTEMPTS = 4


def _read_repository_artifacts(
    request: RequestJSON,
    *,
    endpoint: str,
    name: str | None,
) -> tuple[dict[str, Any], ...]:
    """Read one candidate inventory while rejecting within-read drift."""

    query: dict[str, str | int] = {"per_page": 100, "page": 1}
    if name is not None:
        query["name"] = name
    first = request("GET", f"{endpoint}?{urlencode(query)}")
    artifacts = first.get("artifacts") if isinstance(first, dict) else None
    total = first.get("total_count") if isinstance(first, dict) else None
    if (
        not isinstance(total, int)
        or isinstance(total, bool)
        or total < 0
        or total > 100_000
        or not isinstance(artifacts, list)
        or any(not isinstance(item, dict) for item in artifacts)
    ):
        raise ArtifactInventoryError(
            "repository artifact response must contain a bounded exact object list"
        )
    result = list(artifacts)
    for page in range(2, (total + 99) // 100 + 1):
        query["page"] = page
        value = request("GET", f"{endpoint}?{urlencode(query)}")
        items = value.get("artifacts") if isinstance(value, dict) else None
        if (
            not isinstance(value, dict)
            or value.get("total_count") != total
            or not isinstance(items, list)
            or any(not isinstance(item, dict) for item in items)
        ):
            raise _ArtifactInventoryChanged(
                "repository artifact inventory changed during pagination"
            )
        result.extend(items)
    identities = [item.get("id") for item in result]
    if any(
        not isinstance(value, int) or isinstance(value, bool) or value < 1
        for value in identities
    ):
        raise ArtifactInventoryError(
            "repository artifact inventory contains an invalid identity"
        )
    if len(result) != total or len(set(identities)) != len(identities):
        raise _ArtifactInventoryChanged(
            "repository artifact inventory is incomplete or ambiguous"
        )
    return tuple(result)


def _inventory_fingerprint(
    artifacts: tuple[dict[str, Any], ...],
) -> tuple[dict[str, Any], ...]:
    """Canonicalize exact provider objects for consecutive-read comparison."""

    return tuple(sorted(artifacts, key=lambda item: item["id"]))


def complete_repository_artifacts(
    request: RequestJSON,
    *,
    endpoint: str,
    name: str | None = None,
) -> tuple[dict[str, Any], ...]:
    """Read one bounded, stable, identity-unique repository artifact inventory."""

    if name is not None:
        if not re.fullmatch(r"[A-Za-z0-9_.-]+", name):
            raise ArtifactInventoryError("artifact name filter is unsafe")
    previous: tuple[dict[str, Any], ...] | None = None
    for _ in range(_MAX_STABLE_READ_ATTEMPTS):
        try:
            current = _read_repository_artifacts(
                request,
                endpoint=endpoint,
                name=name,
            )
        except _ArtifactInventoryChanged:
            previous = None
            continue
        fingerprint = _inventory_fingerprint(current)
        if fingerprint == previous:
            return current
        previous = fingerprint
    raise ArtifactInventoryError(
        "repository artifact inventory changed or did not stabilize across bounded reads"
    )
