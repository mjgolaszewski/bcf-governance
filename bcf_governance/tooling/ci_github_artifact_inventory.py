"""Bounded complete GitHub Actions artifact inventory reads."""

from __future__ import annotations

import re
from typing import Any, Callable
from urllib.parse import urlencode


class ArtifactInventoryError(ValueError):
    """Raised when provider pagination cannot prove one exact inventory."""


RequestJSON = Callable[[str, str], Any]


def complete_repository_artifacts(
    request: RequestJSON,
    *,
    endpoint: str,
    name: str | None = None,
) -> tuple[dict[str, Any], ...]:
    """Read one bounded, stable, identity-unique repository artifact inventory."""

    query: dict[str, str | int] = {"per_page": 100, "page": 1}
    if name is not None:
        if not re.fullmatch(r"[A-Za-z0-9_.-]+", name):
            raise ArtifactInventoryError("artifact name filter is unsafe")
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
            raise ArtifactInventoryError(
                "repository artifact inventory changed during pagination"
            )
        result.extend(items)
    identities = [item.get("id") for item in result]
    if (
        len(result) != total
        or any(
            not isinstance(value, int) or isinstance(value, bool) or value < 1
            for value in identities
        )
        or len(set(identities)) != len(identities)
    ):
        raise ArtifactInventoryError(
            "repository artifact inventory is incomplete or ambiguous"
        )
    return tuple(result)
