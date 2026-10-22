"""Exact pinned source identities for non-authoritative adopter compatibility."""

from __future__ import annotations

from dataclasses import asdict, dataclass
import hashlib
import json
from pathlib import Path
from typing import Sequence

import yaml  # type: ignore[import-untyped]


class AdopterSourceError(ValueError):
    """An exact pinned adopter source cannot be admitted."""


@dataclass(frozen=True)
class AdopterSourceIdentity:
    """One exact source in a non-authoritative compatibility observation."""

    id: str
    repository: str
    repository_id: str
    profile: str
    default_branch: str
    commit_sha: str
    tree_sha: str

    def as_dict(self) -> dict[str, str]:
        return asdict(self)


def source_inventory_sha256(sources: Sequence[AdopterSourceIdentity]) -> str:
    """Bind the exact ordered compatibility-source inventory."""

    encoded = json.dumps(
        [source.as_dict() for source in sources],
        separators=(",", ":"),
        sort_keys=True,
    ).encode("utf-8")
    return hashlib.sha256(encoded).hexdigest()


def require_adopter_profile(root: Path, source: AdopterSourceIdentity) -> None:
    """Reject a pinned clone whose declared profile differs from the contract."""

    try:
        profile = yaml.safe_load(
            (root / "governance-profile.yml").read_text(encoding="utf-8")
        )
        selected = profile["profile"]["selected"]
    except (OSError, TypeError, KeyError, yaml.YAMLError) as exc:
        raise AdopterSourceError(
            f"adopter profile is unreadable: {source.repository}"
        ) from exc
    if selected != source.profile:
        raise AdopterSourceError(
            f"adopter profile differs from contract: {source.repository}"
        )
