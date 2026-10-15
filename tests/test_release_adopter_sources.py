from __future__ import annotations

import hashlib
import json
from pathlib import Path

import pytest

from bcf_governance.tooling.release_adopter_sources import (
    AdopterSourceError,
    AdopterSourceIdentity,
    require_adopter_profile,
    source_inventory_sha256,
)


def _source(*, profile: str = "standard") -> AdopterSourceIdentity:
    return AdopterSourceIdentity(
        id="sample-standard-v3",
        repository="owner/sample",
        repository_id="123",
        profile=profile,
        default_branch="pinned-local",
        commit_sha="a" * 40,
        tree_sha="b" * 40,
    )


def test_source_inventory_digest_binds_order_and_every_identity_field() -> None:
    first = _source()
    second = AdopterSourceIdentity(
        **({**first.as_dict(), "id": "other", "commit_sha": "c" * 40})
    )
    expected = hashlib.sha256(
        json.dumps(
            [first.as_dict(), second.as_dict()],
            separators=(",", ":"),
            sort_keys=True,
        ).encode()
    ).hexdigest()
    assert source_inventory_sha256((first, second)) == expected
    assert source_inventory_sha256((second, first)) != expected


def test_pinned_source_profile_must_match_before_compatibility_execution(
    tmp_path: Path,
) -> None:
    (tmp_path / "governance-profile.yml").write_text(
        "profile:\n  selected: standard\n", encoding="utf-8"
    )
    require_adopter_profile(tmp_path, _source())
    with pytest.raises(AdopterSourceError, match="differs from contract"):
        require_adopter_profile(tmp_path, _source(profile="lite"))


def test_missing_profile_fails_closed(tmp_path: Path) -> None:
    with pytest.raises(AdopterSourceError, match="profile is unreadable"):
        require_adopter_profile(tmp_path, _source())
