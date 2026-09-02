from __future__ import annotations

import pytest

from bcf_governance.tooling.ci_github_api import GitHubAPI, GitHubAPIError
from bcf_governance.tooling.release_versions import (
    ReleaseVersionError,
    parse_release_tag,
    parse_release_version,
)


@pytest.mark.parametrize(
    ("value", "tag", "prerelease"),
    [
        ("1.0.0", "v1.0.0", False),
        ("1.0.0a1", "v1.0.0a1", True),
        ("1.0.0b2", "v1.0.0b2", True),
        ("1.0.0rc1", "v1.0.0rc1", True),
    ],
)
def test_public_release_version_policy(value: str, tag: str, prerelease: bool) -> None:
    parsed = parse_release_version(value)
    assert parsed.tag == tag
    assert parsed.prerelease is prerelease
    assert parse_release_tag(tag) == parsed


@pytest.mark.parametrize(
    "value",
    ["1", "1.0", "01.0.0", "1.0.0-rc.1", "1.0.0RC1", "v1.0.0", "1.0.0rc"],
)
def test_public_release_version_policy_rejects_aliases(value: str) -> None:
    with pytest.raises(ReleaseVersionError):
        parse_release_version(value)


def test_github_draft_marks_release_candidates_mechanically(monkeypatch) -> None:
    requests: list[dict[str, object]] = []

    def request(_self, method, path, *, payload=None):
        requests.append({"method": method, "path": path, "payload": payload})
        return {"draft": True}

    monkeypatch.setattr(GitHubAPI, "_request", request)
    api = GitHubAPI(token="test")
    api.create_draft_release(
        "owner/repo", tag="v1.0.0rc1", name="v1.0.0rc1", body="candidate"
    )
    assert requests[0]["payload"]["prerelease"] is True

    with pytest.raises(GitHubAPIError, match="canonical public version"):
        api.release_by_tag("owner/repo", "v1.0")
