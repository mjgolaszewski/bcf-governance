"""Read-only, exact Git-tree custody for main-side closure recomputation."""

from __future__ import annotations

import pytest

from bcf_governance.tooling.ci_github_api import GitHubAPI, GitHubAPIError


TREE = "a" * 40


def _response() -> dict:
    return {
        "sha": TREE, "truncated": False,
        "tree": [
            {"path": "src/a.py", "type": "blob", "sha": "b" * 40},
            {"path": "src", "type": "tree", "sha": "c" * 40},
            {"path": "governance/gate-contracts.yml", "type": "blob", "sha": "d" * 40},
        ],
    }


def test_complete_tree_reads_only_exact_provider_blob_inventory(monkeypatch: pytest.MonkeyPatch) -> None:
    api = GitHubAPI(token="fake")
    observed = []

    def request(method: str, path: str, **_kwargs: object) -> dict:
        observed.append((method, path))
        return _response()

    monkeypatch.setattr(api, "_request", request)
    assert api.complete_tree("owner/repo", TREE) == (
        ("governance/gate-contracts.yml", "d" * 40), ("src/a.py", "b" * 40),
    )
    assert observed == [("GET", f"/repos/owner/repo/git/trees/{TREE}?recursive=1")]


@pytest.mark.parametrize("mutation", [
    lambda value: value.update({"truncated": True}),
    lambda value: value.update({"sha": "e" * 40}),
    lambda value: value["tree"].append(value["tree"][0]),
    lambda value: value["tree"][0].update({"path": "../escape"}),
    lambda value: value["tree"][0].update({"sha": "not-a-sha"}),
])
def test_complete_tree_rejects_incomplete_or_ambiguous_provider_state(
    monkeypatch: pytest.MonkeyPatch, mutation,
) -> None:
    value = _response()
    mutation(value)
    api = GitHubAPI(token="fake")
    monkeypatch.setattr(api, "_request", lambda *_args, **_kwargs: value)
    with pytest.raises(GitHubAPIError):
        api.complete_tree("owner/repo", TREE)
