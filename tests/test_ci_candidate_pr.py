from __future__ import annotations

import copy

import pytest

from bcf_governance.tooling.ci_candidate_pr import ensure_candidate_pull_request
from bcf_governance.tooling.ci_github_pr_mutations import GitHubPRMutationMixin
from bcf_governance.tooling.local_pr import ProspectiveValidationError


REPOSITORY = "owner/repo"
REPOSITORY_ID = 17
BASE = "1" * 40
HEAD = "2" * 40
TREE = "3" * 40


class API:
    def __init__(self, pull_requests: tuple[dict, ...] = ()) -> None:
        self.values = list(copy.deepcopy(pull_requests))
        self.created = 0
        self.updated = 0

    def repository(self, repository: str) -> dict:
        assert repository == REPOSITORY
        return {"id": REPOSITORY_ID, "default_branch": "main"}

    def pull_requests(self, repository: str, *, state: str = "open") -> tuple[dict, ...]:
        assert repository == REPOSITORY and state == "open"
        return tuple(copy.deepcopy(self.values))

    def create_pull_request(self, repository: str, **values: str) -> dict:
        assert repository == REPOSITORY
        assert values["head"] == "feature" and values["base"] == "main"
        assert HEAD in values["body"] and TREE in values["body"]
        self.created += 1
        return _pull(title=values["title"], body=values["body"])

    def update_pull_request_metadata(self, repository: str, number: object, **values: str) -> dict:
        assert repository == REPOSITORY and number == 7
        assert values["node_id"] == "PR_exact7"
        assert values["expected_head_sha"] == HEAD
        self.updated += 1
        return _pull(title=values["title"], body=values["body"])


def _pull(*, title: str = "stale", body: str = "stale") -> dict:
    return {
        "number": 7,
        "node_id": "PR_exact7",
        "state": "open",
        "title": title,
        "body": body,
        "head": {
            "ref": "feature",
            "sha": HEAD,
            "repo": {"id": REPOSITORY_ID},
        },
        "base": {
            "ref": "main",
            "sha": BASE,
            "repo": {"id": REPOSITORY_ID},
        },
    }


def _ensure(api: API) -> dict:
    return ensure_candidate_pull_request(
        api,
        repository=REPOSITORY,
        branch="feature",
        base_ref="main",
        base_sha=BASE,
        head_sha=HEAD,
        tree_sha=TREE,
        title="feat: exact candidate",
        frontier_sha256="4" * 64,
    )


def test_candidate_pr_is_created_once_then_reused_by_exact_identity() -> None:
    created = API()
    assert _ensure(created)["number"] == 7
    assert created.created == 1
    existing = API((_pull(),))
    assert _ensure(existing)["head_sha"] == HEAD
    assert existing.created == 0
    assert existing.updated == 1


def test_existing_candidate_metadata_is_mechanically_reprojected() -> None:
    existing = API((_pull(title="old proposition", body="old subject"),))
    assert _ensure(existing)["number"] == 7
    assert existing.updated == 1


@pytest.mark.parametrize("field", ["head_sha", "base_sha", "head_repository"])
def test_candidate_pr_rejects_moved_or_cross_repository_identity(field: str) -> None:
    value = _pull()
    if field == "head_sha":
        value["head"]["sha"] = "9" * 40
    elif field == "base_sha":
        value["base"]["sha"] = "9" * 40
    else:
        value["head"]["repo"]["id"] = 99
    with pytest.raises(ProspectiveValidationError, match="exact proved subject"):
        _ensure(API((value,)))


def test_candidate_pr_rejects_ambiguous_open_branch() -> None:
    with pytest.raises(ProspectiveValidationError, match="ambiguous"):
        _ensure(API((_pull(), _pull())))


class AutoMergeAPI(GitHubPRMutationMixin):
    def __init__(self) -> None:
        self.requests: list[tuple[str, str, dict | None]] = []

    def repository(self, _repository: str) -> dict:
        return {"allow_auto_merge": False}

    def pull_request(self, _repository: str, _number: object) -> dict:
        return {
            **_pull(),
            "node_id": "PR_exact7",
            "auto_merge": None,
        }

    def _request(
        self,
        method: str,
        path: str,
        *,
        payload: dict | None = None,
        not_found_none: bool = False,
    ):
        assert not not_found_none
        self.requests.append((method, path, payload))
        if path == f"/repos/{REPOSITORY}":
            return {"allow_auto_merge": True}
        return {
            "data": {
                "enablePullRequestAutoMerge": {
                    "pullRequest": {
                        "id": "PR_exact7",
                        "number": 7,
                        "autoMergeRequest": {"mergeMethod": "MERGE"},
                    }
                }
            }
        }


def test_auto_merge_setting_and_request_are_one_derived_merge_method() -> None:
    api = AutoMergeAPI()
    result = api.enable_pull_request_auto_merge(
        REPOSITORY,
        7,
        node_id="PR_exact7",
        expected_head_sha=HEAD,
    )
    assert result == {"status": "enabled", "pull_request": 7}
    assert api.requests[0] == (
        "PATCH",
        f"/repos/{REPOSITORY}",
        {"allow_auto_merge": True},
    )
    assert api.requests[1][0:2] == ("POST", "/graphql")
    assert "MERGE" in api.requests[1][2]["query"]


def test_auto_merge_rejects_moved_subject_before_provider_mutation() -> None:
    api = AutoMergeAPI()
    api.pull_request = lambda *_args, **_kwargs: {  # type: ignore[method-assign]
        **_pull(), "node_id": "PR_exact7", "auto_merge": None,
        "head": {"sha": "9" * 40, "ref": "feature", "repo": {"id": REPOSITORY_ID}},
    }
    with pytest.raises(ValueError, match="identity is not exact"):
        api.enable_pull_request_auto_merge(
            REPOSITORY, 7, node_id="PR_exact7", expected_head_sha=HEAD
        )
    assert api.requests == []


def test_unknown_auto_merge_result_is_observed_before_any_retry() -> None:
    api = AutoMergeAPI()
    api.repository = lambda _repository: {"allow_auto_merge": True}  # type: ignore[method-assign]
    original_request = api._request
    observations = 0

    def pull_request(*_args, **_kwargs):
        nonlocal observations
        observations += 1
        value = {**_pull(), "node_id": "PR_exact7", "auto_merge": None}
        if observations > 1:
            value["auto_merge"] = {"merge_method": "merge"}
        return value

    api.pull_request = pull_request  # type: ignore[method-assign]
    api._request = lambda *_args, **_kwargs: (_ for _ in ()).throw(  # type: ignore[method-assign]
        ValueError("provider response lost")
    )
    result = api.enable_pull_request_auto_merge(
        REPOSITORY, 7, node_id="PR_exact7", expected_head_sha=HEAD
    )
    assert result == {
        "status": "observed_after_unknown_result",
        "pull_request": 7,
    }
    assert observations == 2
    api._request = original_request  # type: ignore[method-assign]
