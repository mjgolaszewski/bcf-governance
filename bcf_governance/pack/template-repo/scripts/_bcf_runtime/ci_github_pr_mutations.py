"""Narrow pull-request mutation adapter for the GitHub control plane."""

from __future__ import annotations

import re
from typing import Any

from .ci_github_errors import GitHubAPIConflictError
from .ci_github_values import positive_id, repository as exact_repository, sha


_SHA = re.compile(r"[a-f0-9]{40}")


class _GraphQLResultError(ValueError):
    """A successful HTTP exchange did not carry one closed GraphQL result."""


def _exact_pull_subject(
    value: object,
    *,
    number: object,
    node_id: str,
    expected_base_sha: str,
    expected_head_sha: str,
    state: str,
) -> dict[str, Any]:
    if not isinstance(value, dict):
        raise ValueError("protected-merge pull request response is not an object")
    head, base = value.get("head"), value.get("base")
    if (
        str(value.get("number")) != str(number)
        or value.get("node_id") != node_id
        or value.get("state") != state
        or not isinstance(head, dict)
        or not isinstance(base, dict)
        or head.get("sha") != expected_head_sha
        or base.get("sha") != expected_base_sha
    ):
        raise ValueError("protected-merge pull request identity is not exact")
    return value


def _is_clean(value: dict[str, Any]) -> bool:
    return value.get("mergeable") is True and value.get("mergeable_state") == "clean"


def _auto_merge_request(value: dict[str, Any]) -> bool:
    request = value.get("auto_merge")
    if not isinstance(request, dict):
        return False
    if request.get("merge_method") != "merge":
        raise ValueError("pull request has a conflicting auto-merge method")
    return True


def _graphql_auto_merge_pull(value: object) -> dict[str, Any]:
    if not isinstance(value, dict):
        raise _GraphQLResultError("provider auto-merge result is not an object")
    errors = value.get("errors")
    if errors not in (None, []):
        if not isinstance(errors, list) or any(not isinstance(item, dict) for item in errors):
            raise _GraphQLResultError("provider auto-merge error inventory is malformed")
        raise _GraphQLResultError("provider auto-merge rejected the exact protected request")
    data = value.get("data")
    operation = data.get("enablePullRequestAutoMerge") if isinstance(data, dict) else None
    result = operation.get("pullRequest") if isinstance(operation, dict) else None
    if not isinstance(result, dict):
        raise _GraphQLResultError("provider auto-merge success data is incomplete")
    return result


class GitHubPRMutationMixin:
    """Expose only exact PR creation and normal protected merge mutations."""

    def _request(
        self,
        method: str,
        path: str,
        *,
        payload: dict[str, Any] | None = None,
        not_found_none: bool = False,
    ) -> Any:
        raise NotImplementedError

    def create_pull_request(
        self,
        repository: str,
        *,
        title: str,
        head: str,
        base: str,
        body: str,
    ) -> dict[str, Any]:
        if (
            not title.strip()
            or len(title) > 256
            or len(body) > 16_384
            or not re.fullmatch(r"[A-Za-z0-9._/-]+", head)
            or not re.fullmatch(r"[A-Za-z0-9._/-]+", base)
            or ".." in head
            or ".." in base
        ):
            raise ValueError("pull request creation identity is unsafe")
        value = self._request(
            "POST",
            f"/repos/{exact_repository(repository)}/pulls",
            payload={"title": title, "head": head, "base": base, "body": body},
        )
        if not isinstance(value, dict) or value.get("state") != "open":
            raise ValueError("provider did not create an open pull request")
        return value

    def update_pull_request_metadata(
        self,
        repository: str,
        number: object,
        *,
        node_id: str,
        expected_head_sha: str,
        title: str,
        body: str,
    ) -> dict[str, Any]:
        """Project exact candidate metadata onto one authenticated open PR."""

        exact_repository(repository)
        numeric = positive_id(number, field="pull request number")
        if (
            not re.fullmatch(r"PR_[A-Za-z0-9_-]+", node_id)
            or not title.strip()
            or len(title) > 256
            or len(body) > 16_384
        ):
            raise ValueError("pull request metadata identity is unsafe")
        expected_sha = sha(expected_head_sha, field="pull request metadata head")
        observed = self.pull_request(repository, numeric)  # type: ignore[attr-defined]
        head = observed.get("head") if isinstance(observed, dict) else None
        if (
            observed.get("state") != "open"
            or observed.get("node_id") != node_id
            or not isinstance(head, dict)
            or head.get("sha") != expected_sha
        ):
            raise ValueError("pull request metadata subject is not exact")
        if observed.get("title") == title and observed.get("body") == body:
            return observed
        updated = self._request(
            "PATCH",
            f"/repos/{exact_repository(repository)}/pulls/{numeric}",
            payload={"title": title, "body": body},
        )
        updated_head = updated.get("head") if isinstance(updated, dict) else None
        if (
            not isinstance(updated, dict)
            or updated.get("state") != "open"
            or updated.get("node_id") != node_id
            or updated.get("title") != title
            or updated.get("body") != body
            or not isinstance(updated_head, dict)
            or updated_head.get("sha") != expected_sha
        ):
            raise ValueError("provider did not bind exact pull request metadata")
        return updated

    def enable_pull_request_auto_merge(
        self,
        repository: str,
        number: object,
        *,
        node_id: str,
        expected_base_sha: str,
        expected_head_sha: str,
    ) -> dict[str, Any]:
        exact_repository(repository)
        numeric = positive_id(number, field="pull request number")
        if not re.fullmatch(r"PR_[A-Za-z0-9_-]+", node_id):
            raise ValueError("pull request node identity is invalid")
        expected_base = sha(expected_base_sha, field="auto-merge pull request base")
        expected_head = sha(expected_head_sha, field="auto-merge pull request head")
        pull = _exact_pull_subject(
            self.pull_request(repository, numeric),  # type: ignore[attr-defined]
            number=numeric,
            node_id=node_id,
            expected_base_sha=expected_base,
            expected_head_sha=expected_head,
            state="open",
        )
        if _auto_merge_request(pull):
            return {"status": "already_enabled", "pull_request": int(numeric)}
        if _is_clean(pull):
            return {"status": "certified_clean", "pull_request": int(numeric)}
        provider_repository = self.repository(repository)  # type: ignore[attr-defined]
        if provider_repository.get("allow_auto_merge") is not True:
            for attempt in range(2):
                try:
                    updated = self._request(
                        "PATCH",
                        f"/repos/{exact_repository(repository)}",
                        payload={"allow_auto_merge": True},
                    )
                except ValueError:
                    observed = self.repository(repository)  # type: ignore[attr-defined]
                    if observed.get("allow_auto_merge") is True:
                        break
                    if attempt == 0:
                        continue
                    raise
                if not isinstance(updated, dict) or updated.get("allow_auto_merge") is not True:
                    raise ValueError("provider did not enable repository auto-merge")
                break
        payload = {
            "query": (
                "mutation($id:ID!){enablePullRequestAutoMerge(input:{"
                "pullRequestId:$id,mergeMethod:MERGE}){pullRequest{"
                "id number autoMergeRequest{mergeMethod}}}}"
            ),
            "variables": {"id": node_id},
        }
        value = None
        for attempt in range(2):
            try:
                value = self._request("POST", "/graphql", payload=payload)
                break
            except ValueError:
                observed = _exact_pull_subject(
                    self.pull_request(repository, numeric),  # type: ignore[attr-defined]
                    number=numeric,
                    node_id=node_id,
                    expected_base_sha=expected_base,
                    expected_head_sha=expected_head,
                    state="open",
                )
                if _auto_merge_request(observed):
                    return {
                        "status": "observed_after_unknown_result",
                        "pull_request": int(numeric),
                    }
                if _is_clean(observed):
                    return {
                        "status": "certified_clean",
                        "pull_request": int(numeric),
                    }
                if attempt == 0:
                    continue
                raise
        try:
            result = _graphql_auto_merge_pull(value)
        except _GraphQLResultError:
            observed = _exact_pull_subject(
                self.pull_request(repository, numeric),  # type: ignore[attr-defined]
                number=numeric,
                node_id=node_id,
                expected_base_sha=expected_base,
                expected_head_sha=expected_head,
                state="open",
            )
            if _auto_merge_request(observed):
                return {
                    "status": "observed_after_provider_rejection",
                    "pull_request": int(numeric),
                }
            if _is_clean(observed):
                return {
                    "status": "certified_clean",
                    "pull_request": int(numeric),
                }
            raise
        request = result.get("autoMergeRequest") if isinstance(result, dict) else None
        if (
            not isinstance(result, dict)
            or result.get("id") != node_id
            or int(result.get("number", 0)) != int(numeric)
            or not isinstance(request, dict)
            or request.get("mergeMethod") != "MERGE"
        ):
            raise ValueError("provider did not bind exact protected auto-merge")
        return {"status": "enabled", "pull_request": int(numeric)}

    def merge_clean_pull_request(
        self,
        repository: str,
        number: object,
        *,
        node_id: str,
        expected_base_sha: str,
        expected_head_sha: str,
    ) -> dict[str, Any]:
        """Complete only an exact provider-clean PR with an ordinary merge commit."""

        exact_repository(repository)
        numeric = positive_id(number, field="pull request number")
        if not re.fullmatch(r"PR_[A-Za-z0-9_-]+", node_id):
            raise ValueError("pull request node identity is invalid")
        expected_base = sha(expected_base_sha, field="normal merge pull request base")
        expected_head = sha(expected_head_sha, field="normal merge pull request head")

        def open_pull() -> dict[str, Any]:
            value = _exact_pull_subject(
                self.pull_request(repository, numeric),  # type: ignore[attr-defined]
                number=numeric,
                node_id=node_id,
                expected_base_sha=expected_base,
                expected_head_sha=expected_head,
                state="open",
            )
            if not _is_clean(value):
                raise ValueError("normal merge requires an exact provider-clean pull request")
            return value

        def merged_pull() -> dict[str, Any] | None:
            value = self.pull_request(repository, numeric)  # type: ignore[attr-defined]
            if not isinstance(value, dict) or value.get("state") != "closed":
                return None
            exact = _exact_pull_subject(
                value,
                number=numeric,
                node_id=node_id,
                expected_base_sha=expected_base,
                expected_head_sha=expected_head,
                state="closed",
            )
            commit = exact.get("merge_commit_sha")
            if exact.get("merged") is not True or not isinstance(commit, str) or _SHA.fullmatch(commit) is None:
                raise ValueError("provider closed the pull request without an exact merge commit")
            return exact

        open_pull()
        payload = {"sha": expected_head, "merge_method": "merge"}
        result: object = None
        for attempt in range(2):
            try:
                result = self._request(
                    "PUT",
                    f"/repos/{exact_repository(repository)}/pulls/{numeric}/merge",
                    payload=payload,
                )
            except GitHubAPIConflictError:
                observed = merged_pull()
                if observed is not None:
                    return {
                        "status": "merged_after_conflict_observation",
                        "pull_request": int(numeric),
                        "merge_commit_sha": str(observed["merge_commit_sha"]),
                    }
                raise
            except ValueError:
                observed = merged_pull()
                if observed is not None:
                    return {
                        "status": "merged_after_unknown_result",
                        "pull_request": int(numeric),
                        "merge_commit_sha": str(observed["merge_commit_sha"]),
                    }
                if attempt == 0:
                    open_pull()
                    continue
                raise
            break
        merge_sha = result.get("sha") if isinstance(result, dict) else None
        if (
            not isinstance(result, dict)
            or result.get("merged") is not True
            or not isinstance(merge_sha, str)
            or _SHA.fullmatch(merge_sha) is None
        ):
            raise ValueError("provider did not return an exact normal merge result")
        observed = merged_pull()
        if observed is None or observed.get("merge_commit_sha") != merge_sha:
            raise ValueError("provider normal merge result is not bound to the merged PR")
        return {
            "status": "merged",
            "pull_request": int(numeric),
            "merge_commit_sha": merge_sha,
        }
