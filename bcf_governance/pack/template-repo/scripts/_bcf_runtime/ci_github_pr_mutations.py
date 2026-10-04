"""Narrow pull-request mutation adapter for the GitHub control plane."""

from __future__ import annotations

import re
from typing import Any

from .ci_github_values import positive_id, repository as exact_repository, sha


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

    def enable_pull_request_auto_merge(
        self,
        repository: str,
        number: object,
        *,
        node_id: str,
        expected_head_sha: str,
    ) -> dict[str, Any]:
        exact_repository(repository)
        numeric = positive_id(number, field="pull request number")
        if not re.fullmatch(r"PR_[A-Za-z0-9_-]+", node_id):
            raise ValueError("pull request node identity is invalid")
        pull = self.pull_request(repository, numeric)  # type: ignore[attr-defined]
        head = pull.get("head") if isinstance(pull, dict) else None
        if (
            pull.get("state") != "open"
            or pull.get("node_id") != node_id
            or not isinstance(head, dict)
            or head.get("sha") != sha(
                expected_head_sha, field="auto-merge pull request head"
            )
        ):
            raise ValueError("auto-merge pull request identity is not exact")
        existing = pull.get("auto_merge")
        if isinstance(existing, dict):
            if existing.get("merge_method") != "merge":
                raise ValueError("pull request has a conflicting auto-merge method")
            return {"status": "already_enabled", "pull_request": int(numeric)}
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
            except ValueError:
                observed = self.pull_request(repository, numeric)  # type: ignore[attr-defined]
                auto_merge = observed.get("auto_merge")
                if isinstance(auto_merge, dict):
                    if auto_merge.get("merge_method") != "merge":
                        raise ValueError(
                            "pull request has a conflicting auto-merge method"
                        )
                    return {
                        "status": "observed_after_unknown_result",
                        "pull_request": int(numeric),
                    }
                if attempt == 0:
                    continue
                raise
        result = (
            value.get("data", {}).get("enablePullRequestAutoMerge", {}).get("pullRequest")
            if isinstance(value, dict)
            else None
        )
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
