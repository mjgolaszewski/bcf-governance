"""Provider projection for one prospectively proved candidate pull request."""

from __future__ import annotations

import re
from typing import Any, Mapping, Protocol

from .local_pr import ProspectiveValidationError


class CandidatePRAPI(Protocol):
    def repository(self, repository: str) -> dict[str, Any]: ...
    def pull_requests(
        self, repository: str, *, state: str = "open"
    ) -> tuple[dict[str, Any], ...]: ...
    def create_pull_request(
        self,
        repository: str,
        *,
        title: str,
        head: str,
        base: str,
        body: str,
    ) -> dict[str, Any]: ...


def _validate(
    value: Mapping[str, Any],
    *,
    repository_id: int,
    branch: str,
    base_ref: str,
    base_sha: str,
    head_sha: str,
) -> dict[str, Any]:
    head = value.get("head")
    base = value.get("base")
    if not isinstance(head, Mapping) or not isinstance(base, Mapping):
        raise ProspectiveValidationError("candidate pull request identity is incomplete")
    head_repo = head.get("repo")
    base_repo = base.get("repo")
    if (
        value.get("state") != "open"
        or not isinstance(value.get("number"), int)
        or isinstance(value.get("number"), bool)
        or int(value["number"]) < 1
        or not re.fullmatch(r"PR_[A-Za-z0-9_-]+", str(value.get("node_id", "")))
        or head.get("ref") != branch
        or head.get("sha") != head_sha
        or base.get("ref") != base_ref
        or base.get("sha") != base_sha
        or not isinstance(head_repo, Mapping)
        or not isinstance(base_repo, Mapping)
        or head_repo.get("id") != repository_id
        or base_repo.get("id") != repository_id
    ):
        raise ProspectiveValidationError(
            "candidate pull request does not bind the exact proved subject"
        )
    return {
        "number": int(value["number"]),
        "node_id": str(value["node_id"]),
        "state": "open",
        "repository_id": repository_id,
        "base_sha": base_sha,
        "head_sha": head_sha,
    }


def ensure_candidate_pull_request(
    api: CandidatePRAPI,
    *,
    repository: str,
    branch: str,
    base_ref: str,
    base_sha: str,
    head_sha: str,
    tree_sha: str,
    title: str,
    frontier_sha256: str,
) -> dict[str, Any]:
    """Create or reuse the sole exact open PR for a proved candidate."""

    observed = api.repository(repository)
    repository_id = observed.get("id") if isinstance(observed, Mapping) else None
    if (
        not isinstance(repository_id, int)
        or isinstance(repository_id, bool)
        or repository_id < 1
        or observed.get("default_branch") != base_ref
        or not re.fullmatch(r"[a-f0-9]{64}", frontier_sha256)
    ):
        raise ProspectiveValidationError(
            "candidate PR provider or recovery identity is invalid"
        )
    matches = []
    for item in api.pull_requests(repository, state="open"):
        head = item.get("head")
        if isinstance(head, Mapping) and head.get("ref") == branch:
            matches.append(item)
    if len(matches) > 1:
        raise ProspectiveValidationError(
            "candidate branch has ambiguous open pull requests"
        )
    if not matches:
        body = (
            "BCF canonical candidate submission.\n\n"
            f"- Base: `{base_sha}`\n"
            f"- Candidate: `{head_sha}`\n"
            f"- Tree: `{tree_sha}`\n"
            f"- Recovery frontier: `{frontier_sha256}`\n\n"
            "Provider certification and protected merge remain authoritative."
        )
        try:
            created = api.create_pull_request(
                repository,
                title=title,
                head=branch,
                base=base_ref,
                body=body,
            )
        except ValueError as exc:
            raise ProspectiveValidationError(
                "provider did not create the exact candidate pull request"
            ) from exc
        matches = [created]
    return _validate(
        matches[0],
        repository_id=repository_id,
        branch=branch,
        base_ref=base_ref,
        base_sha=base_sha,
        head_sha=head_sha,
    )
