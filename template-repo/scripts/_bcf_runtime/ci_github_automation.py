"""Authenticated GitHub reconciliation for bounded automation changelog commits."""

from __future__ import annotations

import hashlib
import json
import re
from typing import Any

from .automation_changelog import render_automation_changelog
from .automation_contracts import (
    AutomationContractError,
    REGISTRY_PATH,
    load_automation_registry_bytes,
    select_producer,
)
from .ci_github_api import GitHubAPI
from .ci_github_authority import packaged_repo_root
from .ci_authority_state import CandidateIdentity
from .ci_github_identity import (
    GitHubControllerError,
    MainIdentity,
    authenticate_trusted_run,
    exact_sha,
    positive_int,
    resolve_main,
)


ADMISSION_WORKFLOW = ".github/workflows/bcf-automation-admission.yml"
RECONCILER_WORKFLOW = ".github/workflows/bcf-automation-reconcile.yml"
COMMIT_MESSAGE = "chore(governance): record automated dependency update"


def _trigger(event: dict[str, Any]) -> tuple[str, int]:
    trigger = event.get("workflow_run")
    if not isinstance(trigger, dict):
        raise GitHubControllerError("workflow_run event payload is missing")
    return (
        str(positive_int(trigger.get("id"), field="triggering run ID")),
        positive_int(trigger.get("run_attempt"), field="triggering run attempt"),
    )


def _pull_request_number(run: dict[str, Any]) -> int:
    values = run.get("pull_requests")
    if not isinstance(values, list) or len(values) != 1 or not isinstance(values[0], dict):
        raise GitHubControllerError("admission run must identify exactly one pull request")
    return positive_int(values[0].get("number"), field="pull request number")


def _pr_identity(pr: dict[str, Any]) -> dict[str, Any]:
    head = pr.get("head")
    base = pr.get("base")
    actor = pr.get("user")
    if not all(isinstance(item, dict) for item in (head, base, actor)):
        raise GitHubControllerError("pull request identity is incomplete")
    head_repo = head.get("repo")
    base_repo = base.get("repo")
    if not isinstance(head_repo, dict) or not isinstance(base_repo, dict):
        raise GitHubControllerError("pull request repository identity is incomplete")
    if pr.get("state") != "open" or pr.get("draft") not in {True, False}:
        raise GitHubControllerError("automation pull request must be open")
    return {
        "number": positive_int(pr.get("number"), field="pull request number"),
        "head_sha": exact_sha(head.get("sha"), field="pull request head SHA"),
        "head_branch": str(head.get("ref", "")),
        "head_repository_id": positive_int(head_repo.get("id"), field="head repository ID"),
        "base_branch": str(base.get("ref", "")),
        "base_repository_id": positive_int(base_repo.get("id"), field="base repository ID"),
        "actor_id": positive_int(actor.get("id"), field="actor ID"),
        "actor_login": str(actor.get("login", "")),
    }


def _changed_inventory(
    files: tuple[dict[str, Any], ...], *, changelog_path: str
) -> tuple[tuple[str, ...], str]:
    normalized: list[tuple[str, str, str]] = []
    for item in files:
        if item.get("status") not in {"added", "modified", "removed"} or item.get("previous_filename") is not None:
            raise AutomationContractError("renamed or unsupported dependency changes are not admitted")
        filename = str(item.get("filename", ""))
        blob = exact_sha(item.get("sha"), field=f"changed blob SHA for {filename}")
        normalized.append((filename, str(item["status"]), blob))
    if len(normalized) != len(set(normalized)):
        raise AutomationContractError("provider returned duplicate changed-file records")
    normalized.sort()
    governed_source = [item for item in normalized if item[0] != changelog_path]
    if not governed_source:
        raise AutomationContractError("automation PR contains no dependency source state")
    raw = json.dumps(governed_source, separators=(",", ":")).encode()
    return tuple(item[0] for item in normalized), hashlib.sha256(raw).hexdigest()


def _authenticated_match(
    observer: GitHubAPI,
    *,
    repository: str,
    registry: dict[str, Any],
    pr_number: int,
    repository_id: int,
) -> tuple[dict[str, Any], Any, str]:
    pr = _pr_identity(observer.pull_request(repository, pr_number))
    if pr["number"] != pr_number:
        raise GitHubControllerError("provider pull request number is inconsistent")
    files = observer.pull_request_files(repository, pr_number)
    confirmed_pr = _pr_identity(observer.pull_request(repository, pr_number))
    if confirmed_pr != pr:
        raise GitHubControllerError(
            "automation pull request advanced while provider state was observed"
        )
    changed_paths, source_state = _changed_inventory(
        files,
        changelog_path=str(registry["policy"]["changelog_path"]),
    )
    match = select_producer(
        registry,
        repository=repository,
        repository_id=repository_id,
        actor_id=pr["actor_id"],
        actor_login=pr["actor_login"],
        head_repository_id=pr["head_repository_id"],
        head_branch=pr["head_branch"],
        changed_paths=changed_paths,
    )
    return pr, match, source_state


def _candidate_identity(
    observer: GitHubAPI, *, repository: str, pr: dict[str, Any]
) -> CandidateIdentity:
    commit = observer.commit(repository, pr["head_sha"])
    tree = commit.get("tree")
    if not isinstance(tree, dict):
        raise GitHubControllerError("automation candidate commit tree is missing")
    return CandidateIdentity(
        checkout_sha=pr["head_sha"],
        tree_sha=exact_sha(tree.get("sha"), field="automation candidate tree SHA"),
    )


def _automation_subject(
    observer: GitHubAPI,
    *,
    repository: str,
    registry: dict[str, Any],
    main: MainIdentity,
    run_id: object,
) -> tuple[dict[str, Any], Any, str, CandidateIdentity]:
    run = observer.run(repository, run_id)
    pr_number = _pull_request_number(run)
    pr, match, source_state = _authenticated_match(
        observer,
        repository=repository,
        registry=registry,
        pr_number=pr_number,
        repository_id=int(main.repository_id),
    )
    if (
        pr["base_branch"] != main.default_branch
        or pr["base_repository_id"] != int(main.repository_id)
    ):
        raise GitHubControllerError(
            "automation pull request does not target current default main"
        )
    return pr, match, source_state, _candidate_identity(
        observer, repository=repository, pr=pr
    )


def admit_automation_pr(
    observer: GitHubAPI,
    *,
    repository: str,
    admission_run_id: object,
    admission_run_attempt: object,
) -> dict[str, Any]:
    """Authenticate a metadata-only automation PR admission without writing state."""

    main = resolve_main(observer, repository)
    registry_content = observer.content(
        repository, REGISTRY_PATH.as_posix(), ref=main.checkout_sha
    )
    registry = load_automation_registry_bytes(
        registry_content.content,
        schema_path=packaged_repo_root() / "schemas/automation-producers.schema.json",
    )
    pr, match, source_state, candidate = _automation_subject(
        observer,
        repository=repository,
        registry=registry,
        main=main,
        run_id=admission_run_id,
    )
    admission = authenticate_trusted_run(
        observer,
        repository=repository,
        main=main,
        run_id=admission_run_id,
        run_attempt=admission_run_attempt,
        workflow_path=ADMISSION_WORKFLOW,
        expected_event="pull_request_target",
        require_success=False,
        expected_candidate=candidate,
    )
    run = observer.run(repository, admission.run_id)
    pr_number = _pull_request_number(run)
    if pr_number != pr["number"]:
        raise GitHubControllerError("admission run pull request identity changed")
    return {
        "status": "admitted",
        "producer_id": str(match.producer["id"]),
        "pull_request": pr_number,
        "source_head": pr["head_sha"],
        "source_state": source_state,
    }


def reconcile_automation_changelog(
    observer: GitHubAPI,
    writer: GitHubAPI,
    *,
    repository: str,
    event: dict[str, Any],
    reconciler_run_id: object,
    reconciler_run_attempt: object,
) -> dict[str, Any]:
    """Authenticate the full PR state and perform one non-force changelog commit."""

    main = resolve_main(observer, repository)
    registry_content = observer.content(
        repository, REGISTRY_PATH.as_posix(), ref=main.checkout_sha
    )
    registry = load_automation_registry_bytes(
        registry_content.content,
        schema_path=packaged_repo_root() / "schemas/automation-producers.schema.json",
    )
    authenticate_trusted_run(
        observer,
        repository=repository,
        main=main,
        run_id=reconciler_run_id,
        run_attempt=reconciler_run_attempt,
        workflow_path=RECONCILER_WORKFLOW,
        expected_event="workflow_run",
        require_success=False,
    )
    trigger_run_id, trigger_attempt = _trigger(event)
    pr, match, source_state, candidate = _automation_subject(
        observer,
        repository=repository,
        registry=registry,
        main=main,
        run_id=trigger_run_id,
    )
    admission = authenticate_trusted_run(
        observer,
        repository=repository,
        main=main,
        run_id=trigger_run_id,
        run_attempt=trigger_attempt,
        workflow_path=ADMISSION_WORKFLOW,
        expected_event="pull_request_target",
        require_success=True,
        expected_candidate=candidate,
    )
    admission_run = observer.run(repository, admission.run_id)
    pr_number = _pull_request_number(admission_run)
    if pr["number"] != pr_number:
        raise GitHubControllerError("admission run pull request identity changed")
    repository_id = int(main.repository_id)
    changelog_path = str(registry["policy"]["changelog_path"])
    current = observer.content(repository, changelog_path, ref=pr["head_sha"])
    projection = render_automation_changelog(
        current.content,
        repository_id=repository_id,
        producer_id=str(match.producer["id"]),
        pr_number=pr_number,
        source_state=source_state,
        dependency_paths=match.dependency_paths,
    )
    common = {
        "repository_id": repository_id,
        "producer_id": str(match.producer["id"]),
        "pull_request": pr_number,
        "source_head": pr["head_sha"],
        "source_state": source_state,
        "dependency_paths": list(match.dependency_paths),
        "marker": projection.marker,
    }
    if not projection.changed:
        return {"status": "unchanged", **common, "commit": pr["head_sha"]}
    writer_repo = writer.repository(repository)
    if positive_int(writer_repo.get("id"), field="writer repository ID") != repository_id:
        raise GitHubControllerError("writer token is scoped to the wrong repository")
    head_ref = writer.reference(repository, f"heads/{pr['head_branch']}")
    target = head_ref.get("object")
    if not isinstance(target, dict) or target.get("type") != "commit" or target.get("sha") != pr["head_sha"]:
        raise GitHubControllerError("automation head advanced before write construction")
    commit = observer.commit(repository, pr["head_sha"])
    tree = commit.get("tree")
    if not isinstance(tree, dict):
        raise GitHubControllerError("automation source tree is missing")
    base_tree = exact_sha(tree.get("sha"), field="automation source tree SHA")
    blob = writer.create_blob(repository, projection.content)
    projected_tree = writer.create_tree(
        repository, base_tree=base_tree, path=changelog_path, blob_sha=blob
    )
    new_commit = writer.create_commit(
        repository,
        message=COMMIT_MESSAGE,
        tree=projected_tree,
        parent=pr["head_sha"],
    )
    writer.update_reference(
        repository,
        branch=pr["head_branch"],
        expected_sha=pr["head_sha"],
        commit_sha=new_commit,
    )
    if not re.fullmatch(r"[a-f0-9]{40}", new_commit):
        raise GitHubControllerError("writer returned an invalid commit identity")
    return {"status": "committed", **common, "commit": new_commit}
