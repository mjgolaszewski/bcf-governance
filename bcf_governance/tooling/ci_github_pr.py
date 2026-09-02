"""Exact-head pull-request aggregation and GitHub check publication."""

from __future__ import annotations

from dataclasses import asdict
import hashlib
import json
from pathlib import Path, PurePosixPath
from typing import Any

from .ci_authority_decisions import (
    StatusConclusion,
    StatusContext,
    StatusObservation,
    decide_status_publication,
)
from .ci_github import GithubReferenceError, authenticate_github_run
from .ci_github_api import GitHubAPI
from .ci_github_authority import packaged_repo_root
from .ci_github_bundle import prepare_output, verify_bundle, write_exclusive
from .ci_github_identity import (
    GitHubControllerError,
    MainIdentity,
    authenticate_trusted_run,
    exact_sha,
    positive_int,
    resolve_main,
)
from .github_protection import PROTECTION_PATH, load_protection_bytes


FINALIZER_WORKFLOW = ".github/workflows/bcf-pr-finalizer.yml"
PUBLISHER_WORKFLOW = ".github/workflows/bcf-pr-status-publisher.yml"
CHECK_CONTEXT = StatusContext.PULL_REQUEST.value
CHECK_APP_ID = 15368


def _trigger(event: dict[str, Any]) -> tuple[str, int]:
    value = event.get("workflow_run")
    if not isinstance(value, dict):
        raise GitHubControllerError("workflow_run event payload is missing")
    return (
        str(positive_int(value.get("id"), field="triggering run ID")),
        positive_int(value.get("run_attempt"), field="triggering run attempt"),
    )


def _pr_number(run: dict[str, Any]) -> int:
    values = run.get("pull_requests")
    if not isinstance(values, list) or len(values) != 1 or not isinstance(values[0], dict):
        raise GitHubControllerError("producer run must identify exactly one pull request")
    return positive_int(values[0].get("number"), field="pull request number")


def _current_head(api: GitHubAPI, repository: str, pr_number: int) -> tuple[str, str]:
    pr = api.pull_request(repository, pr_number)
    head = pr.get("head")
    base = pr.get("base")
    if pr.get("state") != "open" or not isinstance(head, dict) or not isinstance(base, dict):
        raise GitHubControllerError("pull request is no longer open or complete")
    head_repo = head.get("repo")
    base_repo = base.get("repo")
    if not isinstance(head_repo, dict) or not isinstance(base_repo, dict):
        raise GitHubControllerError("pull request repository identity is incomplete")
    repository_id = positive_int(api.repository(repository).get("id"), field="repository ID")
    if positive_int(head_repo.get("id"), field="head repository ID") != repository_id:
        raise GitHubControllerError("PR certification requires a same-repository head")
    if positive_int(base_repo.get("id"), field="base repository ID") != repository_id:
        raise GitHubControllerError("PR certification base repository is not exact")
    return exact_sha(head.get("sha"), field="pull request head SHA"), str(head.get("ref", ""))


def _protection(api: GitHubAPI, repository: str, main: MainIdentity) -> dict[str, Any]:
    content = api.content(repository, PROTECTION_PATH.as_posix(), ref=main.checkout_sha)
    return load_protection_bytes(
        content.content,
        schema_path=packaged_repo_root() / "schemas/github-protection.schema.json",
    )


def _authenticate_candidate_run(
    api: GitHubAPI,
    *,
    repository: str,
    repository_id: str,
    main: MainIdentity,
    workflow_path: str,
    run: dict[str, Any],
    candidate_tree: str,
) -> dict[str, Any]:
    workflow_id = str(positive_int(run.get("workflow_id"), field="producer workflow ID"))
    workflow = api.workflow(repository, workflow_id)
    trusted = api.content(repository, workflow_path, ref=main.checkout_sha)
    try:
        identity = authenticate_github_run(
            expected_repository_id=repository_id,
            expected_workflow_id=workflow_id,
            expected_active_path=workflow_path,
            allowed_events=("pull_request",),
            repository={"id": int(repository_id)},
            workflow=workflow,
            run=run,
            trusted_workflow_bytes=trusted.content,
            trusted_workflow_blob_oid=trusted.blob_oid,
            trusted_workflow_definition_commit=main.checkout_sha,
            candidate_tree_sha=candidate_tree,
        )
    except GithubReferenceError as exc:
        raise GitHubControllerError(f"PR producer run is not authenticated: {exc}") from exc
    return asdict(identity)


def _producer_state(
    api: GitHubAPI,
    *,
    repository: str,
    repository_id: str,
    main: MainIdentity,
    head_sha: str,
    head_tree: str,
    contract: dict[str, Any],
) -> dict[str, Any]:
    path = str(contract["path"])
    runs = api.workflow_runs(
        repository,
        PurePosixPath(path).name,
        head_sha=head_sha,
        event="pull_request",
    )
    exact = [
        run
        for run in runs
        if str(run.get("head_sha")) == head_sha
        and str(run.get("event")) == "pull_request"
        and str(run.get("repository", {}).get("id")) == repository_id
    ]
    if not exact:
        return {"id": contract["id"], "state": "pending", "reason": "not_started"}
    selected = max(
        exact,
        key=lambda item: (
            positive_int(item.get("id"), field="producer run ID"),
            positive_int(item.get("run_attempt"), field="producer run attempt"),
        ),
    )
    identity = _authenticate_candidate_run(
        api,
        repository=repository,
        repository_id=repository_id,
        main=main,
        workflow_path=path,
        run=selected,
        candidate_tree=head_tree,
    )
    status = str(selected.get("status"))
    conclusion = selected.get("conclusion")
    if status != "completed":
        state = "pending"
        reason = status
    elif conclusion != "success":
        state = "failed"
        reason = str(conclusion)
    else:
        jobs = api.jobs(
            repository,
            selected["id"],
            attempt=positive_int(selected.get("run_attempt"), field="producer run attempt"),
        )
        required = tuple(contract["required_job_names"])
        matching = {
            name: [job for job in jobs if job.get("name") == name]
            for name in required
        }
        if any(len(values) != 1 for values in matching.values()):
            state, reason = "failed", "required_job_inventory"
        elif any(
            values[0].get("status") != "completed" or values[0].get("conclusion") != "success"
            for values in matching.values()
        ):
            state, reason = "failed", "required_job_conclusion"
        else:
            state, reason = "successful", "all_required_jobs_green"
    return {
        "id": contract["id"],
        "state": state,
        "reason": reason,
        "run_id": str(selected["id"]),
        "run_attempt": int(selected["run_attempt"]),
        "workflow": identity["workflow"],
    }


def finalize_pr(
    api: GitHubAPI,
    *,
    repository: str,
    event: dict[str, Any],
    finalizer_run_id: object,
    finalizer_run_attempt: object,
    output_root: Path,
) -> dict[str, Any]:
    """Reconstruct the latest complete producer set for the current exact PR head."""

    main = resolve_main(api, repository)
    finalizer = authenticate_trusted_run(
        api,
        repository=repository,
        main=main,
        run_id=finalizer_run_id,
        run_attempt=finalizer_run_attempt,
        workflow_path=FINALIZER_WORKFLOW,
        expected_event="workflow_run",
        require_success=False,
    )
    trigger_id, trigger_attempt = _trigger(event)
    trigger = api.run(repository, trigger_id)
    if positive_int(trigger.get("run_attempt"), field="triggering run attempt") != trigger_attempt:
        raise GitHubControllerError("triggering run attempt does not match provider state")
    pr_number = _pr_number(trigger)
    head_sha, head_branch = _current_head(api, repository, pr_number)
    commit = api.commit(repository, head_sha)
    tree = commit.get("tree")
    if not isinstance(tree, dict):
        raise GitHubControllerError("pull request head tree is missing")
    head_tree = exact_sha(tree.get("sha"), field="pull request head tree SHA")
    protection = _protection(api, repository, main)
    if protection["repository"] != {
        "full_name": repository,
        "numeric_id": int(main.repository_id),
        "branch": main.default_branch,
    }:
        raise GitHubControllerError("PR authority declaration does not match provider repository")
    producers = [
        _producer_state(
            api,
            repository=repository,
            repository_id=main.repository_id,
            main=main,
            head_sha=head_sha,
            head_tree=head_tree,
            contract=contract,
        )
        for contract in protection["pr_certification"]["producer_workflows"]
    ]
    states = {item["state"] for item in producers}
    computed = "failed" if "failed" in states else "pending" if "pending" in states else "successful"
    observation = {
        "schema_version": "1.0",
        "kind": "pr_certification_observation",
        "repository": {"full_name": repository, "numeric_id": int(main.repository_id)},
        "pull_request": pr_number,
        "subject": {"commit_sha": head_sha, "tree_sha": head_tree, "branch": head_branch},
        "computed_state": computed,
        "producers": producers,
        "finalizer": {"run_id": finalizer.run_id, "run_attempt": finalizer.run_attempt, "workflow": asdict(finalizer.workflow)},
    }
    root = prepare_output(output_root)
    digest = write_exclusive(root / "pr-observation.json", observation)
    write_exclusive(
        root / "bundle-manifest.json",
        {
            "schema_version": "1.0",
            "kind": "pr_certification_observation",
            "subject": observation["subject"],
            "computed_state": computed,
            "files": {"pr-observation.json": digest},
        },
    )
    return observation


def _existing_observation(run: dict[str, Any], *, subject: str) -> StatusObservation:
    external = str(run.get("external_id", ""))
    parts = external.split(":")
    if len(parts) != 3 or parts[0] != "bcf-pr-certification":
        raise GitHubControllerError("published PR check lacks exact authority identity")
    conclusions = {
        ("in_progress", None): StatusConclusion.PENDING,
        ("completed", "success"): StatusConclusion.SUCCESS,
        ("completed", "failure"): StatusConclusion.FAILURE,
    }
    key = (run.get("status"), run.get("conclusion"))
    if key not in conclusions:
        raise GitHubControllerError("published PR check has unsupported state")
    return StatusObservation(
        context=StatusContext.PULL_REQUEST,
        subject_sha=subject,
        admission_ordinal=positive_int(parts[1], field="PR check ordinal"),
        control_plane_attempt=positive_int(parts[2], field="PR check attempt"),
        conclusion=conclusions[key],
    )


def publish_pr(
    api: GitHubAPI,
    *,
    repository: str,
    event: dict[str, Any],
    publisher_run_id: object,
    publisher_run_attempt: object,
    bundle_root: Path,
    target_url: str,
) -> dict[str, Any]:
    """Authenticate one finalizer bundle and publish the sole PR check owner."""

    main = resolve_main(api, repository)
    authenticate_trusted_run(
        api,
        repository=repository,
        main=main,
        run_id=publisher_run_id,
        run_attempt=publisher_run_attempt,
        workflow_path=PUBLISHER_WORKFLOW,
        expected_event="workflow_run",
        require_success=False,
    )
    trigger_id, trigger_attempt = _trigger(event)
    finalizer = authenticate_trusted_run(
        api,
        repository=repository,
        main=main,
        run_id=trigger_id,
        run_attempt=trigger_attempt,
        workflow_path=FINALIZER_WORKFLOW,
        expected_event="workflow_run",
        require_success=True,
    )
    artifact_name = f"bcf-pr-finalization-{finalizer.run_id}-{finalizer.run_attempt}"
    matching_artifacts = [
        item
        for item in api.artifacts(repository, finalizer.run_id)
        if item.get("name") == artifact_name and item.get("expired") is False
    ]
    if len(matching_artifacts) != 1:
        raise GitHubControllerError("PR finalization artifact identity is not exact")
    artifact_run = matching_artifacts[0].get("workflow_run")
    if not isinstance(artifact_run, dict) or artifact_run != {
        "id": int(finalizer.run_id),
        "repository_id": int(main.repository_id),
        "head_repository_id": int(main.repository_id),
        "head_branch": main.default_branch,
        "head_sha": main.checkout_sha,
    }:
        raise GitHubControllerError("PR finalization artifact subject is not exact")
    manifest = verify_bundle(bundle_root)
    observation = json.loads((bundle_root / "pr-observation.json").read_text(encoding="utf-8"))
    if manifest.get("kind") != "pr_certification_observation" or manifest.get("subject") != observation.get("subject") or manifest.get("computed_state") != observation.get("computed_state"):
        raise GitHubControllerError("PR certification bundle is inconsistent")
    expected_finalizer = {"run_id": finalizer.run_id, "run_attempt": finalizer.run_attempt, "workflow": asdict(finalizer.workflow)}
    if observation.get("finalizer") != expected_finalizer:
        raise GitHubControllerError("PR certification finalizer identity is not exact")
    subject = observation.get("subject")
    if not isinstance(subject, dict):
        raise GitHubControllerError("PR certification subject is missing")
    head_sha, _ = _current_head(api, repository, positive_int(observation.get("pull_request"), field="pull request number"))
    if subject.get("commit_sha") != head_sha:
        raise GitHubControllerError("PR certification subject is not the current pull request head")
    states = {"pending": StatusConclusion.PENDING, "failed": StatusConclusion.FAILURE, "successful": StatusConclusion.SUCCESS}
    computed = str(observation.get("computed_state"))
    if computed not in states:
        raise GitHubControllerError("PR certification computed state is unsupported")
    existing_runs = [
        run
        for run in api.check_runs(repository, sha=head_sha)
        if run.get("name") == CHECK_CONTEXT
        and isinstance(run.get("app"), dict)
        and run["app"].get("id") == CHECK_APP_ID
    ]
    existing = [_existing_observation(run, subject=head_sha) for run in existing_runs]
    current = max(
        existing,
        key=lambda item: (item.admission_ordinal, item.control_plane_attempt),
        default=None,
    )
    proposed = StatusObservation(
        context=StatusContext.PULL_REQUEST,
        subject_sha=head_sha,
        admission_ordinal=int(finalizer.run_id),
        control_plane_attempt=finalizer.run_attempt,
        conclusion=states[computed],
    )
    decision = decide_status_publication(
        proposed=proposed,
        current=current,
        trusted_publisher=True,
    )
    if decision.publish:
        status = "in_progress" if states[computed] is StatusConclusion.PENDING else "completed"
        conclusion = None if status == "in_progress" else states[computed].value
        created = api.create_check_run(
            repository,
            name=CHECK_CONTEXT,
            sha=head_sha,
            status=status,
            conclusion=conclusion,
            details_url=target_url,
            external_id=f"bcf-pr-certification:{finalizer.run_id}:{finalizer.run_attempt}",
            title=f"BCF PR certification {computed}",
            summary=f"Authenticated exact-head producer aggregation is {computed}.",
        )
        app = created.get("app")
        if not isinstance(app, dict) or app.get("id") != CHECK_APP_ID:
            raise GitHubControllerError("provider created PR certification under the wrong App")
    return {
        "status": "published" if decision.publish else "suppressed",
        "reason": decision.reason,
        "computed_state": computed,
        "subject_sha": head_sha,
        "admission_ordinal": int(finalizer.run_id),
    }
