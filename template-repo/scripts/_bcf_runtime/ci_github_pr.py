"""Exact-head pull-request aggregation and GitHub check publication."""

from __future__ import annotations

from dataclasses import asdict
import hashlib
import io
import json
from pathlib import Path, PurePosixPath
import tempfile
from typing import Any
import zipfile

import yaml

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
from .ci_pr_transition import transition_is_applicable, verify_transition_equivalence
from .github_protection import PROTECTION_PATH, load_protection_bytes
from .governance_truth import TruthfulnessError, derive_truth


FINALIZER_WORKFLOW = ".github/workflows/bcf-pr-finalizer.yml"
PUBLISHER_WORKFLOW = ".github/workflows/bcf-pr-status-publisher.yml"
CHECK_CONTEXT = StatusContext.PULL_REQUEST.value
CHECK_APP_ID = 15368
EVALUATOR_RUNTIME_PATH = "bcf_governance/tooling/ci_github_pr.py"
PROTECTED_EVALUATOR_PATHS = (
    ".github/workflows/bcf-pr-finalizer.yml",
    ".github/workflows/bcf-pr-status-publisher.yml",
    EVALUATOR_RUNTIME_PATH,
    "governance/ci-graph.yml",
    "governance/github-protection.yml",
)
MAX_EVALUATOR_ARTIFACT_BYTES = 104_857_600
MAX_EVALUATOR_EXPANDED_BYTES = 209_715_200


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


def _current_pr(
    api: GitHubAPI, repository: str, pr_number: int
) -> tuple[str, str, str, str]:
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
    return (
        exact_sha(head.get("sha"), field="pull request head SHA"),
        str(head.get("ref", "")),
        exact_sha(base.get("sha"), field="pull request base SHA"),
        str(base.get("ref", "")),
    )


def _current_head(api: GitHubAPI, repository: str, pr_number: int) -> tuple[str, str]:
    head, branch, _base, _base_branch = _current_pr(api, repository, pr_number)
    return head, branch


def _protection(api: GitHubAPI, repository: str, main: MainIdentity) -> dict[str, Any]:
    content = api.content(repository, PROTECTION_PATH.as_posix(), ref=main.checkout_sha)
    return load_protection_bytes(
        content.content,
        schema_path=packaged_repo_root() / "schemas/github-protection.schema.json",
    )


def _evaluator_identity(
    api: GitHubAPI,
    *,
    repository: str,
    main: MainIdentity,
    protection: dict[str, Any],
    base_sha: str,
    base_branch: str,
) -> dict[str, Any]:
    if base_sha != main.checkout_sha or base_branch != main.default_branch:
        raise GitHubControllerError(
            "PR evaluator base is not the current protected default branch"
        )
    projection = protection.get("projection")
    profile = projection.get("profile") if isinstance(projection, dict) else None
    if profile == "lite":
        raise GitHubControllerError(
            "Lite direct PR truth cannot invoke independent certification"
        )
    if profile not in {None, "standard"}:
        raise GitHubControllerError("ordinary evaluator profile is unsupported")
    graph_content = api.content(
        repository, "governance/ci-graph.yml", ref=base_sha
    )
    try:
        graph = yaml.safe_load(graph_content.content)
        controller = graph["trusted_controller"]
        controller_kind = controller["kind"]
    except (KeyError, TypeError, yaml.YAMLError) as exc:
        raise GitHubControllerError("protected-base evaluator graph is malformed") from exc
    if controller_kind == "executable":
        mode = "protected_base"
        controller_identity = None
    elif controller_kind in {"self_governance_policy", "governed_controller_policy"}:
        mode = "managed_controller"
        policy_path = controller.get("policy_path")
        if not isinstance(policy_path, str):
            raise GitHubControllerError("managed evaluator policy path is missing")
        policy_content = api.content(repository, policy_path, ref=base_sha)
        try:
            policy = yaml.safe_load(policy_content.content)
            installed = policy["runner_security"]["trusted_controller_installation"]
            controller_identity = {
                "commit_sha": exact_sha(
                    installed["installed_commit_sha"],
                    field="installed evaluator controller SHA",
                ),
                "policy_path": policy_path,
                "policy_blob_oid": policy_content.blob_oid,
                "policy_sha256": hashlib.sha256(policy_content.content).hexdigest(),
            }
        except (KeyError, TypeError, yaml.YAMLError) as exc:
            raise GitHubControllerError(
                "managed evaluator installation identity is malformed"
            ) from exc
    else:
        raise GitHubControllerError("protected-base evaluator source is unsupported")
    runtime = api.content(repository, EVALUATOR_RUNTIME_PATH, ref=base_sha)
    finalizer = api.content(repository, FINALIZER_WORKFLOW, ref=base_sha)
    check = protection.get("pr_certification")
    if not isinstance(check, dict) or check.get("context") != CHECK_CONTEXT or check.get(
        "publisher_app_id"
    ) != CHECK_APP_ID:
        raise GitHubControllerError("PR evaluator check identity is not exact")
    declared_mode = check.get("evaluator_mode")
    if declared_mode is not None and declared_mode != mode:
        raise GitHubControllerError(
            "PR evaluator source differs from the reviewed protection contract"
        )
    return {
        "mode": mode,
        "base": {
            "commit_sha": base_sha,
            "tree_sha": main.tree_sha,
            "branch": base_branch,
        },
        "runtime": {
            "path": EVALUATOR_RUNTIME_PATH,
            "blob_oid": runtime.blob_oid,
            "sha256": hashlib.sha256(runtime.content).hexdigest(),
        },
        "workflow": {
            "path": FINALIZER_WORKFLOW,
            "blob_oid": finalizer.blob_oid,
            "sha256": hashlib.sha256(finalizer.content).hexdigest(),
            "definition_commit": base_sha,
        },
        "graph": {
            "path": "governance/ci-graph.yml",
            "blob_oid": graph_content.blob_oid,
            "sha256": hashlib.sha256(graph_content.content).hexdigest(),
        },
        "controller": controller_identity,
        "protected_paths": list(PROTECTED_EVALUATOR_PATHS),
        "check": {"context": CHECK_CONTEXT, "publisher_app_id": CHECK_APP_ID},
    }


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


def _extract_evidence_archive(raw: bytes, destination: Path) -> None:
    try:
        archive = zipfile.ZipFile(io.BytesIO(raw))
    except zipfile.BadZipFile as exc:
        raise GitHubControllerError("candidate evidence artifact is not a ZIP archive") from exc
    members = archive.infolist()
    if sum(member.file_size for member in members) > MAX_EVALUATOR_EXPANDED_BYTES:
        raise GitHubControllerError("candidate evidence artifact expands beyond its bound")
    for member in members:
        path = PurePosixPath(member.filename)
        if (
            path.is_absolute()
            or ".." in path.parts
            or member.is_dir()
            or not path.parts
        ):
            if member.is_dir() and not path.is_absolute() and ".." not in path.parts:
                continue
            raise GitHubControllerError("candidate evidence artifact contains an unsafe member")
        target = destination.joinpath(*path.parts)
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_bytes(archive.read(member))


def _independent_truth(
    api: GitHubAPI,
    *,
    repository: str,
    repository_id: str,
    run: dict[str, Any],
    candidate_root: Path,
    head_sha: str,
    head_tree: str,
) -> dict[str, Any]:
    run_id = str(positive_int(run.get("id"), field="producer run ID"))
    run_attempt = positive_int(run.get("run_attempt"), field="producer run attempt")
    artifacts = api.artifacts(repository, run_id)
    prefix = f"-{run_id}-{run_attempt}"
    selected = [
        artifact
        for artifact in artifacts
        if isinstance(artifact.get("name"), str)
        and (
            artifact["name"] == f"bcf-session{prefix}"
            or artifact["name"].startswith(f"bcf-evidence{prefix}-")
        )
    ]
    names = [str(artifact["name"]) for artifact in selected]
    if len(names) != len(set(names)) or f"bcf-session{prefix}" not in names or not any(
        name.startswith(f"bcf-evidence{prefix}-") for name in names
    ):
        raise GitHubControllerError("candidate evidence artifact inventory is incomplete")
    identities: list[dict[str, Any]] = []
    with tempfile.TemporaryDirectory(prefix="bcf-pr-evaluator-") as temporary:
        evidence_root = Path(temporary)
        for artifact in selected:
            workflow_run = artifact.get("workflow_run")
            if not isinstance(workflow_run, dict) or any(
                (
                    str(workflow_run.get(field)) != expected
                    for field, expected in (
                        ("id", run_id),
                        ("repository_id", repository_id),
                        ("head_repository_id", repository_id),
                        ("head_sha", head_sha),
                    )
                )
            ):
                raise GitHubControllerError("candidate evidence artifact subject is not exact")
            artifact_id = str(positive_int(artifact.get("id"), field="evidence artifact ID"))
            digest = str(artifact.get("digest", ""))
            if not digest.startswith("sha256:") or len(digest) != 71:
                raise GitHubControllerError("candidate evidence provider digest is malformed")
            raw = api.artifact_bytes(
                repository,
                artifact_id,
                maximum_bytes=MAX_EVALUATOR_ARTIFACT_BYTES,
            )
            if f"sha256:{hashlib.sha256(raw).hexdigest()}" != digest:
                raise GitHubControllerError("candidate evidence bytes do not match provider digest")
            destination = evidence_root / str(artifact["name"])
            _extract_evidence_archive(raw, destination)
            identities.append(
                {"id": artifact_id, "name": artifact["name"], "provider_digest": digest}
            )
        try:
            truth = derive_truth(candidate_root, evidence_root, evaluation_mode="pr")
        except TruthfulnessError as exc:
            raise GitHubControllerError(
                f"protected evaluator rejected candidate evidence: {exc}"
            ) from exc
    subject = truth.get("subject")
    if (
        truth.get("status") != "pass"
        or truth.get("merge_eligibility") != "eligible"
        or not isinstance(subject, dict)
        or subject.get("commit_sha") != head_sha
        or subject.get("tree_sha") != head_tree
    ):
        raise GitHubControllerError("protected evaluator truth is not exact and eligible")
    return {
        "status": "pass",
        "subject": {"commit_sha": head_sha, "tree_sha": head_tree},
        "report_sha256": hashlib.sha256(
            json.dumps(truth, sort_keys=True, separators=(",", ":")).encode()
        ).hexdigest(),
        "artifacts": sorted(identities, key=lambda item: str(item["name"])),
    }


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
    candidate_root: Path | None = None,
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
    head_sha, head_branch, base_sha, base_branch = _current_pr(
        api, repository, pr_number
    )
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
    evaluator = _evaluator_identity(
        api,
        repository=repository,
        main=main,
        protection=protection,
        base_sha=base_sha,
        base_branch=base_branch,
    )
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
    if candidate_root is not None:
        candidate = candidate_root.resolve()
        for producer in producers:
            if producer["state"] != "successful":
                continue
            run = api.run(repository, producer["run_id"])
            producer["independent_truth"] = _independent_truth(
                api,
                repository=repository,
                repository_id=main.repository_id,
                run=run,
                candidate_root=candidate,
                head_sha=head_sha,
                head_tree=head_tree,
            )
    by_id = {item["id"]: item for item in producers}
    package = by_id.get("package")
    governance = by_id.get("governance")
    if isinstance(package, dict) and isinstance(governance, dict):
        transition = transition_is_applicable(
            api,
            repository=repository,
            main=main,
            protection=protection,
            head_sha=head_sha,
            head_branch=head_branch,
            package_state=package,
            schema_root=packaged_repo_root(),
        )
        if transition is not None:
            transition_contract, _successor_protection = transition
            equivalent = verify_transition_equivalence(
                api,
                repository=repository,
                main=main,
                contract=transition_contract,
                pr_number=pr_number,
                head_sha=head_sha,
                head_tree=head_tree,
                head_branch=head_branch,
                governance_state=governance,
            )
            producers = [equivalent if item["id"] == "package" else item for item in producers]
    states = {item["state"] for item in producers}
    computed = "failed" if "failed" in states else "pending" if "pending" in states else "successful"
    observation = {
        "schema_version": "1.0",
        "kind": "pr_certification_observation",
        "repository": {"full_name": repository, "numeric_id": int(main.repository_id)},
        "pull_request": pr_number,
        "subject": {"commit_sha": head_sha, "tree_sha": head_tree, "branch": head_branch},
        "computed_state": computed,
        "evaluator": evaluator,
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
    pr_number = positive_int(observation.get("pull_request"), field="pull request number")
    head_sha, _, base_sha, base_branch = _current_pr(api, repository, pr_number)
    if subject.get("commit_sha") != head_sha:
        raise GitHubControllerError("PR certification subject is not the current pull request head")
    protection = _protection(api, repository, main)
    expected_evaluator = _evaluator_identity(
        api,
        repository=repository,
        main=main,
        protection=protection,
        base_sha=base_sha,
        base_branch=base_branch,
    )
    if observation.get("evaluator") != expected_evaluator:
        raise GitHubControllerError("PR certification evaluator identity is not exact")
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
