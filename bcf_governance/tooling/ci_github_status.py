"""Trusted exact-main status publication and revocation authority."""

from __future__ import annotations

from dataclasses import asdict
import json
from pathlib import Path
from typing import Any
from urllib.parse import parse_qs, urlencode, urlsplit, urlunsplit

from .ci_authority_certification import verify_ci_certification
from .ci_authority_decisions import (
    StatusConclusion,
    StatusContext,
    StatusObservation,
    decide_status_publication,
)
from .ci_github_api import GitHubAPI
from .ci_github_authority import packaged_repo_root
from .ci_github_bundle import verify_bundle
from .ci_github_identity import (
    GitHubControllerError,
    MainIdentity,
    authenticate_trusted_run,
    positive_int,
    resolve_main,
)


STATUS_CONTEXT = "bcf/exact-main-certification"


def _status_target(target_url: str, *, ordinal: int, attempt: int) -> str:
    parsed = urlsplit(target_url)
    if parsed.scheme != "https" or not parsed.netloc or parsed.fragment:
        raise GitHubControllerError("status target URL must be fragment-free HTTPS")
    query = parse_qs(parsed.query, keep_blank_values=True)
    if "bcf_ordinal" in query or "bcf_attempt" in query:
        raise GitHubControllerError("status target URL already contains BCF authority")
    query["bcf_ordinal"] = [str(ordinal)]
    query["bcf_attempt"] = [str(attempt)]
    encoded = urlencode(
        sorted((key, item) for key, values in query.items() for item in values)
    )
    return urlunsplit((parsed.scheme, parsed.netloc, parsed.path, encoded, ""))


def _status_observation(payload: dict[str, Any], subject: str) -> StatusObservation:
    if payload.get("context") != STATUS_CONTEXT:
        raise GitHubControllerError("status observation has wrong context")
    target = payload.get("target_url")
    if not isinstance(target, str):
        raise GitHubControllerError("published BCF status lacks authority target URL")
    query = parse_qs(urlsplit(target).query)
    if set(query).intersection({"bcf_ordinal", "bcf_attempt"}) != {
        "bcf_ordinal", "bcf_attempt",
    }:
        raise GitHubControllerError("published BCF status lacks admission authority")
    if len(query["bcf_ordinal"]) != 1 or len(query["bcf_attempt"]) != 1:
        raise GitHubControllerError("published BCF status has duplicate admission authority")
    ordinal = positive_int(query["bcf_ordinal"][0], field="published admission ordinal")
    attempt = positive_int(query["bcf_attempt"][0], field="published control attempt")
    conclusions = {
        "success": StatusConclusion.SUCCESS,
        "failure": StatusConclusion.FAILURE,
        "error": StatusConclusion.FAILURE,
        "pending": StatusConclusion.PENDING,
    }
    state = str(payload.get("state"))
    if state not in conclusions:
        raise GitHubControllerError("published BCF status has unsupported state")
    return StatusObservation(
        context=StatusContext.EXACT_MAIN,
        subject_sha=subject,
        admission_ordinal=ordinal,
        control_plane_attempt=attempt,
        conclusion=conclusions[state],
    )


def _current_status(
    api: GitHubAPI, repository: str, subject: str
) -> StatusObservation | None:
    matching = [
        value for value in api.commit_statuses(repository, sha=subject)
        if value.get("context") == STATUS_CONTEXT
    ]
    if not matching:
        return None
    observations = [_status_observation(value, subject) for value in matching]
    latest_order = max(
        (value.admission_ordinal, value.control_plane_attempt) for value in observations
    )
    latest = [
        value for value in observations
        if (value.admission_ordinal, value.control_plane_attempt) == latest_order
    ]
    if len({value.conclusion for value in latest}) != 1:
        raise GitHubControllerError("equal published authority has conflicting conclusions")
    return latest[0]


def publish_observation(
    api: GitHubAPI,
    *,
    repository: str,
    subject_sha: str,
    current_default_main_sha: str,
    admission_ordinal: int,
    control_plane_attempt: int,
    conclusion: StatusConclusion,
    description: str,
    target_url: str,
) -> dict[str, Any]:
    """Apply the canonical total-order status decision and publish when authoritative."""

    proposed = StatusObservation(
        context=StatusContext.EXACT_MAIN,
        subject_sha=subject_sha,
        admission_ordinal=admission_ordinal,
        control_plane_attempt=control_plane_attempt,
        conclusion=conclusion,
    )
    decision = decide_status_publication(
        proposed=proposed,
        current=_current_status(api, repository, subject_sha),
        trusted_publisher=True,
        current_default_main_sha=current_default_main_sha,
    )
    if decision.publish:
        api.status(
            repository,
            sha=subject_sha,
            state=conclusion.value,
            context=STATUS_CONTEXT,
            description=description,
            target_url=_status_target(
                target_url,
                ordinal=admission_ordinal,
                attempt=control_plane_attempt,
            ),
        )
    return {
        "status": "published" if decision.publish else "suppressed",
        "reason": decision.reason,
        "subject_sha": subject_sha,
        "admission_ordinal": admission_ordinal,
    }


def publish(
    api: GitHubAPI,
    *,
    repository: str,
    bundle_dir: Path,
    target_url: str,
    collector_run_id: object,
    collector_run_attempt: object,
    collector_workflow_path: str,
    collector_workflow_id: object | None = None,
    collector_workflow_sha256: str | None = None,
) -> dict[str, Any]:
    """Reverify one authenticated finalizer bundle before status publication."""

    if bundle_dir.is_symlink():
        raise GitHubControllerError("certification bundle cannot be a symlink")
    root = bundle_dir.resolve()
    manifest = verify_bundle(root)
    if manifest.get("kind") == "authority_observation":
        observation = json.loads(
            (root / "authority-observation.json").read_text(encoding="utf-8")
        )
        if (
            observation.get("kind") != "authority_observation"
            or observation.get("subject") != manifest.get("subject")
            or str(observation.get("admission", {}).get("admission_ordinal"))
            != str(manifest.get("admission_ordinal"))
            or observation.get("computed_state") != manifest.get("computed_state")
        ):
            raise GitHubControllerError("authority observation bundle is inconsistent")
        state = observation.get("computed_state")
        conclusions = {
            "pending": StatusConclusion.PENDING,
            "failed": StatusConclusion.FAILURE,
        }
        if state not in conclusions:
            raise GitHubControllerError("authority observation state is unsupported")
        subject_record = observation["subject"]
        main = resolve_main(api, repository)
        subject = str(subject_record["commit_sha"])
        subject_tree = str(subject_record["tree_sha"])
        commit = api.commit(repository, subject)
        tree = commit.get("tree")
        if not isinstance(tree, dict) or str(tree.get("sha")) != subject_tree:
            raise GitHubControllerError("authority observation tree is not authenticated")
        collector_main = MainIdentity(
            repository_id=main.repository_id,
            default_branch=main.default_branch,
            checkout_sha=subject,
            tree_sha=subject_tree,
        )
        collector = authenticate_trusted_run(
            api,
            repository=repository,
            main=collector_main,
            run_id=collector_run_id,
            run_attempt=collector_run_attempt,
            workflow_path=collector_workflow_path,
            expected_event="workflow_run",
            require_success=True,
            expected_workflow_id=collector_workflow_id,
            expected_workflow_sha256=collector_workflow_sha256,
        )
        if observation.get("collector") != {
            "run_id": collector.run_id,
            "run_attempt": collector.run_attempt,
            "workflow": asdict(collector.workflow),
        }:
            raise GitHubControllerError("authority observation collector is not exact")
        admission = observation["admission"]
        result = publish_observation(
            api,
            repository=repository,
            subject_sha=subject,
            current_default_main_sha=main.checkout_sha,
            admission_ordinal=int(admission["admission_ordinal"]),
            control_plane_attempt=int(admission["run_attempt"]),
            conclusion=conclusions[state],
            description=f"BCF exact-main {state}",
            target_url=target_url,
        )
        return {**result, "computed_state": state}
    if manifest.get("kind") not in {None, "certification"}:
        raise GitHubControllerError("certification bundle kind is unsupported")
    report = json.loads((root / "ci-certification.json").read_text(encoding="utf-8"))
    verification = verify_ci_certification(
        packaged_repo_root(),
        authority_path=root / "ci-authority.json",
        certification_path=root / "ci-certification.json",
        session_manifest_path=root / "evidence-session.json",
    )
    if (
        manifest.get("subject")
        != {
            "commit_sha": report["subject"]["checkout_sha"],
            "tree_sha": report["subject"]["tree_sha"],
        }
        or str(manifest.get("admission_ordinal"))
        != str(report["admission"]["admission_ordinal"])
        or manifest.get("computed_state") != verification.computed_state
    ):
        raise GitHubControllerError(
            "certification bundle manifest does not match verified certification"
        )
    main = resolve_main(api, repository)
    subject = str(report["subject"]["checkout_sha"])
    subject_tree = str(report["subject"]["tree_sha"])
    subject_commit = api.commit(repository, subject)
    observed_tree = subject_commit.get("tree")
    if not isinstance(observed_tree, dict) or str(observed_tree.get("sha")) != subject_tree:
        raise GitHubControllerError("certification subject tree is not provider-authenticated")
    collector_main = MainIdentity(
        repository_id=main.repository_id,
        default_branch=main.default_branch,
        checkout_sha=subject,
        tree_sha=subject_tree,
    )
    collector_identity = authenticate_trusted_run(
        api,
        repository=repository,
        main=collector_main,
        run_id=collector_run_id,
        run_attempt=collector_run_attempt,
        workflow_path=collector_workflow_path,
        expected_event="workflow_run",
        require_success=True,
        expected_workflow_id=collector_workflow_id,
        expected_workflow_sha256=collector_workflow_sha256,
    )
    session = json.loads((root / "evidence-session.json").read_text(encoding="utf-8"))
    producer = session.get("producer")
    if not isinstance(producer, dict) or producer != {
        "kind": "workflow",
        "provider": "github",
        "repository": repository,
        "repository_id": main.repository_id,
        "run_id": collector_identity.run_id,
        "run_attempt": str(collector_identity.run_attempt),
        "producer_id": "bcf-trusted-finalizer",
    }:
        raise GitHubControllerError(
            "certification session is not bound to the authenticated finalizer run"
        )
    conclusion = (
        StatusConclusion.SUCCESS
        if verification.status == "pass"
        else StatusConclusion.FAILURE
    )
    result = publish_observation(
        api,
        repository=repository,
        subject_sha=subject,
        current_default_main_sha=main.checkout_sha,
        admission_ordinal=int(report["admission"]["admission_ordinal"]),
        control_plane_attempt=int(report["admission"]["control_plane_run_attempt"]),
        conclusion=conclusion,
        description=f"BCF exact-main {verification.computed_state}",
        target_url=target_url,
    )
    return {
        **result,
        "computed_state": verification.computed_state,
    }
