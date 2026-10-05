"""Provider-authenticated routine controller transition compilation and custody."""

from __future__ import annotations

import hashlib
import os
from pathlib import Path
import re
from typing import Any, Mapping

import yaml

from .ci_authority_contracts import authority_role_jobs
from .ci_authority_pins import verify_provider_workflow_authority
from .ci_github_api import GitHubAPI
from .ci_github_authority import (
    authenticate_role_run,
    load_authority,
    packaged_repo_root,
)
from .ci_github_identity import (
    GitHubControllerError,
    MainIdentity,
    positive_int,
    resolve_main,
    resolve_run_subject,
)
from .ci_github_membership import (
    AdmissionTopologyState,
    classify_admission_topology,
)
from .ci_self_controller import (
    compile_self_controller_pin,
    resolve_self_controller_artifact,
    validate_controller_installation,
    validate_controller_pin,
)
from .controller_transition_provider_custody import (
    TRANSITION_REPORT,
    github_is_ancestor as _is_ancestor,
    receipt_from_zip as _receipt_from_zip,
)
from .prior_evidence_transport import (
    _archive_files,
    authenticate_merged_pull,
    authenticate_pr_certification,
)
from .controller_custody import compile_controller_custody, require_controller_execution
from .routine_controller_rotation import (
    RoutineRotationError,
    advance_transition,
    alternate_policy_lane_contract,
    classify_provider_callback_topology,
    controller_policy_digest,
    effective_controller_pin,
    select_controller_chain,
    transition_follows_normalization,
    transition_id,
    validate_transition,
)
from .routine_controller_callback import (
    load_callback_outcome,
    validate_active_outcome,
    validate_no_transition_outcome,
)
from .routine_controller_admission_custody import authenticate_admission_custody
from .routine_controller_decision import (
    ControllerTransitionClass,
    RoutineDecision,
    validate_routine_decision,
)
from .ci_controller_provider import (
    policy_digest as _policy_digest,
    runner_policy as _runner_policy,
)


TRANSITION_ARTIFACT_PREFIX = "bcf-controller-transition-"
STAGE_JOB_PREFIXES = {
    "bootstrap": "Bootstrap routine controller / ",
    "probe": "Probe routine controller / ",
    "promotion": "Promote routine controller / ",
}


def _no_transition(
    main: MainIdentity,
    *,
    reason: str,
    admission_run_id: object,
    admission_run_attempt: object,
    controller_custody: Mapping[str, Any],
) -> dict[str, Any]:
    return validate_routine_decision({
        "schema_version": "1.0",
        "decision": RoutineDecision.NO_TRANSITION.value,
        "transition_class": ControllerTransitionClass.NONE.value,
        "applicable": False,
        "reason": reason,
        "subject": {
            "commit_sha": main.checkout_sha,
            "tree_sha": main.tree_sha,
        },
        "admission": {
            "run_id": str(positive_int(admission_run_id, field="admission run ID")),
            "run_attempt": str(
                positive_int(admission_run_attempt, field="admission run attempt")
            ),
        },
        "controller_custody": dict(controller_custody),
        "release_authority": False,
    })


def _authorized_transition(
    main: MainIdentity,
    *,
    repository: str,
    admission_run_id: object,
    admission_run_attempt: object,
    installed_commit: str,
    target: Mapping[str, str],
    implementation_pr: object,
    policy_before: str,
    policy_after: str,
    runners: tuple[str, ...],
) -> dict[str, Any]:
    transition_class = (
        ControllerTransitionClass.PROTECTED_POLICY_CHANGE.value
        if policy_before != policy_after
        else ControllerTransitionClass.RUNTIME_ONLY.value
    )
    identity = transition_id(
        repository_id=main.repository_id,
        installed_commit=installed_commit,
        subject_commit=main.checkout_sha,
        subject_tree=main.tree_sha,
        artifact_digest=target["BCF_BOOTSTRAP_ARTIFACT_DIGEST"],
    )
    receipt = {
        "schema_version": "1.0",
        "transition_id": identity,
        "state": "authorized",
        "repository": {"id": main.repository_id, "full_name": repository},
        "subject": {"commit_sha": main.checkout_sha, "tree_sha": main.tree_sha},
        "authority": {
            "installed_controller_commit": installed_commit,
            "admission_run_id": str(positive_int(admission_run_id, field="admission run ID")),
            "admission_run_attempt": str(positive_int(admission_run_attempt, field="admission run attempt")),
            "implementation_pr": str(positive_int(implementation_pr, field="implementation PR")),
            "policy_before_sha256": policy_before,
            "policy_after_sha256": policy_after,
        },
        "artifact": {
            "id": target["BCF_BOOTSTRAP_ARTIFACT_ID"],
            "name": target["BCF_BOOTSTRAP_ARTIFACT_NAME"],
            "provider_digest": target["BCF_BOOTSTRAP_ARTIFACT_DIGEST"],
            "wheel_sha256": target["BCF_BOOTSTRAP_WHEEL_SHA256"],
            "run_id": target["BCF_BOOTSTRAP_RUN_ID"],
            "run_attempt": target["BCF_BOOTSTRAP_RUN_ATTEMPT"],
            "commit_sha": target["BCF_BOOTSTRAP_COMMIT_SHA"],
            "tree_sha": target["BCF_BOOTSTRAP_TREE_SHA"],
        },
        "required_runners": list(runners),
        "bootstrap": [],
        "probe": [],
        "promotion": [],
    }
    return validate_routine_decision({
        "schema_version": "1.0",
        "decision": RoutineDecision.ROUTINE_TRANSITION_AUTHORIZED.value,
        "transition_class": transition_class,
        "applicable": True,
        "reason": (
            "pending_protected_policy_rotation"
            if transition_class == ControllerTransitionClass.PROTECTED_POLICY_CHANGE
            else "pending_controller_rotation"
        ),
        "transition": validate_transition(packaged_repo_root(), receipt),
    })


def _sha256(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()


def _active_receipts(
    api: GitHubAPI,
    repository: str,
    *,
    current: MainIdentity,
    normalization_subject: str,
) -> tuple[dict[str, Any], ...]:
    receipts: list[dict[str, Any]] = []
    pattern = re.compile(rf"^{TRANSITION_ARTIFACT_PREFIX}([a-f0-9]{{64}})$")
    for artifact in api.repository_artifacts(repository):
        name = str(artifact.get("name", ""))
        match = pattern.fullmatch(name)
        if match is None:
            continue
        if artifact.get("expired") is not False:
            raise GitHubControllerError("active controller transition artifact expired")
        artifact_id = positive_int(
            artifact.get("id"), field="transition artifact ID"
        )
        raw = api.artifact_bytes(
            repository, artifact_id, maximum_bytes=1_048_576
        )
        if artifact.get("digest") != f"sha256:{_sha256(raw)}":
            raise GitHubControllerError(
                "controller transition artifact bytes do not match provider digest"
            )
        receipt = validate_transition(
            packaged_repo_root(),
            _receipt_from_zip(raw),
        )
        if receipt["state"] != "active" or receipt["transition_id"] != match.group(1):
            raise GitHubControllerError("controller transition artifact identity is invalid")
        if receipt["repository"] != {
            "id": current.repository_id,
            "full_name": repository,
        }:
            raise GitHubControllerError(
                "controller transition repository identity is not exact"
            )
        subject = receipt["subject"]["commit_sha"]
        if not _is_ancestor(
            api, repository, base=subject, head=current.checkout_sha
        ):
            continue
        activation = receipt["activation"]
        run_subject = resolve_run_subject(
            api,
            repository,
            run_id=activation["run_id"],
            run_attempt=activation["run_attempt"],
        )
        if (
            run_subject.checkout_sha != subject
            or run_subject.tree_sha != receipt["subject"]["tree_sha"]
        ):
            raise GitHubControllerError("controller transition run subject is not exact")
        authority = load_authority(
            api, repository, run_subject, required_version="1.1"
        )
        authenticate_role_run(
            api,
            repository=repository,
            main=run_subject,
            authority=authority,
            role="controller_rotation",
            run_id=activation["run_id"],
            run_attempt=activation["run_attempt"],
            require_success=True,
        )
        workflow_run = artifact.get("workflow_run")
        if not isinstance(workflow_run, dict) or workflow_run != {
            "id": int(activation["run_id"]),
            "repository_id": int(current.repository_id),
            "head_repository_id": int(current.repository_id),
            "head_branch": current.default_branch,
            "head_sha": subject,
        }:
            raise GitHubControllerError(
                "controller transition artifact provider subject is not exact"
            )
        try:
            follows_normalization = transition_follows_normalization(
                transition_subject=subject,
                normalization_subject=normalization_subject,
                is_ancestor=lambda base, head: _is_ancestor(
                    api, repository, base=base, head=head
                ),
            )
        except RoutineRotationError as exc:
            raise GitHubControllerError(str(exc)) from exc
        if not follows_normalization:
            continue
        receipts.append(receipt)
    return tuple(receipts)


def _resolve_effective_controller_state(
    api: GitHubAPI, *, repository: str
) -> tuple[dict[str, Any], tuple[dict[str, Any], ...]]:
    """Resolve the public controller projection and its authenticated chain once."""

    current = resolve_main(api, repository)
    baseline, installation, _ = _runner_policy(
        api, repository, main=current
    )
    authority = load_authority(api, repository, current, required_version="1.1")
    roles = authority.get("roles")
    if not isinstance(roles, dict) or "controller_rotation" not in roles:
        return (
            {
                "source": "source_policy",
                "subject": {
                    "commit_sha": current.checkout_sha,
                    "tree_sha": current.tree_sha,
                },
                "normalization_subject": installation["subject_commit_sha"],
                "pin": baseline,
                "transition_ids": [],
            },
            (),
        )
    receipts = _active_receipts(
        api,
        repository,
        current=current,
        normalization_subject=installation["subject_commit_sha"],
    )
    ancestors = [
        value["subject"]["commit_sha"] for value in receipts
    ]
    chain = select_controller_chain(
        packaged_repo_root(),
        receipts,
        repository_id=current.repository_id,
        baseline_installed_commit=installation["installed_commit_sha"],
        ancestor_commits=ancestors,
    )
    pin = validate_controller_pin(effective_controller_pin(baseline, chain))
    return (
        {
            "source": "provider_transition" if chain else "source_policy",
            "subject": {
                "commit_sha": current.checkout_sha,
                "tree_sha": current.tree_sha,
            },
            "normalization_subject": installation["subject_commit_sha"],
            "pin": pin,
            "transition_ids": [value["transition_id"] for value in chain],
        },
        tuple(chain),
    )


def resolve_effective_controller(
    api: GitHubAPI, *, repository: str
) -> dict[str, Any]:
    """Resolve source baseline plus the unique provider-authenticated active chain."""

    resolved, _ = _resolve_effective_controller_state(api, repository=repository)
    return resolved


def effective_controller_authority(
    api: GitHubAPI, *, repository: str, repo_root: Path | None = None
) -> dict[str, str]:
    """Project the exact provider-composed identity accepted by preflight."""

    if repo_root is not None:
        verify_provider_workflow_authority(
            repo_root,
            authority_path=Path("governance/ci-authority.yml"),
            api=api,
            repository=repository,
        )
    pin = resolve_effective_controller(api, repository=repository)["pin"]
    return {
        "controller_commit_sha": pin["BCF_BOOTSTRAP_COMMIT_SHA"],
        "controller_bundle_sha256": pin["BCF_BOOTSTRAP_WHEEL_SHA256"],
    }


def _materialize_provider_controller(
    api: GitHubAPI,
    *,
    repository: str,
    admission_run_id: object,
    admission_run_attempt: object,
    artifact_dir: Path,
) -> None:
    """Use exact pre-materialized N bytes or fetch N+1 after rotation is required."""

    if artifact_dir.is_dir() and not artifact_dir.is_symlink():
        return
    if artifact_dir.exists() or artifact_dir.is_symlink():
        raise GitHubControllerError("routine controller artifact root is not a directory")

    _, artifact = resolve_self_controller_artifact(
        api,
        repository=repository,
        trigger_run_id=admission_run_id,
        trigger_run_attempt=admission_run_attempt,
    )
    raw = api.artifact_bytes(repository, artifact.artifact_id, maximum_bytes=104_857_600)
    if artifact.provider_digest != f"sha256:{_sha256(raw)}":
        raise GitHubControllerError("routine controller artifact differs from provider digest")
    artifact_dir.mkdir(mode=0o700, parents=True)
    for relative, content in _archive_files(raw).items():
        target_path = artifact_dir / relative
        target_path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
        target_path.write_bytes(content)


def project_effective_controller_custody_observation(
    api: GitHubAPI, *, repository: str
) -> dict[str, Any]:
    """Compile a non-authoritative route observation for trusted reauthentication."""

    return compile_controller_custody(
        resolve_effective_controller(api, repository=repository),
        repository=repository,
    )


def authorize_transition(
    api: GitHubAPI,
    *,
    repository: str,
    admission_run_id: object,
    admission_run_attempt: object,
    artifact_dir: Path,
) -> dict[str, Any]:
    """Compile one protected routine transition without candidate authorization."""

    main = resolve_main(api, repository)
    run_subject = resolve_run_subject(
        api,
        repository,
        run_id=admission_run_id,
        run_attempt=admission_run_attempt,
    )
    if run_subject != main:
        raise GitHubControllerError("controller transition admission was superseded")
    authority = load_authority(api, repository, main, required_version="1.1")
    authenticate_role_run(
        api,
        repository=repository,
        main=main,
        authority=authority,
        role="admission",
        run_id=admission_run_id,
        run_attempt=admission_run_attempt,
        require_success=False,
    )
    topology = classify_admission_topology(
        api,
        repository=repository,
        main=main,
        authority=authority,
        admission_run_id=admission_run_id,
        admission_run_attempt=admission_run_attempt,
    )
    if topology.state not in {
        AdmissionTopologyState.CERTIFIABLE,
        AdmissionTopologyState.PENDING_ROTATION,
    }:
        raise GitHubControllerError(
            f"routine controller topology is noncertifying: {topology.reason}"
        )
    current = resolve_effective_controller(api, repository=repository)
    custody = authenticate_admission_custody(
        api,
        repository=repository,
        main=main,
        authority=authority,
        admission_run_id=admission_run_id,
        admission_run_attempt=admission_run_attempt,
        effective=current,
    )
    if topology.state is AdmissionTopologyState.CERTIFIABLE:
        return _no_transition(
            main,
            reason="controller_current",
            admission_run_id=admission_run_id,
            admission_run_attempt=admission_run_attempt,
            controller_custody=custody,
        )
    _materialize_provider_controller(
        api,
        repository=repository,
        admission_run_id=admission_run_id,
        admission_run_attempt=admission_run_attempt,
        artifact_dir=artifact_dir,
    )
    target = compile_self_controller_pin(
        api,
        repository=repository,
        artifact_dir=artifact_dir,
        trigger_run_id=admission_run_id,
        trigger_run_attempt=admission_run_attempt,
    )
    current_pin = validate_controller_pin(current["pin"])
    if target["BCF_BOOTSTRAP_COMMIT_SHA"] == current_pin["BCF_BOOTSTRAP_COMMIT_SHA"]:
        raise GitHubControllerError("routine controller transition has no new target")
    pull, candidate, source_main, _ = authenticate_merged_pull(
        api, repository, main=main
    )
    authenticate_pr_certification(
        api,
        repository,
        candidate_sha=candidate.checkout_sha,
        merged_at=str(pull["merged_at"]),
    )
    before = _policy_digest(api, repository, ref=source_main.checkout_sha)
    after = _policy_digest(api, repository, ref=main.checkout_sha)
    _, _, runners = _runner_policy(api, repository, main=main)
    return _authorized_transition(
        main,
        repository=repository,
        admission_run_id=admission_run_id,
        admission_run_attempt=admission_run_attempt,
        installed_commit=current_pin["BCF_BOOTSTRAP_COMMIT_SHA"],
        target=target,
        implementation_pr=pull["number"],
        policy_before=before,
        policy_after=after,
        runners=runners,
    )


def _stage_proofs(
    jobs: tuple[dict[str, Any], ...],
    *,
    stage: str,
    runners: tuple[str, ...],
    controller_commit: str,
    run_id: str,
    run_attempt: int,
) -> list[dict[str, str]]:
    prefix = STAGE_JOB_PREFIXES[stage]
    selected = {
        str(job.get("name", ""))[len(prefix):]: job
        for job in jobs
        if str(job.get("name", "")).startswith(prefix)
    }
    if set(selected) != set(runners) or any(
        job.get("status") != "completed" or job.get("conclusion") != "success"
        for job in selected.values()
    ):
        raise GitHubControllerError(f"{stage} runner proof inventory is not exactly green")
    return [
        {
            "runner": runner,
            "controller_commit": controller_commit,
            "run_id": run_id,
            "run_attempt": str(run_attempt),
            "job_id": str(positive_int(selected[runner].get("id"), field=f"{stage} job ID")),
        }
        for runner in runners
    ]


def advance_provider_transition(
    api: GitHubAPI,
    *,
    repository: str,
    receipt: Mapping[str, Any],
    stage: str,
    rotation_run_id: object,
    rotation_run_attempt: object,
) -> dict[str, Any]:
    """Compile one stage from exact provider jobs under the installed controller."""

    current = validate_transition(packaged_repo_root(), dict(receipt))
    subject = resolve_run_subject(
        api,
        repository,
        run_id=rotation_run_id,
        run_attempt=rotation_run_attempt,
    )
    if subject.checkout_sha != current["subject"]["commit_sha"] or (
        subject.tree_sha != current["subject"]["tree_sha"]
    ):
        raise GitHubControllerError("rotation workflow subject differs from transition")
    if resolve_main(api, repository).checkout_sha != subject.checkout_sha:
        raise GitHubControllerError("controller transition was superseded before activation")
    authority = load_authority(api, repository, subject, required_version="1.1")
    identity = authenticate_role_run(
        api,
        repository=repository,
        main=subject,
        authority=authority,
        role="controller_rotation",
        run_id=rotation_run_id,
        run_attempt=rotation_run_attempt,
        require_success=False,
    )
    expected_jobs = {str(value["job_id"]) for value in authority_role_jobs(
        authority, "controller_rotation"
    )}
    jobs = api.jobs(repository, identity.run_id, attempt=identity.run_attempt)
    names = {str(value.get("name", "")) for value in jobs}
    if not names or not names.issubset(expected_jobs):
        raise GitHubControllerError("rotation workflow job inventory exceeds authority")
    proofs = _stage_proofs(
        jobs,
        stage=stage,
        runners=tuple(current["required_runners"]),
        controller_commit=current["artifact"]["commit_sha"],
        run_id=identity.run_id,
        run_attempt=identity.run_attempt,
    )
    states = {
        "bootstrap": "installing",
        "probe": "probed",
        "promotion": "active",
    }
    activation = None
    if stage == "promotion":
        activation = {
            "transition_id": current["transition_id"],
            "authorizing_controller_commit": current["authority"]["installed_controller_commit"],
            "run_id": identity.run_id,
            "run_attempt": str(identity.run_attempt),
        }
    return advance_transition(
        packaged_repo_root(),
        current,
        state=states[stage],
        proofs=proofs,
        activation=activation,
    )


def dispatch_post_rotation_certification(
    api: GitHubAPI,
    *,
    repository: str,
    callback_run_id: object,
    callback_run_attempt: object,
    rotation_run_id: object,
    rotation_run_attempt: object,
) -> dict[str, Any]:
    """Authenticate callback authority and request one fresh exact-main cycle."""

    main = resolve_main(api, repository)
    authority = load_authority(api, repository, main, required_version="1.1")
    authenticate_role_run(
        api,
        repository=repository,
        main=main,
        authority=authority,
        role="controller_rotation_callback",
        run_id=callback_run_id,
        run_attempt=callback_run_attempt,
        require_success=False,
    )
    rotation = authenticate_role_run(
        api,
        repository=repository,
        main=main,
        authority=authority,
        role="controller_rotation",
        run_id=rotation_run_id,
        run_attempt=rotation_run_attempt,
        require_success=True,
    )
    topology = classify_provider_callback_topology(
        api,
        repository=repository,
        main=main,
        authority=authority,
        run_id=rotation.run_id,
        run_attempt=rotation.run_attempt,
    )
    resolved, active_chain = _resolve_effective_controller_state(
        api, repository=repository
    )
    custody = compile_controller_custody(resolved, repository=repository)
    require_controller_execution(custody)
    raw_outcome = load_callback_outcome(
        Path(os.environ.get("BCF_CONTROLLER_CUSTODY_PATH", ""))
    )
    if topology == "no_transition":
        validate_no_transition_outcome(
            raw_outcome,
            subject={"commit_sha": main.checkout_sha, "tree_sha": main.tree_sha},
            custody=custody,
        )
        return {
            "status": "no_transition",
            "dispatched": False,
            "subject": {
                "commit_sha": main.checkout_sha,
                "tree_sha": main.tree_sha,
            },
            "rotation_run_id": rotation.run_id,
            "rotation_run_attempt": rotation.run_attempt,
            "release_authority": False,
        }
    if resolved["source"] != "provider_transition":
        raise GitHubControllerError("no active provider controller transition exists")
    matching = [
        value
        for value in active_chain
        if value["transition_id"] == resolved["transition_ids"][-1]
    ]
    if len(matching) != 1 or matching[0]["activation"] != {
        "transition_id": matching[0]["transition_id"],
        "authorizing_controller_commit": matching[0]["authority"][
            "installed_controller_commit"
        ],
        "run_id": rotation.run_id,
        "run_attempt": str(rotation.run_attempt),
    }:
        raise GitHubControllerError("rotation callback does not bind the active transition")
    transition = matching[0]
    if validate_active_outcome(packaged_repo_root(), raw_outcome) != transition:
        raise GitHubControllerError(
            "active callback outcome differs from provider transition"
        )
    exact_main_subject = {"commit_sha": main.checkout_sha, "tree_sha": main.tree_sha}
    if transition["subject"] != exact_main_subject:
        raise GitHubControllerError("rotation admission subject is not exact main")
    admission = authenticate_role_run(
        api,
        repository=repository,
        main=main,
        authority=authority,
        role="admission",
        run_id=transition["authority"]["admission_run_id"], run_attempt=transition["authority"]["admission_run_attempt"],
        require_success=True,
    )
    api.rerun_workflow(repository, admission.run_id)
    return {
        "status": "rerun_requested",
        "subject": resolved["subject"],
        "controller_commit": resolved["pin"]["BCF_BOOTSTRAP_COMMIT_SHA"],
        "transition_id": resolved["transition_ids"][-1],
        "rotation_run_id": rotation.run_id,
        "rotation_run_attempt": rotation.run_attempt,
        "source_run_id": admission.run_id,
        "source_run_attempt": admission.run_attempt,
        "expected_run_attempt": admission.run_attempt + 1,
        "release_authority": False,
    }
