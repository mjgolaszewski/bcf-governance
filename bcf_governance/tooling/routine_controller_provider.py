"""Provider-authenticated routine controller transition compilation and custody."""

from __future__ import annotations

import hashlib
import json
from enum import StrEnum
from pathlib import Path
import re
from typing import Any, Mapping

import yaml

from .ci_authority_contracts import authority_role_jobs
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
    validate_controller_installation,
    validate_controller_pin,
)
from .controller_transition_provider_custody import (
    TRANSITION_REPORT,
    github_is_ancestor as _is_ancestor,
    receipt_from_zip as _receipt_from_zip,
)
from .prior_evidence_transport import (
    authenticate_merged_pull,
    authenticate_pr_certification,
)
from .routine_controller_rotation import (
    ALTERNATE_POLICY_LANE_SEQUENCE,
    GovernedControllerLane,
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


TRANSITION_ARTIFACT_PREFIX = "bcf-controller-transition-"
ROTATION_POLICY_PATHS = (
    "governance/github-protection.yml",
    "governance/self-governance-policy.yml",
    "governance/ci-extensions/bcf-trusted-control.yml",
    "schemas/controller-transition.schema.json",
)
STAGE_JOB_PREFIXES = {
    "bootstrap": "Bootstrap routine controller / ",
    "probe": "Probe routine controller / ",
    "promotion": "Promote routine controller / ",
}


class RoutineDecision(StrEnum):
    NO_TRANSITION = "no_transition"
    ROUTINE_TRANSITION_AUTHORIZED = "routine_transition_authorized"
    ALTERNATE_LANE_REQUIRED = "alternate_lane_required"


class ControllerTransitionClass(StrEnum):
    NONE = "none"
    RUNTIME_ONLY = "runtime_only"
    PROTECTED_POLICY_CHANGE = "protected_policy_change"


def _exact_keys(value: Mapping[str, Any], expected: set[str], *, field: str) -> None:
    if set(value) != expected:
        raise GitHubControllerError(f"{field} inventory is not exact")


def _exact_sha(value: object, *, field: str) -> str:
    text = str(value)
    if re.fullmatch(r"[a-f0-9]{40}", text) is None:
        raise GitHubControllerError(f"{field} is not an exact Git identity")
    return text


def _exact_digest(value: object, *, field: str) -> str:
    text = str(value)
    if re.fullmatch(r"[a-f0-9]{64}", text) is None:
        raise GitHubControllerError(f"{field} is not an exact SHA-256 digest")
    return text


def validate_routine_decision(value: Mapping[str, Any]) -> dict[str, Any]:
    """Validate a closed routine-controller decision before transport."""

    common = {
        "schema_version", "decision", "transition_class", "applicable",
        "reason",
    }
    decision = str(value.get("decision", ""))
    if decision == RoutineDecision.ROUTINE_TRANSITION_AUTHORIZED.value:
        _exact_keys(value, common | {"transition"}, field="routine decision")
        if (
            value.get("schema_version") != "1.0"
            or value.get("transition_class") != ControllerTransitionClass.RUNTIME_ONLY
            or value.get("applicable") is not True
            or value.get("reason") != "pending_controller_rotation"
        ):
            raise GitHubControllerError("routine transition decision is invalid")
        result = dict(value)
        result["transition"] = validate_transition(
            packaged_repo_root(), value.get("transition")
        )
        return result

    subject_admission = common | {"subject", "admission", "release_authority"}
    if decision == RoutineDecision.NO_TRANSITION.value:
        _exact_keys(value, subject_admission, field="routine decision")
        if (
            value.get("schema_version") != "1.0"
            or value.get("transition_class") != ControllerTransitionClass.NONE
            or value.get("applicable") is not False
            or value.get("reason") != "controller_current"
        ):
            raise GitHubControllerError("no-transition decision is invalid")
    elif decision == RoutineDecision.ALTERNATE_LANE_REQUIRED.value:
        _exact_keys(
            value,
            subject_admission | {"authority", "target", "alternate_lane"},
            field="routine decision",
        )
        if (
            value.get("schema_version") != "1.0"
            or value.get("transition_class")
            != ControllerTransitionClass.PROTECTED_POLICY_CHANGE
            or value.get("applicable") is not False
            or value.get("reason") != "authorization_policy_changed"
        ):
            raise GitHubControllerError("alternate-lane decision is invalid")
        authority = value.get("authority")
        if not isinstance(authority, Mapping):
            raise GitHubControllerError("alternate-lane authority is invalid")
        _exact_keys(
            authority,
            {
                "installed_controller_commit", "implementation_pr",
                "candidate_commit_sha", "source_main_commit_sha",
                "policy_before_sha256", "policy_after_sha256",
            },
            field="alternate-lane authority",
        )
        _exact_sha(authority["installed_controller_commit"], field="installed controller")
        positive_int(authority["implementation_pr"], field="implementation PR")
        _exact_sha(authority["candidate_commit_sha"], field="candidate commit")
        _exact_sha(authority["source_main_commit_sha"], field="source main commit")
        before = _exact_digest(authority["policy_before_sha256"], field="prior policy")
        after = _exact_digest(authority["policy_after_sha256"], field="candidate policy")
        if before == after:
            raise GitHubControllerError("alternate lane requires an exact policy change")
        validate_controller_pin(value.get("target"))
        lane = value.get("alternate_lane")
        if not isinstance(lane, Mapping):
            raise GitHubControllerError("alternate lane is invalid")
        _exact_keys(
            lane,
            {"id", "required_sequence", "required_initial_state", "required_terminal_state"},
            field="alternate lane",
        )
        if (
            lane.get("id") != GovernedControllerLane.ORDINARY_PROTECTED_N_N_PLUS_1
            or lane.get("required_sequence") != list(ALTERNATE_POLICY_LANE_SEQUENCE)
            or lane.get("required_initial_state") != "ordinary-pending-rotation"
            or lane.get("required_terminal_state") != "ordinary-current"
        ):
            raise GitHubControllerError("alternate lane contract is invalid")
    else:
        raise GitHubControllerError("routine decision is unknown")

    subject = value.get("subject")
    admission = value.get("admission")
    if not isinstance(subject, Mapping) or not isinstance(admission, Mapping):
        raise GitHubControllerError("routine decision identity is invalid")
    _exact_keys(subject, {"commit_sha", "tree_sha"}, field="decision subject")
    _exact_sha(subject["commit_sha"], field="decision commit")
    _exact_sha(subject["tree_sha"], field="decision tree")
    _exact_keys(admission, {"run_id", "run_attempt"}, field="decision admission")
    positive_int(admission["run_id"], field="admission run ID")
    positive_int(admission["run_attempt"], field="admission run attempt")
    if value.get("release_authority") is not False:
        raise GitHubControllerError("routine decision cannot grant release authority")
    return dict(value)


def _no_transition(
    main: MainIdentity,
    *,
    reason: str,
    admission_run_id: object,
    admission_run_attempt: object,
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
        "release_authority": False,
    })


def _policy_change_route(
    main: MainIdentity,
    *,
    admission_run_id: object,
    admission_run_attempt: object,
    installed_commit: str,
    target: Mapping[str, str],
    implementation_pr: object,
    candidate_commit: str,
    source_main_commit: str,
    policy_before: str,
    policy_after: str,
) -> dict[str, Any]:
    return validate_routine_decision({
        "schema_version": "1.0",
        "decision": RoutineDecision.ALTERNATE_LANE_REQUIRED.value,
        "transition_class": ControllerTransitionClass.PROTECTED_POLICY_CHANGE.value,
        "applicable": False,
        "reason": "authorization_policy_changed",
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
        "authority": {
            "installed_controller_commit": installed_commit,
            "implementation_pr": str(
                positive_int(implementation_pr, field="implementation PR")
            ),
            "candidate_commit_sha": candidate_commit,
            "source_main_commit_sha": source_main_commit,
            "policy_before_sha256": policy_before,
            "policy_after_sha256": policy_after,
        },
        "target": dict(target),
        "alternate_lane": alternate_policy_lane_contract(),
        "release_authority": False,
    })


def _sha256(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()


def _policy_digest(
    api: GitHubAPI, repository: str, *, ref: str
) -> str:
    return controller_policy_digest(
        lambda path: api.content(repository, path, ref=ref).content
    )


def _runner_policy(
    api: GitHubAPI, repository: str, *, main: MainIdentity
) -> tuple[dict[str, str], dict[str, str], tuple[str, ...]]:
    content = api.content(
        repository, "governance/self-governance-policy.yml", ref=main.checkout_sha
    )
    try:
        payload = yaml.safe_load(content.content.decode("utf-8"))
        runner = payload["runner_security"]
        pin = validate_controller_pin(runner["trusted_controller_artifact"])
        installation = validate_controller_installation(
            runner["trusted_controller_installation"]
        )
        labels = tuple(str(value) for value in runner["trusted_instance_labels"])
    except (KeyError, TypeError, UnicodeDecodeError, yaml.YAMLError) as exc:
        raise GitHubControllerError("routine controller source policy is invalid") from exc
    if len(labels) < 2 or labels != tuple(sorted(set(labels))):
        raise GitHubControllerError("routine controller runner inventory is not canonical")
    if pin["BCF_BOOTSTRAP_COMMIT_SHA"] != installation["installed_commit_sha"]:
        raise GitHubControllerError(
            "routine controller authority requires ordinary-current source custody"
        )
    return pin, installation, labels


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


def resolve_effective_controller(
    api: GitHubAPI, *, repository: str
) -> dict[str, Any]:
    """Resolve source baseline plus the unique provider-authenticated active chain."""

    current = resolve_main(api, repository)
    baseline, installation, _ = _runner_policy(
        api, repository, main=current
    )
    authority = load_authority(api, repository, current, required_version="1.1")
    roles = authority.get("roles")
    if not isinstance(roles, dict) or "controller_rotation" not in roles:
        return {
            "source": "source_policy",
            "subject": {
                "commit_sha": current.checkout_sha,
                "tree_sha": current.tree_sha,
            },
            "normalization_subject": installation["subject_commit_sha"],
            "pin": baseline,
            "transition_ids": [],
        }
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
    return {
        "source": "provider_transition" if chain else "source_policy",
        "subject": {
            "commit_sha": current.checkout_sha,
            "tree_sha": current.tree_sha,
        },
        "normalization_subject": installation["subject_commit_sha"],
        "pin": pin,
        "transition_ids": [value["transition_id"] for value in chain],
    }


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
    if topology.state is AdmissionTopologyState.CERTIFIABLE:
        return _no_transition(
            main,
            reason="controller_current",
            admission_run_id=admission_run_id,
            admission_run_attempt=admission_run_attempt,
        )
    if topology.state is not AdmissionTopologyState.PENDING_ROTATION:
        raise GitHubControllerError(
            f"routine controller topology is noncertifying: {topology.reason}"
        )
    current = resolve_effective_controller(api, repository=repository)
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
    if before != after:
        return _policy_change_route(
            main,
            admission_run_id=admission_run_id,
            admission_run_attempt=admission_run_attempt,
            installed_commit=current_pin["BCF_BOOTSTRAP_COMMIT_SHA"],
            target=target,
            implementation_pr=pull["number"],
            candidate_commit=candidate.checkout_sha,
            source_main_commit=source_main.checkout_sha,
            policy_before=before,
            policy_after=after,
        )
    _, _, runners = _runner_policy(api, repository, main=main)
    identity = transition_id(
        repository_id=main.repository_id,
        installed_commit=current_pin["BCF_BOOTSTRAP_COMMIT_SHA"],
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
            "installed_controller_commit": current_pin["BCF_BOOTSTRAP_COMMIT_SHA"],
            "admission_run_id": str(positive_int(admission_run_id, field="admission run ID")),
            "admission_run_attempt": str(positive_int(admission_run_attempt, field="admission run attempt")),
            "implementation_pr": str(positive_int(pull["number"], field="implementation PR")),
            "policy_before_sha256": before,
            "policy_after_sha256": after,
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
        "transition_class": ControllerTransitionClass.RUNTIME_ONLY.value,
        "applicable": True,
        "reason": "pending_controller_rotation",
        "transition": validate_transition(packaged_repo_root(), receipt),
    })


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
    if topology == "no_transition":
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
    resolved = resolve_effective_controller(api, repository=repository)
    if resolved["source"] != "provider_transition":
        raise GitHubControllerError("no active provider controller transition exists")
    receipts = _active_receipts(
        api,
        repository,
        current=main,
        normalization_subject=resolved["normalization_subject"],
    )
    matching = [
        value
        for value in receipts
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
