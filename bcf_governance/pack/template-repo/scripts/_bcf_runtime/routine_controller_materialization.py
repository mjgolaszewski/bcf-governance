"""Exact installed-N to N+1 routine-transition materialization."""

from __future__ import annotations

from pathlib import Path
from typing import Any, Mapping

from .ci_controller_provider import policy_digest, runner_policy
from .ci_github_api import GitHubAPI
from .ci_github_authority import authenticate_role_run, load_authority
from .ci_github_identity import GitHubControllerError, positive_int, resolve_main
from .ci_self_controller import (
    compile_self_controller_pin,
    validate_controller_pin,
)
from .ci_recovery_frontier import controller_transition_frontier
from .prior_evidence_transport import (
    authenticate_merged_pull,
    authenticate_pr_certification,
)
from .routine_controller_provider import (
    _authorized_transition,
    resolve_effective_controller,
    validate_routine_decision,
)


def materialize_transition_authorization(
    api: GitHubAPI,
    *,
    repository: str,
    decision: Mapping[str, Any],
    artifact_dir: Path,
) -> dict[str, Any]:
    """Materialize one exact transition from an installed-N rotation decision."""

    route = validate_routine_decision(decision)
    action = controller_transition_frontier(route)["action"]["kind"]
    if action == "invoke_routine_transition":
        return route
    if action != "invoke_exact_alternate_lane":
        raise GitHubControllerError("materialization requires a rotation decision")
    main = resolve_main(api, repository)
    if route["subject"] != {
        "commit_sha": main.checkout_sha,
        "tree_sha": main.tree_sha,
    }:
        raise GitHubControllerError("alternate-lane subject is not exact main")
    authority = load_authority(api, repository, main, required_version="1.1")
    authenticate_role_run(
        api,
        repository=repository,
        main=main,
        authority=authority,
        role="admission",
        run_id=route["admission"]["run_id"],
        run_attempt=route["admission"]["run_attempt"],
        require_success=False,
    )
    current = validate_controller_pin(
        resolve_effective_controller(api, repository=repository)["pin"]
    )
    route_authority = route["authority"]
    if current["BCF_BOOTSTRAP_COMMIT_SHA"] != route_authority[
        "installed_controller_commit"
    ]:
        raise GitHubControllerError("alternate-lane installed controller changed")
    target = compile_self_controller_pin(
        api,
        repository=repository,
        artifact_dir=artifact_dir,
        trigger_run_id=route["admission"]["run_id"],
        trigger_run_attempt=route["admission"]["run_attempt"],
    )
    if target != route["target"]:
        raise GitHubControllerError("alternate-lane target differs from installed-N decision")
    pull, candidate, source_main, _ = authenticate_merged_pull(
        api, repository, main=main
    )
    authenticate_pr_certification(
        api,
        repository,
        candidate_sha=candidate.checkout_sha,
        merged_at=str(pull["merged_at"]),
    )
    exact_authority = {
        "installed_controller_commit": current["BCF_BOOTSTRAP_COMMIT_SHA"],
        "implementation_pr": str(positive_int(pull["number"], field="implementation PR")),
        "candidate_commit_sha": candidate.checkout_sha,
        "source_main_commit_sha": source_main.checkout_sha,
        "policy_before_sha256": policy_digest(
            api, repository, ref=source_main.checkout_sha
        ),
        "policy_after_sha256": policy_digest(api, repository, ref=main.checkout_sha),
    }
    if exact_authority != route_authority:
        raise GitHubControllerError("alternate-lane authority differs from provider state")
    _, _, runners = runner_policy(api, repository, main=main)
    return _authorized_transition(
        main,
        repository=repository,
        admission_run_id=route["admission"]["run_id"],
        admission_run_attempt=route["admission"]["run_attempt"],
        installed_commit=current["BCF_BOOTSTRAP_COMMIT_SHA"],
        target=target,
        implementation_pr=pull["number"],
        policy_before=exact_authority["policy_before_sha256"],
        policy_after=exact_authority["policy_after_sha256"],
        runners=runners,
    )
