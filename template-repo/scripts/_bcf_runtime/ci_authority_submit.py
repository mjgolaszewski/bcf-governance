"""One agent-facing prospective proof and exact-commit push authority."""

from __future__ import annotations

from pathlib import Path
import hashlib
import re
from typing import Any, Callable

from .ci_github_api import GitHubAPI
from .ci_github_identity import GitHubControllerError
from .ci_github_values import GitHubValueError, remote_repository
from .ci_candidate_pr import ensure_candidate_pull_request
from .candidate_provider_recovery import (
    execute_candidate_provider_recovery,
    resolve_candidate_provider_recovery,
)
from .ci_graph_contracts import validate_ci_graph
from .ci_graph_post_merge import authored_candidate_title, post_merge_evaluation
from .ci_recovery_frontier import protected_merge_frontier, submission_frontier
from .github_protection import load_protection
from .local_pr import (
    CandidateIdentity,
    LocalPRContext,
    ProspectiveValidationError,
    _candidate_identity,
    _confirm_unchanged,
    _run,
    resolve_local_pr_context,
    run_prospective_train,
)
from .ordinary_protection_projection import validate_ordinary_protection_submission


Runner = Callable[..., Any]
_SAFE_BRANCH = re.compile(r"(?!.*\.\.)(?!.*@\{)[A-Za-z0-9][A-Za-z0-9._/-]*")


def _command_error(result: Any) -> str:
    return result.stderr.strip() or result.stdout.strip() or "git push failed"


def _remote_repository(remote_url: str) -> str:
    try:
        return remote_repository(remote_url)
    except GitHubValueError as exc:
        raise ProspectiveValidationError(
            "candidate submission requires an exact GitHub remote"
        ) from exc


def _provider_repository(
    repo_root: Path,
    *,
    remote: str,
    provider_api: GitHubAPI,
    runner: Runner,
) -> str:
    result = runner(
        ["git", "remote", "get-url", remote], cwd=repo_root
    )
    if result.returncode:
        raise ProspectiveValidationError(
            f"cannot resolve candidate repository remote: {_command_error(result)}"
        )
    repository = _remote_repository(result.stdout)
    observed = provider_api.repository(repository)
    repository_id = observed.get("id") if isinstance(observed, dict) else None
    if (
        not isinstance(repository_id, int)
        or isinstance(repository_id, bool)
        or repository_id <= 0
        or observed.get("full_name") != repository
    ):
        raise ProspectiveValidationError(
            "authenticated provider repository does not match candidate remote"
        )
    return repository


def _canonical_inputs(
    repo_root: Path,
    *,
    context: LocalPRContext,
    provider_api: GitHubAPI,
    runner: Runner,
) -> tuple[str, str | None, str]:
    evaluation = post_merge_evaluation(validate_ci_graph(repo_root).graph)
    if evaluation.lane == "direct_protected_main":
        repository = _provider_repository(
            repo_root,
            remote=context.remote,
            provider_api=provider_api,
            runner=runner,
        )
    else:
        protection = load_protection(repo_root)
        repository = str(protection["repository"]["full_name"])
    try:
        validate_ordinary_protection_submission(
            provider_api,
            repo_root=repo_root,
            repository=repository,
            base_sha=context.base_sha,
        )
    except GitHubControllerError as exc:
        raise ProspectiveValidationError(str(exc)) from exc
    return (
        evaluation.mode,
        evaluation.target,
        repository,
    )


def _push_exact_candidate(
    repo_root: Path,
    *,
    context: LocalPRContext,
    identity: CandidateIdentity,
    runner: Runner,
) -> None:
    branch = context.head_ref
    if branch == "detached-head" or _SAFE_BRANCH.fullmatch(branch) is None:
        raise ProspectiveValidationError("candidate submission requires a safe named branch")
    result = runner(
        ["git", "push", context.remote, f"{identity.commit_sha}:refs/heads/{branch}"],
        cwd=repo_root,
    )
    if result.returncode:
        raise ProspectiveValidationError(
            f"exact candidate push failed: {_command_error(result)}"
        )


def _request_protected_auto_merge(
    repo_root: Path,
    *,
    provider_api: GitHubAPI,
    repository: str,
    identity: CandidateIdentity,
    pull_request: dict[str, Any],
    prospective_frontier_sha256: str,
) -> tuple[dict[str, Any], dict[str, Any]]:
    protection_path = repo_root / "governance/github-protection.yml"
    if not protection_path.is_file() or protection_path.is_symlink():
        raise ProspectiveValidationError(
            "candidate submission lacks canonical protection identity"
        )
    frontier = protected_merge_frontier(
        identity={
            "repository": repository,
            "repository_id": str(pull_request["repository_id"]),
            "pull_request": str(pull_request["number"]),
            "base_sha": identity.base_sha,
            "head_sha": identity.commit_sha,
            "tree_sha": identity.tree_sha,
            "protection_sha256": hashlib.sha256(
                protection_path.read_bytes()
            ).hexdigest(),
        },
        state="prospective_proved",
        certification_identity=f"prospective:{prospective_frontier_sha256}",
    )
    if frontier["action"]["kind"] != "request_provider_auto_merge":
        raise ProspectiveValidationError(
            "proved candidate frontier did not select protected auto-merge"
        )
    try:
        result = provider_api.enable_pull_request_auto_merge(
            repository,
            pull_request["number"],
            node_id=str(pull_request["node_id"]),
            expected_head_sha=identity.commit_sha,
        )
    except ValueError as exc:
        raise ProspectiveValidationError(
            "provider did not bind exact protected auto-merge"
        ) from exc
    return result, frontier


def submit_candidate(
    repo_root: Path,
    *,
    semantic_intent: str | None = None,
    python_executable: Path,
    provider_api: GitHubAPI,
    remote: str = "origin",
    runner: Runner = _run,
) -> dict[str, object]:
    """Prove and push only the exact immutable candidate that passed the train."""

    root = repo_root.resolve()
    context = resolve_local_pr_context(root, remote=remote, runner=runner)
    identity = _candidate_identity(root, context, runner=runner)
    mode, target, repository = _canonical_inputs(
        root,
        context=context,
        provider_api=provider_api,
        runner=runner,
    )
    try:
        candidate_title = authored_candidate_title(root, mode=mode, target=target)
    except ValueError as exc:
        raise ProspectiveValidationError(str(exc)) from exc
    recovery_identity = {
        "repository": repository,
        "base_sha": identity.base_sha,
        "head_sha": identity.commit_sha,
        "tree_sha": identity.tree_sha,
    }
    initial_frontier = submission_frontier(
        identity=recovery_identity, prospective_proved=False
    )
    if initial_frontier["action"]["kind"] != "run_prospective_and_push":
        raise ProspectiveValidationError(
            "candidate recovery frontier did not select canonical submission"
        )
    if semantic_intent is not None and semantic_intent != mode:
        raise ProspectiveValidationError(
            "submitted semantic intent does not match the canonical exact-main intent"
        )
    proof = run_prospective_train(
        root,
        semantic_intent=mode,
        evaluation_target=target,
        subject_commit=identity.commit_sha,
        subject_tree=identity.tree_sha,
        remote=remote,
        python_executable=python_executable,
        repository=repository,
        provider_api=provider_api,
        runner=runner,
    )
    if proof.get("status") != "prospectively_admissible_provider_proof_required":
        raise ProspectiveValidationError(
            "candidate submission requires a complete prospective proof"
        )
    proved_frontier = submission_frontier(
        identity=recovery_identity, prospective_proved=True
    )
    if proved_frontier["action"]["kind"] != "push_exact_candidate":
        raise ProspectiveValidationError(
            "proved candidate recovery frontier did not select exact push"
        )
    _confirm_unchanged(
        root,
        initial_context=context,
        initial_identity=identity,
        remote=remote,
        runner=runner,
    )
    _push_exact_candidate(
        root, context=context, identity=identity, runner=runner
    )
    pull_request = ensure_candidate_pull_request(
        provider_api,
        repository=repository,
        branch=context.head_ref,
        base_ref=context.default_branch,
        base_sha=identity.base_sha,
        head_sha=identity.commit_sha,
        tree_sha=identity.tree_sha,
        title=candidate_title,
        frontier_sha256=str(proved_frontier["frontier_sha256"]),
    )
    provider_frontier = resolve_candidate_provider_recovery(
        provider_api,
        repository=repository,
        pull_request=pull_request,
        base_sha=identity.base_sha,
        head_sha=identity.commit_sha,
        tree_sha=identity.tree_sha,
    )
    provider_action = str(provider_frontier["action"]["kind"])
    if provider_action == "stop":
        raise ProspectiveValidationError(
            "exact candidate provider execution has a terminal failure"
        )
    auto_merge, merge_frontier = _request_protected_auto_merge(
        root,
        provider_api=provider_api,
        repository=repository,
        identity=identity,
        pull_request=pull_request,
        prospective_frontier_sha256=str(proved_frontier["frontier_sha256"]),
    )
    provider_retry_submitted = execute_candidate_provider_recovery(
        provider_api,
        repository=repository,
        frontier=provider_frontier,
    )
    return {
        "status": (
            "provider_retry_submitted" if provider_retry_submitted else "submitted"
        ),
        "subject": identity.as_dict(),
        "repository": repository,
        "branch": context.head_ref,
        "semantic_intent": mode,
        "evaluation_target": target,
        "prospective_status": proof["status"],
        "provider_authority_substituted": False,
        "recovery_frontier": proved_frontier,
        "pull_request": pull_request,
        "protected_merge_frontier": merge_frontier,
        "candidate_provider_frontier": provider_frontier,
        "provider_retry_submitted": provider_retry_submitted,
        "auto_merge": auto_merge,
    }
