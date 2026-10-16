"""One agent-facing prospective proof and exact-commit push authority."""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
import hashlib
import json
import re
import time
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
from .ci_graph_post_merge import authored_candidate_title, authored_post_merge_scope, post_merge_evaluation
from .ci_recovery_frontier import protected_merge_frontier, submission_frontier
from .github_protection import load_protection
from .local_pr import (
    CandidateIdentity,
    LocalPRContext,
    ProspectiveValidationError,
    ProgressSink,
    _candidate_identity,
    _confirm_unchanged,
    _run,
    resolve_local_pr_context,
    run_prospective_train,
)
from .operational_observations import progress_event, validate_progress_stream
from .ordinary_protection_projection import validate_ordinary_protection_submission
from .local_execution_admission import local_gate_lease
from .nested_cli_runtime import exact_nested_cli_command
from .release_version_projection import validate_authored_release_target
from .test_manifests import validate_authored_test_reference_inventories
from .semantic_ownership_scan import validate_authored_semantic_ownership
from .runtime_capacity import executing_runtime_version
from .ci_graph_timeouts import gate_timeout_contract
from .governance_validation.authored_phase_state import validate_authored_phase_state
from .governance_validation.ci_state_matrix import validate_ci_state_matrix


Runner = Callable[..., Any]
_SAFE_BRANCH = re.compile(r"(?!.*\.\.)(?!.*@\{)[A-Za-z0-9][A-Za-z0-9._/-]*")


def _normalize_submission(
    root: Path,
    *,
    python_executable: Path,
    execution_id: str,
    semantic_intent: str | None,
    runner: Runner,
) -> None:
    """Settle derived state before consuming its submission authority projection."""

    try:
        if (root / "plans/phase-ledger.yml").is_file():
            validate_authored_phase_state(root)
        try:
            version = executing_runtime_version()
        except RuntimeError as exc:
            raise ProspectiveValidationError(str(exc)) from exc
        validate_authored_release_target(root, version)
        gate_timeout_contract(root)
        validate_ci_state_matrix(root, authored_only=True)
        if semantic_intent is not None and semantic_intent != authored_post_merge_scope(root)[0]:
            raise ProspectiveValidationError(
                "submitted semantic intent does not match the authored lifecycle intent"
            )
        validate_authored_test_reference_inventories(root, python_executable=python_executable)
        validate_authored_semantic_ownership(root)
    except ValueError as exc:
        raise ProspectiveValidationError(str(exc)) from exc
    with local_gate_lease(execution_id):
        command = exact_nested_cli_command(
            "reconcile", "--repo-root", str(root), "--python", str(python_executable),
        )
        checked = runner([*command, "--check"], cwd=root)
        if checked.returncode == 0:
            return
        # Only the existing canonical owner decides whether inputs can converge.
        # Keep its deferred write callbacks behind its CLI mutation boundary.
        result = runner([*command, "--commit-derived", "--apply"], cwd=root)
        if result.returncode:
            detail = result.stderr.strip() or result.stdout.strip() or f"exit {result.returncode}"
            raise ProspectiveValidationError(
                f"canonical submission normalization failed: {detail}"
            )
        settled = runner([*command, "--check"], cwd=root)
        if settled.returncode:
            detail = settled.stderr.strip() or settled.stdout.strip() or f"exit {settled.returncode}"
            raise ProspectiveValidationError(
                f"canonical submission normalization did not converge: {detail}"
            )


@dataclass(frozen=True)
class SubmissionAuthority:
    """Complete lane-scoped authority required by every submit consumer."""

    mode: str
    target: str | None
    lane: str
    repository: str
    repository_id: int
    protection_sha256: str


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
) -> tuple[str, int]:
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
    return repository, repository_id


def _provider_repository_id(
    provider_api: GitHubAPI, *, repository: str
) -> int:
    observed = provider_api.repository(repository)
    repository_id = observed.get("id") if isinstance(observed, dict) else None
    if (
        not isinstance(repository_id, int)
        or isinstance(repository_id, bool)
        or repository_id <= 0
        or observed.get("full_name") != repository
    ):
        raise ProspectiveValidationError(
            "authenticated provider repository does not match candidate authority"
        )
    return repository_id


def _direct_protection_identity(
    repo_root: Path,
    *,
    repository: str,
    repository_id: int,
    applicability: str,
) -> str:
    graph = repo_root / "governance/ci-graph.yml"
    if not graph.is_file() or graph.is_symlink():
        raise ProspectiveValidationError(
            "direct protected-main submission lacks canonical graph identity"
        )
    payload = {
        "applicability": applicability,
        "graph_sha256": hashlib.sha256(graph.read_bytes()).hexdigest(),
        "lane": "direct_protected_main",
        "repository": repository,
        "repository_id": repository_id,
    }
    return hashlib.sha256(
        json.dumps(payload, sort_keys=True, separators=(",", ":")).encode()
    ).hexdigest()


def _canonical_inputs(
    repo_root: Path,
    *,
    context: LocalPRContext,
    provider_api: GitHubAPI,
    runner: Runner,
) -> SubmissionAuthority:
    evaluation = post_merge_evaluation(validate_ci_graph(repo_root).graph)
    if evaluation.lane == "direct_protected_main":
        repository, repository_id = _provider_repository(
            repo_root,
            remote=context.remote,
            provider_api=provider_api,
            runner=runner,
        )
    else:
        protection = load_protection(repo_root)
        repository = str(protection["repository"]["full_name"])
        repository_id = _provider_repository_id(
            provider_api, repository=repository
        )
    try:
        applicability = validate_ordinary_protection_submission(
            provider_api,
            repo_root=repo_root,
            repository=repository,
            base_sha=context.base_sha,
        )
    except GitHubControllerError as exc:
        raise ProspectiveValidationError(str(exc)) from exc
    protection_path = repo_root / "governance/github-protection.yml"
    protection_sha256 = (
        _direct_protection_identity(
            repo_root,
            repository=repository,
            repository_id=repository_id,
            applicability=applicability,
        )
        if evaluation.lane == "direct_protected_main"
        else hashlib.sha256(protection_path.read_bytes()).hexdigest()
    )
    return SubmissionAuthority(
        mode=evaluation.mode,
        target=evaluation.target,
        lane=evaluation.lane,
        repository=repository,
        repository_id=repository_id,
        protection_sha256=protection_sha256,
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
    *,
    provider_api: GitHubAPI,
    authority: SubmissionAuthority,
    identity: CandidateIdentity,
    pull_request: dict[str, Any],
    prospective_frontier_sha256: str,
) -> tuple[dict[str, Any], dict[str, Any]]:
    if pull_request.get("repository_id") != authority.repository_id:
        raise ProspectiveValidationError(
            "candidate pull request repository identity changed after admission"
        )
    frontier = protected_merge_frontier(
        identity={
            "repository": authority.repository,
            "repository_id": str(pull_request["repository_id"]),
            "pull_request": str(pull_request["number"]),
            "base_sha": identity.base_sha,
            "head_sha": identity.commit_sha,
            "tree_sha": identity.tree_sha,
            "protection_sha256": authority.protection_sha256,
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
            authority.repository,
            pull_request["number"],
            node_id=str(pull_request["node_id"]),
            expected_base_sha=identity.base_sha,
            expected_head_sha=identity.commit_sha,
        )
    except ValueError as exc:
        raise ProspectiveValidationError(
            "provider did not bind exact protected auto-merge"
        ) from exc
    if result.get("status") == "certified_clean":
        frontier = protected_merge_frontier(
            identity={
                "repository": authority.repository,
                "repository_id": str(pull_request["repository_id"]),
                "pull_request": str(pull_request["number"]),
                "base_sha": identity.base_sha,
                "head_sha": identity.commit_sha,
                "tree_sha": identity.tree_sha,
                "protection_sha256": authority.protection_sha256,
            },
            state="certified_mergeable",
            certification_identity=f"prospective:{prospective_frontier_sha256}",
        )
        if frontier["action"]["kind"] != "merge_commit":
            raise ProspectiveValidationError(
                "certified candidate frontier did not select a normal merge commit"
            )
        try:
            result = provider_api.merge_clean_pull_request(
                authority.repository,
                pull_request["number"],
                node_id=str(pull_request["node_id"]),
                expected_base_sha=identity.base_sha,
                expected_head_sha=identity.commit_sha,
            )
        except ValueError as exc:
            raise ProspectiveValidationError(
                "provider did not bind exact normal protected merge"
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
    progress_sink: ProgressSink | None = None,
) -> dict[str, object]:
    """Prove and push only the exact immutable candidate that passed the train."""

    root = repo_root.resolve()
    context = resolve_local_pr_context(root, remote=remote, runner=runner)
    identity = _candidate_identity(root, context, runner=runner)
    progress = []
    progress_started = time.monotonic_ns()
    progress_identity = 'submission:' + identity.commit_sha

    def emit(stage: str, state: str) -> None:
        progress.append(progress_event(kind="submission_progress", execution_id=progress_identity, sequence=len(progress) + 1,
            stage=stage, state=state, monotonic_ms=(time.monotonic_ns() - progress_started) // 1000000))
        validate_progress_stream(progress)
        if progress_sink is not None:
            progress_sink(progress[-1])

    emit('normalization', 'started')
    try:
        _normalize_submission(
            root,
            python_executable=python_executable,
            execution_id=identity.commit_sha,
            semantic_intent=semantic_intent,
            runner=runner,
        )
    except (ValueError, OSError) as exc:
        try:
            emit('normalization', 'failed')
        except Exception as observation_error:
            raise exc from observation_error
        raise
    emit('normalization', 'complete')
    context = resolve_local_pr_context(root, remote=remote, runner=runner)
    identity = _candidate_identity(root, context, runner=runner)
    emit('submission_authority', 'started')
    try:
        authority = _canonical_inputs(
            root,
            context=context,
            provider_api=provider_api,
            runner=runner,
        )
    except (ValueError, OSError) as exc:
        try:
            emit('submission_authority', 'failed')
        except Exception as observation_error:
            raise exc from observation_error
        raise
    emit('submission_authority', 'complete')
    try:
        candidate_title = authored_candidate_title(
            root, mode=authority.mode, target=authority.target
        )
    except ValueError as exc:
        raise ProspectiveValidationError(str(exc)) from exc
    recovery_identity = {
        "repository": authority.repository,
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
    if semantic_intent is not None and semantic_intent != authority.mode:
        raise ProspectiveValidationError(
            "submitted semantic intent does not match the canonical exact-main intent"
        )
    proof = run_prospective_train(
        root,
        semantic_intent=authority.mode,
        evaluation_target=authority.target,
        subject_commit=identity.commit_sha,
        subject_tree=identity.tree_sha,
        remote=remote,
        python_executable=python_executable,
        repository=authority.repository,
        provider_api=provider_api,
        runner=runner,
        progress_sink=progress_sink,
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
        repository=authority.repository,
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
        repository=authority.repository,
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
        provider_api=provider_api,
        authority=authority,
        identity=identity,
        pull_request=pull_request,
        prospective_frontier_sha256=str(proved_frontier["frontier_sha256"]),
    )
    provider_retry_submitted = execute_candidate_provider_recovery(
        provider_api,
        repository=authority.repository,
        frontier=provider_frontier,
        candidate=identity,
        context=context,
        pull_request=pull_request,
    )
    return {
        "status": (
            "provider_retry_submitted"
            if provider_retry_submitted
            else "merged"
            if str(auto_merge.get("status", "")).startswith("merged")
            else "submitted"
        ),
        "subject": identity.as_dict(),
        "repository": authority.repository,
        "branch": context.head_ref,
        "semantic_intent": authority.mode,
        "evaluation_target": authority.target,
        "prospective_status": proof["status"],
        "provider_authority_substituted": False,
        "recovery_frontier": proved_frontier,
        "pull_request": pull_request,
        "protected_merge_frontier": merge_frontier,
        "candidate_provider_frontier": provider_frontier,
        "provider_retry_submitted": provider_retry_submitted,
        "auto_merge": auto_merge,
    }
