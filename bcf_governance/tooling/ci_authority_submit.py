"""One agent-facing prospective proof and exact-commit push authority."""

from __future__ import annotations

from pathlib import Path
import re
from typing import Any, Callable
from urllib.parse import urlparse

from .ci_github_api import GitHubAPI
from .ci_graph_contracts import validate_ci_graph
from .ci_graph_post_merge import post_merge_evaluation
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


Runner = Callable[..., Any]
_SAFE_BRANCH = re.compile(r"(?!.*\.\.)(?!.*@\{)[A-Za-z0-9][A-Za-z0-9._/-]*")
_REPOSITORY = re.compile(r"[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+")


def _command_error(result: Any) -> str:
    return result.stderr.strip() or result.stdout.strip() or "git push failed"


def _remote_repository(remote_url: str) -> str:
    value = remote_url.strip()
    scp = re.fullmatch(
        r"git@github\.com:(?P<repository>[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+?)(?:\.git)?",
        value,
    )
    if scp is not None:
        return scp.group("repository")
    parsed = urlparse(value)
    if (
        parsed.scheme not in {"https", "ssh"}
        or parsed.hostname not in {"github.com", "ssh.github.com"}
        or parsed.query
        or parsed.fragment
        or parsed.password is not None
    ):
        raise ProspectiveValidationError(
            "candidate submission requires an exact GitHub remote"
        )
    repository = parsed.path.removeprefix("/").removesuffix(".git")
    if _REPOSITORY.fullmatch(repository) is None:
        raise ProspectiveValidationError(
            "candidate submission remote does not identify exact owner/name"
        )
    return repository


def _provider_repository(
    repo_root: Path,
    *,
    context: LocalPRContext,
    provider_api: GitHubAPI,
    runner: Runner,
) -> str:
    result = runner(
        ["git", "remote", "get-url", context.remote], cwd=repo_root
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
            context=context,
            provider_api=provider_api,
            runner=runner,
        )
    else:
        protection = load_protection(repo_root)
        repository = str(protection["repository"]["full_name"])
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
    return {
        "status": "submitted",
        "subject": identity.as_dict(),
        "repository": repository,
        "branch": context.head_ref,
        "semantic_intent": mode,
        "evaluation_target": target,
        "prospective_status": proof["status"],
        "provider_authority_substituted": False,
    }
