"""One agent-facing prospective proof and exact-commit push authority."""

from __future__ import annotations

from pathlib import Path
import re
from typing import Any, Callable

from .ci_github_api import GitHubAPI
from .ci_graph_contracts import validate_ci_graph
from .ci_graph_execution import exact_main_evaluation
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


def _canonical_inputs(repo_root: Path) -> tuple[str, str | None, str]:
    evaluation = exact_main_evaluation(validate_ci_graph(repo_root).workflows)
    protection = load_protection(repo_root)
    return (
        evaluation.mode,
        evaluation.target,
        str(protection["repository"]["full_name"]),
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
        detail = result.stderr.strip() or result.stdout.strip() or "git push failed"
        raise ProspectiveValidationError(f"exact candidate push failed: {detail}")


def submit_candidate(
    repo_root: Path,
    *,
    semantic_intent: str,
    python_executable: Path,
    provider_api: GitHubAPI,
    remote: str = "origin",
    runner: Runner = _run,
) -> dict[str, object]:
    """Prove and push only the exact immutable candidate that passed the train."""

    root = repo_root.resolve()
    context = resolve_local_pr_context(root, remote=remote, runner=runner)
    identity = _candidate_identity(root, context, runner=runner)
    mode, target, repository = _canonical_inputs(root)
    if semantic_intent != mode:
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
