"""Exact candidate identity and lifecycle proposition for prospective proof."""

from __future__ import annotations

from pathlib import Path

from .ci_github_api import GitHubAPI
from .ci_graph_contracts import CIGraphError, validate_ci_graph
from .ci_graph_post_merge import authored_candidate_title, candidate_post_merge_evaluation, post_merge_evaluation
from .local_pr_context import (
    ProspectiveValidationError,
    Runner,
    _candidate_identity,
    require_clean_candidate_root,
    _run,
    resolve_local_pr_context,
)


def canonical_prospective_inputs(
    repo_root: Path,
    *,
    remote: str = "origin",
    runner: Runner = _run,
    provider_api: GitHubAPI | None = None,
) -> dict[str, str | None]:
    """Derive the immutable subject, proposition, and submit-ready metadata."""

    root = require_clean_candidate_root(repo_root, runner=runner)
    context = resolve_local_pr_context(root, remote=remote, runner=runner, provider_api=provider_api)
    identity = _candidate_identity(root, context, runner=runner)
    try:
        evaluation = candidate_post_merge_evaluation(post_merge_evaluation(validate_ci_graph(root).graph), context=context)
        authored_candidate_title(root, mode=evaluation.mode, target=evaluation.target)
    except CIGraphError as exc:
        raise ProspectiveValidationError(str(exc)) from exc
    return {
        "semantic_intent": evaluation.mode,
        "evaluation_target": evaluation.target,
        "subject_commit": identity.commit_sha,
        "subject_tree": identity.tree_sha,
    }
