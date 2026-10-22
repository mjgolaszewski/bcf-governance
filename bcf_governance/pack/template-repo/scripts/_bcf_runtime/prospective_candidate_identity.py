"""Exact candidate identity and lifecycle proposition for prospective proof."""

from __future__ import annotations

from pathlib import Path

from .ci_graph_contracts import CIGraphError, validate_ci_graph
from .ci_graph_post_merge import authored_candidate_title, post_merge_evaluation
from .local_pr_context import (
    ProspectiveValidationError,
    Runner,
    _candidate_identity,
    _run,
    resolve_local_pr_context,
)


def canonical_prospective_inputs(
    repo_root: Path,
    *,
    remote: str = "origin",
    runner: Runner = _run,
) -> dict[str, str | None]:
    """Derive the immutable subject, proposition, and submit-ready metadata."""

    root = repo_root.resolve()
    context = resolve_local_pr_context(root, remote=remote, runner=runner)
    identity = _candidate_identity(root, context, runner=runner)
    try:
        evaluation = post_merge_evaluation(validate_ci_graph(root).graph)
        authored_candidate_title(root, mode=evaluation.mode, target=evaluation.target)
    except CIGraphError as exc:
        raise ProspectiveValidationError(str(exc)) from exc
    return {
        "semantic_intent": evaluation.mode,
        "evaluation_target": evaluation.target,
        "subject_commit": identity.commit_sha,
        "subject_tree": identity.tree_sha,
    }
