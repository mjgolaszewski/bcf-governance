"""Closed authority projections for prospective provider lanes."""

from __future__ import annotations

import hashlib
from typing import Any

from .ci_authority_decisions import status_context_for_evaluation
from .ci_graph_post_merge import PostMergeEvaluation
from .evaluation_scope import is_terminal_phase_certification


def direct_policy_identity(
    *,
    base_sha: str,
    base_tree: str,
    candidate_sha: str,
    candidate_tree: str,
    base_graph: bytes,
    candidate_graph: bytes,
) -> dict[str, Any]:
    """Bind direct protected-main authority to exact canonical graph bytes."""

    return {
        "source": {
            "commit_sha": base_sha,
            "tree_sha": base_tree,
            "policy_sha256": hashlib.sha256(base_graph).hexdigest(),
        },
        "candidate": {
            "commit_sha": candidate_sha,
            "tree_sha": candidate_tree,
            "policy_sha256": hashlib.sha256(candidate_graph).hexdigest(),
        },
    }


def provider_boundaries(
    evaluation: PostMergeEvaluation,
    *,
    controller_state: str,
    transition_class: str,
    policy_identity: dict[str, Any],
    controller_probe: dict[str, Any] | None,
) -> list[dict[str, Any]]:
    """Project exact-main and controller custody without an untyped bypass."""

    direct = evaluation.lane == "direct_protected_main"
    lifecycle = {
        "id": "controller_lifecycle",
        "state": (
            "not_adopted_direct_lane"
            if direct
            else "rotation_required" if controller_state == "pending_rotation"
            else "ordinary_current_required"
        ),
        "transition_class": transition_class,
    }
    if direct:
        lifecycle["governed_alternate_lane"] = {
            "lane": evaluation.lane,
            "workflow_id": evaluation.workflow_id,
            "terminal_job_id": evaluation.terminal_job_id,
            "policy_sha256": policy_identity["candidate"]["policy_sha256"],
        }
    else:
        lifecycle["no_transition_callback_probe"] = controller_probe
    return [
        {
            "id": "exact_main",
            "state": (
                "direct_protected_main_reexecution_required"
                if direct else "fresh_provider_subject_required"
            ),
            **evaluation.as_dict(),
        },
        lifecycle,
    ]


def terminal_boundaries(
    evaluation: PostMergeEvaluation,
    *,
    proposition: dict[str, Any],
    proposition_sha256: str,
    bounded_truth: dict[str, Any],
) -> list[dict[str, Any]]:
    """Project finalization/publication authority for one explicit provider lane."""

    direct = evaluation.lane == "direct_protected_main"
    return [
        {
            "id": "finalizer",
            "state": (
                "same_workflow_terminal_truth_required" if direct else "provider_required"
            ),
            "proposition_sha256": proposition_sha256,
            "terminal_job_id": evaluation.terminal_job_id,
        },
        {
            "id": "publisher",
            "state": (
                "provider_job_conclusion_required" if direct else "provider_required"
            ),
            "scope": evaluation.mode,
            "status_context": (
                evaluation.terminal_job_id
                if direct else status_context_for_evaluation(evaluation.mode).value
            ),
        },
        {
            "id": "successor_or_release_eligibility",
            "state": "proved_scope",
            "eligible_successors": proposition["eligible_successors"],
            "release_authority": not direct and is_terminal_phase_certification(
                {
                    "evaluation_scope": bounded_truth["evaluation_scope"],
                    "certified_proposition": proposition,
                }
            ),
        },
    ]
