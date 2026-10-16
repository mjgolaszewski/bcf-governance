"""Closed authority projections for prospective provider lanes."""

from __future__ import annotations

import hashlib
import json
from pathlib import Path
import subprocess
from typing import Any, Callable, Literal, overload

from .ci_authority_decisions import status_context_for_evaluation
from .ci_graph_post_merge import PostMergeEvaluation
from .ci_github_values import sha
from .local_pr_context import CandidateIdentity, LocalPRContext, Runner, _changed_paths, _checked, _run
from .evaluation_scope import is_terminal_phase_certification
from .routine_controller_rotation import ROTATION_POLICY_PATHS, controller_policy_digest


ORDINARY_AUTHORITY_POLICY_PATHS = (
    "governance/ci-graph.yml",
    "governance/ci-authority.yml",
)


class ProspectiveLaneError(ValueError):
    """Raised when an exact prospective authority input cannot be resolved."""


@overload
def git_blob(
    repo_root: Path, *, ref: str, path: str, allow_absent: Literal[False] = False
) -> bytes: ...


@overload
def git_blob(
    repo_root: Path, *, ref: str, path: str, allow_absent: Literal[True]
) -> bytes | None: ...


def git_blob(
    repo_root: Path, *, ref: str, path: str, allow_absent: bool = False
) -> bytes | None:
    """Read one exact Git blob, optionally authenticating path absence."""

    result = subprocess.run(
        ["git", "show", f"{ref}:{path}"], cwd=repo_root, capture_output=True, check=False
    )
    if result.returncode == 0:
        return result.stdout
    if allow_absent:
        inventory = subprocess.run(
            ["git", "ls-tree", "-z", ref, "--", path],
            cwd=repo_root,
            capture_output=True,
            check=False,
        )
        if inventory.returncode == 0 and inventory.stdout == b"":
            return None
    detail = result.stderr.decode("utf-8", errors="replace").strip()
    raise ProspectiveLaneError(
        f"cannot resolve authority policy {path} at {ref}: {detail or 'git show failed'}"
    )


def controller_policy_identity(
    *,
    base_sha: str,
    base_tree: str,
    candidate_sha: str,
    candidate_tree: str,
    read_blob: Callable[[str, str], bytes],
) -> dict[str, Any]:
    """Bind both exact controller-policy projections without orchestration ownership."""

    source_digest = controller_policy_digest(lambda path: read_blob(base_sha, path))
    candidate_digest = controller_policy_digest(lambda path: read_blob(candidate_sha, path))
    return {
        "source": {
            "commit_sha": base_sha,
            "tree_sha": base_tree,
            "policy_sha256": source_digest,
        },
        "candidate": {
            "commit_sha": candidate_sha,
            "tree_sha": candidate_tree,
            "policy_sha256": candidate_digest,
        },
    }


def ordinary_authority_policy_identity(
    *,
    base_sha: str,
    base_tree: str,
    candidate_sha: str,
    candidate_tree: str,
    read_blob: Callable[[str, str], bytes | None],
) -> dict[str, Any]:
    """Bind exact present/absent policy paths for an executable controller."""

    def projection(ref: str, *, require_graph: bool) -> dict[str, Any]:
        paths: dict[str, dict[str, str | None]] = {}
        for path in ORDINARY_AUTHORITY_POLICY_PATHS:
            raw = read_blob(ref, path)
            if require_graph and path == "governance/ci-graph.yml" and raw is None:
                raise ProspectiveLaneError("candidate ordinary exact-main graph is absent")
            paths[path] = {
                "state": "absent" if raw is None else "present",
                "sha256": None if raw is None else hashlib.sha256(raw).hexdigest(),
            }
        encoded = json.dumps(paths, sort_keys=True, separators=(",", ":")).encode()
        return {"policy_paths": paths, "policy_sha256": hashlib.sha256(encoded).hexdigest()}

    return {
        "source": {
            "commit_sha": base_sha,
            "tree_sha": base_tree,
            **projection(base_sha, require_graph=False),
        },
        "candidate": {
            "commit_sha": candidate_sha,
            "tree_sha": candidate_tree,
            **projection(candidate_sha, require_graph=True),
        },
    }


def ordinary_authority_applicability(policy_identity: dict[str, Any]) -> str:
    """Classify the exact provider-authority bootstrap state or fail closed."""

    try:
        source = policy_identity["source"]["policy_paths"][
            "governance/ci-authority.yml"
        ]["state"]
        candidate = policy_identity["candidate"]["policy_paths"][
            "governance/ci-authority.yml"
        ]["state"]
    except (KeyError, TypeError) as exc:
        raise ProspectiveLaneError(
            "ordinary provider-authority applicability is incomplete"
        ) from exc
    if source not in {"absent", "present"} or candidate not in {
        "absent", "present"
    }:
        raise ProspectiveLaneError(
            "ordinary provider-authority applicability is invalid"
        )
    if source == "present" and candidate == "absent":
        raise ProspectiveLaneError(
            "candidate removes established provider workflow authority"
        )
    return (
        "bootstrap_provider_authority_absent"
        if candidate == "absent"
        else "provider_verification_required"
    )


def prospective_policy_binding(
    repo_root: Path,
    *,
    lane: str,
    custody_state: str,
    changed_paths: tuple[str, ...],
    base_sha: str,
    base_tree: str,
    candidate_sha: str,
    candidate_tree: str,
    policy_context: LocalPRContext | None = None,
    runner: Runner = _run,
) -> tuple[str, dict[str, Any]]:
    """Classify and bind the exact applicable post-merge policy surface."""

    if policy_context is not None:
        source_sha, source_tree = policy_context.protected_default_sha, policy_context.protected_default_tree
        if policy_context.base_sha != base_sha or policy_context.head_sha != candidate_sha:
            raise ProspectiveLaneError("policy context does not bind the candidate comparison subject")
        if (source_sha is None) != (source_tree is None):
            raise ProspectiveLaneError("protected default policy snapshot is incomplete")
        if source_sha is None and (policy_context.repository is not None or policy_context.comparison_base_ref != policy_context.default_branch):
            raise ProspectiveLaneError("authenticated policy context lacks its protected default snapshot")
        if source_sha is not None:
            try:
                base_sha = sha(source_sha, field="protected default policy commit")
                base_tree = sha(source_tree, field="protected default policy tree")
                observed_tree = _checked(runner, ["git", "rev-parse", "--verify", f"{base_sha}^{{tree}}"], cwd=repo_root)
                if observed_tree != base_tree:
                    raise ProspectiveLaneError("protected default policy tree disagrees with exact Git subject")
                changed_paths = _changed_paths(repo_root, CandidateIdentity(candidate_sha, candidate_tree, base_sha), runner=runner)
            except ValueError as exc:
                raise ProspectiveLaneError(str(exc)) from exc
    read = lambda ref, path: git_blob(repo_root, ref=ref, path=path)
    if lane == "direct_protected_main":
        base_graph = git_blob(
            repo_root,
            ref=base_sha,
            path="governance/ci-graph.yml",
            allow_absent=True,
        )
        transition = (
            "fresh_direct_graph_adoption"
            if base_graph is None
            else "direct_graph_change"
            if "governance/ci-graph.yml" in changed_paths
            else "direct_runtime_only"
        )
        identity = direct_policy_identity(
            base_sha=base_sha,
            base_tree=base_tree,
            candidate_sha=candidate_sha,
            candidate_tree=candidate_tree,
            base_graph=base_graph,
            candidate_graph=read(candidate_sha, "governance/ci-graph.yml"),
        )
    elif custody_state == "ordinary_executable_controller":
        transition = (
            "ordinary_authority_change"
            if set(changed_paths).intersection(ORDINARY_AUTHORITY_POLICY_PATHS)
            else "ordinary_runtime_only"
        )
        identity = ordinary_authority_policy_identity(
            base_sha=base_sha,
            base_tree=base_tree,
            candidate_sha=candidate_sha,
            candidate_tree=candidate_tree,
            read_blob=lambda ref, path: git_blob(
                repo_root, ref=ref, path=path, allow_absent=True
            ),
        )
    else:
        transition = (
            "protected_policy_change"
            if set(changed_paths).intersection(ROTATION_POLICY_PATHS)
            else "runtime_only"
        )
        identity = controller_policy_identity(
            base_sha=base_sha,
            base_tree=base_tree,
            candidate_sha=candidate_sha,
            candidate_tree=candidate_tree,
            read_blob=read,
        )
        if (
            transition == "protected_policy_change"
            and identity["source"]["policy_sha256"]
            == identity["candidate"]["policy_sha256"]
        ):
            raise ProspectiveLaneError(
                "protected controller-policy paths changed without a policy identity change"
            )
    return transition, identity


def direct_policy_identity(
    *,
    base_sha: str,
    base_tree: str,
    candidate_sha: str,
    candidate_tree: str,
    base_graph: bytes | None,
    candidate_graph: bytes,
) -> dict[str, Any]:
    """Bind direct protected-main authority to exact canonical graph bytes."""

    return {
        "source": {
            "commit_sha": base_sha,
            "tree_sha": base_tree,
            "policy_state": "absent" if base_graph is None else "present",
            "policy_sha256": (
                None if base_graph is None else hashlib.sha256(base_graph).hexdigest()
            ),
        },
        "candidate": {
            "commit_sha": candidate_sha,
            "tree_sha": candidate_tree,
            "policy_state": "present",
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
            else "ordinary_executable_controller"
            if controller_state == "ordinary_executable"
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
    elif controller_state != "ordinary_executable":
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
    if evaluation.mode == "pr":
        return [
            {
                "id": "finalizer",
                "state": "provider_noncertifying_observation_required",
                "proposition_sha256": proposition_sha256,
                "terminal_job_id": evaluation.terminal_job_id,
            },
            {
                "id": "publisher",
                "state": "provider_suppression_required",
                "scope": "pr",
                "status_context": None,
            },
            {
                "id": "successor_or_release_eligibility",
                "state": "proved_scope",
                "eligible_successors": [],
                "release_authority": False,
            },
        ]
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
