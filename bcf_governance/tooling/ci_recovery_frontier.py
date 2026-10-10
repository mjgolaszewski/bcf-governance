"""Closed next-action projection from authenticated CI and provider state."""

from __future__ import annotations

import hashlib
import json
import re
from typing import Any, Mapping, Sequence


class RecoveryFrontierError(ValueError):
    """Authenticated state does not select one closed legal action."""


_SHA = re.compile(r"^[a-f0-9]{40}$")
_DIGEST = re.compile(r"^[a-f0-9]{64}$")

_EDGES = {
    ("candidate_submission", "exact_candidate"): (
        "run_prospective_and_push", "provider_proof_required"
    ),
    ("candidate_submission", "prospective_proved"): (
        "push_exact_candidate", "pr_provider_pending"
    ),
    ("candidate_provider", "not_started"): (
        "observe_exact_provider_run", "pr_provider_pending"
    ),
    ("candidate_provider", "active"): (
        "observe_same_provider_run", "pr_provider_pending"
    ),
    ("candidate_provider", "succeeded"): (
        "observe_pr_certification", "pr_certification_pending"
    ),
    ("candidate_provider", "retryable_terminal_transport"): (
        "rerun_exact_provider_workflow", "pr_provider_pending"
    ),
    ("candidate_provider", "terminal_failure"): ("stop", "terminal_blocked"),
    ("candidate_provider", "retry_exhausted"): ("stop", "terminal_blocked"),
    ("provider_read", "transient"): ("retry_identical_read", "provider_observation"),
    ("provider_read", "success"): ("consume_exact_read", "operation_continues"),
    ("provider_read", "terminal"): ("stop", "terminal_blocked"),
    ("provider_read", "exhausted"): ("stop", "terminal_blocked"),
    ("protected_merge", "pending"): ("observe_same_subject", "pr_pending"),
    ("protected_merge", "prospective_proved"): (
        "request_provider_auto_merge", "pr_pending"
    ),
    ("protected_merge", "certified_mergeable"): (
        "merge_commit", "exact_main_required"
    ),
    ("protected_merge", "base_advanced"): (
        "reconstruct_candidate", "fresh_candidate_required"
    ),
    ("protected_merge", "superseded"): ("stop", "superseded"),
    ("controller_transition", "controller_current"): (
        "emit_no_transition", "ordinary_current"
    ),
    ("controller_transition", "pending_rotation"): (
        "invoke_routine_transition", "ordinary_current"
    ),
    ("controller_transition", "protected_policy_change"): (
        "invoke_exact_alternate_lane", "ordinary_current"
    ),
    ("mutation_result", "unknown"): (
        "observe_mutation_state", "classified_mutation_result"
    ),
    ("mutation_result", "committed"): ("consume_exact_result", "operation_continues"),
    ("mutation_result", "not_committed"): (
        "retry_same_idempotent_operation", "classified_mutation_result"
    ),
    ("mutation_result", "conflict"): ("stop", "terminal_blocked"),
}


def _canonical(value: Mapping[str, Any]) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(",", ":")).encode()


def _strings(values: Sequence[object], *, field: str) -> list[str]:
    result = [str(value) for value in values]
    if any(not value or "\0" in value or "\n" in value for value in result):
        raise RecoveryFrontierError(f"{field} contains an invalid identity")
    if len(result) != len(set(result)):
        raise RecoveryFrontierError(f"{field} must be unique")
    return sorted(result)


def compile_recovery_frontier(
    *,
    operation: str,
    state: str,
    identity: Mapping[str, Any],
    owner: str,
    prerequisites: Sequence[object] = (),
    preserve: Sequence[object] = (),
    invalidate: Sequence[object] = (),
    transition_class: str = "none",
    alternate_lane: Mapping[str, Any] | None = None,
    idempotency_key: str | None = None,
) -> dict[str, Any]:
    """Compile the sole legal action and successor for one closed state edge."""

    edge = _EDGES.get((operation, state))
    if edge is None:
        raise RecoveryFrontierError("operation state has no governed recovery edge")
    if not owner or "\0" in owner or "\n" in owner:
        raise RecoveryFrontierError("recovery action owner is invalid")
    if not isinstance(identity, Mapping) or not identity:
        raise RecoveryFrontierError("recovery identity must be complete")
    preserved = _strings(preserve, field="preserved proof inventory")
    invalidated = _strings(invalidate, field="invalidated proof inventory")
    if set(preserved) & set(invalidated):
        raise RecoveryFrontierError("proof cannot be preserved and invalidated")
    if operation == "provider_read":
        request = str(identity.get("request_sha256", ""))
        if _DIGEST.fullmatch(request) is None:
            raise RecoveryFrontierError("provider read identity is not exact")
    if operation == "candidate_submission":
        required = {"repository", "base_sha", "head_sha", "tree_sha"}
        if set(identity) != required or any(
            _SHA.fullmatch(str(identity[name])) is None
            for name in required - {"repository"}
        ) or not str(identity["repository"]):
            raise RecoveryFrontierError("candidate recovery identity is not exact")
    if operation == "candidate_provider":
        common = {
            "repository", "repository_id", "pull_request", "base_sha",
            "head_sha", "tree_sha", "workflow_id", "workflow_path",
        }
        run_fields = {"run_id", "run_attempt"}
        expected = common if state == "not_started" else common | run_fields
        if state in {"retryable_terminal_transport", "retry_exhausted"}:
            expected |= {"terminal_job_id"}
        if set(identity) != expected or any(
            _SHA.fullmatch(str(identity[name])) is None
            for name in {"base_sha", "head_sha", "tree_sha"}
        ):
            raise RecoveryFrontierError(
                "candidate provider recovery identity is not exact"
            )
        numeric = {"repository_id", "pull_request", "workflow_id"}
        if state != "not_started":
            numeric |= run_fields
        if state in {"retryable_terminal_transport", "retry_exhausted"}:
            numeric |= {"terminal_job_id"}
        if (
            not str(identity["repository"])
            or str(identity["workflow_path"]) != ".github/workflows/governance.yml"
            or any(
                not str(identity[name]).isdigit() or int(str(identity[name])) < 1
                for name in numeric
            )
        ):
            raise RecoveryFrontierError(
                "candidate provider recovery identity is invalid"
            )
    if operation == "protected_merge":
        required = {
            "repository", "repository_id", "pull_request", "base_sha",
            "head_sha", "tree_sha", "protection_sha256",
        }
        if set(identity) != required or any(
            _SHA.fullmatch(str(identity[name])) is None
            for name in {"base_sha", "head_sha", "tree_sha"}
        ) or _DIGEST.fullmatch(str(identity["protection_sha256"])) is None:
            raise RecoveryFrontierError("protected merge identity is not exact")
        if (
            not str(identity["repository"])
            or not str(identity["repository_id"]).isdigit()
            or int(str(identity["repository_id"])) < 1
            or not str(identity["pull_request"]).isdigit()
            or int(str(identity["pull_request"])) < 1
        ):
            raise RecoveryFrontierError("protected merge provider identity is invalid")
    if operation == "controller_transition":
        required = {"subject_commit", "subject_tree", "installed_controller", "target_controller"}
        if set(identity) != required or any(
            _SHA.fullmatch(str(identity[name])) is None for name in required
        ):
            raise RecoveryFrontierError("controller recovery identity is not exact")
        if state == "controller_current" and (
            identity["installed_controller"] != identity["target_controller"]
        ):
            raise RecoveryFrontierError("current controller identity disagrees")
        if state != "controller_current" and (
            identity["installed_controller"] == identity["target_controller"]
        ):
            raise RecoveryFrontierError("controller transition silently collapses target and installation")
    if alternate_lane is not None and state != "protected_policy_change":
        raise RecoveryFrontierError("alternate lane applies only to its exact transition class")
    if state == "protected_policy_change" and not alternate_lane:
        raise RecoveryFrontierError("protected policy change lacks its governed alternate lane")
    action, successor = edge
    body: dict[str, Any] = {
        "schema_version": "1.0",
        "kind": "ci_recovery_frontier",
        "operation": operation,
        "state": state,
        "identity": dict(identity),
        "transition_class": transition_class,
        "prerequisites": _strings(prerequisites, field="recovery prerequisites"),
        "action": {"kind": action, "owner": owner},
        "effects": {"preserve": preserved, "invalidate": invalidated},
        "successor": successor,
        "release_authority": False,
    }
    if alternate_lane is not None:
        body["alternate_lane"] = dict(alternate_lane)
    if idempotency_key is not None:
        if not idempotency_key or "\0" in idempotency_key or "\n" in idempotency_key:
            raise RecoveryFrontierError("recovery idempotency identity is invalid")
        body["idempotency_key"] = idempotency_key
    body["frontier_sha256"] = hashlib.sha256(_canonical(body)).hexdigest()
    return body


def provider_read_frontier(*, request_sha256: str, outcome: str) -> dict[str, Any]:
    """Derive the next action for one immutable provider GET observation."""

    return compile_recovery_frontier(
        operation="provider_read",
        state=outcome,
        identity={"request_sha256": request_sha256},
        owner="provider_read.open_provider_get",
        prerequisites=("same_method", "same_url", "bounded_attempt"),
        preserve=("request_identity",),
    )


def submission_frontier(
    *, identity: Mapping[str, Any], prospective_proved: bool
) -> dict[str, Any]:
    """Derive the complete local candidate submission action."""

    return compile_recovery_frontier(
        operation="candidate_submission",
        state="prospective_proved" if prospective_proved else "exact_candidate",
        identity=identity,
        owner="ci_authority_submit.submit_candidate",
        prerequisites=("clean_tree", "base_ancestor", "exact_lifecycle_intent"),
        preserve=("exact_candidate_identity",),
    )


def candidate_provider_frontier(
    *, identity: Mapping[str, Any], state: str
) -> dict[str, Any]:
    """Derive one action from the authenticated exact candidate provider state."""

    return compile_recovery_frontier(
        operation="candidate_provider",
        state=state,
        identity=identity,
        owner="candidate_provider_recovery.resolve_candidate_provider_recovery",
        prerequisites=(
            "exact_pr_subject",
            "protected_base_workflow",
            "exact_run_attempt_inventory",
            "closed_failure_classification",
        ),
        preserve=("exact_candidate_identity",),
        invalidate=("failed_attempt_non_authority",)
        if state == "retryable_terminal_transport" else (),
        idempotency_key=(
            f"{identity.get('repository')}:{identity.get('pull_request')}:"
            f"{identity.get('head_sha')}:{identity.get('run_id', 'pending')}:"
            f"{identity.get('run_attempt', 'pending')}"
        ),
    )


def protected_merge_frontier(
    *,
    identity: Mapping[str, Any],
    state: str,
    certification_identity: str,
) -> dict[str, Any]:
    """Derive the sole protected-merge action for one certified PR subject."""

    return compile_recovery_frontier(
        operation="protected_merge",
        state=state,
        identity=identity,
        owner="ci_github_pr_mutations.enable_pull_request_auto_merge",
        prerequisites=(
            "exact_pr_subject",
            "app_15368_certification",
            "clean_governed_protection",
            "normal_merge_commit",
        ),
        preserve=("authenticated_pr_evidence", certification_identity),
        invalidate=("base_bound_prospective_proof",) if state == "base_advanced" else (),
        idempotency_key=(
            f"{identity.get('repository')}:{identity.get('pull_request')}:"
            f"{identity.get('head_sha')}:{identity.get('base_sha')}"
        ),
    )


def controller_transition_frontier(value: Mapping[str, Any]) -> dict[str, Any]:
    """Project one validated routine decision into its sole governed operation."""

    decision = str(value.get("decision", ""))
    if decision == "no_transition":
        custody = value.get("controller_custody")
        if not isinstance(custody, Mapping):
            raise RecoveryFrontierError("no-transition custody is missing")
        controller = custody.get("controller")
        if not isinstance(controller, Mapping):
            raise RecoveryFrontierError("no-transition controller identity is missing")
        installed = target = str(controller.get("commit_sha", ""))
        state, transition = "controller_current", "none"
        lane = None
    elif decision == "routine_transition_authorized":
        transition_value = value.get("transition")
        if not isinstance(transition_value, Mapping):
            raise RecoveryFrontierError("routine transition identity is missing")
        authority = transition_value.get("authority")
        artifact = transition_value.get("artifact")
        if not isinstance(authority, Mapping) or not isinstance(artifact, Mapping):
            raise RecoveryFrontierError("routine transition authority is missing")
        installed = str(authority.get("installed_controller_commit", ""))
        target = str(artifact.get("commit_sha", ""))
        state, transition, lane = "pending_rotation", str(value.get("transition_class")), None
    elif decision == "alternate_lane_required":
        authority = value.get("authority")
        target_value = value.get("target")
        if not isinstance(authority, Mapping) or not isinstance(target_value, Mapping):
            raise RecoveryFrontierError("alternate controller authority is missing")
        installed = str(authority.get("installed_controller_commit", ""))
        target = str(target_value.get("BCF_BOOTSTRAP_COMMIT_SHA", ""))
        state, transition = "protected_policy_change", "protected_policy_change"
        lane_value = value.get("alternate_lane")
        lane = lane_value if isinstance(lane_value, Mapping) else None
    else:
        raise RecoveryFrontierError("routine decision has no recovery frontier")
    subject = (
        transition_value.get("subject")
        if decision == "routine_transition_authorized"
        else value.get("subject")
    )
    if not isinstance(subject, Mapping):
        raise RecoveryFrontierError("controller decision subject is missing")
    return compile_recovery_frontier(
        operation="controller_transition",
        state=state,
        identity={
            "subject_commit": subject.get("commit_sha"),
            "subject_tree": subject.get("tree_sha"),
            "installed_controller": installed,
            "target_controller": target,
        },
        owner="routine_controller_materialization.materialize_routine_decision",
        prerequisites=("exact_subject", "exact_artifact", "authenticated_provider_state"),
        preserve=("semantic_evidence",),
        transition_class=transition,
        alternate_lane=lane,
    )
