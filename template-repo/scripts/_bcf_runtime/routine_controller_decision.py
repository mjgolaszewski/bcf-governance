"""Closed semantic contract for routine controller decisions."""

from __future__ import annotations

from enum import StrEnum
import re
from typing import Any, Mapping

from .ci_github_authority import packaged_repo_root
from .ci_github_identity import GitHubControllerError, positive_int
from .ci_self_controller import validate_controller_pin
from .controller_custody import validate_controller_custody
from .routine_controller_rotation import (
    ALTERNATE_POLICY_LANE_SEQUENCE,
    GovernedControllerLane,
    validate_transition,
)


class RoutineDecision(StrEnum):
    NO_TRANSITION = "no_transition"
    ROUTINE_TRANSITION_AUTHORIZED = "routine_transition_authorized"
    ALTERNATE_LANE_REQUIRED = "alternate_lane_required"


class ControllerTransitionClass(StrEnum):
    NONE = "none"
    RUNTIME_ONLY = "runtime_only"
    PROTECTED_POLICY_CHANGE = "protected_policy_change"


def _exact_keys(value: Mapping[str, Any], expected: set[str], *, field: str) -> None:
    if set(value) != expected:
        raise GitHubControllerError(f"{field} inventory is not exact")


def _exact_sha(value: object, *, field: str) -> str:
    text = str(value)
    if re.fullmatch(r"[a-f0-9]{40}", text) is None:
        raise GitHubControllerError(f"{field} is not an exact Git identity")
    return text


def _exact_digest(value: object, *, field: str) -> str:
    text = str(value)
    if re.fullmatch(r"[a-f0-9]{64}", text) is None:
        raise GitHubControllerError(f"{field} is not an exact SHA-256 digest")
    return text


def validate_routine_decision(value: Mapping[str, Any]) -> dict[str, Any]:
    """Validate a closed routine-controller decision before transport."""

    common = {"schema_version", "decision", "transition_class", "applicable", "reason"}
    decision = str(value.get("decision", ""))
    if decision == RoutineDecision.ROUTINE_TRANSITION_AUTHORIZED.value:
        _exact_keys(value, common | {"transition"}, field="routine decision")
        transition_class = str(value.get("transition_class", ""))
        reasons = {
            ControllerTransitionClass.RUNTIME_ONLY.value: "pending_controller_rotation",
            ControllerTransitionClass.PROTECTED_POLICY_CHANGE.value: "pending_protected_policy_rotation",
        }
        if (value.get("schema_version") != "1.0" or transition_class not in reasons
                or value.get("applicable") is not True
                or value.get("reason") != reasons[transition_class]):
            raise GitHubControllerError("routine transition decision is invalid")
        result = dict(value)
        result["transition"] = validate_transition(packaged_repo_root(), value.get("transition"))
        authority = result["transition"]["authority"]
        derived = (ControllerTransitionClass.PROTECTED_POLICY_CHANGE.value
                   if authority["policy_before_sha256"] != authority["policy_after_sha256"]
                   else ControllerTransitionClass.RUNTIME_ONLY.value)
        if transition_class != derived:
            raise GitHubControllerError("routine transition class differs from exact policy custody")
        return result

    subject_admission = common | {"subject", "admission", "release_authority"}
    if decision == RoutineDecision.NO_TRANSITION.value:
        _exact_keys(value, subject_admission | {"controller_custody"}, field="routine decision")
        if (value.get("schema_version") != "1.0"
                or value.get("transition_class") != ControllerTransitionClass.NONE
                or value.get("applicable") is not False
                or value.get("reason") != "controller_current"):
            raise GitHubControllerError("no-transition decision is invalid")
    elif decision == RoutineDecision.ALTERNATE_LANE_REQUIRED.value:
        _exact_keys(value, subject_admission | {"authority", "target", "alternate_lane"}, field="routine decision")
        if (value.get("schema_version") != "1.0"
                or value.get("transition_class") != ControllerTransitionClass.PROTECTED_POLICY_CHANGE
                or value.get("applicable") is not False
                or value.get("reason") != "authorization_policy_changed"):
            raise GitHubControllerError("alternate-lane decision is invalid")
        authority = value.get("authority")
        if not isinstance(authority, Mapping):
            raise GitHubControllerError("alternate-lane authority is invalid")
        _exact_keys(authority, {"installed_controller_commit", "implementation_pr", "candidate_commit_sha", "source_main_commit_sha", "policy_before_sha256", "policy_after_sha256"}, field="alternate-lane authority")
        _exact_sha(authority["installed_controller_commit"], field="installed controller")
        positive_int(authority["implementation_pr"], field="implementation PR")
        _exact_sha(authority["candidate_commit_sha"], field="candidate commit")
        _exact_sha(authority["source_main_commit_sha"], field="source main commit")
        if _exact_digest(authority["policy_before_sha256"], field="prior policy") == _exact_digest(authority["policy_after_sha256"], field="candidate policy"):
            raise GitHubControllerError("alternate lane requires an exact policy change")
        validate_controller_pin(value.get("target"))
        lane = value.get("alternate_lane")
        if not isinstance(lane, Mapping):
            raise GitHubControllerError("alternate lane is invalid")
        _exact_keys(lane, {"id", "required_sequence", "required_initial_state", "required_terminal_state"}, field="alternate lane")
        if (lane.get("id") != GovernedControllerLane.ORDINARY_PROTECTED_N_N_PLUS_1
                or lane.get("required_sequence") != list(ALTERNATE_POLICY_LANE_SEQUENCE)
                or lane.get("required_initial_state") != "ordinary-pending-rotation"
                or lane.get("required_terminal_state") != "ordinary-current"):
            raise GitHubControllerError("alternate lane contract is invalid")
    else:
        raise GitHubControllerError("routine decision is unknown")
    subject, admission = value.get("subject"), value.get("admission")
    if not isinstance(subject, Mapping) or not isinstance(admission, Mapping):
        raise GitHubControllerError("routine decision identity is invalid")
    _exact_keys(subject, {"commit_sha", "tree_sha"}, field="decision subject")
    _exact_sha(subject["commit_sha"], field="decision commit")
    _exact_sha(subject["tree_sha"], field="decision tree")
    _exact_keys(admission, {"run_id", "run_attempt"}, field="decision admission")
    positive_int(admission["run_id"], field="admission run ID")
    positive_int(admission["run_attempt"], field="admission run attempt")
    if value.get("release_authority") is not False:
        raise GitHubControllerError("routine decision cannot grant release authority")
    result = dict(value)
    if decision == RoutineDecision.NO_TRANSITION.value:
        result["controller_custody"] = validate_controller_custody(value.get("controller_custody"))
    return result
