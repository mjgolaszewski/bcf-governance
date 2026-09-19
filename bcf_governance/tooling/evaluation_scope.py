"""Closed evaluation scope and certified-proposition semantics."""

from __future__ import annotations

from dataclasses import dataclass
from enum import StrEnum
import re
from typing import Any


class EvaluationScopeError(ValueError):
    """Raised when evaluation intent, target, or proposition is ambiguous."""


class EvaluationIntent(StrEnum):
    PR_PROGRESS = "pr"
    WORKITEM_CERTIFICATION = "workitem"
    PHASE_CLOSURE = "closure"


_TARGET = re.compile(r"^[A-Z][A-Z0-9]*(?:-[A-Z0-9]+)+$")


@dataclass(frozen=True)
class EvaluationScope:
    """One exact evaluation intent and its typed target."""

    intent: EvaluationIntent
    target_kind: str
    target_id: str

    def as_dict(self) -> dict[str, Any]:
        return {
            "intent": self.intent.value,
            "target": {"kind": self.target_kind, "id": self.target_id},
        }


def evaluation_scope(
    intent: str, *, target: str | None, phase_id: str, subject_commit: str
) -> EvaluationScope:
    """Decode a closed intent and bind its exact canonical target."""

    try:
        selected = EvaluationIntent(intent)
    except ValueError as exc:
        raise EvaluationScopeError("evaluation intent is unsupported") from exc
    if selected is EvaluationIntent.WORKITEM_CERTIFICATION:
        if not isinstance(target, str) or _TARGET.fullmatch(target) is None:
            raise EvaluationScopeError(
                "bounded workitem certification requires one exact target"
            )
        return EvaluationScope(selected, "workitem", target)
    if target is not None:
        raise EvaluationScopeError(
            "only bounded workitem certification accepts an explicit target"
        )
    if selected is EvaluationIntent.PHASE_CLOSURE:
        return EvaluationScope(selected, "phase", phase_id)
    return EvaluationScope(selected, "pull_request_progress", subject_commit)


def certified_proposition(
    scope: EvaluationScope,
    *,
    subject: dict[str, Any],
    status: str,
    workitems: dict[str, Any],
) -> dict[str, Any]:
    """Project the sole proposition implied by a truth evaluation."""

    conclusion = "success" if status == "pass" else "failure"
    authorizes: list[str] = []
    successors: list[str] = []
    predicate = {
        EvaluationIntent.PR_PROGRESS: "pull_request_progress_valid",
        EvaluationIntent.WORKITEM_CERTIFICATION: "workitem_closed",
        EvaluationIntent.PHASE_CLOSURE: "phase_closed",
    }[scope.intent]
    if scope.intent is EvaluationIntent.WORKITEM_CERTIFICATION:
        items = workitems.get("items") if isinstance(workitems, dict) else None
        reports = {
            str(item.get("id")): item
            for item in items or []
            if isinstance(item, dict)
        }
        target = reports.get(scope.target_id)
        if not isinstance(target, dict) or target.get("effective_state") != "closed":
            conclusion = "failure"
        else:
            successors = sorted(
                item_id
                for item_id, item in reports.items()
                if scope.target_id in item.get("predecessors", [])
                and item.get("eligible") is True
            )
            authorizes = ["declared_successor_workitem_eligibility"]
    return {
        "predicate": predicate,
        "target": {"kind": scope.target_kind, "id": scope.target_id},
        "subject": {
            "commit_sha": subject["commit_sha"],
            "tree_sha": subject["tree_sha"],
        },
        "conclusion": conclusion,
        "authorizes": authorizes,
        "eligible_successors": successors,
    }


def validate_certified_proposition(
    report: dict[str, Any], *, subject: dict[str, str]
) -> dict[str, Any]:
    """Decode a truth proposition without permitting scope erasure."""

    scope = report.get("evaluation_scope")
    proposition = report.get("certified_proposition")
    if not isinstance(scope, dict) or not isinstance(proposition, dict):
        raise EvaluationScopeError("truth report lacks typed evaluation scope")
    target = scope.get("target")
    if not isinstance(target, dict) or proposition.get("target") != target:
        raise EvaluationScopeError("truth proposition target does not match evaluation")
    if proposition.get("subject") != subject:
        raise EvaluationScopeError("truth proposition subject is not exact")
    intent = scope.get("intent")
    expected = {
        "pr": "pull_request_progress_valid",
        "workitem": "workitem_closed",
        "closure": "phase_closed",
    }.get(intent)
    if expected is None or proposition.get("predicate") != expected:
        raise EvaluationScopeError("truth proposition does not match evaluation intent")
    if proposition.get("conclusion") not in {"success", "failure"}:
        raise EvaluationScopeError("truth proposition conclusion is invalid")
    if (report.get("status") == "pass") != (
        proposition.get("conclusion") == "success"
    ):
        raise EvaluationScopeError("truth status and proposition conclusion disagree")
    authorizes = proposition.get("authorizes")
    successors = proposition.get("eligible_successors")
    if not isinstance(authorizes, list) or not isinstance(successors, list):
        raise EvaluationScopeError("truth proposition authority is invalid")
    if intent == "workitem":
        expected_authority = (
            ["declared_successor_workitem_eligibility"]
            if proposition.get("conclusion") == "success"
            else []
        )
        if authorizes != expected_authority or (
            proposition.get("conclusion") == "failure" and successors
        ):
            raise EvaluationScopeError("bounded proposition authority is not exact")
    elif authorizes or successors:
        raise EvaluationScopeError("non-bounded proposition carries bounded authority")
    return proposition


def is_terminal_phase_certification(certification: dict[str, Any]) -> bool:
    """Return whether certification conveys only successful terminal closure."""

    return (
        certification.get("evaluation_scope", {}).get("intent") == "closure"
        and certification.get("certified_proposition", {}).get("predicate") == "phase_closed"
        and certification.get("certified_proposition", {}).get("conclusion") == "success"
    )
