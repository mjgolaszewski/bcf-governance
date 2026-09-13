"""Closed candidate runner selection compiled before GitHub allocates a job."""

from __future__ import annotations

import copy
import json
import re
from typing import Any

from .ci_graph_errors import CIGraphError


HOSTED_RUNNERS = frozenset({"ubuntu-24.04", "ubuntu-latest"})
LOCAL_CASES = (
    "same_repository_pull_request",
    "protected_push",
    "protected_schedule",
    "protected_dispatch",
)
_PLATFORM_LABELS = frozenset({"self-hosted", "linux", "windows", "macos", "x64", "arm", "arm64"})
_MATRIX_LABEL = re.compile(r"\$\{\{ matrix\.([A-Za-z0-9][A-Za-z0-9._-]*) \}\}")
_LITERAL_LABEL = re.compile(r"[A-Za-z0-9][A-Za-z0-9._-]*")


def _trusted_labels(graph: dict[str, Any]) -> set[str]:
    """Conservatively include every declared trusted selector's possible label."""
    result: set[str] = set()
    for resource_id, resource in graph["resource_classes"].items():
        if resource["trust"] != "trusted":
            continue
        labels = resource["runner"]
        for label in labels if isinstance(labels, list) else [labels]:
            axis = _MATRIX_LABEL.fullmatch(label)
            if axis is None:
                result.add(label.lower())
                continue
            jobs = [job for workflow in graph["workflows"] for job in workflow["jobs"]
                    if job["resource_class"] == resource_id]
            if not jobs:
                raise CIGraphError("candidate routing cannot resolve an unused trusted matrix selector")
            for job in jobs:
                matrix = job.get("strategy", {}).get("matrix", job.get("matrix", {}))
                values = matrix.get(axis[1], [])
                includes = matrix.get("include", [])
                if not isinstance(values, list) or not isinstance(includes, list) or any(
                    not isinstance(row, dict) for row in includes
                ):
                    raise CIGraphError("candidate routing requires a resolved trusted selector matrix")
                values = [*values, *(row[axis[1]] for row in includes if axis[1] in row)]
                if not values or any(not isinstance(value, str) or not _LITERAL_LABEL.fullmatch(value)
                                     for value in values):
                    raise CIGraphError("candidate routing requires literal, resolved trusted matrix labels")
                result.update(value.lower() for value in values)
    return result


def validate_candidate_routing(
    graph: dict[str, Any], *, storage_contract: dict[str, Any] | None = None
) -> None:
    """Reject routing declarations that could bypass candidate resource custody."""
    routed = [(key, value) for key, value in graph["resource_classes"].items() if "routing" in value]
    if not routed:
        return
    trusted = _trusted_labels(graph)
    identities = {resource["routing"]["repository_id"] for _, resource in routed}
    if len(identities) != 1:
        raise CIGraphError("candidate routing policies must bind one repository identity")
    if storage_contract is not None and identities != {str(storage_contract["provider"]["repository_id"])}:
        raise CIGraphError("candidate routing repository identity differs from evidence storage")
    for resource_id, resource in routed:
        policy = resource["routing"]
        if resource["trust"] != "candidate" or resource["hosted"] is not True:
            raise CIGraphError(f"routed resource {resource_id} must remain candidate and potentially hosted")
        if not isinstance(resource["runner"], str) or resource["runner"] not in HOSTED_RUNNERS:
            raise CIGraphError(f"routed resource {resource_id} requires a supported literal hosted fallback")
        labels = {label.lower() for label in policy["local_runner"]}
        if "self-hosted" not in labels or not (labels - _PLATFORM_LABELS - trusted):
            raise CIGraphError(f"routed resource {resource_id} lacks a dedicated local candidate label")
        if len(labels) != len(policy["local_runner"]):
            raise CIGraphError(f"routed resource {resource_id} duplicates case-insensitive local labels")
        if labels & HOSTED_RUNNERS:
            raise CIGraphError(f"routed resource {resource_id} mixes hosted and local runner labels")
        if any(case != "same_repository_pull_request" for case in policy["local_cases"]) and not policy["allowed_refs"]:
            raise CIGraphError(f"routed resource {resource_id} requires explicit protected branch refs")
        if any(ref.endswith(("/", ".")) or ".." in ref or "//" in ref
               or any(part.startswith(".") or part.endswith(".lock") for part in ref.split("/"))
               for ref in policy["allowed_refs"]):
            raise CIGraphError(f"routed resource {resource_id} has an invalid literal branch ref")


def _literal(value: str) -> str:
    return "'" + value.replace("'", "''") + "'"


def _eligibility(policy: dict[str, Any]) -> str:
    """Use only native GitHub context; reusable callers cannot supply trust flags."""
    identity = policy["repository_id"]
    common = (
        f"github.repository_id == {_literal(identity)} && "
        f"github.event.repository.id == {identity} && "
        "github.event.repository.private == true"
    )
    branches = " || ".join(f"github.ref == {_literal(ref)}" for ref in sorted(policy["allowed_refs"]))
    protected = f"github.ref_type == 'branch' && github.ref_protected == true && ({branches})"
    cases = {
        "same_repository_pull_request": (
            "github.event_name == 'pull_request' && "
            f"github.event.pull_request.head.repo.id == {identity} && "
            f"github.event.pull_request.base.repo.id == {identity}"
        ),
        "protected_push": f"github.event_name == 'push' && {protected}",
        "protected_schedule": f"github.event_name == 'schedule' && {protected}",
        "protected_dispatch": f"github.event_name == 'workflow_dispatch' && {protected}",
    }
    selected = " || ".join(f"({cases[case]})" for case in LOCAL_CASES if case in policy["local_cases"])
    return f"{common} && ({selected})"


def render_runner(resource: dict[str, Any]) -> str | list[str]:
    """Preserve literal/matrix legacy runners or emit one closed selection."""
    if "routing" not in resource:
        return copy.deepcopy(resource["runner"])
    policy = resource["routing"]
    local = json.dumps(policy["local_runner"], separators=(",", ":"))
    hosted = json.dumps([resource["runner"]], separators=(",", ":"))
    return "${{ fromJSON((" + _eligibility(policy) + ") && " + _literal(local) + " || " + _literal(hosted) + ") }}"


def routing_audit(resource: dict[str, Any]) -> dict[str, Any]:
    """Expose both allocation alternatives without claiming observed admission."""
    if "routing" not in resource:
        return {}
    policy = resource["routing"]
    return {"runner_routing": {
        **copy.deepcopy(policy), "hosted_fallback": resource["runner"],
        "local_eligibility": _eligibility(policy), "runs_on": render_runner(resource),
        "unmatched_context": "hosted", "hosted_restrictions_apply": True,
        "trust_boundary": "Reviewed generated workflow and provider-maintained dedicated candidate labels; no protection against arbitrary workflow replacement or provider mislabeling.",
    }}


def runner_remediation(resource: dict[str, Any]) -> str:
    """Describe allocation prerequisites while retaining the legacy diagnostic."""
    if "routing" not in resource:
        return f"confirm provider runner mapping {resource['runner']!r} before dispatch"
    policy = resource["routing"]
    return (f"confirm hosted fallback {resource['runner']!r} and dedicated local candidate mapping "
            f"{policy['local_runner']!r}; local eligibility: {_eligibility(policy)}; "
            "all other contexts use hosted execution; verify reviewed workflow and provider label custody before allocation")
