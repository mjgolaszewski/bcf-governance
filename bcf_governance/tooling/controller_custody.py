"""Closed transport contract for one provider-authenticated controller identity."""

from __future__ import annotations

from collections.abc import Mapping
import os
from pathlib import Path
import re
import sys
from typing import Any

from .ci_github_identity import GitHubControllerError, exact_sha
from .ci_self_controller import validate_controller_pin


CUSTODY_KEYS = {
    "schema_version",
    "kind",
    "repository",
    "subject",
    "source",
    "transition_ids",
    "controller",
}
CONTROLLER_KEYS = {
    "commit_sha",
    "tree_sha",
    "wheel_sha256",
    "artifact_id",
    "artifact_name",
    "provider_digest",
    "run_id",
    "run_attempt",
}


def compile_controller_custody(
    resolved: Mapping[str, Any], *, repository: str
) -> dict[str, Any]:
    """Project the effective-controller resolver result without losing custody."""

    try:
        pin = validate_controller_pin(resolved["pin"])
        subject = dict(resolved["subject"])
        transition_ids = list(resolved["transition_ids"])
        source = str(resolved["source"])
    except (KeyError, TypeError, ValueError) as exc:
        raise GitHubControllerError(
            "effective controller result cannot produce exact custody"
        ) from exc
    return validate_controller_custody(
        {
            "schema_version": "1.0",
            "kind": "controller_custody",
            "repository": {
                "full_name": repository,
                "repository_id": pin["BCF_BOOTSTRAP_REPOSITORY_ID"],
            },
            "subject": subject,
            "source": source,
            "transition_ids": transition_ids,
            "controller": {
                "commit_sha": pin["BCF_BOOTSTRAP_COMMIT_SHA"],
                "tree_sha": pin["BCF_BOOTSTRAP_TREE_SHA"],
                "wheel_sha256": pin["BCF_BOOTSTRAP_WHEEL_SHA256"],
                "artifact_id": pin["BCF_BOOTSTRAP_ARTIFACT_ID"],
                "artifact_name": pin["BCF_BOOTSTRAP_ARTIFACT_NAME"],
                "provider_digest": pin["BCF_BOOTSTRAP_ARTIFACT_DIGEST"],
                "run_id": pin["BCF_BOOTSTRAP_RUN_ID"],
                "run_attempt": pin["BCF_BOOTSTRAP_RUN_ATTEMPT"],
            },
        }
    )


def validate_controller_custody(value: Any) -> dict[str, Any]:
    """Decode only the exact additive custody contract understood by consumers."""

    if not isinstance(value, Mapping) or set(value) != CUSTODY_KEYS:
        raise GitHubControllerError("controller custody inventory is not exact")
    if value.get("schema_version") != "1.0" or value.get("kind") != "controller_custody":
        raise GitHubControllerError("controller custody version or kind is unsupported")
    repository = value.get("repository")
    subject = value.get("subject")
    controller = value.get("controller")
    transitions = value.get("transition_ids")
    if (
        not isinstance(repository, Mapping)
        or set(repository) != {"full_name", "repository_id"}
        or not isinstance(subject, Mapping)
        or set(subject) != {"commit_sha", "tree_sha"}
        or not isinstance(controller, Mapping)
        or set(controller) != CONTROLLER_KEYS
        or not isinstance(transitions, list)
        or any(re.fullmatch(r"[a-f0-9]{64}", item) is None for item in transitions)
        or len(set(transitions)) != len(transitions)
    ):
        raise GitHubControllerError("controller custody sections are not exact")
    pin = validate_controller_pin(
        {
            "BCF_BOOTSTRAP_ARTIFACT_ID": controller["artifact_id"],
            "BCF_BOOTSTRAP_ARTIFACT_NAME": controller["artifact_name"],
            "BCF_BOOTSTRAP_ARTIFACT_DIGEST": controller["provider_digest"],
            "BCF_BOOTSTRAP_RUN_ID": controller["run_id"],
            "BCF_BOOTSTRAP_RUN_ATTEMPT": controller["run_attempt"],
            "BCF_BOOTSTRAP_COMMIT_SHA": controller["commit_sha"],
            "BCF_BOOTSTRAP_TREE_SHA": controller["tree_sha"],
            "BCF_BOOTSTRAP_REPOSITORY_ID": repository["repository_id"],
            "BCF_BOOTSTRAP_WHEEL_SHA256": controller["wheel_sha256"],
        }
    )
    if re.fullmatch(
        r"[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+", str(repository["full_name"])
    ) is None:
        raise GitHubControllerError("controller custody repository is malformed")
    if subject.get("commit_sha") is None or subject.get("tree_sha") is None:
        raise GitHubControllerError("controller custody subject is incomplete")
    normalized = {
        "schema_version": "1.0",
        "kind": "controller_custody",
        "repository": {
            "full_name": str(repository["full_name"]),
            "repository_id": pin["BCF_BOOTSTRAP_REPOSITORY_ID"],
        },
        "subject": {
            "commit_sha": exact_sha(subject["commit_sha"], field="custody subject commit"),
            "tree_sha": exact_sha(subject["tree_sha"], field="custody subject tree"),
        },
        "source": str(value["source"]),
        "transition_ids": list(transitions),
        "controller": {
            "commit_sha": pin["BCF_BOOTSTRAP_COMMIT_SHA"],
            "tree_sha": pin["BCF_BOOTSTRAP_TREE_SHA"],
            "wheel_sha256": pin["BCF_BOOTSTRAP_WHEEL_SHA256"],
            "artifact_id": pin["BCF_BOOTSTRAP_ARTIFACT_ID"],
            "artifact_name": pin["BCF_BOOTSTRAP_ARTIFACT_NAME"],
            "provider_digest": pin["BCF_BOOTSTRAP_ARTIFACT_DIGEST"],
            "run_id": pin["BCF_BOOTSTRAP_RUN_ID"],
            "run_attempt": pin["BCF_BOOTSTRAP_RUN_ATTEMPT"],
        },
    }
    if normalized["source"] not in {"source_policy", "provider_transition"}:
        raise GitHubControllerError("controller custody source is unsupported")
    return normalized


def authority_identity(custody: Mapping[str, Any]) -> dict[str, str]:
    """Project the legacy two-field assurance identity from exact custody."""

    value = validate_controller_custody(custody)["controller"]
    return {
        "controller_commit_sha": value["commit_sha"],
        "controller_bundle_sha256": value["wheel_sha256"],
    }


def require_controller_execution(custody: Mapping[str, Any]) -> None:
    """Bind a privileged consumer to the exact installed target it selected."""

    if os.environ.get("BCF_CONTROLLER_EXECUTION_REQUIRED") != "true":
        return
    expected = validate_controller_custody(custody)["controller"]["commit_sha"]
    observed = Path(sys.prefix).resolve().name
    if observed != expected:
        raise GitHubControllerError(
            "executing controller does not match authenticated custody"
        )
