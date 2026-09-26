"""Canonical policy owner for repositories that install trusted controllers."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any, Callable, Mapping

from jsonschema import Draft202012Validator
import yaml

from .ci_graph_yaml import GraphYAMLError, load_yaml_path


POLICY_PATH = "governance/trusted-controller-policy.yml"
POLICY_SCHEMA = "schemas/trusted-controller-policy.schema.json"
ROTATION_EXTENSION = "governance/ci-extensions/bcf-controller-rotation.yml"
REQUIRED_ROTATION_POLICY_PATHS = {
    POLICY_PATH,
    "governance/ci-graph.yml",
    "governance/github-protection.yml",
    ROTATION_EXTENSION,
    "schemas/controller-transition.schema.json",
}


class TrustedControllerPolicyError(ValueError):
    """Raised when installed controller custody is absent or ambiguous."""


def graph_controller_policy_path(graph: Mapping[str, Any]) -> str | None:
    """Return the declared custody owner, or None for executable-only adopters."""

    contract = graph.get("trusted_controller")
    if not isinstance(contract, Mapping):
        raise TrustedControllerPolicyError("CI graph trusted controller is invalid")
    kind = contract.get("kind")
    if kind == "executable":
        return None
    path = contract.get("policy_path")
    if kind == "self_governance_policy" and path == "governance/self-governance-policy.yml":
        return str(path)
    if kind == "governed_controller_policy" and path == POLICY_PATH:
        return str(path)
    raise TrustedControllerPolicyError("CI graph controller policy owner is invalid")


def validate_installed_controller_policy(
    repo_root: Path, payload: object
) -> dict[str, Any]:
    """Validate the closed adopter policy and its mandatory rotation inputs."""

    if not isinstance(payload, dict):
        raise TrustedControllerPolicyError("trusted controller policy must be one object")
    try:
        schema = json.loads((repo_root / POLICY_SCHEMA).read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise TrustedControllerPolicyError(
            "trusted controller policy schema is unavailable"
        ) from exc
    errors = sorted(
        Draft202012Validator(schema).iter_errors(payload),
        key=lambda item: list(item.absolute_path),
    )
    if errors:
        location = ".".join(str(item) for item in errors[0].absolute_path) or "<root>"
        raise TrustedControllerPolicyError(
            f"trusted controller policy violation at {location}: {errors[0].message}"
        )
    declared_paths = payload["rotation_policy_paths"]
    if declared_paths != sorted(declared_paths):
        raise TrustedControllerPolicyError(
            "trusted controller rotation policy paths are not canonical"
        )
    paths = set(declared_paths)
    missing = sorted(REQUIRED_ROTATION_POLICY_PATHS - paths)
    if missing:
        raise TrustedControllerPolicyError(
            "trusted controller rotation policy inventory is incomplete: "
            + ", ".join(missing)
        )
    runners = payload["runner_security"]
    if (
        runners["trusted_controller_artifact"]["BCF_BOOTSTRAP_COMMIT_SHA"]
        != runners["trusted_controller_installation"]["installed_commit_sha"]
    ):
        raise TrustedControllerPolicyError(
            "trusted controller target and installed identity must begin ordinary-current"
        )
    if runners["trusted_labels"] != sorted(set(runners["trusted_labels"])):
        raise TrustedControllerPolicyError("trusted controller labels are not canonical")
    if runners["trusted_instance_labels"] != sorted(
        set(runners["trusted_instance_labels"])
    ):
        raise TrustedControllerPolicyError(
            "trusted controller runner inventory is not canonical"
        )
    return payload


def load_installed_controller_policy(repo_root: Path) -> dict[str, Any]:
    try:
        payload = load_yaml_path(repo_root / POLICY_PATH)
    except GraphYAMLError as exc:
        raise TrustedControllerPolicyError(str(exc)) from exc
    return validate_installed_controller_policy(repo_root, payload)


def load_graph_controller_policy(
    repo_root: Path, graph: Mapping[str, Any]
) -> tuple[dict[str, Any], str]:
    """Load the controller policy owned by a validated graph declaration."""

    relative = graph_controller_policy_path(graph)
    if relative is None:
        raise TrustedControllerPolicyError("governed controller policy is unavailable")
    try:
        payload = load_yaml_path(repo_root / relative)
    except GraphYAMLError as exc:
        raise TrustedControllerPolicyError(str(exc)) from exc
    if relative == POLICY_PATH:
        payload = validate_installed_controller_policy(repo_root, payload)
    return payload, relative


def source_controller_policy(
    fetch: Callable[[str], bytes], *, schema_root: Path
) -> tuple[dict[str, Any], tuple[str, ...]]:
    """Resolve provider-fetched controller custody through its graph owner."""

    try:
        graph = yaml.safe_load(fetch("governance/ci-graph.yml"))
        policy_path = graph_controller_policy_path(graph)
        if policy_path is None:
            raise TrustedControllerPolicyError(
                "routine controller management is not installed"
            )
        payload = yaml.safe_load(fetch(policy_path))
    except (AttributeError, TypeError, UnicodeDecodeError, yaml.YAMLError) as exc:
        raise TrustedControllerPolicyError(
            "routine controller source policy is invalid"
        ) from exc
    if policy_path == "governance/self-governance-policy.yml":
        return payload, ()
    validated = validate_installed_controller_policy(schema_root, payload)
    return validated, tuple(validated["rotation_policy_paths"])
