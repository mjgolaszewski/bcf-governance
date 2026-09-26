"""Provider-side policy projection for routine trusted-controller rotation."""

from __future__ import annotations

from typing import Any

from .ci_controller_policy import (
    TrustedControllerPolicyError,
    source_controller_policy,
)
from .ci_github_api import GitHubAPI
from .ci_github_authority import packaged_repo_root
from .ci_github_identity import GitHubControllerError, MainIdentity
from .ci_self_controller import (
    validate_controller_installation,
    validate_controller_pin,
)
from .routine_controller_rotation import controller_policy_digest


SELF_ROTATION_POLICY_PATHS = (
    "governance/github-protection.yml",
    "governance/self-governance-policy.yml",
    "governance/ci-extensions/bcf-trusted-control.yml",
    "schemas/controller-transition.schema.json",
)


def source_policy(
    api: GitHubAPI, repository: str, *, ref: str
) -> tuple[dict[str, Any], tuple[str, ...]]:
    try:
        payload, paths = source_controller_policy(
            lambda path: api.content(repository, path, ref=ref).content,
            schema_root=packaged_repo_root(),
        )
    except TrustedControllerPolicyError as exc:
        raise GitHubControllerError(str(exc)) from exc
    return payload, paths or SELF_ROTATION_POLICY_PATHS


def policy_digest(api: GitHubAPI, repository: str, *, ref: str) -> str:
    _, paths = source_policy(api, repository, ref=ref)
    return controller_policy_digest(
        lambda path: api.content(repository, path, ref=ref).content,
        policy_paths=paths,
    )


def runner_policy(
    api: GitHubAPI, repository: str, *, main: MainIdentity
) -> tuple[dict[str, str], dict[str, str], tuple[str, ...]]:
    payload, _ = source_policy(api, repository, ref=main.checkout_sha)
    try:
        runner = payload["runner_security"]
        pin = validate_controller_pin(runner["trusted_controller_artifact"])
        installation = validate_controller_installation(
            runner["trusted_controller_installation"]
        )
        labels = tuple(str(value) for value in runner["trusted_instance_labels"])
    except (KeyError, TypeError) as exc:
        raise GitHubControllerError(
            "routine controller source policy is invalid"
        ) from exc
    if len(labels) < 2 or labels != tuple(sorted(set(labels))):
        raise GitHubControllerError(
            "routine controller runner inventory is not canonical"
        )
    if pin["BCF_BOOTSTRAP_COMMIT_SHA"] != installation["installed_commit_sha"]:
        raise GitHubControllerError(
            "routine controller authority requires ordinary-current source custody"
        )
    if pin["BCF_BOOTSTRAP_REPOSITORY_ID"] != main.repository_id:
        raise GitHubControllerError(
            "routine controller source policy belongs to another repository"
        )
    return pin, installation, labels
