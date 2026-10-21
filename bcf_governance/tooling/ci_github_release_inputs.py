"""Mechanically resolve the provider inputs for one release authorization.

Copyright 2026 Michael Golaszewski.
Licensed under the MIT License.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import yaml

from .semantic_yaml import SemanticYAMLError, load_unique_yaml_text
from .governance_validation.common import GovernanceValidationError
from .governance_validation.supplemental_releases import declared_release_train_terminal

from .ci_authority_contracts import authority_role_workflow
from .ci_github_api import GitHubAPI
from .ci_github_artifacts import (
    ProviderArtifact,
    provider_artifact_reference,
    provider_artifact_reference_keys,
    resolve_role_artifact,
)
from .ci_github_authority import authenticate_role_job_inventory, load_authority
from .ci_github_bundle import write_exclusive
from .ci_github_identity import (
    GitHubControllerError,
    MainIdentity,
    positive_int,
    resolve_main,
)
from .ci_github_membership import select_latest_admission
from .ci_self_controller import resolve_self_controller_artifact
from .controller_custody import compile_controller_custody, require_controller_execution
from .routine_controller_provider import resolve_effective_controller
from .release_versions import ReleaseVersion, ReleaseVersionError, parse_release_version


RELEASE_INPUT_KEYS = {
    "schema_version",
    "authority_contract_version",
    "subject",
    "exact_main",
    "certification_artifact",
    "controller",
}
PUBLIC_CONTRACTS_PATH = "governance/public-contracts.yml"


def _release_version_at_main(
    api: GitHubAPI, *, repository: str, main: MainIdentity
) -> ReleaseVersion:
    """Read release identity from authenticated current-main contract bytes."""

    content = api.content(repository, PUBLIC_CONTRACTS_PATH, ref=main.checkout_sha)
    if content.path != PUBLIC_CONTRACTS_PATH:
        raise GitHubControllerError("release contract path is not exact")
    try:
        value = load_unique_yaml_text(content.content.decode("utf-8"))
        document = value["document"]
        package = value["package"]
        version = package["version"]
    except (KeyError, TypeError, UnicodeDecodeError, yaml.YAMLError, SemanticYAMLError) as exc:
        raise GitHubControllerError("current-main release contract is invalid") from exc
    if (
        not isinstance(document, dict)
        or document.get("path") != PUBLIC_CONTRACTS_PATH
        or not isinstance(version, str)
    ):
        raise GitHubControllerError("current-main release contract identity is invalid")
    try:
        return parse_release_version(version)
    except ReleaseVersionError as exc:
        raise GitHubControllerError("current-main release version is not releasable") from exc


def require_terminal_release_phase_at_main(
    api: GitHubAPI, *, repository: str, main: MainIdentity,
) -> str:
    """Reject intermediate phase release work using exact-main declarations.

    This is a necessary declaration gate, not independent predecessor truth.
    The authorizer still authenticates the exact terminal phase certification.
    """
    version = _release_version_at_main(api, repository=repository, main=main)
    documents: dict[str, dict[str, Any]] = {}
    paths = {
        "product": "plans/product-spec.yml",
        "build": "plans/build-plan.yml",
        "ledger": "plans/phase-ledger.yml",
        "history": "plans/phase-history.yml",
    }
    for name, path in paths.items():
        content = api.content(repository, path, ref=main.checkout_sha)
        if content.path != path:
            raise GitHubControllerError("release train source path is not exact")
        try:
            value = load_unique_yaml_text(content.content.decode("utf-8"))
        except (UnicodeDecodeError, yaml.YAMLError, SemanticYAMLError) as exc:
            raise GitHubControllerError("release train source is invalid") from exc
        if (
            not isinstance(value, dict)
            or not isinstance(value.get("document"), dict)
            or value["document"].get("path") != path
        ):
            raise GitHubControllerError("release train source identity is invalid")
        documents[name] = value
    try:
        terminal = declared_release_train_terminal(
            product=documents["product"], build=documents["build"],
            ledger=documents["ledger"], history=documents["history"],
            version=version.value,
        )
    except GovernanceValidationError as exc:
        raise GitHubControllerError(f"release train declaration is invalid: {exc}") from exc
    active = documents["ledger"]["active_phase"]
    if active["id"] != terminal:
        raise GitHubControllerError(f"release train requires terminal phase {terminal}")
    if active.get("lifecycle_status") != "completed":
        raise GitHubControllerError("release train terminal phase is not authored complete")
    release = next(
        row["release_train"] for row in documents["product"]["execution_phases"]
        if row["phase_id"] == terminal
    )
    if documents["ledger"]["release_trains"][release].get("status") not in {"active", "completed"}:
        raise GitHubControllerError("release train is not active or completed")
    return terminal


def _exact_role_run(
    api: GitHubAPI, *, repository: str, main: MainIdentity,
    authority: dict[str, Any], role: str, event: str,
) -> tuple[str, int]:
    """Select the latest exact-context role attempt without success fallback."""

    workflow = authority_role_workflow(authority, role)
    if event not in workflow["allowed_events"]:
        raise GitHubControllerError(f"{role} event is not admitted by authority")
    runs = api.workflow_runs(
        repository, workflow["workflow_id"], head_sha=main.checkout_sha, event=event,
    )
    exact = [
        run for run in runs
        if str(run.get("head_sha")) == main.checkout_sha
        and str(run.get("head_branch")) == main.default_branch
        and str(run.get("repository", {}).get("id")) == main.repository_id
        and str(run.get("head_repository", {}).get("id")) == main.repository_id
        and str(run.get("event")) == event
    ]
    if not exact:
        raise GitHubControllerError(f"no exact-main {role.replace('_', ' ')} run exists")
    coordinates = [
        (positive_int(run.get("id"), field="role run ID"),
         positive_int(run.get("run_attempt"), field="role run attempt"))
        for run in exact
    ]
    if len(coordinates) != len(set(coordinates)):
        raise GitHubControllerError("exact role run inventory is ambiguous")
    selected = exact[max(range(len(exact)), key=lambda index: coordinates[index])]
    identity, _ = authenticate_role_job_inventory(
        api, repository=repository, main=main, authority=authority, role=role,
        run_id=selected.get("id"), run_attempt=selected.get("run_attempt"),
        require_success=True, require_terminal=True,
    )
    if (identity.run_id, identity.run_attempt) != (
        str(selected["id"]), int(selected["run_attempt"]),
    ):
        raise GitHubControllerError("selected role run changed during authentication")
    observed = api.run(repository, identity.run_id)
    if identity.workflow.event != event or any(
        observed.get(key) != selected.get(key) for key in (
            "id", "run_attempt", "workflow_id", "head_sha", "head_branch", "event",
            "repository", "head_repository", "status", "conclusion",
        )
    ):
        raise GitHubControllerError("selected role run metadata changed during authentication")
    return identity.run_id, identity.run_attempt


def _exact_finalizer_run(
    api: GitHubAPI, *, repository: str, main: MainIdentity, authority: dict[str, Any],
) -> tuple[str, int]:
    return _exact_role_run(
        api, repository=repository, main=main, authority=authority,
        role="finalizer", event="workflow_run",
    )


def _exact_collector_run(
    api: GitHubAPI, *, repository: str, main: MainIdentity, authority: dict[str, Any],
) -> tuple[str, int]:
    return _exact_role_run(
        api, repository=repository, main=main, authority=authority,
        role="release_collector", event="workflow_run",
    )


def resolve_release_authorization_inputs(
    api: GitHubAPI,
    *,
    repository: str,
    output_path: Path,
) -> dict[str, Any]:
    """Resolve release inputs without caller-selected provider identities."""

    main = resolve_main(api, repository)
    require_terminal_release_phase_at_main(api, repository=repository, main=main)
    require_controller_execution(
        compile_controller_custody(
            resolve_effective_controller(api, repository=repository),
            repository=repository,
        )
    )
    authority = load_authority(api, repository, main, required_version="1.1")
    admission_run_id, admission_attempt = select_latest_admission(
        api, repository=repository, main=main, authority=authority
    )
    controller_subject, controller_artifact = resolve_self_controller_artifact(
        api, repository=repository
    )
    if controller_subject != {
        "repository_id": main.repository_id,
        "commit_sha": main.checkout_sha,
        "tree_sha": main.tree_sha,
    } or (
        controller_artifact.run_id != admission_run_id
        or controller_artifact.run_attempt != admission_attempt
    ):
        raise GitHubControllerError("release controller is not from the newest exact main")
    finalizer_run_id, finalizer_attempt = _exact_finalizer_run(
        api, repository=repository, main=main, authority=authority
    )
    certification = resolve_role_artifact(
        api,
        repository=repository,
        main=main,
        authority=authority,
        role="finalizer",
        run_id=finalizer_run_id,
        run_attempt=finalizer_attempt,
        artifact_name=(
            f"bcf-exact-main-certification-{finalizer_run_id}-{finalizer_attempt}"
        ),
        require_success=True,
    )
    payload = {
        "schema_version": "1.0",
        "authority_contract_version": "1.1",
        "subject": {
            "commit_sha": main.checkout_sha,
            "tree_sha": main.tree_sha,
        },
        "exact_main": {
            "run_id": admission_run_id,
            "run_attempt": admission_attempt,
        },
        "certification_artifact": provider_artifact_reference(certification),
        "controller": {
            **provider_artifact_reference(controller_artifact),
            "commit_sha": main.checkout_sha,
            "tree_sha": main.tree_sha,
        },
    }
    if resolve_main(api, repository) != main:
        raise GitHubControllerError("release source moved during input resolution")
    write_exclusive(output_path, payload)
    return payload


def load_release_authorization_inputs(path: Path) -> dict[str, Any]:
    """Decode only the exact resolver-owned release-input representation."""

    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeError, ValueError) as exc:
        raise GitHubControllerError("release authorization inputs are invalid") from exc
    if not isinstance(value, dict) or set(value) != RELEASE_INPUT_KEYS:
        raise GitHubControllerError("release authorization input inventory is not exact")
    if value.get("schema_version") != "1.0" or (
        value.get("authority_contract_version") != "1.1"
    ):
        raise GitHubControllerError("release authorization input version is unsupported")
    subject = value.get("subject")
    exact_main = value.get("exact_main")
    certification = value.get("certification_artifact")
    controller = value.get("controller")
    if not all(isinstance(item, dict) for item in (
        subject, exact_main, certification, controller
    )):
        raise GitHubControllerError("release authorization input sections are invalid")
    provider_artifact_reference(certification, label="certification artifact")
    controller_keys = provider_artifact_reference_keys() | {"commit_sha", "tree_sha"}
    if set(controller) != controller_keys:
        raise GitHubControllerError("controller artifact identity is not exact")
    provider_artifact_reference(
        {key: controller[key] for key in provider_artifact_reference_keys()},
        label="controller artifact",
    )
    return value


def release_input_outputs(value: dict[str, Any]) -> dict[str, object]:
    """Project the minimal scalar download coordinates for workflow wiring."""

    certification = value["certification_artifact"]
    controller = value["controller"]
    return {
        "subject_commit": value["subject"]["commit_sha"],
        "subject_tree": value["subject"]["tree_sha"],
        "certification_artifact_id": certification["artifact_id"],
        "certification_run_id": certification["run_id"],
        "controller_artifact_id": controller["artifact_id"],
        "controller_run_id": controller["run_id"],
    }


def resolve_release_publication_inputs(
    api: GitHubAPI,
    *,
    repository: str,
    trigger_run_id: object,
    trigger_run_attempt: object,
    output_path: Path,
) -> dict[str, Any]:
    """Resolve the newest exact-main release receipt without operator coordinates."""

    main = resolve_main(api, repository)
    require_controller_execution(
        compile_controller_custody(
            resolve_effective_controller(api, repository=repository),
            repository=repository,
        )
    )
    release_version = _release_version_at_main(
        api, repository=repository, main=main
    )
    authority = load_authority(api, repository, main, required_version="1.1")
    collector_run_id, collector_attempt = _exact_collector_run(
        api, repository=repository, main=main, authority=authority
    )
    if (
        str(positive_int(trigger_run_id, field="release publication trigger run ID"))
        != collector_run_id
        or positive_int(
            trigger_run_attempt, field="release publication trigger attempt"
        )
        != collector_attempt
    ):
        raise GitHubControllerError(
            "release publication trigger is not the exact collector run"
        )
    receipt = resolve_role_artifact(
        api,
        repository=repository,
        main=main,
        authority=authority,
        role="release_collector",
        run_id=collector_run_id,
        run_attempt=collector_attempt,
        artifact_name=(
            f"bcf-release-receipt-{collector_run_id}-{collector_attempt}"
        ),
        require_success=True,
    )
    payload = {
        "schema_version": "1.0",
        "authority_contract_version": "1.1",
        "subject": {
            "commit_sha": main.checkout_sha,
            "tree_sha": main.tree_sha,
        },
        "tag": release_version.tag,
        "receipt_artifact": provider_artifact_reference(receipt),
    }
    write_exclusive(output_path, payload)
    return payload


def release_publication_outputs(value: dict[str, Any]) -> dict[str, object]:
    """Project closed scalar coordinates for trusted workflow wiring."""

    receipt = value["receipt_artifact"]
    return {
        "subject_commit": value["subject"]["commit_sha"],
        "subject_tree": value["subject"]["tree_sha"],
        "tag": value["tag"],
        "receipt_artifact_id": receipt["artifact_id"],
        "receipt_artifact_name": receipt["artifact_name"],
        "receipt_provider_digest": receipt["provider_digest"],
        "receipt_run_id": receipt["run_id"],
        "receipt_run_attempt": receipt["run_attempt"],
    }
