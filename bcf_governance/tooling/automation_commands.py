"""Transactional operator commands for trusted automation adoption."""

from __future__ import annotations

import copy
from dataclasses import dataclass
from pathlib import Path
import subprocess
from typing import Any

import yaml

from .automation_contracts import (
    AutomationContractError,
    REGISTRY_PATH,
    dependabot_allowed_paths,
    load_automation_registry,
)
from .ci_github_api import GitHubAPI
from .ci_graph_render import GENERATED_HEADER
from .governance_install.transaction import apply_transaction


DEPENDABOT_PATH = Path(".github/dependabot.yml")


@dataclass(frozen=True)
class AutomationAdoptionResult:
    status: str
    changed_paths: tuple[str, ...]
    producer_id: str

    def as_dict(self) -> dict[str, object]:
        return {
            "status": self.status,
            "changed_paths": list(self.changed_paths),
            "producer_id": self.producer_id,
        }


def _dependabot_configuration(repo_root: Path) -> dict[str, Any]:
    path = repo_root / DEPENDABOT_PATH
    if path.is_symlink() or not path.is_file():
        raise AutomationContractError("Dependabot adoption requires .github/dependabot.yml")
    try:
        value = yaml.safe_load(path.read_text(encoding="utf-8"))
    except (OSError, yaml.YAMLError) as exc:
        raise AutomationContractError(f"cannot load .github/dependabot.yml: {exc}") from exc
    if not isinstance(value, dict):
        raise AutomationContractError(".github/dependabot.yml must be a mapping")
    return value


def _tracked_repository_paths(repo_root: Path) -> tuple[str, ...]:
    result = subprocess.run(
        ["git", "-C", str(repo_root), "ls-files", "-z"],
        capture_output=True,
        check=False,
    )
    if result.returncode:
        raise AutomationContractError(
            "Dependabot adoption requires an exact Git-tracked file inventory"
        )
    try:
        values = tuple(
            sorted(value.decode("utf-8") for value in result.stdout.split(b"\0") if value)
        )
    except UnicodeDecodeError as exc:
        raise AutomationContractError(
            "Dependabot adoption requires UTF-8 Git-tracked paths"
        ) from exc
    if not values:
        raise AutomationContractError("Dependabot adoption found no Git-tracked files")
    return values


def _renderer_owned_paths(
    repo_root: Path, repository_paths: tuple[str, ...]
) -> tuple[str, ...]:
    owned: list[str] = []
    for relative in repository_paths:
        if not relative.startswith(".github/"):
            continue
        path = repo_root / relative
        if path.is_symlink() or not path.is_file():
            continue
        try:
            with path.open(encoding="utf-8") as stream:
                first_line = stream.readline().rstrip("\n")
        except (OSError, UnicodeDecodeError):
            continue
        if first_line == GENERATED_HEADER:
            owned.append(relative)
    return tuple(owned)


def _desired_dependabot(
    api: GitHubAPI,
    *,
    repo_root: Path,
    repository: str,
    current: dict[str, Any] | None,
) -> dict[str, Any]:
    provider_repo = api.repository(repository)
    repository_identity = {
        "full_name": repository,
        "numeric_id": provider_repo.get("id"),
    }
    if current is not None and current["repository"] != repository_identity:
        raise AutomationContractError("automation registry repository is not provider-authenticated")
    actor = api.user("dependabot[bot]")
    if actor.get("type") != "Bot" or actor.get("login") != "dependabot[bot]":
        raise AutomationContractError("provider Dependabot identity is not exact")
    tracked_paths = _tracked_repository_paths(repo_root)
    classes, paths = dependabot_allowed_paths(
        _dependabot_configuration(repo_root),
        repository_paths=tracked_paths,
        excluded_paths=_renderer_owned_paths(repo_root, tracked_paths),
    )
    unsafe = [
        path
        for path in paths
        if (repo_root / path).is_symlink() or not (repo_root / path).is_file()
    ]
    if unsafe:
        raise AutomationContractError(
            "Dependabot dependency files must be tracked regular files: "
            + ", ".join(unsafe)
        )
    producer = {
        "id": "dependabot",
        "type": "dependabot",
        "activation_state": "active",
        "actor_id": int(actor["id"]),
        "actor_login": "dependabot[bot]",
        "same_repository_head": True,
        "branch_patterns": ["dependabot/**"],
        "dependency_change_classes": list(classes),
        "allowed_paths": list(paths),
        "controls": {
            "positive": ["dependabot-changelog-reconcile"],
            "adversarial": ["dependabot-numeric-identity-and-path-rejection"],
            "topology": ["trusted-automation-no-candidate-authority"],
            "cleanup": ["trusted-automation-no-persistent-workspace"],
        },
    }
    desired = copy.deepcopy(current) if current is not None else {
        "document": {
            "kind": "automation_producer_registry",
            "name": "BCF Trusted Automation Producers",
            "id": "bcf-automation-producers",
            "version": "1.0.0",
            "status": "active",
            "path": REGISTRY_PATH.as_posix(),
        },
        "schema_version": "1.0",
        "provider": "github",
        "repository": repository_identity,
        "policy": {
            "changelog_path": "CHANGELOG.md",
            "section": "Changed",
            "entry_template": "- Automated dependency update `{producer_id}` from PR #{pr_number}: {dependency_paths}.",
            "marker_prefix": "bcf-automation-changelog",
            "maximum_changed_paths": 40,
            "trusted_resource_class": "trusted-control",
            "protected_environment": "bcf-trusted-automation",
            "observer_token_environment": "GITHUB_TOKEN",
            "writer_token_environment": "BCF_AUTOMATION_APP_TOKEN",
        },
        "producers": [],
    }
    desired["producers"] = [
        item for item in desired["producers"] if item["id"] != "dependabot"
    ] + [producer]
    desired["producers"].sort(key=lambda item: item["id"])
    return desired


def adopt_dependabot(
    api: GitHubAPI,
    *,
    repo_root: Path,
    repository: str,
    apply: bool,
) -> AutomationAdoptionResult:
    root = repo_root.resolve()
    current = load_automation_registry(root) if (root / REGISTRY_PATH).is_file() else None
    desired = _desired_dependabot(
        api, repo_root=root, repository=repository, current=current
    )
    if current == desired:
        return AutomationAdoptionResult("clean", (), "dependabot")
    if not apply:
        return AutomationAdoptionResult("drift", (REGISTRY_PATH.as_posix(),), "dependabot")

    def mutate(shadow: Path) -> None:
        path = shadow / REGISTRY_PATH
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(yaml.safe_dump(desired, sort_keys=False), encoding="utf-8")

    apply_transaction(
        root, managed_paths=(REGISTRY_PATH.as_posix(),), mutate_shadow=mutate
    )
    load_automation_registry(root)
    return AutomationAdoptionResult("applied", (REGISTRY_PATH.as_posix(),), "dependabot")
