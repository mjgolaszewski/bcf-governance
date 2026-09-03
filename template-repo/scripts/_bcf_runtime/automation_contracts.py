"""Canonical contracts for bounded trusted automation producers."""

from __future__ import annotations

from dataclasses import dataclass
from fnmatch import fnmatchcase
import json
from pathlib import Path, PurePosixPath
import re
from typing import Any

from jsonschema import Draft202012Validator
import yaml


REGISTRY_PATH = Path("governance/automation-producers.yml")
SCHEMA_PATH = Path("schemas/automation-producers.schema.json")
SAFE_PATH = re.compile(r"^(?!/)(?!.*(?:^|/)\.\.(?:/|$))[A-Za-z0-9._/@+-]+$")


class AutomationContractError(ValueError):
    """Raised when automation authority is absent or ambiguous."""


@dataclass(frozen=True)
class ProducerMatch:
    producer: dict[str, Any]
    dependency_paths: tuple[str, ...]


def _mapping(path: Path) -> dict[str, Any]:
    if path.is_symlink() or not path.is_file():
        raise AutomationContractError(f"automation contract is missing or unsafe: {path}")
    try:
        value = yaml.safe_load(path.read_text(encoding="utf-8"))
    except (OSError, yaml.YAMLError) as exc:
        raise AutomationContractError(f"cannot load automation contract {path}: {exc}") from exc
    if not isinstance(value, dict):
        raise AutomationContractError(f"automation contract must be a mapping: {path}")
    return value


def _validate_registry(registry: object, *, schema_path: Path) -> dict[str, Any]:
    try:
        schema = json.loads(schema_path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise AutomationContractError(f"cannot load automation schema: {exc}") from exc
    errors = sorted(
        Draft202012Validator(schema).iter_errors(registry),
        key=lambda item: list(item.absolute_path),
    )
    if errors:
        error = errors[0]
        location = ".".join(str(item) for item in error.absolute_path) or "<root>"
        raise AutomationContractError(
            f"automation registry schema violation at {location}: {error.message}"
        )
    if not isinstance(registry, dict):
        raise AutomationContractError("automation contract must be a mapping")
    ids = [str(item["id"]) for item in registry["producers"]]
    identities = [int(item["actor_id"]) for item in registry["producers"]]
    if len(ids) != len(set(ids)) or len(identities) != len(set(identities)):
        raise AutomationContractError("producer IDs and numeric actor identities must be unique")
    return registry


def load_automation_registry_bytes(content: bytes, *, schema_path: Path) -> dict[str, Any]:
    try:
        value = yaml.safe_load(content.decode("utf-8"))
    except (UnicodeDecodeError, yaml.YAMLError) as exc:
        raise AutomationContractError(f"cannot decode automation contract: {exc}") from exc
    return _validate_registry(value, schema_path=schema_path)


def load_automation_registry(repo_root: Path) -> dict[str, Any]:
    """Load and structurally validate the sole automation registry owner."""

    repo_root = repo_root.resolve()
    return _validate_registry(
        _mapping(repo_root / REGISTRY_PATH), schema_path=repo_root / SCHEMA_PATH
    )


def _safe_path(value: object) -> str:
    text = str(value)
    path = PurePosixPath(text)
    if not SAFE_PATH.fullmatch(text) or path.is_absolute() or ".." in path.parts:
        raise AutomationContractError(f"provider returned unsafe changed path: {text!r}")
    return text


def select_producer(
    registry: dict[str, Any],
    *,
    repository: str,
    repository_id: int,
    actor_id: int,
    actor_login: str,
    head_repository_id: int,
    head_branch: str,
    changed_paths: tuple[str, ...],
) -> ProducerMatch:
    """Select one active producer from authenticated numeric provider identity."""

    declared_repo = registry["repository"]
    if repository != declared_repo["full_name"] or repository_id != declared_repo["numeric_id"]:
        raise AutomationContractError("provider repository identity does not match the registry")
    if head_repository_id != repository_id:
        raise AutomationContractError("automation producer head must belong to the same repository")
    candidates = [
        item
        for item in registry["producers"]
        if item["activation_state"] == "active" and int(item["actor_id"]) == actor_id
    ]
    if len(candidates) != 1:
        raise AutomationContractError("numeric actor identity does not select one active producer")
    producer = candidates[0]
    if actor_login != producer["actor_login"]:
        raise AutomationContractError("actor login does not match its registered numeric identity")
    if not any(fnmatchcase(head_branch, pattern) for pattern in producer["branch_patterns"]):
        raise AutomationContractError("automation branch is outside the producer contract")
    maximum = int(registry["policy"]["maximum_changed_paths"])
    if not changed_paths or len(changed_paths) > maximum:
        raise AutomationContractError("automation changed-path inventory is empty or excessive")
    safe_paths = tuple(sorted({_safe_path(value) for value in changed_paths}))
    if len(safe_paths) != len(changed_paths):
        raise AutomationContractError("automation changed-path inventory contains duplicates")
    changelog = str(registry["policy"]["changelog_path"])
    dependency_paths = tuple(path for path in safe_paths if path != changelog)
    if not dependency_paths:
        raise AutomationContractError("automation PR contains no dependency change")
    rejected = [
        path
        for path in dependency_paths
        if not any(fnmatchcase(path, pattern) for pattern in producer["allowed_paths"])
    ]
    if rejected:
        raise AutomationContractError(
            f"automation PR contains unexpected paths: {', '.join(rejected)}"
        )
    return ProducerMatch(producer=producer, dependency_paths=dependency_paths)


def _dependabot_match_subject(path: str, ecosystem: object) -> str:
    return path if ecosystem == "github-actions" else PurePosixPath(path).name


def dependabot_allowed_paths(
    configuration: dict[str, Any],
    *,
    repository_paths: tuple[str, ...],
    excluded_paths: tuple[str, ...] = (),
) -> tuple[tuple[str, ...], tuple[str, ...]]:
    """Derive exact tracked dependency surfaces from dependabot.yml and Git."""

    updates = configuration.get("updates")
    if configuration.get("version") != 2 or not isinstance(updates, list) or not updates:
        raise AutomationContractError("dependabot.yml must declare version 2 updates")
    tracked = tuple(sorted({_safe_path(value) for value in repository_paths}))
    if len(tracked) != len(repository_paths):
        raise AutomationContractError("Git-tracked path inventory contains duplicates")
    excluded = {_safe_path(value) for value in excluded_paths}
    if len(excluded) != len(excluded_paths) or not excluded.issubset(tracked):
        raise AutomationContractError(
            "Dependabot excluded paths must be a duplicate-free tracked subset"
        )
    paths: set[str] = set()
    classes: set[str] = set()
    ecosystem_patterns = {
        "pip": ("python", ("pyproject.toml", "requirements*.txt", "uv.lock", "poetry.lock", "Pipfile.lock")),
        "npm": ("npm", ("package.json", "package-lock.json", "npm-shrinkwrap.json", "yarn.lock", "pnpm-lock.yaml")),
        "github-actions": ("github-actions", (".github/workflows/*.yml", ".github/workflows/*.yaml", ".github/actions/*/action.yml", ".github/actions/*/action.yaml")),
        "docker": ("docker", ("Dockerfile*", "docker-compose*.yml", "docker-compose*.yaml")),
    }
    for update in updates:
        if not isinstance(update, dict):
            raise AutomationContractError("dependabot update entries must be mappings")
        ecosystem = update.get("package-ecosystem")
        directory = update.get("directory")
        if ecosystem not in ecosystem_patterns or not isinstance(directory, str):
            raise AutomationContractError(f"unsupported Dependabot ecosystem: {ecosystem!r}")
        root = directory.strip("/")
        if directory != "/" and _safe_path(root) != root:
            raise AutomationContractError("Dependabot directory is unsafe")
        change_class, names = ecosystem_patterns[ecosystem]
        classes.add(change_class)
        prefix = f"{root}/" if root else ""
        matches = {
            path
            for path in tracked
            if (not prefix or path.startswith(prefix))
            and any(
                fnmatchcase(_dependabot_match_subject(path, ecosystem), name)
                for name in names
            )
        }
        matches.difference_update(excluded)
        if not matches:
            raise AutomationContractError(
                f"Dependabot {ecosystem} update at {directory} has no eligible tracked "
                "dependency files after mechanical exclusions"
            )
        paths.update(matches)
    return tuple(sorted(classes)), tuple(sorted(paths))
