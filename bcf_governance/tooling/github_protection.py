"""Deterministic GitHub ruleset inspection and compare-before-apply authority."""

from __future__ import annotations

from dataclasses import dataclass
import hashlib
import json
from pathlib import Path
import re
import subprocess
from typing import Any

from jsonschema import Draft202012Validator
import yaml

from .automation_contracts import (
    AutomationContractError,
    load_automation_registry,
    select_producer,
)
from .ci_github_api import GitHubAPI
from .ci_github_identity import GitHubControllerError, positive_int
from .ci_github_identity import resolve_main


PROTECTION_PATH = Path("governance/github-protection.yml")
SCHEMA_PATH = Path("schemas/github-protection.schema.json")
CHECK_EXTERNAL_ID = re.compile(r"^bcf-pr-certification:[1-9][0-9]*:[1-9][0-9]*$")


@dataclass(frozen=True)
class ProtectionResult:
    status: str
    repository: str
    ruleset_id: str | None
    differences: tuple[str, ...]

    def as_dict(self) -> dict[str, object]:
        return {
            "status": self.status,
            "repository": self.repository,
            "ruleset_id": self.ruleset_id,
            "differences": list(self.differences),
        }


@dataclass(frozen=True)
class ProviderProtectionSnapshot:
    status: str
    sha256: str
    ruleset_id: int | None
    detail: dict[str, Any] | None

    def declaration_identity(self) -> dict[str, object]:
        value: dict[str, object] = {"status": self.status, "sha256": self.sha256}
        if self.ruleset_id is not None:
            value["ruleset_id"] = self.ruleset_id
        return value


def _validate_protection(value: object, *, schema_path: Path) -> dict[str, Any]:
    try:
        schema = json.loads(schema_path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise GitHubControllerError(f"cannot load GitHub protection schema: {exc}") from exc
    if not isinstance(value, dict):
        raise GitHubControllerError("GitHub protection declaration must be a mapping")
    errors = sorted(
        Draft202012Validator(schema).iter_errors(value),
        key=lambda item: list(item.absolute_path),
    )
    if errors:
        error = errors[0]
        location = ".".join(str(item) for item in error.absolute_path) or "<root>"
        raise GitHubControllerError(
            f"GitHub protection schema violation at {location}: {error.message}"
        )
    return value


def load_protection_bytes(content: bytes, *, schema_path: Path) -> dict[str, Any]:
    try:
        value = yaml.safe_load(content.decode("utf-8"))
    except (UnicodeDecodeError, yaml.YAMLError) as exc:
        raise GitHubControllerError(f"cannot decode GitHub protection declaration: {exc}") from exc
    return _validate_protection(value, schema_path=schema_path)


def load_protection(repo_root: Path) -> dict[str, Any]:
    root = repo_root.resolve()
    path = root / PROTECTION_PATH
    if path.is_symlink() or not path.is_file():
        raise GitHubControllerError("GitHub protection declaration is missing or unsafe")
    try:
        value = yaml.safe_load(path.read_text(encoding="utf-8"))
    except (OSError, yaml.YAMLError) as exc:
        raise GitHubControllerError(f"cannot load GitHub protection declaration: {exc}") from exc
    return _validate_protection(value, schema_path=root / SCHEMA_PATH)


def desired_ruleset(declaration: dict[str, Any]) -> dict[str, Any]:
    """Project the complete provider payload from the canonical declaration."""

    rule = declaration["ruleset"]
    checks = [
        {"context": item["context"], "integration_id": item["integration_id"]}
        for item in rule["required_status_checks"]
    ]
    return {
        "name": rule["name"],
        "target": "branch",
        "enforcement": rule["enforcement"],
        "bypass_actors": [],
        "conditions": {
            "ref_name": {
                "include": [f"refs/heads/{declaration['repository']['branch']}"],
                "exclude": [],
            }
        },
        "rules": [
            {
                "type": "pull_request",
                "parameters": {
                    "allowed_merge_methods": rule.get(
                        "allowed_merge_methods", ["merge", "squash", "rebase"]
                    ),
                    "dismiss_stale_reviews_on_push": rule["dismiss_stale_reviews_on_push"],
                    "require_code_owner_review": rule.get(
                        "require_code_owner_review", False
                    ),
                    "require_extra_approval_for_unattributed_changes": rule.get(
                        "require_extra_approval_for_unattributed_changes", False
                    ),
                    "require_last_push_approval": rule["require_last_push_approval"],
                    "required_approving_review_count": rule["required_approving_review_count"],
                    "required_review_thread_resolution": rule["required_review_thread_resolution"],
                    "required_reviewers": [],
                },
            },
            {
                "type": "required_status_checks",
                "parameters": {
                    "do_not_enforce_on_create": False,
                    "required_status_checks": checks,
                    "strict_required_status_checks_policy": rule["strict_required_status_checks_policy"],
                },
            },
            {"type": "non_fast_forward"},
            {"type": "deletion"},
        ],
    }


def _normalized_provider(value: dict[str, Any]) -> dict[str, Any]:
    allowed = {"name", "target", "enforcement", "bypass_actors", "conditions", "rules"}
    normalized = {key: value.get(key) for key in allowed}
    rules = normalized.get("rules")
    if not isinstance(rules, list):
        return normalized
    normalized_rules: list[Any] = []
    for item in rules:
        if not isinstance(item, dict):
            normalized_rules.append(item)
            continue
        copied = dict(item)
        parameters = copied.get("parameters")
        if isinstance(parameters, dict):
            copied_parameters = dict(parameters)
            checks = copied_parameters.get("required_status_checks")
            if isinstance(checks, list):
                copied_parameters["required_status_checks"] = sorted(
                    checks,
                    key=lambda check: (
                        str(check.get("context", "")) if isinstance(check, dict) else "",
                        str(check.get("integration_id", "")) if isinstance(check, dict) else "",
                    ),
                )
            methods = copied_parameters.get("allowed_merge_methods")
            if isinstance(methods, list):
                copied_parameters["allowed_merge_methods"] = sorted(methods)
            copied["parameters"] = copied_parameters
        normalized_rules.append(copied)
    normalized["rules"] = sorted(
        normalized_rules,
        key=lambda item: str(item.get("type", "")) if isinstance(item, dict) else "",
    )
    return normalized


def _select_declared_ruleset(
    api: GitHubAPI,
    *,
    repository: str,
    declaration: dict[str, Any],
) -> dict[str, Any] | None:
    inventory = api.repository_rulesets(repository)
    matches = [
        value
        for value in inventory
        if value.get("name") == declaration["ruleset"]["name"]
    ]
    if len(matches) > 1:
        raise GitHubControllerError("provider has duplicate canonical rulesets")
    branch = declaration["repository"]["branch"]
    overlaps = []
    for item in inventory:
        ruleset_id = positive_int(item.get("id"), field="ruleset ID")
        detail = api.ruleset(repository, ruleset_id)
        if _targets_declared_branch(detail, branch=branch):
            overlaps.append(detail)
    if len(overlaps) > 1:
        raise GitHubControllerError(
            "provider has ambiguous rulesets targeting the declared branch"
        )
    if matches:
        matched_id = positive_int(matches[0].get("id"), field="ruleset ID")
        if not overlaps or positive_int(
            overlaps[0].get("id"), field="ruleset ID"
        ) != matched_id:
            raise GitHubControllerError(
                "canonical ruleset does not target the declared branch"
            )
        return overlaps[0]
    return overlaps[0] if overlaps else None


def _targets_declared_branch(value: dict[str, Any], *, branch: str) -> bool:
    if value.get("target") != "branch":
        return False
    conditions = value.get("conditions")
    ref_name = conditions.get("ref_name") if isinstance(conditions, dict) else None
    includes = ref_name.get("include") if isinstance(ref_name, dict) else None
    return isinstance(includes, list) and (
        f"refs/heads/{branch}" in includes or "~DEFAULT_BRANCH" in includes
    )


def provider_protection_snapshot(
    api: GitHubAPI, *, repository: str, branch: str
) -> ProviderProtectionSnapshot:
    """Bind one complete branch-target ruleset observation or exact absence."""

    matches: list[dict[str, Any]] = []
    for item in api.repository_rulesets(repository):
        ruleset_id = positive_int(item.get("id"), field="ruleset ID")
        detail = api.ruleset(repository, ruleset_id)
        if _targets_declared_branch(detail, branch=branch):
            matches.append(detail)
    if len(matches) > 1:
        raise GitHubControllerError(
            "provider has ambiguous rulesets targeting the declared branch"
        )
    detail = matches[0] if matches else None
    if detail is not None and (
        "bypass_actors" not in detail or not isinstance(detail["bypass_actors"], list)
    ):
        raise GitHubControllerError(
            "protection inspection bypass actors are absent or redacted"
        )
    ruleset_id = (
        positive_int(detail.get("id"), field="ruleset ID")
        if detail is not None
        else None
    )
    payload = {
        "repository": repository,
        "branch": branch,
        "status": "present" if detail is not None else "missing",
        "ruleset": (
            {"id": ruleset_id, **_normalized_provider(detail)}
            if detail is not None
            else None
        ),
    }
    digest = hashlib.sha256(
        json.dumps(payload, sort_keys=True, separators=(",", ":")).encode()
    ).hexdigest()
    return ProviderProtectionSnapshot(
        status=str(payload["status"]),
        sha256=digest,
        ruleset_id=ruleset_id,
        detail=detail,
    )


def inspect_protection(
    api: GitHubAPI, *, repo_root: Path, repository: str
) -> ProtectionResult:
    declaration = load_protection(repo_root)
    return inspect_protection_declaration(
        api, repository=repository, declaration=declaration
    )


def inspect_protection_declaration(
    api: GitHubAPI, *, repository: str, declaration: dict[str, Any]
) -> ProtectionResult:
    """Inspect provider protection against an already authenticated declaration."""

    expected_repo = declaration["repository"]
    provider_repo = api.repository(repository)
    if repository != expected_repo["full_name"] or positive_int(
        provider_repo.get("id"), field="repository ID"
    ) != int(expected_repo["numeric_id"]):
        raise GitHubControllerError("protection repository identity does not match")
    selected = _select_declared_ruleset(
        api, repository=repository, declaration=declaration
    )
    if selected is None:
        return ProtectionResult("missing", repository, None, ("ruleset",))
    ruleset_id = str(positive_int(selected.get("id"), field="ruleset ID"))
    detail = selected
    if "bypass_actors" not in detail or not isinstance(detail["bypass_actors"], list):
        raise GitHubControllerError(
            "protection inspection bypass actors are absent or redacted"
        )
    actual = _normalized_provider(detail)
    desired = _normalized_provider(desired_ruleset(declaration))
    differences = tuple(
        sorted(key for key in desired if actual.get(key) != desired.get(key))
    )
    return ProtectionResult(
        "clean" if not differences else "drift",
        repository,
        ruleset_id,
        differences,
    )


def _require_current_canary(
    api: GitHubAPI,
    *,
    repo_root: Path,
    repository: str,
    declaration: dict[str, Any],
) -> dict[str, Any]:
    provider_repo = api.repository(repository)
    repository_id = positive_int(provider_repo.get("id"), field="repository ID")
    registry = load_automation_registry(repo_root)
    authority = declaration["pr_certification"]
    successful: list[dict[str, Any]] = []
    for pull in api.pull_requests(repository, state="open"):
        head = pull.get("head")
        user = pull.get("user")
        if not pull.get("draft") or not isinstance(head, dict) or not isinstance(user, dict):
            continue
        head_repo = head.get("repo")
        if not isinstance(head_repo, dict):
            continue
        files = api.pull_request_files(repository, pull.get("number"))
        paths = tuple(str(value.get("filename", "")) for value in files)
        try:
            select_producer(
                registry,
                repository=repository,
                repository_id=repository_id,
                actor_id=positive_int(user.get("id"), field="actor ID"),
                actor_login=str(user.get("login", "")),
                head_repository_id=positive_int(
                    head_repo.get("id"), field="head repository ID"
                ),
                head_branch=str(head.get("ref", "")),
                changed_paths=paths,
            )
        except (AutomationContractError, GitHubControllerError):
            continue
        head_sha = str(head.get("sha", ""))
        successful.extend(
            run
            for run in api.check_runs(repository, sha=head_sha)
            if run.get("name") == authority["context"]
            and isinstance(run.get("app"), dict)
            and run["app"].get("id") == authority["publisher_app_id"]
            and run.get("head_sha") == head_sha
            and run.get("status") == "completed"
            and run.get("conclusion") == "success"
            and isinstance(run.get("external_id"), str)
            and CHECK_EXTERNAL_ID.fullmatch(run["external_id"])
        )
    if len(successful) != 1:
        raise GitHubControllerError(
            "protection activation requires one current successful controlled automation PR certification canary"
        )
    return successful[0]


def apply_protection(
    api: GitHubAPI, *, repo_root: Path, repository: str
) -> ProtectionResult:
    declaration = load_protection(repo_root)
    if declaration["schema_version"] == "1.1":
        _require_reviewed_protection_source(
            api,
            repo_root=repo_root,
            repository=repository,
            declaration=declaration,
        )
    else:
        _require_current_canary(
            api,
            repo_root=repo_root,
            repository=repository,
            declaration=declaration,
        )
    current = inspect_protection(api, repo_root=repo_root, repository=repository)
    desired = desired_ruleset(declaration)
    if current.status == "clean":
        return current
    if declaration["schema_version"] == "1.1":
        expected = declaration["projection"]["provider_prestate"]
        snapshot = provider_protection_snapshot(
            api,
            repository=repository,
            branch=declaration["repository"]["branch"],
        )
        if snapshot.declaration_identity() != expected:
            raise GitHubControllerError(
                "provider protection changed after the reviewed proposal"
            )
    if current.ruleset_id is None:
        updated = api.create_ruleset(repository, desired)
    else:
        updated = api.update_ruleset(repository, current.ruleset_id, desired)
    ruleset_id = str(positive_int(updated.get("id"), field="updated ruleset ID"))
    verified = inspect_protection(api, repo_root=repo_root, repository=repository)
    if verified.status != "clean" or verified.ruleset_id != ruleset_id:
        raise GitHubControllerError("provider protection did not converge to the declaration")
    return ProtectionResult("applied", repository, ruleset_id, ())


def _require_reviewed_protection_source(
    api: GitHubAPI,
    *,
    repo_root: Path,
    repository: str,
    declaration: dict[str, Any],
) -> None:
    """Require an ordinary-adopter declaration from exact protected main."""

    root = repo_root.resolve()
    status = subprocess.run(
        ["git", "status", "--porcelain"], cwd=root, capture_output=True, text=True,
        check=False,
    )
    head = subprocess.run(
        ["git", "rev-parse", "HEAD"], cwd=root, capture_output=True, text=True,
        check=False,
    )
    if status.returncode or status.stdout or head.returncode:
        raise GitHubControllerError(
            "protection apply requires an exact clean reviewed source checkout"
        )
    main = resolve_main(api, repository)
    if head.stdout.strip() != main.checkout_sha:
        raise GitHubControllerError(
            "protection declaration is not the current protected-main source"
        )
    remote = api.content(repository, PROTECTION_PATH.as_posix(), ref=main.checkout_sha)
    local = (root / PROTECTION_PATH).read_bytes()
    if remote.content != local:
        raise GitHubControllerError(
            "provider protected-main declaration differs from the reviewed source"
        )
    expected_repo = declaration["repository"]
    if int(main.repository_id) != int(expected_repo["numeric_id"]):
        raise GitHubControllerError("reviewed protection repository identity changed")
