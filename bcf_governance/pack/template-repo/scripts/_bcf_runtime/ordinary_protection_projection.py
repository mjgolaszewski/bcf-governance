"""Ordinary-adopter GitHub protection proposal projection.

Copyright 2026 Michael Golaszewski.
Licensed under the MIT License.
"""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
import subprocess
from typing import Any

import yaml

from .ci_github_api import GitHubAPI
from .ci_github_identity import GitHubControllerError, positive_int
from .ci_graph_contracts import validate_ci_graph
from .github_protection import (
    PROTECTION_PATH,
    inspect_protection,
    load_protection,
    provider_protection_snapshot,
)
from .governance_install.transaction import apply_transaction
from .local_pr_context import Runner, resolve_local_pr_context


@dataclass(frozen=True)
class OrdinaryProtectionProjection:
    status: str
    changed_paths: tuple[str, ...]
    declaration: dict[str, Any]


def _git_file(repo_root: Path, commit: str, relative: Path) -> bytes | None:
    result = subprocess.run(
        ["git", "show", f"{commit}:{relative.as_posix()}"],
        cwd=repo_root,
        capture_output=True,
        check=False,
    )
    if result.returncode:
        return None
    return result.stdout


def validate_ordinary_protection_submission(
    api: GitHubAPI,
    *,
    repo_root: Path,
    repository: str,
    base_sha: str,
) -> str:
    """Admit an exact proposal or require reviewed source/provider parity."""

    root = repo_root.resolve()
    path = root / PROTECTION_PATH
    if not path.is_file() or path.is_symlink():
        return "absent"
    declaration = load_protection(root)
    if declaration["schema_version"] != "1.1":
        return "self_contract"
    if declaration["repository"]["full_name"] != repository:
        raise GitHubControllerError(
            "ordinary protection declaration names the wrong repository"
        )
    current = path.read_bytes()
    base = _git_file(root, base_sha, PROTECTION_PATH)
    if base == current:
        observed = inspect_protection(api, repo_root=root, repository=repository)
        if observed.status != "clean":
            raise GitHubControllerError(
                "reviewed ordinary protection declaration does not match provider state"
            )
        return "reviewed_provider_match"
    snapshot = provider_protection_snapshot(
        api,
        repository=repository,
        branch=declaration["repository"]["branch"],
    )
    if snapshot.declaration_identity() != declaration["projection"]["provider_prestate"]:
        raise GitHubControllerError(
            "ordinary protection proposal provider pre-state is stale"
        )
    return "exact_proposal"


def validate_direct_protection_prospective(
    api: GitHubAPI | None,
    *,
    repo_root: Path,
    repository: str | None,
    lane: str,
    remote: str,
    runner: Runner,
) -> None:
    """Bind direct-adopter prospective proof to exact protection state."""

    root = repo_root.resolve()
    if (
        lane != "direct_protected_main"
        or repository is None
        or api is None
        or not (root / PROTECTION_PATH).is_file()
    ):
        return
    context = resolve_local_pr_context(root, remote=remote, runner=runner)
    validate_ordinary_protection_submission(
        api,
        repo_root=root,
        repository=repository,
        base_sha=context.base_sha,
    )


def _profile(repo_root: Path) -> str:
    path = repo_root / "governance-profile.yml"
    try:
        payload = yaml.safe_load(path.read_text(encoding="utf-8"))
    except (OSError, yaml.YAMLError) as exc:
        raise GitHubControllerError(f"cannot load adopter profile: {exc}") from exc
    selected = payload.get("profile", {}).get("selected") if isinstance(payload, dict) else None
    if selected not in {"lite", "standard"}:
        raise GitHubControllerError(
            "ordinary protection projection requires a Lite or Standard adopter"
        )
    return str(selected)


def _producer_workflows(repo_root: Path) -> list[dict[str, object]]:
    compiled = validate_ci_graph(repo_root)
    candidates = [
        workflow
        for workflow in compiled.workflows
        if workflow.get("role") == "pull-request"
    ]
    if len(candidates) != 1:
        raise GitHubControllerError(
            "ordinary protection projection requires one pull-request workflow"
        )
    workflow = candidates[0]
    terminal = [
        str(job.get("display_name", ""))
        for job in workflow.get("jobs", [])
        if job.get("required") is True
        and job.get("semantic_role") == "terminal-governance-truth"
    ]
    if len(terminal) != 1 or not terminal[0]:
        raise GitHubControllerError(
            "ordinary protection projection requires one terminal truth job"
        )
    return [
        {
            "id": str(workflow["id"]),
            "path": str(workflow["path"]),
            "required_job_names": terminal,
        }
    ]


def _rule(detail: dict[str, Any], kind: str) -> dict[str, Any] | None:
    matches = [
        value
        for value in detail.get("rules", [])
        if isinstance(value, dict) and value.get("type") == kind
    ]
    if len(matches) > 1:
        raise GitHubControllerError(f"provider protection duplicates {kind} rule")
    return matches[0] if matches else None


def _supported_existing_ruleset(detail: dict[str, Any]) -> dict[str, Any]:
    allowed_types = {"pull_request", "required_status_checks", "non_fast_forward", "deletion"}
    rules = detail.get("rules")
    if not isinstance(rules, list) or any(
        not isinstance(value, dict) or value.get("type") not in allowed_types
        for value in rules
    ):
        raise GitHubControllerError(
            "provider protection contains an unsupported ordinary-adopter rule"
        )
    bypass = detail.get("bypass_actors")
    if bypass != []:
        raise GitHubControllerError(
            "ordinary protection proposal requires an exact empty bypass inventory"
        )
    pull = _rule(detail, "pull_request")
    pull_parameters = pull.get("parameters") if pull is not None else {}
    if not isinstance(pull_parameters, dict):
        raise GitHubControllerError("provider pull-request protection is malformed")
    reviewers = pull_parameters.get("required_reviewers", [])
    if reviewers != []:
        raise GitHubControllerError(
            "provider required-reviewer identities are not representable by this contract"
        )
    methods = pull_parameters.get("allowed_merge_methods", ["merge", "squash", "rebase"])
    if (
        not isinstance(methods, list)
        or not methods
        or len(set(methods)) != len(methods)
        or any(value not in {"merge", "squash", "rebase"} for value in methods)
    ):
        raise GitHubControllerError("provider allowed merge methods are malformed")
    checks_rule = _rule(detail, "required_status_checks")
    check_parameters = checks_rule.get("parameters") if checks_rule is not None else {}
    if not isinstance(check_parameters, dict):
        raise GitHubControllerError("provider required-status protection is malformed")
    if check_parameters.get("do_not_enforce_on_create", False) is not False:
        raise GitHubControllerError(
            "provider protection does not enforce required checks on creation"
        )
    raw_checks = check_parameters.get("required_status_checks", [])
    if not isinstance(raw_checks, list) or any(not isinstance(value, dict) for value in raw_checks):
        raise GitHubControllerError("provider required status checks are malformed")
    checks: list[dict[str, object]] = []
    for value in raw_checks:
        context = value.get("context")
        if not isinstance(context, str) or not context:
            raise GitHubControllerError("provider required status context is malformed")
        checks.append(
            {
                "context": context,
                "integration_id": positive_int(
                    value.get("integration_id"), field="status integration ID"
                ),
            }
        )
    aggregate = {"context": "bcf/pr-certification", "integration_id": 15368}
    if aggregate not in checks:
        checks.append(aggregate)
    checks.sort(key=lambda value: (str(value["context"]), int(value["integration_id"])))
    return {
        "name": str(detail.get("name") or "main-governance"),
        "enforcement": "active",
        "bypass_actors": [],
        "required_status_checks": checks,
        "strict_required_status_checks_policy": bool(
            check_parameters.get("strict_required_status_checks_policy", True)
        ),
        "required_approving_review_count": positive_int(
            pull_parameters.get("required_approving_review_count", 0),
            field="required approving review count",
        ) if pull_parameters.get("required_approving_review_count", 0) else 0,
        "dismiss_stale_reviews_on_push": bool(
            pull_parameters.get("dismiss_stale_reviews_on_push", True)
        ),
        "require_last_push_approval": bool(
            pull_parameters.get("require_last_push_approval", False)
        ),
        "required_review_thread_resolution": bool(
            pull_parameters.get("required_review_thread_resolution", True)
        ),
        "block_force_pushes": True,
        "block_deletions": True,
        "allowed_merge_methods": methods,
        "require_code_owner_review": bool(
            pull_parameters.get("require_code_owner_review", False)
        ),
        "require_extra_approval_for_unattributed_changes": bool(
            pull_parameters.get(
                "require_extra_approval_for_unattributed_changes", False
            )
        ),
    }


def _default_ruleset() -> dict[str, Any]:
    return {
        "name": "main-governance",
        "enforcement": "active",
        "bypass_actors": [],
        "required_status_checks": [
            {"context": "bcf/pr-certification", "integration_id": 15368}
        ],
        "strict_required_status_checks_policy": True,
        "required_approving_review_count": 0,
        "dismiss_stale_reviews_on_push": True,
        "require_last_push_approval": False,
        "required_review_thread_resolution": True,
        "block_force_pushes": True,
        "block_deletions": True,
        "allowed_merge_methods": ["merge", "squash", "rebase"],
        "require_code_owner_review": False,
        "require_extra_approval_for_unattributed_changes": False,
    }


def compile_ordinary_protection_proposal(
    api: GitHubAPI, *, repo_root: Path, repository: str
) -> dict[str, Any]:
    """Compile one reviewable declaration from exact adopter and provider state."""

    root = repo_root.resolve()
    provider = api.repository(repository)
    repository_id = positive_int(provider.get("id"), field="repository ID")
    full_name = provider.get("full_name")
    branch = provider.get("default_branch")
    if full_name != repository or not isinstance(branch, str) or not branch:
        raise GitHubControllerError("ordinary protection repository identity is not exact")
    snapshot = provider_protection_snapshot(
        api, repository=repository, branch=branch
    )
    ruleset = (
        _supported_existing_ruleset(snapshot.detail)
        if snapshot.detail is not None
        else _default_ruleset()
    )
    return {
        "document": {
            "kind": "github_protection",
            "name": "BCF GitHub Main Protection",
            "id": "bcf-github-main-protection",
            "version": "1.1.0",
            "status": "active",
            "path": PROTECTION_PATH.as_posix(),
        },
        "schema_version": "1.1",
        "repository": {
            "full_name": repository,
            "numeric_id": repository_id,
            "branch": branch,
        },
        "pr_certification": {
            "context": "bcf/pr-certification",
            "publisher_app_id": 15368,
            "producer_workflows": _producer_workflows(root),
        },
        "ruleset": ruleset,
        "projection": {
            "kind": "ordinary_adopter",
            "profile": _profile(root),
            "provider_prestate": snapshot.declaration_identity(),
        },
    }


def _render(value: dict[str, Any]) -> bytes:
    return yaml.safe_dump(value, sort_keys=False, width=1000).encode("utf-8")


def apply_ordinary_protection_projection(
    *, repo_root: Path, projection: OrdinaryProtectionProjection
) -> OrdinaryProtectionProjection:
    """Write the exact previously compiled proposal without rereading provider state."""

    root = repo_root.resolve()
    if projection.status == "clean":
        return projection
    if projection.status != "actionable" or projection.changed_paths != (
        PROTECTION_PATH.as_posix(),
    ):
        raise GitHubControllerError("ordinary protection projection plan is invalid")
    declaration = projection.declaration

    def mutate(shadow: Path) -> None:
        target = shadow / PROTECTION_PATH
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_bytes(_render(declaration))

    apply_transaction(
        root, managed_paths=(PROTECTION_PATH.as_posix(),), mutate_shadow=mutate
    )
    loaded = load_protection(root)
    if loaded != declaration:
        raise GitHubControllerError(
            "ordinary protection projection did not converge"
        )
    return OrdinaryProtectionProjection(
        "changed", (PROTECTION_PATH.as_posix(),), declaration
    )


def project_ordinary_protection(
    api: GitHubAPI, *, repo_root: Path, repository: str, apply: bool
) -> OrdinaryProtectionProjection:
    """Plan or write the proposal without mutating provider protection."""

    root = repo_root.resolve()
    path = root / PROTECTION_PATH
    if path.is_symlink() or (path.exists() and not path.is_file()):
        raise GitHubControllerError("ordinary protection declaration is unsafe")
    if path.is_file():
        declaration = load_protection(root)
        expected = declaration["repository"]
        if (
            declaration["schema_version"] != "1.1"
            or expected["full_name"] != repository
            or declaration.get("projection", {}).get("profile") != _profile(root)
        ):
            raise GitHubControllerError(
                "existing protection declaration is not the ordinary-adopter contract"
            )
        return OrdinaryProtectionProjection("clean", (), declaration)
    declaration = compile_ordinary_protection_proposal(
        api, repo_root=root, repository=repository
    )
    if not apply:
        return OrdinaryProtectionProjection(
            "actionable", (PROTECTION_PATH.as_posix(),), declaration
        )

    return apply_ordinary_protection_projection(
        repo_root=root,
        projection=OrdinaryProtectionProjection(
            "actionable", (PROTECTION_PATH.as_posix(),), declaration
        ),
    )
