"""Profile-contract-v2 readiness and backward-compatible version selection."""

from __future__ import annotations

from dataclasses import asdict, dataclass
from datetime import datetime, timezone
import json
from pathlib import Path
import subprocess
from typing import Any

from jsonschema import Draft202012Validator
import yaml

from .ci_authority_contracts import CIAuthorityContractError, validate_ci_contract
from .ci_adopt_github import (
    GithubAdoptionError,
    plan_github_adoption,
    render_github_adoption,
    render_github_control_plane,
)
from .ci_github import GithubReferenceError, validate_reference_topology
from .runtime_capacity import RuntimeCapacityError, load_runtime_contract


CONTRACT_ORDER = {"1.0": 1, "2.0": 2}


class ProfileV2Error(ValueError):
    """Raised before mutation when a contract-v2 repository is incomplete."""


@dataclass(frozen=True)
class ProfileV2Readiness:
    status: str
    profile: str
    profile_contract_version: str
    semantic_representations: int
    capability_na_records: int
    ci_authority: str
    github_topology: str
    runtime_capacity: str

    def as_dict(self) -> dict[str, object]:
        return asdict(self)


def current_contract_version(repo_root: Path) -> str:
    path = repo_root / "governance-profile.yml"
    if not path.is_file():
        return "1.0"
    payload = yaml.safe_load(path.read_text(encoding="utf-8"))
    if not isinstance(payload, dict):
        raise ProfileV2Error("governance-profile.yml must contain a mapping")
    value = str(payload.get("profile_contract_version", "1.0"))
    if value not in CONTRACT_ORDER:
        raise ProfileV2Error("profile_contract_version must be 1.0 or 2.0")
    return value


def current_profile(repo_root: Path) -> str | None:
    path = repo_root / "governance-profile.yml"
    if not path.is_file():
        return None
    payload = yaml.safe_load(path.read_text(encoding="utf-8"))
    if not isinstance(payload, dict):
        raise ProfileV2Error("governance-profile.yml must contain a mapping")
    profile = payload.get("profile")
    return str(profile.get("selected")) if isinstance(profile, dict) else None


def resolve_install_contract_version(
    repo_root: Path,
    profile: str | None,
    requested: str | None,
    upgrade: bool,
    reset_options: bool = False,
) -> tuple[str, str]:
    """Fresh Standard/Regulated use v2; upgrades preserve version and normally profile."""

    if requested is not None and requested not in CONTRACT_ORDER:
        raise ProfileV2Error("profile contract version must be 1.0 or 2.0")
    if not upgrade:
        selected = profile or "standard"
        return selected, requested or ("1.0" if selected == "lite" else "2.0")
    existing_profile = current_profile(repo_root)
    existing_version = current_contract_version(repo_root)
    if reset_options:
        selected = profile or existing_profile
        if selected not in {"lite", "standard", "regulated"}:
            raise ProfileV2Error("--reset-options requires a valid --profile")
        if requested is not None and requested != existing_version:
            raise ProfileV2Error(
                "upgrade preserves profile contract version; use bcf profile promote for v2"
            )
        return selected, existing_version
    if existing_profile not in {"lite", "standard", "regulated"}:
        raise ProfileV2Error("upgrade target has no valid existing governance profile")
    if requested is not None and requested != existing_version:
        raise ProfileV2Error(
            "upgrade preserves profile contract version; use bcf profile promote for v2"
        )
    if profile is not None and profile != existing_profile:
        raise ProfileV2Error(
            "upgrade preserves selected profile; use bcf profile promote for profile changes"
        )
    return existing_profile, existing_version


def _trigger_is_active(repo_root: Path, trigger: dict[str, Any]) -> bool:
    kind = trigger["kind"]
    value = str(trigger["value"])
    if kind == "tracked_path_exists":
        relative = Path(value)
        if relative.is_absolute() or ".." in relative.parts:
            raise ProfileV2Error("tracked_path_exists trigger must be repository-relative")
        result = subprocess.run(
            ["git", "ls-files", "--error-unmatch", "--", value],
            cwd=repo_root,
            check=False,
            capture_output=True,
        )
        return result.returncode == 0
    if kind == "declaration_exists":
        return any(
            value in path.read_text(encoding="utf-8")
            for path in repo_root.rglob("*.yml")
            if "capability-na" not in path.parts and ".git" not in path.parts
        )
    if kind == "profile_changes":
        return current_profile(repo_root) != value
    raise ProfileV2Error(f"unsupported N/A re-review trigger: {kind}")


def assert_monotonic_contract_change(current: str, target: str) -> None:
    if current not in CONTRACT_ORDER or target not in CONTRACT_ORDER:
        raise ProfileV2Error("profile contract version must be 1.0 or 2.0")
    if CONTRACT_ORDER[target] < CONTRACT_ORDER[current]:
        raise ProfileV2Error("profile contract version cannot be downgraded")


def _load_mapping(path: Path) -> dict[str, Any]:
    if not path.is_file() or path.is_symlink():
        raise ProfileV2Error(f"required v2 artifact must be a regular file: {path}")
    payload = yaml.safe_load(path.read_text(encoding="utf-8"))
    if not isinstance(payload, dict):
        raise ProfileV2Error(f"{path} must contain a mapping")
    return payload


def _schema(repo_root: Path, name: str) -> dict[str, Any]:
    payload = json.loads((repo_root / "schemas" / name).read_text(encoding="utf-8"))
    if not isinstance(payload, dict):
        raise ProfileV2Error(f"schemas/{name} must contain an object")
    return payload


def _validate_schema(repo_root: Path, name: str, payload: dict[str, Any]) -> None:
    errors = sorted(
        Draft202012Validator(_schema(repo_root, name)).iter_errors(payload),
        key=lambda error: ([str(part) for part in error.absolute_path], error.message),
    )
    if errors:
        location = ".".join(str(part) for part in errors[0].absolute_path)
        raise ProfileV2Error(f"{name}:{location}: {errors[0].message}")


def _head(repo_root: Path) -> str:
    status = subprocess.run(
        ["git", "status", "--porcelain=v1", "--untracked-files=all", "--ignored=no"],
        cwd=repo_root,
        check=False,
        capture_output=True,
        text=True,
    )
    if status.returncode != 0 or status.stdout:
        raise ProfileV2Error("profile-v2 readiness requires a clean committed HEAD")
    result = subprocess.run(
        ["git", "rev-parse", "HEAD"],
        cwd=repo_root,
        check=False,
        capture_output=True,
        text=True,
    )
    if result.returncode != 0:
        raise ProfileV2Error("profile-v2 readiness requires a committed Git HEAD")
    return result.stdout.strip()


def _assert_subject_commit(repo_root: Path, subject_commit: object, head: str) -> None:
    if not isinstance(subject_commit, str):
        raise ProfileV2Error("N/A subject_commit must be a Git commit")
    exists = subprocess.run(
        ["git", "cat-file", "-e", f"{subject_commit}^{{commit}}"],
        cwd=repo_root,
        check=False,
        capture_output=True,
    )
    ancestor = subprocess.run(
        ["git", "merge-base", "--is-ancestor", subject_commit, head],
        cwd=repo_root,
        check=False,
        capture_output=True,
    )
    if exists.returncode != 0 or ancestor.returncode != 0:
        raise ProfileV2Error("N/A subject_commit must be an ancestor of current HEAD")


def validate_profile_v2_readiness(
    repo_root: Path,
    *,
    profile: str,
    evaluated_at: datetime | None = None,
) -> ProfileV2Readiness:
    """Validate all declared v2 capabilities without creating or inferring owners."""

    if profile not in {"standard", "regulated"}:
        raise ProfileV2Error("profile-v2 readiness applies to standard or regulated")
    registry = _load_mapping(repo_root / "governance/canonical-representations.yml")
    _validate_schema(repo_root, "canonical-representations.schema.json", registry)
    representations = registry.get("representations")
    if not isinstance(representations, list) or not representations:
        raise ProfileV2Error("profile v2 requires at least one declared semantic representation")
    head = _head(repo_root)
    instant = evaluated_at or datetime.now(timezone.utc)
    na_paths = sorted((repo_root / "governance/capability-na").glob("*.yml"))
    for path in na_paths:
        payload = _load_mapping(path)
        try:
            validate_ci_contract(repo_root, "capability_na", payload, evaluated_at=instant)
        except CIAuthorityContractError as exc:
            raise ProfileV2Error(f"{path.relative_to(repo_root)}: {exc}") from exc
        _assert_subject_commit(repo_root, payload.get("subject_commit"), head)
        trigger = payload.get("re_review_trigger")
        if isinstance(trigger, dict) and _trigger_is_active(repo_root, trigger):
            raise ProfileV2Error(
                f"{path.relative_to(repo_root)} deterministic re-review trigger is active"
            )
        if profile == "regulated":
            raise ProfileV2Error("regulated profile requirements cannot be bypassed by N/A")
    authority_path = repo_root / "governance/ci-authority.yml"
    authority_state = "absent"
    if authority_path.exists():
        try:
            validate_ci_contract(repo_root, "authority", _load_mapping(authority_path))
        except CIAuthorityContractError as exc:
            raise ProfileV2Error(f"governance/ci-authority.yml: {exc}") from exc
        authority_state = "valid"
    topology_path = repo_root / "governance/github-ci-topology.yml"
    topology_state = "absent"
    if topology_path.exists():
        topology = _load_mapping(topology_path)
        _validate_schema(repo_root, "github-ci-topology.schema.json", topology)
        try:
            validate_reference_topology(topology)
        except GithubReferenceError as exc:
            raise ProfileV2Error(f"governance/github-ci-topology.yml: {exc}") from exc
        roles = {str(role["id"]): role for role in topology["roles"]}
        common = {
            "default_branch": str(topology["default_branch"]),
            "candidate_labels": tuple(roles["exact-ref-producer"]["runner_labels"]),
            "trusted_labels": tuple(roles["trusted-finalizer"]["runner_labels"]),
        }
        if "producer_workflows" in topology:
            desired = render_github_control_plane(
                **common,
                producer_workflow_names=tuple(topology["producer_workflows"]),
                dispatch_exact_ref=bool(topology.get("dispatch_exact_ref", False)),
                controller_commit=topology.get("controller_commit"),
            )
        else:
            desired = render_github_adoption(
                **common, producer_argv=tuple(topology["producer_argv"])
            )
        try:
            adoption = plan_github_adoption(repo_root, desired=desired)
        except GithubAdoptionError as exc:
            raise ProfileV2Error(f"installed GitHub topology is unsafe: {exc}") from exc
        if adoption.status != "clean":
            raise ProfileV2Error(
                "declared GitHub topology is missing managed workflows: "
                + ", ".join(adoption.changed_paths)
            )
        topology_state = "valid"
    runtime_path = repo_root / "governance/ci-runtime.yml"
    runtime_state = "absent"
    if runtime_path.exists():
        try:
            load_runtime_contract(runtime_path)
        except RuntimeCapacityError as exc:
            raise ProfileV2Error(f"governance/ci-runtime.yml: {exc}") from exc
        runtime_state = "valid"
    return ProfileV2Readiness(
        status="ready",
        profile=profile,
        profile_contract_version="2.0",
        semantic_representations=len(representations),
        capability_na_records=len(na_paths),
        ci_authority=authority_state,
        github_topology=topology_state,
        runtime_capacity=runtime_state,
    )
