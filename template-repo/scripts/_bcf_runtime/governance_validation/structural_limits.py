"""Cheap hard-limit checks that must precede projections and behavioral gates."""

from __future__ import annotations

from pathlib import Path
from typing import Any

from .common import (
    GovernanceValidationError,
    _load_yaml,
    _require_mapping,
    _require_positive_int,
)
from .context_budgets import _validate_context_budgets
from .audit_artifacts import _validated_code_root


def validate_tooling_context_membership(repo_root: Path) -> None:
    """Fail early when a self-governed tooling module has no unique context."""

    policy_path = repo_root / "governance/self-governance-policy.yml"
    if not policy_path.is_file():
        return
    contexts = _load_yaml(policy_path).get("tooling_contexts")
    if not isinstance(contexts, dict) or not contexts:
        raise GovernanceValidationError("self-governance tooling_contexts are missing")
    tooling_root = repo_root / "bcf_governance/tooling"
    for path in sorted(tooling_root.rglob("*.py")):
        relative = path.relative_to(tooling_root).as_posix()
        if relative == "__init__.py" or relative.endswith("/__init__.py"):
            continue
        matches = [
            name
            for name, prefixes in contexts.items()
            if isinstance(prefixes, list)
            and any(
                isinstance(prefix, str)
                and (relative == prefix or relative.startswith(prefix))
                for prefix in prefixes
            )
        ]
        if len(matches) != 1:
            raise GovernanceValidationError(
                f"tooling context membership: {relative} maps to {matches}"
            )


def validate_context_budgets(repo_root: Path) -> int:
    """Validate exact authored context bytes through the canonical budget owner."""

    manifest = _require_mapping(
        _load_yaml(repo_root / "governance/artifact-manifest.yml"),
        context="governance/artifact-manifest.yml",
    )
    _validate_context_budgets(repo_root, manifest)
    budgets = _require_mapping(
        manifest.get("context_budgets"),
        context="governance/artifact-manifest.yml context_budgets",
    )
    return len(
        _require_mapping(
            budgets.get("agent_required_files"),
            context=(
                "governance/artifact-manifest.yml "
                "context_budgets.agent_required_files"
            ),
        )
    )


def validate_production_module_size(repo_root: Path) -> int:
    """Reject production Python modules beyond the governed LOC cap."""

    payload = _require_mapping(
        _load_yaml(repo_root / "architecture-boundaries.yml"),
        context="architecture-boundaries.yml",
    )
    architecture = _require_mapping(
        payload.get("architecture"), context="architecture-boundaries.yml architecture"
    )
    policy = _require_mapping(
        architecture.get("production_module_policy"),
        context="architecture-boundaries.yml architecture.production_module_policy",
    )
    cap = _require_positive_int(
        policy.get("max_loc"),
        context=(
            "architecture-boundaries.yml "
            "architecture.production_module_policy.max_loc"
        ),
    )
    raw_roots = architecture.get("source_roots")
    if not isinstance(raw_roots, list) or not raw_roots:
        raise GovernanceValidationError(
            "architecture-boundaries.yml architecture.source_roots must be a non-empty list"
        )
    root_names = [
        _validated_code_root(
            repo_root,
            str(value),
            context="architecture-boundaries.yml architecture.source_roots",
        )
        for value in raw_roots
        if isinstance(value, str) and value
    ]
    if len(root_names) != len(raw_roots):
        raise GovernanceValidationError(
            "architecture-boundaries.yml architecture.source_roots is invalid"
        )
    roots = [repo_root / name for name in root_names if (repo_root / name).is_dir()]
    modules = sorted(
        path
        for root in roots
        for path in root.rglob("*.py")
        if "__pycache__" not in path.parts
    )
    violations = [
        f"{path.relative_to(repo_root)}:{len(path.read_text(encoding='utf-8').splitlines())}"
        for path in modules
        if len(path.read_text(encoding="utf-8").splitlines()) > cap
    ]
    if violations:
        raise GovernanceValidationError(
            "production module LOC cap exceeded: " + ", ".join(violations)
        )
    return len(modules)


def validate_structural_limits(repo_root: Path) -> dict[str, Any]:
    """Run all directly measurable hard limits before longer validation."""
    validate_tooling_context_membership(repo_root)

    return {
        "context_files": validate_context_budgets(repo_root),
        "production_modules": validate_production_module_size(repo_root),
    }
