"""context budget validation helpers."""
# ruff: noqa: F403,F405

from __future__ import annotations

from .common import *  # noqa: F403,F405


def _context_budget_limits(budget: Any, *, context: str) -> tuple[int, int | None]:
    if isinstance(budget, int):
        return _require_positive_int(budget, context=context), None

    budget_mapping = _require_mapping(budget, context=context)
    line_hard_cap = _require_positive_int(
        budget_mapping.get("line_hard_cap"),
        context=f"{context}.line_hard_cap",
    )
    kib_hard_cap = _require_positive_int(
        budget_mapping.get("kib_hard_cap"),
        context=f"{context}.kib_hard_cap",
    )
    return line_hard_cap, kib_hard_cap


def _agent_required_context_files(
    repo_root: Path, context_budgets: dict[str, Any]
) -> dict[str, Path]:
    agent_required_files = _require_mapping(
        context_budgets.get("agent_required_files"),
        context="governance/artifact-manifest.yml context_budgets.agent_required_files",
    )
    paths: dict[str, Path] = {}
    for relative_path in agent_required_files:
        paths[str(relative_path)] = _require_path(
            repo_root,
            str(relative_path),
            context=(
                "governance/artifact-manifest.yml "
                f"context_budgets.agent_required_files.{relative_path}"
            ),
        )
    return paths


def _validate_context_budgets(repo_root: Path, manifest: dict[str, Any]) -> None:
    context_budgets = _require_mapping(
        manifest.get("context_budgets"),
        context="governance/artifact-manifest.yml context_budgets",
    )
    agent_required_files = _require_mapping(
        context_budgets.get("agent_required_files"),
        context="governance/artifact-manifest.yml context_budgets.agent_required_files",
    )
    violations: list[str] = []
    for relative_path, budget in agent_required_files.items():
        budget_context = (
            "governance/artifact-manifest.yml "
            f"context_budgets.agent_required_files.{relative_path}"
        )
        line_hard_cap, kib_hard_cap = _context_budget_limits(budget, context=budget_context)
        path = _require_path(repo_root, str(relative_path), context=budget_context)
        raw_content = path.read_bytes()
        line_count = len(raw_content.decode("utf-8").splitlines())
        if line_count > line_hard_cap:
            violations.append(
                f"{relative_path} has {line_count} lines; line budget is {line_hard_cap}"
            )
        if kib_hard_cap is not None and len(raw_content) > kib_hard_cap * 1024:
            size_kib = len(raw_content) / 1024
            violations.append(
                f"{relative_path} is {size_kib:.1f} KiB; KiB budget is {kib_hard_cap}"
            )
    if violations:
        raise GovernanceValidationError(
            "agent-required governance files exceeded context budgets:\n" + "\n".join(violations)
        )
    advisory = context_budgets.get("aggregate_agent_required_kib_advisory")
    if advisory is not None:
        _require_positive_int(
            advisory,
            context=(
                "governance/artifact-manifest.yml "
                "context_budgets.aggregate_agent_required_kib_advisory"
            ),
        )


def _context_budget_advisories(repo_root: Path) -> list[str]:
    manifest_path = repo_root / "governance/artifact-manifest.yml"
    if not manifest_path.exists():
        return []
    manifest = _load_yaml(manifest_path)
    context_budgets = _require_mapping(
        manifest.get("context_budgets"),
        context="governance/artifact-manifest.yml context_budgets",
    )
    advisory = context_budgets.get("aggregate_agent_required_kib_advisory")
    if advisory is None:
        return []
    advisory_kib = _require_positive_int(
        advisory,
        context=(
            "governance/artifact-manifest.yml "
            "context_budgets.aggregate_agent_required_kib_advisory"
        ),
    )
    total_bytes = sum(
        path.stat().st_size
        for path in _agent_required_context_files(repo_root, context_budgets).values()
    )
    if total_bytes <= advisory_kib * 1024:
        return []
    return [
        "agent-required governance context is "
        f"{total_bytes / 1024:.1f} KiB; recommended maximum is {advisory_kib} KiB"
    ]
