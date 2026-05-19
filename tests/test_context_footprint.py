from __future__ import annotations

from pathlib import Path


REPO_ROOT = Path(__file__).resolve().parents[1]
TEMPLATE_ROOT = REPO_ROOT / "template-repo"


def _line_count(relative_path: str) -> int:
    return len((TEMPLATE_ROOT / relative_path).read_text(encoding="utf-8").splitlines())


def test_agent_facing_governance_files_remain_small_context_friendly() -> None:
    budgets = {
        "AGENTS.md": 8,
        "CLAUDE.md": 8,
        "AGENTS.yml": 180,
        "MEMORY.yml": 105,
        "architecture-boundaries.yml": 120,
        "governance-profile.yml": 95,
        "governance/artifact-manifest.yml": 80,
        "governance/repo-cleanup-contract.yml": 90,
        "plans/build-plan.yml": 95,
        "plans/phase-ledger.yml": 95,
        "plans/product-spec.yml": 40,
        "contracts/observability/v1/telemetry.contract.yml": 70,
        "contracts/observability/v1/logging.contract.yml": 70,
    }

    violations = [
        f"{path} has {_line_count(path)} lines; budget is {budget}"
        for path, budget in budgets.items()
        if _line_count(path) > budget
    ]

    assert not violations, "agent-facing context files exceeded line budgets:\n" + "\n".join(violations)


def test_append_policy_requires_terse_entries_with_full_intent() -> None:
    agents = (TEMPLATE_ROOT / "AGENTS.yml").read_text(encoding="utf-8")

    assert "append entries tersely" in agents
    assert "full intent" in agents
