from __future__ import annotations

from pathlib import Path

import yaml


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
        "plans/phase-history.yml": 40,
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


def test_agent_deconstruction_contract_caps_source_files_at_800_loc() -> None:
    agents = yaml.safe_load((TEMPLATE_ROOT / "AGENTS.yml").read_text(encoding="utf-8"))
    contract = agents["structural_guardrails"]["agent_deconstruction_contract"]

    assert contract["max_loc"] == 800
    assert contract["oversized_file_response"] == "start_deconstruction_phase_before_adding_feature_behavior"
    assert set(contract["required_phase_rules"]) >= {
        "one_fatty_per_phase",
        "characterization_test_first",
        "preserve_cli_entrypoint",
        "split_by_responsibility",
        "split_shape_plan_validate_execute_report",
        "ast_boundary_gate",
        "targeted_tests",
        "delete_dead_code_immediately",
    }
