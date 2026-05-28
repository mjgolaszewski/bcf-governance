from __future__ import annotations

from pathlib import Path

import yaml


REPO_ROOT = Path(__file__).resolve().parents[1]
TEMPLATE_ROOT = REPO_ROOT / "template-repo"


def _line_count(relative_path: str) -> int:
    return len((TEMPLATE_ROOT / relative_path).read_text(encoding="utf-8").splitlines())


def _kib_size(relative_path: str) -> float:
    return (TEMPLATE_ROOT / relative_path).stat().st_size / 1024


def _budget_value(budget: object, key: str) -> int | None:
    if isinstance(budget, int):
        return budget if key == "line_hard_cap" else None
    if isinstance(budget, dict) and isinstance(budget.get(key), int):
        return int(budget[key])
    return None


def test_agent_facing_governance_files_remain_small_context_friendly() -> None:
    manifest = yaml.safe_load(
        (TEMPLATE_ROOT / "governance/artifact-manifest.yml").read_text(encoding="utf-8")
    )
    budgets = dict(manifest["context_budgets"]["agent_required_files"])
    budgets.update(
        {
            "contracts/observability/v1/telemetry.contract.yml": {"line_hard_cap": 70},
            "contracts/observability/v1/logging.contract.yml": {"line_hard_cap": 70},
        }
    )

    violations: list[str] = []
    for path, budget in budgets.items():
        line_hard_cap = _budget_value(budget, "line_hard_cap")
        kib_hard_cap = _budget_value(budget, "kib_hard_cap")
        if line_hard_cap is not None and _line_count(path) > line_hard_cap:
            violations.append(
                f"{path} has {_line_count(path)} lines; line budget is {line_hard_cap}"
            )
        if kib_hard_cap is not None and _kib_size(path) > kib_hard_cap:
            violations.append(f"{path} is {_kib_size(path):.1f} KiB; KiB budget is {kib_hard_cap}")

    assert not violations, "agent-facing context files exceeded context budgets:\n" + "\n".join(violations)


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


def test_governance_scripts_stay_under_deconstruction_cap() -> None:
    roots = [
        REPO_ROOT / "scripts",
        TEMPLATE_ROOT / "scripts",
        REPO_ROOT / "bcf_governance/pack/template-repo/scripts",
    ]
    violations: list[str] = []
    for root in roots:
        for path in sorted(root.rglob("*.py")):
            if "__pycache__" in path.parts:
                continue
            line_count = len(path.read_text(encoding="utf-8").splitlines())
            if line_count > 800:
                violations.append(f"{path.relative_to(REPO_ROOT)} has {line_count} lines")

    assert not violations, "governance scripts exceeded 800 LOC:\n" + "\n".join(violations)
