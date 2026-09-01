from __future__ import annotations

from pathlib import Path

import pytest
import yaml

from bcf_governance.tooling.self_workflow_contracts import (
    SelfWorkflowContractError,
    validate_self_workflow_contracts,
)


REPO_ROOT = Path(__file__).resolve().parents[1]


def test_self_workflow_contracts_are_one_preflight_owned_mechanical_control() -> None:
    assert validate_self_workflow_contracts(REPO_ROOT) == 22


@pytest.mark.parametrize(
    ("field", "value", "diagnostic"),
    (
        ("hosted_fallback_allowed", True, "fallback"),
        ("candidate_substrate", "persistent_shared_vm", "fresh hosted VM"),
        ("coordination_policy", ["polling"], "coordination"),
    ),
)
def test_self_policy_cannot_weaken_compiled_graph_boundaries(
    tmp_path: Path,
    field: str,
    value: object,
    diagnostic: str,
) -> None:
    policy = yaml.safe_load(
        (REPO_ROOT / "governance/self-governance-policy.yml").read_text(
            encoding="utf-8"
        )
    )
    policy["runner_security"][field] = value
    target = tmp_path / "governance/self-governance-policy.yml"
    target.parent.mkdir(parents=True)
    target.write_text(yaml.safe_dump(policy), encoding="utf-8")
    with pytest.raises(SelfWorkflowContractError, match=diagnostic):
        validate_self_workflow_contracts(tmp_path)
