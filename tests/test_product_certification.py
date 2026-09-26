from __future__ import annotations

import copy
from pathlib import Path

import pytest

from bcf_governance.tooling.ci_graph_contracts import validate_ci_graph
from bcf_governance.tooling.governance_validation.product_certification import (
    ProductCertificationError,
    validate_product_certification,
)


ROOT = Path(__file__).resolve().parents[1]


def _sample(index: int) -> dict[str, object]:
    return {
        "subject_commit": f"{index + 1:x}" * 40,
        "custody": {
            "pr_run": f"{100 + index}/1",
            "exact_main_run": f"{200 + index}/1",
            "finalizer_run": f"{300 + index}/1",
            "publisher_run": f"{400 + index}/1",
        },
        "feedback_seconds": 100 + index,
        "certification_seconds": 200 + index,
        "reused_groups": 16,
        "new_groups": 0,
        "invalidated_groups": 0,
        "nodes_avoided": 16,
        "critical_path": "provider_publication",
    }


def _rotation(installed: str, target: str, index: int) -> dict[str, object]:
    return {
        "installed_controller": installed,
        "target_controller": target,
        "implementation_pr_count": 1,
        "bookkeeping_pr_count": 0,
        "copied_identity_count": 0,
        "transition_run": f"{500 + index}/1",
        "receipt_artifact": str(600 + index),
        "final_publisher_run": f"{700 + index}/1",
    }


def _contract() -> dict[str, object]:
    samples = [_sample(index) for index in range(5)]
    adopter_samples = copy.deepcopy(samples)
    for index, sample in enumerate(adopter_samples):
        sample["custody"] = {
            "fixture_run": f"installed-adopter-equivalent-{index + 1}",
            "proof_node": "tests.test_profile_flows::test_fresh_adopter_projects_opt_in_one_pr_controller_rotation",
        }
    workflows = [
        {
            "id": item["id"],
            "proposition": f"workflow:{item['id']}",
            "provider_boundary": "github_actions",
        }
        for item in validate_ci_graph(ROOT).workflows
    ]
    invalidation_nodes = {
        "implementation": "tests.test_evidence_planning::test_isolated_implementation_change_invalidates_only_its_domain",
        "test_population": "tests.test_evidence_planning::test_test_population_change_executes_only_dependent_groups",
        "evidence_runtime": "tests.test_evidence_planning::test_detector_change_invalidates_detector_dependents",
        "governance_profile": "tests.test_evidence_planning::test_unknown_behavior_path_expands_to_full_relevant_profile",
        "toolchain_dependencies": "tests.test_evidence_planning::test_toolchain_change_reports_toolchain_and_environment_contract",
        "workflow_trust": "tests.test_evidence_planning::test_trust_change_reports_trust_and_artifact_identity",
        "negative_control_oracle": "tests.test_evidence_planning::test_main_side_qualification_recomputes_digest_and_control_inventory",
    }
    first, second, third = "a" * 40, "b" * 40, "c" * 40
    return {
        "equivalent_transitions": {"self": samples, "adopter": adopter_samples},
        "selective_invalidation": [
            {"class": key, "proof_node": value, "decision": "invalidate"}
            for key, value in invalidation_nodes.items()
        ],
        "routine_rotations": {
            "self": [_rotation(first, second, 1), _rotation(second, third, 2)],
            "adopter": [_rotation(first, second, 3), _rotation(second, third, 4)],
            "adopter_proof_node": "tests.test_profile_flows::test_fresh_adopter_projects_opt_in_one_pr_controller_rotation",
        },
        "simplicity": {
            "workflows": workflows,
            "mechanisms": [
                {
                    "id": "prospective-train",
                    "proposition": "candidate_downstream_admissibility",
                    "provider_boundary": "local_non_authoritative",
                },
                {
                    "id": "protected-pr",
                    "proposition": "protected_candidate_admission",
                    "provider_boundary": "github_branch_protection",
                },
            ],
        },
        "derived_metrics": {
            "self_feedback_median_seconds": 102,
            "self_feedback_p95_seconds": 104,
            "self_certification_median_seconds": 202,
            "self_certification_p95_seconds": 204,
            "adopter_feedback_median_seconds": 102,
            "adopter_feedback_p95_seconds": 104,
            "adopter_certification_median_seconds": 202,
            "adopter_certification_p95_seconds": 204,
        },
        "release_authority": False,
    }


def test_product_certification_recomputes_complete_empirical_contract() -> None:
    validate_product_certification(ROOT, _contract())


@pytest.mark.parametrize(
    ("mutation", "message"),
    [
        (lambda value: value["equivalent_transitions"]["self"].pop(), "five observations"),
        (lambda value: value["selective_invalidation"].pop(), "classes are not exact"),
        (lambda value: value["routine_rotations"]["self"][1].update(installed_controller="f" * 40), "discontinuous"),
        (lambda value: value["routine_rotations"]["self"][0].update(bookkeeping_pr_count=1), "redundant rotation ceremony"),
        (lambda value: value["simplicity"]["mechanisms"][1].update(proposition="candidate_downstream_admissibility"), "unique propositions"),
        (lambda value: value["derived_metrics"].update(self_feedback_median_seconds=1), "metrics are not mechanically derived"),
    ],
)
def test_product_certification_rejects_incomplete_or_broadened_proof(
    mutation, message: str
) -> None:
    contract = _contract()
    mutation(contract)
    with pytest.raises(ProductCertificationError, match=message):
        validate_product_certification(ROOT, contract)
