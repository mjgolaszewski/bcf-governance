from __future__ import annotations

import copy
from pathlib import Path

import pytest

from bcf_governance.tooling.ci_controller_policy import (
    TrustedControllerPolicyError,
    validate_installed_controller_policy,
)


ROOT = Path(__file__).resolve().parents[1]
SHA = "a" * 40
TREE = "b" * 40
DIGEST = "c" * 64


def policy() -> dict:
    return {
        "schema_version": "1.0",
        "runner_security": {
            "trusted_labels": ["Linux", "X64", "fixture", "self-hosted"],
            "trusted_instance_labels": ["fixture-control-1", "fixture-control-2"],
            "trusted_controller_artifact": {
                "BCF_BOOTSTRAP_ARTIFACT_ID": "1",
                "BCF_BOOTSTRAP_ARTIFACT_NAME": "bcf-controller",
                "BCF_BOOTSTRAP_ARTIFACT_DIGEST": f"sha256:{DIGEST}",
                "BCF_BOOTSTRAP_RUN_ID": "1",
                "BCF_BOOTSTRAP_RUN_ATTEMPT": "1",
                "BCF_BOOTSTRAP_COMMIT_SHA": SHA,
                "BCF_BOOTSTRAP_TREE_SHA": TREE,
                "BCF_BOOTSTRAP_REPOSITORY_ID": "1",
                "BCF_BOOTSTRAP_WHEEL_SHA256": DIGEST,
            },
            "trusted_controller_installation": {
                "schema_version": "1.0",
                "installed_commit_sha": SHA,
                "subject_commit_sha": SHA,
                "subject_tree_sha": TREE,
                "bootstrap_run_id": "1",
                "bootstrap_run_attempt": "1",
                "probe_run_id": "2",
                "probe_run_attempt": "1",
            },
        },
        "rotation_policy_paths": [
            "governance/ci-extensions/bcf-controller-rotation.yml",
            "governance/ci-graph.yml",
            "governance/github-protection.yml",
            "governance/trusted-controller-policy.yml",
            "schemas/controller-transition.schema.json",
        ],
    }


def test_installed_controller_policy_is_closed_and_ordinary_current() -> None:
    assert validate_installed_controller_policy(ROOT, policy()) == policy()


@pytest.mark.parametrize("defect", ("target", "runner", "path", "field"))
def test_installed_controller_policy_rejects_ambiguous_custody(defect: str) -> None:
    value = copy.deepcopy(policy())
    if defect == "target":
        value["runner_security"]["trusted_controller_installation"][
            "installed_commit_sha"
        ] = "d" * 40
    elif defect == "runner":
        value["runner_security"]["trusted_instance_labels"] = [
            "fixture-control-1", "fixture-control-1"
        ]
    elif defect == "path":
        value["rotation_policy_paths"].remove("governance/ci-graph.yml")
    else:
        value["candidate_authority"] = True
    with pytest.raises(TrustedControllerPolicyError):
        validate_installed_controller_policy(ROOT, value)
