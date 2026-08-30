"""Emit the reproducible standard profile input used by this repository."""

from __future__ import annotations

import argparse
import sys
from pathlib import Path
from typing import Any

import yaml


TEST_CONTROLS = {
    "architecture-test": (
        "architecture-boundaries.yml",
        "source_roots: [bcf_governance]",
        "source_roots: [missing_package]",
        "tests.test_self_governance_contracts::test_source_roots_match_packaged_implementation",
    ),
    "architecture-module-size": (
        "architecture-boundaries.yml",
        "max_loc: 800",
        "max_loc: 1",
        "tests.test_self_governance_contracts::test_production_modules_respect_self_governance_loc_cap",
    ),
    "architecture-layer-membership": (
        "architecture-boundaries.yml",
        "path_tokens: [pack]",
        "path_tokens: [missing_pack]",
        "tests.test_self_governance_contracts::test_source_layout_maps_to_declared_package_layers",
    ),
    "architecture-context-membership": (
        "governance/self-governance-policy.yml",
        "validation: [check_governance_exposure.py, doctor_governance_pack.py, preflight.py, validate_governance_yaml.py, governance_validation/]",
        "validation: [check_governance_exposure.py, doctor_governance_pack.py, preflight.py, validate_governance_yaml.py, missing_validation/]",
        "tests.test_self_governance_contracts::test_tooling_modules_map_to_exactly_one_context",
    ),
    "architecture-import-boundaries": (
        "bcf_governance/__init__.py",
        "from ._version import __version__",
        "import scripts\nfrom ._version import __version__",
        "tests.test_self_governance_contracts::test_packaged_code_does_not_import_public_wrapper_package",
    ),
    "architecture-cqrs-side": (
        "governance/self-governance-policy.yml",
        "read_only: [doctor, exposure-scan, preflight, publish-audit, truth, validate]",
        "read_only: [doctor, exposure-scan, preflight, publish-audit, validate]",
        "tests.test_self_governance_contracts::test_cli_command_query_sides_are_complete_and_disjoint",
    ),
    "architecture-router-thinness": (
        "governance/self-governance-policy.yml",
        "thin_wrapper_loc_cap: 20",
        "thin_wrapper_loc_cap: 1",
        "tests.test_self_governance_contracts::test_cli_and_source_wrappers_remain_thin",
    ),
    "architecture-duplication": (
        "template-repo/scripts/_bcf_runtime/governance_validation/required_artifacts.py",
        '"""Semantic contracts for standard repository root artifacts."""',
        '"""Mutated standalone runtime contract."""',
        "tests.test_self_governance_contracts::test_template_and_private_runtime_copies_are_exact",
    ),
    "test": (
        "template-repo/governance/artifact-manifest.yml",
        "readme: {path: README.md, contract: project_readme}",
        "readme: {path: README.md, contract: broken_readme}",
        "tests.test_validate_governance_yaml::test_artifact_manifest_requires_standard_repository_artifact_contracts",
    ),
    "contract-test": (
        "template-repo/governance/artifact-manifest.yml",
        "pull_request_policy: required_update",
        "pull_request_policy: optional",
        "tests.test_validate_governance_yaml::test_artifact_manifest_requires_standard_repository_artifact_contracts",
    ),
}

TEST_SELECTORS = {
    "architecture-test": ["tests/test_self_governance_contracts.py::test_source_roots_match_packaged_implementation"],
    "architecture-module-size": ["tests/test_self_governance_contracts.py::test_production_modules_respect_self_governance_loc_cap"],
    "architecture-layer-membership": ["tests/test_self_governance_contracts.py::test_source_layout_maps_to_declared_package_layers"],
    "architecture-context-membership": ["tests/test_self_governance_contracts.py::test_tooling_modules_map_to_exactly_one_context"],
    "architecture-import-boundaries": ["tests/test_self_governance_contracts.py::test_packaged_code_does_not_import_public_wrapper_package"],
    "architecture-cqrs-side": ["tests/test_self_governance_contracts.py::test_cli_command_query_sides_are_complete_and_disjoint"],
    "architecture-router-thinness": ["tests/test_self_governance_contracts.py::test_cli_and_source_wrappers_remain_thin"],
    "architecture-duplication": ["tests/test_self_governance_contracts.py::test_template_and_private_runtime_copies_are_exact"],
    "contract-test": [
        "tests/test_self_governance_contracts.py::test_required_repository_artifact_contract_is_executable",
        "tests/test_validate_governance_yaml.py::test_artifact_manifest_requires_standard_repository_artifact_contracts",
        "tests/test_validate_governance_yaml.py::test_pull_request_validation_requires_changelog_update",
    ],
    "test": ["@test_roots"],
}

DIAGNOSTIC_CONTROLS = {
    "lint": (
        "README.md",
        "# BCF Governance",
        "# BCF Governance  ",
    ),
    "typecheck": (
        "bcf_governance/_version.py",
        '__version__ = "0.6.1"',
        'VERSION = "0.6.1"',
    ),
    "security-secret-scan": (
        "README.md",
        "BCF is an executable governance framework",
        "QUtJQUlPU0ZPRE5ON0VYQU1QTEUgQkNGIGlzIGFuIGV4ZWN1dGFibGUgZ292ZXJuYW5jZSBmcmFtZXdvcms=",
    ),
    "security-dependency-audit": (
        "pyproject.toml",
        '"jsonschema>=4.21,<5",',
        '"jsonschema>=4.21,<4",',
    ),
    "security-sbom": (
        "governance/self-governance-policy.yml",
        "sbom_format: CycloneDX",
        "sbom_format: Unknown",
    ),
    "security-vulnerability-scan": (
        "governance/self-governance-policy.yml",
        "forbid_subprocess_shell: true",
        "forbid_subprocess_shell: false",
    ),
    "security-review": (
        "governance/findings.yml",
        "reviews: []",
        "reviews:\n  - invalid",
    ),
    "runtime-smoke": (
        "manifest.yml",
        "version: 0.6.1",
        "version: 0.0.0",
    ),
}


def _test_gate(target: str, control: tuple[str, str, str, str]) -> dict[str, Any]:
    path, search, replace, node_id = control
    return {
        "invocation": {
            "argv": ["python3", ".github/scripts/run_self_governance_gate.py", target],
            "cwd": ".",
            "env": {},
            "required_env": [],
        },
        "evidence": {
            "kind": "test_suite",
            "test_contract": {
                "junit_xml": f".artifacts/junit/{target}.xml",
                "selectors": TEST_SELECTORS[target],
                "expected_node_manifest": f"governance/test-manifests/{target}.txt",
                "expected_nodes_mode": "exact",
                "min_collected": 1,
                "min_executed": 1,
                "max_skipped": 0,
                "artifact_binding": "non_authoritative_until_captured",
            },
        },
        "negative_controls": [
            {
                "id": f"{target}-behavior-must-fail",
                "mutation": {"path": path, "search": search, "replace": replace},
                "oracle": {"kind": "test_node_failure", "node_ids": [node_id]},
            }
        ],
    }


def _diagnostic_gate(target: str, control: tuple[str, str, str]) -> dict[str, Any]:
    path, search, replace = control
    mutation = {"path": path, "search": search, "replace": replace}
    if target == "security-secret-scan":
        mutation = {"path": path, "search": search, "replace_base64": replace}
    evidence: dict[str, Any] = {"kind": "gate"}
    env: dict[str, str] = {}
    if target == "security-sbom":
        evidence["output_requirements"] = [
            {"path": ".artifacts/sbom.json", "media_type": "application/json"}
        ]
    elif target == "security-vulnerability-scan":
        evidence["output_requirements"] = [
            {"path": ".artifacts/vulnerability-scan.json", "media_type": "application/json"}
        ]
    elif target == "security-review":
        evidence = {
            "kind": "security_review",
            "output_requirements": [
                {"path": "governance/findings.yml", "media_type": "application/yaml"}
            ],
            "environment_assertions": [
                {"name": "BCF_EXECUTION_PROFILE", "operator": "equals", "value": "production"}
            ],
        }
        env = {"BCF_EXECUTION_PROFILE": "production"}
    elif target == "runtime-smoke":
        evidence = {
            "kind": "runtime_health",
            "output_requirements": [
                {"path": ".artifacts/runtime-smoke.json", "media_type": "application/json"}
            ],
            "environment_assertions": [
                {"name": "BCF_EXECUTION_PROFILE", "operator": "equals", "value": "production"}
            ],
        }
        env = {"BCF_EXECUTION_PROFILE": "production"}
    return {
        "invocation": {
            "argv": ["python3", ".github/scripts/run_self_governance_gate.py", target],
            "cwd": ".",
            "env": env,
            "required_env": [],
        },
        "evidence": evidence,
        "negative_controls": [
            {
                "id": f"{target}-behavior-must-fail",
                "mutation": mutation,
                "oracle": {
                    "kind": "diagnostic",
                    "exit_codes": [1],
                    "stream": "stderr",
                    "regex": f"self-governance gate {target} failed:",
                },
            }
        ],
    }


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--output", type=Path)
    args = parser.parse_args()
    gates = {
        **{target: _test_gate(target, control) for target, control in TEST_CONTROLS.items()},
        **{
            target: _diagnostic_gate(target, control)
            for target, control in DIAGNOSTIC_CONTROLS.items()
        },
    }
    text = yaml.safe_dump(
        {
            "schema_version": "1.0",
            "target_profile": "standard",
            "gates": gates,
            "provenance": {},
        },
        sort_keys=False,
        width=120,
    )
    if args.output is None:
        sys.stdout.write(text)
    else:
        args.output.write_text(text, encoding="utf-8")


if __name__ == "__main__":
    main()
