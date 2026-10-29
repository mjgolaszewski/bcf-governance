"""Built-in gate profile declarations, without repository effects."""

from __future__ import annotations

from typing import Any


def _builtin_contracts() -> dict[str, dict[str, Any]]:
    return {
        "governance-validate": {
            "invocation": {
                "argv": ["python3", "scripts/validate_governance_yaml.py", "--repo-root", "."],
                "cwd": ".",
                "env": {},
                "required_env": [],
            },
            "evidence": {"kind": "gate"},
            "negative_controls": [
                {
                    "id": "authored-verified-state-is-rejected",
                    "mutation": {
                        "path": "@active_phase_log",
                        "yaml_path": "document.status",
                        "value": "verified",
                    },
                    "oracle": {
                        "kind": "diagnostic",
                        "exit_codes": [1],
                        "stream": "stderr",
                        "regex": "verified.*(?:not one of|computed)",
                    },
                }
            ],
        },
        "governance-exposure-scan": {
            "invocation": {
                "argv": ["python3", "scripts/check_governance_exposure.py", "--repo-root", "."],
                "cwd": ".",
                "env": {},
                "required_env": [],
            },
            "evidence": {"kind": "gate"},
            "negative_controls": [
                {
                    "id": "local-workspace-path-is-rejected",
                    "mutation": {
                        "path": "MEMORY.yml",
                        "yaml_path": "stable_decisions.canonical_governance_guide",
                        "value_base64": "L1VzZXJzL2V4YW1wbGUvcHJpdmF0ZS9BR0VOVFMueW1s",
                    },
                    "oracle": {
                        "kind": "diagnostic",
                        "exit_codes": [1],
                        "stream": "stdout",
                        "regex": "local_workspace_path",
                    },
                }
            ],
        },
    }

def _semantic_owner_control(index: int) -> dict[str, Any]:
    return {
        "id": f"canonical-owner-{index + 1}-is-enforced",
        "mutation": {
            "path": "governance/canonical-representations.yml",
            "yaml_path": f"representations.{index}.authorized_constructors_and_factories",
            "value": ["scripts/_bcf_runtime/missing.py::owner"],
        },
        "oracle": {
            "kind": "diagnostic",
            "exit_codes": [1],
            "stream": "stdout",
            "regex": "owner must be an authorized constructor",
        },
    }

def _v2_builtin_contracts() -> dict[str, dict[str, Any]]:
    return {
        "semantic-ownership": {
            "invocation": {
                "argv": ["python3", "scripts/semantic_ownership.py", "--repo-root", "."],
                "cwd": ".",
                "env": {},
                "required_env": [],
            },
            "evidence": {
                "kind": "gate",
                "output_requirements": [
                    {
                        "path": ".artifacts/semantic-ownership/report.json",
                        "media_type": "application/json",
                    }
                ],
            },
            "negative_controls": [
                _semantic_owner_control(0),
            ],
        }
    }
