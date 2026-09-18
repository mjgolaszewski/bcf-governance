from __future__ import annotations

from pathlib import Path

import yaml

from bcf_governance.tooling.truth_receipts import _multi_claim_test_issues


def _repo(tmp_path: Path, *, declare_manifest: bool = True) -> Path:
    root = tmp_path / "repo"
    manifest = root / "governance/test-manifests/subset.txt"
    manifest.parent.mkdir(parents=True)
    manifest.write_text("tests.test_subset::test_required\n", encoding="utf-8")
    test_contract = (
        {"expected_node_manifest": "governance/test-manifests/subset.txt"}
        if declare_manifest
        else {}
    )
    registry = {
        "gates": {
            "test": {
                "evidence": {"kind": "test_suite", "test_contract": test_contract}
            }
        },
        "claim_model": {
            "version": "1.0",
            "dependency_sets": {"all": ["**"]},
            "execution_groups": {
                "python-tests": {"producer": "test", "claims": ["subset", "broad"]}
            },
            "claims": {
                claim: {
                    "truth": claim,
                    "execution_group": "python-tests",
                    "legacy_gate": "test",
                    "dependencies": {
                        "subject": ["all"],
                        "detector": ["all"],
                        "test_population": ["all"],
                        "toolchain": ["all"],
                        "trust": ["all"],
                    },
                    "qualification_scope": "subject",
                    "profiles": ["normal"],
                }
                for claim in ("subset", "broad")
            },
        },
    }
    path = root / "governance/gate-contracts.yml"
    path.write_text(yaml.safe_dump(registry, sort_keys=False), encoding="utf-8")
    return root


def test_green_broad_run_missing_required_subset_cannot_overclaim(tmp_path: Path) -> None:
    root = _repo(tmp_path)
    receipt = {
        "schema_version": "3.0",
        "kind": "test_suite",
        "claims": ["subset", "broad"],
        "observations": {"test_node_ids": ["tests.test_other::test_green"]},
    }
    assert _multi_claim_test_issues(root, receipt) == [
        "claim_subset_expected_test_nodes_missing",
        "claim_broad_expected_test_nodes_missing",
    ]


def test_test_claim_without_population_manifest_fails_closed(tmp_path: Path) -> None:
    root = _repo(tmp_path, declare_manifest=False)
    receipt = {
        "schema_version": "3.0",
        "kind": "test_suite",
        "claims": ["subset"],
        "observations": {"test_node_ids": ["tests.test_subset::test_required"]},
    }
    assert _multi_claim_test_issues(root, receipt) == [
        "claim_subset_test_manifest_undeclared"
    ]


def test_malformed_required_claim_gate_contract_fails_closed(tmp_path: Path) -> None:
    root = _repo(tmp_path)
    path = root / "governance/gate-contracts.yml"
    registry = yaml.safe_load(path.read_text(encoding="utf-8"))
    del registry["claim_model"]["execution_groups"]["python-tests"]
    path.write_text(yaml.safe_dump(registry, sort_keys=False), encoding="utf-8")
    receipt = {
        "schema_version": "3.0",
        "kind": "test_suite",
        "claims": ["subset"],
        "observations": {"test_node_ids": ["tests.test_subset::test_required"]},
    }

    assert _multi_claim_test_issues(root, receipt) == ["claim_contract_unreadable"]
