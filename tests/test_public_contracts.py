from __future__ import annotations

from pathlib import Path
import shutil

import pytest
import yaml

from bcf_governance.tooling.public_contracts import (
    PublicContractError,
    validate_public_contracts,
)


REPO_ROOT = Path(__file__).resolve().parents[1]


def _fixture(tmp_path: Path) -> Path:
    root = tmp_path / "repo"
    (root / "governance").mkdir(parents=True)
    (root / "bcf_governance/tooling").mkdir(parents=True)
    shutil.copytree(REPO_ROOT / "schemas", root / "schemas")
    for relative in (
        "governance/public-contracts.yml",
        "governance/ci-graph.yml",
        "bcf_governance/_version.py",
        "bcf_governance/cli.py",
        "bcf_governance/tooling/ci_graph_render.py",
        "pyproject.toml",
    ):
        destination = root / relative
        destination.parent.mkdir(parents=True, exist_ok=True)
        shutil.copy2(REPO_ROOT / relative, destination)
    return root


def test_public_contract_inventory_matches_executable_owners() -> None:
    inventory = validate_public_contracts(REPO_ROOT)
    assert inventory.package_version == "1.0.1"
    assert inventory.command_count == 19
    assert inventory.contract_count == 6


@pytest.mark.parametrize(
    ("path", "key", "value", "message"),
    [
        pytest.param(
            "package",
            "version",
            "0.0.0",
            "package version",
            id="package-version-mismatch",
        ),
        ("cli", "top_level_commands", ["validate"], "CLI command inventory"),
        ("ci_graph", "extension_points", ["preflight"], "extension points"),
        ("ci_graph", "executor_kinds", ["command"], "executor kinds"),
        ("ci_graph", "generated_header", "hand written", "provenance header"),
        (
            "compatibility",
            "project_owned_paths",
            ["governance/ci-graph.yml"],
            "project-owned paths",
        ),
    ],
)
def test_public_contract_mutants_fail_at_the_canonical_owner(
    tmp_path: Path, path: str, key: str, value: object, message: str
) -> None:
    root = _fixture(tmp_path)
    contract_path = root / "governance/public-contracts.yml"
    payload = yaml.safe_load(contract_path.read_text(encoding="utf-8"))
    payload[path][key] = value
    contract_path.write_text(yaml.safe_dump(payload, sort_keys=False), encoding="utf-8")
    with pytest.raises(PublicContractError, match=message):
        validate_public_contracts(root)


def test_schema_version_mutant_cannot_be_hidden_by_registry_edit(tmp_path: Path) -> None:
    root = _fixture(tmp_path)
    schema_path = root / "schemas/ci-authority.schema.json"
    text = schema_path.read_text(encoding="utf-8").replace(
        '"enum": ["1.0", "1.1"]', '"enum": ["1.1"]', 1
    )
    schema_path.write_text(text, encoding="utf-8")
    with pytest.raises(PublicContractError, match="ci_authority readable versions"):
        validate_public_contracts(root)
