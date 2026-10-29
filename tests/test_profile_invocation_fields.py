"""Optional invocation fields survive a complete native Standard compilation."""
from __future__ import annotations

import copy
import json
import shutil
from pathlib import Path
from typing import Any

import jsonschema
import pytest
import yaml

from bcf_governance.tooling.governance_profiles import (
    ProfileContractError,
    apply_profile_contract,
    load_contract,
)

ROOT = Path(__file__).resolve().parents[1]
FIXTURES = Path(__file__).with_name("fixtures") / "profile-invocation"
CASES = json.loads((FIXTURES / "cases.json").read_text())["cases"]


@pytest.mark.parametrize("case", CASES, ids=[case["id"] for case in CASES])
def test_full_standard_invocation_fields(case: dict[str, Any], tmp_path: Path) -> None:
    payload = json.loads((FIXTURES / "healthy-21.json").read_text())
    before = copy.deepcopy(payload)
    groups = payload["application_assurance"]["groups"]
    assert len(groups) == 21
    invocation = groups["runtime-smoke"]["gate"]["invocation"]
    for key in ("state", "timeout_seconds", "requires_execution_owner"):
        invocation.pop(key, None)
    invocation.update(copy.deepcopy(case["invocation_patch"]))
    expected = copy.deepcopy(invocation)
    if case["expected"] == "schema-or-contract-refusal":
        with pytest.raises(ProfileContractError):
            load_contract(ROOT / "template-repo", "standard", None,
                          contract_version="3.0", config_payload=payload, fresh_install=True)
        return
    compiled = load_contract(ROOT / "template-repo", "standard", None,
                             contract_version="3.0", config_payload=payload, fresh_install=True)
    assert compiled["gates"]["runtime-smoke"]["invocation"] == expected
    assert len(compiled["gates"]) == 21
    assert payload["application_assurance"]["groups"].keys() == before["application_assurance"]["groups"].keys()
    schema = json.loads((ROOT / "schemas/gate-contracts.schema.json").read_text())
    consumer = tmp_path / "consumer"
    (consumer / "governance").mkdir(parents=True)
    for relative in ("governance-profile.yml", "governance/evidence-policy.yml"):
        shutil.copyfile(ROOT / "template-repo" / relative, consumer / relative)
    apply_profile_contract(consumer, compiled, write_workflow=False)
    persisted = yaml.safe_load((consumer / "governance/gate-contracts.yml").read_text())
    assert persisted["gates"]["runtime-smoke"]["invocation"] == expected
    jsonschema.Draft202012Validator(schema).validate(persisted)
