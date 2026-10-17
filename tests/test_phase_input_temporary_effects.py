"""Classify only the temporary verifier's actual write leaves, with causal removal."""

from copy import deepcopy
from pathlib import Path

import pytest
import yaml

from bcf_governance.tooling.semantic_ownership_inventory import discover_python_source
from bcf_governance.tooling.semantic_operation_effects import (
    SemanticOperationEffectError, validated_operation_effect_inventory,
)

ROOT = Path(__file__).resolve().parents[1]
SOURCE = "bcf_governance/tooling/trusted_inputs.py"
LEAVES = [SOURCE + "::path.parent.mkdir", SOURCE + "::path.write_bytes"]


@pytest.mark.parametrize("operation_id", ["governance.cli.preflight.v1", "governance.cli.truth.v1"])
@pytest.mark.parametrize("leaf", LEAVES)
def test_temporary_phase_write_leaf_is_declared_and_causal(operation_id, leaf):
    operations = yaml.safe_load((ROOT / "governance/application-operations.yml").read_text())["operations"]
    public = next(value for value in operations if value["id"] == operation_id)
    assert leaf in public["non_authoritative_output_effects"]
    assert SOURCE + "::verify_phase_closure_input" not in public["non_authoritative_output_effects"]
    assert all(value not in public["allowed_mutation_ports"] + public["allowed_authority_ports"] for value in LEAVES)
    # This fixture qualifies the real helper's leaves; the complete public graph is checked separately.
    inventory = discover_python_source(ROOT, files=[ROOT / SOURCE])
    helper = {"id": operation_id, "allowed_mutation_ports": [], "allowed_authority_ports": [],
              "non_authoritative_output_effects": LEAVES}
    observed = validated_operation_effect_inventory(helper, SOURCE + "::verify_phase_closure_input", inventory)
    assert {row[2] for row in observed} == set(LEAVES)
    removed = deepcopy(helper)
    removed["non_authoritative_output_effects"].remove(leaf)
    with pytest.raises(SemanticOperationEffectError, match="undeclared write effects"):
        validated_operation_effect_inventory(removed, SOURCE + "::verify_phase_closure_input", inventory)
