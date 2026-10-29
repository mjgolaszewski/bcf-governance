"""Supplement v83 with producer/initializer effect controls; source-only UNRUN."""
from __future__ import annotations

from pathlib import Path

import pytest

from bcf_governance.tooling.semantic_operation_effects import (
    SemanticOperationEffectError,
    validate_operation_effects,
)
from bcf_governance.tooling.semantic_ownership_inventory import (
    discover_python_source,
    resolve_python_imports,
)


@pytest.mark.parametrize("location", ["producer", "initializer"])
@pytest.mark.parametrize("effect,reason", [
    ("path.write_text('changed')", "undeclared write"),
    ("publish_release()", "undeclared authority"),
])
def test_return_identity_keeps_producer_and_initializer_effects(
    tmp_path: Path, location: str, effect: str, reason: str,
) -> None:
    model = """class Model:
    capabilities = ()

    def has_capability(self, capability: str) -> bool:
        return capability in self.capabilities
"""
    if location == "initializer":
        model += "\n    def __init__(self):\n        " + effect + "\n"
    producer = "\ndef produce():\n"
    if location == "producer":
        producer += "    " + effect + "\n"
    producer += "    return Model()\n"
    consumer = """
def check():
    claims = produce()
    return claims.has_capability('bdmcp:session_read')
"""
    path = tmp_path / "sample.py"
    path.write_text(model + producer + consumer)
    inventory = resolve_python_imports(
        tmp_path, discover_python_source(tmp_path, [path]),
    )
    function = next(row for row in inventory["functions"]
                    if row["symbol"] == "sample.py::check")
    assert any(call.get("called_symbol") == "sample.py::Model.has_capability"
               for call in function["calls"])
    assert any(call.get("called_symbol") == "sample.py::produce"
               for call in function["calls"])
    if location == "initializer":
        producer_function = next(row for row in inventory["functions"]
                                 if row["symbol"] == "sample.py::produce")
        assert any(call.get("called_symbol") == "sample.py::Model.__init__"
                   for call in producer_function["calls"])
    operation = {"id": "receiver-query", "allowed_mutation_ports": [],
                 "allowed_authority_ports": [], "non_authoritative_output_effects": []}
    with pytest.raises(SemanticOperationEffectError, match=reason):
        validate_operation_effects(operation, "sample.py::check", inventory)
