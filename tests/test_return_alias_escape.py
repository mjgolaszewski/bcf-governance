"""An escaped alias invalidates every possibly aliased local receiver."""
from __future__ import annotations

import ast
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
from bcf_governance.tooling.semantic_python_return_facts import discover_return_facts


@pytest.mark.parametrize("escape", [
    "external.interact(alias)",
    "external.interact(value=alias)",
    "alias.interact()",
])
def test_neutral_alias_escape_invalidates_original_receiver(escape: str) -> None:
    source = ("class Model: pass\ndef produce():\n obj = Model()\n alias = obj\n "
              + escape + "\n return obj\n")
    facts = discover_return_facts(ast.parse(source), path="sample.py")[0]
    assert facts["returns"][0]["alternatives"] == [
        {"kind": "unknown", "reason": "escaped_to_call"}]


@pytest.mark.parametrize("escape", [
    "external.interact(alias)",
    "external.interact(value=alias)",
    "alias.interact()",
])
def test_native_alias_escape_refuses_original_receiver(tmp_path: Path, escape: str) -> None:
    source = ("class Model:\n def has_capability(self, value): return True\n"
              "def check():\n obj = Model()\n alias = obj\n "
              + escape + "\n return obj.has_capability('read')\n")
    path = tmp_path / "sample.py"
    path.write_text(source)
    inventory = resolve_python_imports(tmp_path, discover_python_source(tmp_path, [path]))
    operation = {"id": "query", "allowed_mutation_ports": [],
                 "allowed_authority_ports": [], "non_authoritative_output_effects": []}
    with pytest.raises(SemanticOperationEffectError, match="unresolved"):
        validate_operation_effects(operation, "sample.py::check", inventory)
