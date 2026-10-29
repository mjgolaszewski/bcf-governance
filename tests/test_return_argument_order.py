"""Captured arguments cannot retain model provenance across later evaluation."""
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

SOURCE = """class Model:
    def has_capability(self, value): return True
def identity(value, ignored): return value
"""
QUERY = {"id": "query", "allowed_mutation_ports": [],
         "allowed_authority_ports": [], "non_authoritative_output_effects": []}


@pytest.mark.parametrize("arguments", [
    "obj, external.interact(obj)",
    "value=obj, ignored=external.interact(obj)",
])
def test_neutral_captured_arguments_become_unknown(arguments: str) -> None:
    source = SOURCE + "def check():\n obj = Model()\n return identity(" + arguments + ")\n"
    facts = next(row for row in discover_return_facts(ast.parse(source), path="sample.py")
                 if row["symbol"] == "sample.py::check")
    call = next(row for row in facts["call_sites"] if row["callee"] == "identity")
    origins = [*call["arguments"], *(row["origins"] for row in call["keywords"])]
    assert origins and all(group == [{"kind": "unknown", "reason": "argument_after_evaluation"}]
                           for group in origins)


@pytest.mark.parametrize("arguments", [
    "obj, external.interact(obj)",
    "value=obj, ignored=external.interact(obj)",
])
def test_native_captured_argument_alias_is_not_a_model(tmp_path: Path, arguments: str) -> None:
    path = tmp_path / "sample.py"
    path.write_text(SOURCE + "def check():\n obj = Model()\n returned = identity(" + arguments
                    + ")\n return returned.has_capability('read')\n")
    inventory = resolve_python_imports(tmp_path, discover_python_source(tmp_path, [path]))
    with pytest.raises(SemanticOperationEffectError, match="unresolved"):
        validate_operation_effects(QUERY, "sample.py::check", inventory)


def test_simple_argument_alias_return_keeps_real_model_edge(tmp_path: Path) -> None:
    path = tmp_path / "sample.py"
    path.write_text(SOURCE + "def check():\n obj = Model()\n returned = identity(obj, None)\n"
                    " return returned.has_capability('read')\n")
    inventory = resolve_python_imports(tmp_path, discover_python_source(tmp_path, [path]))
    function = next(row for row in inventory["functions"] if row["symbol"] == "sample.py::check")
    assert any(call.get("called_symbol") == "sample.py::Model.has_capability"
               for call in function["calls"])
    assert validate_operation_effects(QUERY, "sample.py::check", inventory) == (0, 0)


@pytest.mark.parametrize("escape", ["produce", "value=produce"])
def test_escaped_source_function_is_unknown_even_without_a_model_read(
    tmp_path: Path, escape: str,
) -> None:
    path = tmp_path / "sample.py"
    path.write_text("def produce(): return 1\ndef check():\n external.interact("
                    + escape + ")\n return produce()\n")
    inventory = resolve_python_imports(tmp_path, discover_python_source(tmp_path, [path]))
    with pytest.raises(SemanticOperationEffectError, match="unresolved"):
        validate_operation_effects(QUERY, "sample.py::check", inventory)
