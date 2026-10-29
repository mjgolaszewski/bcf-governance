"""Source binding/argument evaluation stability controls; source-only UNRUN."""
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

MODEL = """class Model:
    def has_capability(self, capability): return True
    def validate(self, ignored): return self
def produce(): return Model()
"""
QUERY = {"id": "query", "allowed_mutation_ports": [],
         "allowed_authority_ports": [], "non_authoritative_output_effects": []}


@pytest.mark.parametrize("binding", ["Model", "produce"])
@pytest.mark.parametrize("argument", ["{binding}", "value={binding}"])
def test_escaped_source_class_or_function_is_not_stable(
    tmp_path: Path, binding: str, argument: str,
) -> None:
    path = tmp_path / "sample.py"
    path.write_text(MODEL + "def check():\n external.interact("
                    + argument.format(binding=binding)
                    + ")\n return produce().has_capability('read')\n")
    inventory = resolve_python_imports(tmp_path, discover_python_source(tmp_path, [path]))
    with pytest.raises(SemanticOperationEffectError, match="unresolved"):
        validate_operation_effects(QUERY, "sample.py::check", inventory)


def test_neutral_bound_receiver_is_unknown_after_argument_evaluation() -> None:
    source = MODEL + "def check():\n obj = Model()\n alias = obj\n return obj.validate(external.interact(alias))\n"
    facts = next(row for row in discover_return_facts(ast.parse(source), path="sample.py")
                 if row["symbol"] == "sample.py::check")
    outer = next(call for call in facts["call_sites"] if call["callee"] == "obj.validate")
    assert outer["receiver_origins"] == [
        {"kind": "unknown", "reason": "receiver_after_argument_evaluation"}]


def test_native_bound_receiver_cannot_borrow_pre_argument_identity(tmp_path: Path) -> None:
    path = tmp_path / "sample.py"
    path.write_text(MODEL + "def check():\n obj = Model()\n alias = obj\n"
                    " validated = obj.validate(external.interact(alias))\n"
                    " return validated.has_capability('read')\n")
    inventory = resolve_python_imports(tmp_path, discover_python_source(tmp_path, [path]))
    with pytest.raises(SemanticOperationEffectError, match="unresolved"):
        validate_operation_effects(QUERY, "sample.py::check", inventory)


@pytest.mark.parametrize("kind", ["factory", "class"])
@pytest.mark.parametrize("hop", ["caller", "bridge"])
@pytest.mark.parametrize("mutation", ["assign", "delete", "conditional"])
def test_every_import_hop_must_keep_its_binding(
    tmp_path: Path, kind: str, hop: str, mutation: str,
) -> None:
    target = "produce" if kind == "factory" else "Model"
    replacement = {"assign": "entry = external_callable\n", "delete": "del entry\n",
                   "conditional": "if flag:\n entry = external_callable\n"}[mutation]
    files = {"factory.py": MODEL, "bridge.py": f"from factory import {target} as entry\n",
             "consumer.py": "from bridge import entry\n"}
    files["consumer.py" if hop == "caller" else "bridge.py"] += replacement
    files["consumer.py"] += "def check(): return entry().has_capability('read')\n"
    paths = []
    for name, source in files.items():
        path = tmp_path / name
        path.write_text(source)
        paths.append(path)
    inventory = resolve_python_imports(tmp_path, discover_python_source(tmp_path, paths))
    with pytest.raises(SemanticOperationEffectError, match="unresolved"):
        validate_operation_effects(QUERY, "consumer.py::check", inventory)


@pytest.mark.parametrize("target", ["produce", "Model"])
def test_unmodified_reexport_chain_keeps_source_method_edge(tmp_path: Path, target: str) -> None:
    files = {"factory.py": MODEL, "bridge.py": f"from factory import {target} as entry\n",
             "consumer.py": "from bridge import entry\ndef check(): return entry().has_capability('read')\n"}
    paths = []
    for name, source in files.items():
        path = tmp_path / name
        path.write_text(source)
        paths.append(path)
    inventory = resolve_python_imports(tmp_path, discover_python_source(tmp_path, paths))
    row = next(row for row in inventory["functions"] if row["symbol"] == "consumer.py::check")
    assert any(call.get("called_symbol") == "factory.py::Model.has_capability"
               for call in row["calls"])
    assert validate_operation_effects(QUERY, "consumer.py::check", inventory) == (0, 0)
