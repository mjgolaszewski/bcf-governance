"""Portable proposed dispatcher contract; source-only, not yet qualified.

Reduced source shapes are tied to actual SDK spans in fixture-contract.json.
These exercise the native pipeline; they do not execute SDK or model bodies.
"""
from __future__ import annotations

from pathlib import Path
from typing import Any

import pytest

from bcf_governance.tooling.semantic_operation_effects import (
    SemanticOperationEffectError,
    validate_operation_effects,
)
from bcf_governance.tooling.semantic_ownership_inventory import (
    discover_python_source,
    resolve_python_imports,
)


MODEL = """class Model:
    capabilities = ()

    def has_capability(self, capability: str) -> bool:
        return capability in self.capabilities
"""
QUERY = {"id": "receiver-query", "allowed_mutation_ports": [],
         "allowed_authority_ports": [], "non_authoritative_output_effects": []}


def _native(tmp_path: Path, files: dict[str, str]) -> dict[str, Any]:
    paths = []
    for relative, source in files.items():
        path = tmp_path / relative
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(source)
        paths.append(path)
    return resolve_python_imports(tmp_path, discover_python_source(tmp_path, paths))


def _edge(inventory: dict[str, Any], caller: str, target: str) -> None:
    function = next(row for row in inventory["functions"] if row["symbol"] == caller)
    assert any(call.get("called_symbol") == target for call in function["calls"])


def test_source_constructor_return_model_method(tmp_path: Path) -> None:
    source = MODEL + """
def produce():
    return Model()

def check():
    claims = produce()
    return claims.has_capability('bdmcp:session_read')
"""
    inventory = _native(tmp_path, {"sample.py": source})
    _edge(inventory, "sample.py::check", "sample.py::Model.has_capability")
    assert validate_operation_effects(QUERY, "sample.py::check", inventory) == (0, 0)


def test_source_real_self_return_keeps_receiver(tmp_path: Path) -> None:
    source = MODEL + """
    def validate_production(self):
        return self

def check():
    config = Model()
    validated = config.validate_production()
    return validated.has_capability('bdmcp:session_read')
"""
    inventory = _native(tmp_path, {"sample.py": source})
    _edge(inventory, "sample.py::check", "sample.py::Model.validate_production")
    _edge(inventory, "sample.py::check", "sample.py::Model.has_capability")
    assert validate_operation_effects(QUERY, "sample.py::check", inventory) == (0, 0)


def test_conditional_mixed_return_cannot_borrow_exact_model(tmp_path: Path) -> None:
    source = MODEL + """
def produce(flag, alternate):
    if flag:
        return Model()
    return alternate

def check(flag, alternate):
    claims = produce(flag, alternate)
    return claims.has_capability('bdmcp:session_read')
"""
    inventory = _native(tmp_path, {"sample.py": source})
    with pytest.raises(SemanticOperationEffectError, match="unresolved"):
        validate_operation_effects(QUERY, "sample.py::check", inventory)


@pytest.mark.parametrize("effect,reason", [
    ("path.write_text('changed')", "undeclared write"),
    ("publish_release()", "undeclared authority"),
])
def test_returned_model_method_effect_traversed(
    tmp_path: Path, effect: str, reason: str,
) -> None:
    source = MODEL.replace("return capability in self.capabilities", effect
                           + "\n        return capability in self.capabilities") + """
def produce():
    return Model()

def check():
    claims = produce()
    return claims.has_capability('bdmcp:session_read')
"""
    inventory = _native(tmp_path, {"sample.py": source})
    _edge(inventory, "sample.py::check", "sample.py::Model.has_capability")
    with pytest.raises(SemanticOperationEffectError, match=reason):
        validate_operation_effects(QUERY, "sample.py::check", inventory)


def test_annotated_injected_producer_is_unknown(tmp_path: Path) -> None:
    source = MODEL + """
class Producer:
    def produce(self) -> Model:
        return Model()

def check(producer: Producer):
    claims = producer.produce()
    return claims.has_capability('bdmcp:session_read')
"""
    inventory = _native(tmp_path, {"sample.py": source})
    with pytest.raises(SemanticOperationEffectError, match="unresolved"):
        validate_operation_effects(QUERY, "sample.py::check", inventory)


@pytest.mark.parametrize("hidden_write", [False, True])
def test_multimodule_factory_alias_preserves_model_and_effect(
    tmp_path: Path, hidden_write: bool,
) -> None:
    model = MODEL
    if hidden_write:
        model = model.replace("return capability in self.capabilities",
                              "path.write_text('changed')\n"
                              "        return capability in self.capabilities")
    files = {
        "models.py": model,
        "decoder.py": "from models import Model\ndef decode(): return Model()\n",
        "bridge.py": "from decoder import decode as factory\n",
        "consumer.py": "from bridge import factory as decode_claims\n"
                       "def check():\n    claims = decode_claims()\n"
                       "    return claims.has_capability('bdmcp:session_read')\n",
    }
    inventory = _native(tmp_path, files)
    _edge(inventory, "consumer.py::check", "models.py::Model.has_capability")
    if hidden_write:
        with pytest.raises(SemanticOperationEffectError, match="undeclared write"):
            validate_operation_effects(QUERY, "consumer.py::check", inventory)
    else:
        assert validate_operation_effects(QUERY, "consumer.py::check", inventory) == (0, 0)


def test_returned_receiver_reassignment_invalidates_origin(tmp_path: Path) -> None:
    source = MODEL + """
def produce():
    return Model()

def check(alternate):
    claims = produce()
    claims = alternate
    return claims.has_capability('bdmcp:session_read')
"""
    inventory = _native(tmp_path, {"sample.py": source})
    with pytest.raises(SemanticOperationEffectError, match="unresolved"):
        validate_operation_effects(QUERY, "sample.py::check", inventory)
