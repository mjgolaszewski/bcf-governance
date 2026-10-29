"""Native conservative-flow regressions for the proposed supported dispatcher."""
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

MODEL = """class Model:
    def has_capability(self, value): return True
def produce(): return Model()
"""


@pytest.mark.parametrize("body", [
    "    claims = produce()\n    external(claims)\n    return claims.has_capability('read')\n",
    "    claims = produce()\n    return claims.has_capability('read') or other.has_capability('read')\n",
    "    claims = produce()\n    if flag:\n        claims = other\n    return claims.has_capability('read')\n",
    "    for value in other:\n        claims = produce()\n        return claims.has_capability('read')\n",
])
def test_unsupported_flow_cannot_keep_receiver_permission(tmp_path: Path, body: str) -> None:
    path = tmp_path / "sample.py"
    path.write_text(MODEL + "def check(flag, other):\n" + body)
    inventory = resolve_python_imports(tmp_path, discover_python_source(tmp_path, [path]))
    operation = {"id": "query", "allowed_mutation_ports": [],
                 "allowed_authority_ports": [], "non_authoritative_output_effects": []}
    with pytest.raises(SemanticOperationEffectError, match="unresolved"):
        validate_operation_effects(operation, "sample.py::check", inventory)


@pytest.mark.parametrize("mutation", [
    "import sample\nsample.Model = replacement\n",
    "def replace():\n global Model\n Model = replacement\n",
])
def test_global_source_binding_changes_refuse_result_identity(tmp_path: Path, mutation: str) -> None:
    path = tmp_path / "sample.py"
    path.write_text(MODEL + "def check():\n return produce().has_capability('read')\n")
    other = tmp_path / "other.py"
    other.write_text(mutation)
    inventory = resolve_python_imports(tmp_path, discover_python_source(tmp_path, [path, other]))
    operation = {"id": "query", "allowed_mutation_ports": [],
                 "allowed_authority_ports": [], "non_authoritative_output_effects": []}
    with pytest.raises(SemanticOperationEffectError, match="unresolved"):
        validate_operation_effects(operation, "sample.py::check", inventory)


def test_constructor_argument_effect_is_preserved(tmp_path: Path) -> None:
    path = tmp_path / "sample.py"
    path.write_text("class Model:\n def __init__(self, value): pass\n"
                    "def check(): return Model(path.write_text('changed'))\n")
    inventory = resolve_python_imports(tmp_path, discover_python_source(tmp_path, [path]))
    operation = {"id": "query", "allowed_mutation_ports": [],
                 "allowed_authority_ports": [], "non_authoritative_output_effects": []}
    with pytest.raises(SemanticOperationEffectError, match="undeclared write"):
        validate_operation_effects(operation, "sample.py::check", inventory)


@pytest.mark.parametrize("prefix,entry", [
    ("Alias = Model\n", "Alias()"),
    ("factory = produce\n", "factory()"),
])
def test_unsupported_callable_alias_is_not_an_effect_bypass(
    tmp_path: Path, prefix: str, entry: str,
) -> None:
    path = tmp_path / "sample.py"
    path.write_text(MODEL + prefix + "def check(): return " + entry + "\n")
    inventory = resolve_python_imports(tmp_path, discover_python_source(tmp_path, [path]))
    operation = {"id": "query", "allowed_mutation_ports": [],
                 "allowed_authority_ports": [], "non_authoritative_output_effects": []}
    with pytest.raises(SemanticOperationEffectError, match="unresolved"):
        validate_operation_effects(operation, "sample.py::check", inventory)
