"""Portable native refusal controls for unsupported descriptor decorators."""
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


@pytest.mark.parametrize("prefix,decorator", [
    ("", "custom"),
    ("import builtins\n", "builtins.property"),
    ("from functools import cached_property\n", "cached_property"),
    ("staticmethod = custom\n", "staticmethod"),
])
def test_unproven_decorator_descriptor_read_cannot_hide_write(
    tmp_path: Path, prefix: str, decorator: str,
) -> None:
    path = tmp_path / "sample.py"
    path.write_text(prefix + "class C:\n    @" + decorator
                    + "\n    def value(self): return path.write_text('changed')\n"
                    + "    def read(self): return self.value\n")
    inventory = resolve_python_imports(
        tmp_path, discover_python_source(tmp_path, [path]),
    )
    operation = {"id": "descriptor-query", "allowed_mutation_ports": [],
                 "allowed_authority_ports": [], "non_authoritative_output_effects": []}
    with pytest.raises(SemanticOperationEffectError, match="unresolved"):
        validate_operation_effects(operation, "sample.py::C.read", inventory)


@pytest.mark.parametrize("decorator", ["classmethod", "staticmethod"])
@pytest.mark.parametrize("mutation_form", ["attribute", "setattr"])
def test_other_module_method_decorator_rebinding_cannot_hide_descriptor_write(
    tmp_path: Path, decorator: str, mutation_form: str,
) -> None:
    path = tmp_path / "sample.py"
    path.write_text("class C:\n    @" + decorator
                    + "\n    def value(receiver): return path.write_text('changed')\n"
                    + "    def read(self): return self.value\n")
    other = tmp_path / "other.py"
    mutation = (f"builtins.{decorator} = custom" if mutation_form == "attribute"
                else f"setattr(builtins, '{decorator}', custom)")
    other.write_text("import builtins\n" + mutation + "\n")
    inventory = resolve_python_imports(
        tmp_path, discover_python_source(tmp_path, [path, other]),
    )
    operation = {"id": "descriptor-query", "allowed_mutation_ports": [],
                 "allowed_authority_ports": [], "non_authoritative_output_effects": []}
    with pytest.raises(SemanticOperationEffectError, match="unresolved"):
        validate_operation_effects(operation, "sample.py::C.read", inventory)


@pytest.mark.parametrize("decorator", ["classmethod", "staticmethod"])
def test_genuine_method_reference_does_not_invoke_decorated_body(
    tmp_path: Path, decorator: str,
) -> None:
    path = tmp_path / "sample.py"
    path.write_text("class C:\n    @" + decorator
                    + "\n    def value(receiver): return path.write_text('not invoked')\n"
                    + "    def read(self): return self.value\n")
    inventory = resolve_python_imports(
        tmp_path, discover_python_source(tmp_path, [path]),
    )
    operation = {"id": "descriptor-query", "allowed_mutation_ports": [],
                 "allowed_authority_ports": [], "non_authoritative_output_effects": []}
    assert validate_operation_effects(operation, "sample.py::C.read", inventory) == (0, 0)


@pytest.mark.parametrize("decorator", ["classmethod", "staticmethod"])
@pytest.mark.parametrize("mutation_scope", ["class", "module"])
def test_rebound_method_member_cannot_acquire_inert_descriptor_permission(
    tmp_path: Path, decorator: str, mutation_scope: str,
) -> None:
    path = tmp_path / "sample.py"
    replacement = "    value = descriptor\n" if mutation_scope == "class" else ""
    suffix = "\nC.value = descriptor\n" if mutation_scope == "module" else ""
    path.write_text("from external import descriptor\nclass C:\n    @" + decorator
                    + "\n    def value(receiver): return 'original method'\n"
                    + replacement + "    def read(self): return self.value\n" + suffix)
    inventory = resolve_python_imports(
        tmp_path, discover_python_source(tmp_path, [path]),
    )
    operation = {"id": "descriptor-query", "allowed_mutation_ports": [],
                 "allowed_authority_ports": [], "non_authoritative_output_effects": []}
    with pytest.raises(SemanticOperationEffectError, match="unresolved"):
        validate_operation_effects(operation, "sample.py::C.read", inventory)
