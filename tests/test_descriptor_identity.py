"""Source-prepared qualification cases; not executed by Aster."""
from __future__ import annotations

import ast
from typing import Any

import pytest

from bcf_governance.tooling.semantic_python_descriptor_identity import (
    descriptor_source_facts,
    resolve_descriptor_dispatch,
)


def _inventory(source: str) -> dict[str, Any]:
    syntax = descriptor_source_facts(ast.parse(source), path="sample.py")
    functions = []
    classes = []
    for row in syntax["classes"]:
        classes.append({"symbol": row["symbol"], "bases": []})
        for method in row["methods"]:
            functions.append({
                "symbol": method["symbol"], "calls": [],
                "effect_unresolved": ([{"dispatch_kind": "decorated_method"}]
                                      if method["decorators"] else []),
            })
    return {"descriptor_syntax": [syntax], "classes": classes, "functions": functions}


def _resolve(source: str, modules: dict[str, str] | None = None) -> dict[str, Any]:
    inventory = _inventory(source)
    resolve_descriptor_dispatch(inventory, module_index=modules or {})
    return inventory


def _function(inventory: dict[str, Any], suffix: str) -> dict[str, Any]:
    functions: list[dict[str, Any]] = inventory["functions"]
    return next(row for row in functions if row["symbol"].endswith(suffix))


def test_same_instance_getter_is_an_effect_traversal_edge() -> None:
    result = _resolve("""
class Claims:
    @property
    def methods(self):
        return self.amr
    def read(self):
        return self.methods
""")
    call = _function(result, "Claims.read")["calls"][0]
    assert call["called_symbol"] == "sample.py::Claims.methods"
    assert call["dispatch_resolution"] == "exact_property_getter"
    assert not _function(result, "Claims.methods")["effect_unresolved"]


def test_cross_object_name_is_candidate_only() -> None:
    result = _resolve("""
class Claims:
    @property
    def methods(self):
        return self.amr
    def read(self, other: Claims):
        return other.methods
""")
    function = _function(result, "Claims.read")
    assert function["effect_unresolved"][-1]["port_eligible"] is False
    assert function["property_reads"][0]["candidate_getters"] == ["sample.py::Claims.methods"]
    assert not function["calls"]


@pytest.mark.parametrize("body", ["path.write_text('changed')", "publish_release()"])
def test_descriptor_identity_does_not_replace_or_hide_body_calls(body: str) -> None:
    inventory = _inventory(f"class C:\n    @property\n    def value(self):\n        return {body}\n")
    getter = _function(inventory, "C.value")
    original = {"called_symbol": "external::effect", "call_name": body.split("(")[0]}
    getter["calls"].append(original)
    resolve_descriptor_dispatch(inventory, module_index={})
    assert getter["calls"] == [original]


@pytest.mark.parametrize("prefix", ["property = fake\n", "from fake import property\n", "from fake import *\n"])
def test_shadowed_property_is_not_builtin(prefix: str) -> None:
    result = _resolve(prefix + "class C:\n    @property\n    def value(self): return 1\n")
    assert _function(result, "C.value")["effect_unresolved"]


@pytest.mark.parametrize("extra", [
    "    @value.setter\n    def value(self, item): pass\n",
    "    @value.deleter\n    def value(self): pass\n",
    "    value = fake\n",
    "    def __getattribute__(self, name): return fake(name)\n",
])
def test_descriptor_overrides_and_rebindings_remain_unresolved(extra: str) -> None:
    result = _resolve("class C:\n    @property\n    def value(self): return 1\n" + extra)
    assert all(row["effect_unresolved"] for row in result["functions"] if row["symbol"].endswith("C.value"))


@pytest.mark.parametrize("suffix", ["\nclass D(C): pass\n", "\nC.value = fake\n"])
def test_known_subclass_or_external_rebinding_blocks_exact_getter(suffix: str) -> None:
    result = _resolve("class C:\n    @property\n    def value(self): return 1\n" + suffix)
    assert _function(result, "C.value")["effect_unresolved"]


def test_real_dataclass_import_requires_source_root_resolution() -> None:
    source = "from dataclasses import dataclass\n@dataclass(frozen=True)\nclass C:\n    @property\n    def value(self): return 1\n"
    assert not _function(_resolve(source), "C.value")["effect_unresolved"]
    assert _function(_resolve(source, {"dataclasses": "dataclasses.py"}), "C.value")["effect_unresolved"]


@pytest.mark.parametrize("base", ["ValueError", "RuntimeError", "Exception"])
def test_exact_builtin_super_constructor(base: str) -> None:
    result = _resolve(f"class Rejected({base}):\n    def __init__(self, message):\n        super().__init__(message)\n")
    function = _function(result, "Rejected.__init__")
    assert function["builtin_super_constructors"][0]["target"] == f"builtin:{base}.__init__"


@pytest.mark.parametrize("source", [
    "ValueError = Fake\nclass E(ValueError):\n    def __init__(self): super().__init__('x')\n",
    "super = Fake\nclass E(ValueError):\n    def __init__(self): super().__init__('x')\n",
    "class E(ValueError):\n    def __init__(self, super): super().__init__('x')\n",
    "class E(ValueError):\n    def __init__(self): super(E, self).__init__('x')\n",
    "class E(ValueError, Other):\n    def __init__(self): super().__init__('x')\n",
    "class E(ValueError):\n    def __init__(self): super().__init__('x')\nclass Child(E): pass\n",
])
def test_ambiguous_super_has_no_builtin_admission(source: str) -> None:
    assert not _function(_resolve(source), "E.__init__").get("builtin_super_constructors")


def test_nested_body_is_not_attached_to_outer_function() -> None:
    syntax = descriptor_source_facts(ast.parse("class C:\n    def outer(self):\n        def delayed(): return other.value\n        return 1\n"), path="sample.py")
    assert not syntax["classes"][0]["methods"][0]["attribute_reads"]




def test_getter_attribute_write_is_not_purity() -> None:
    result = _resolve("class C:\n    @property\n    def value(self):\n        self.cache = 1\n        return self.cache\n")
    calls = _function(result, "C.value")["calls"]
    assert any(call.get("effect") == "write" for call in calls)


def test_same_line_explicit_super_does_not_borrow_zero_argument_admission() -> None:
    result = _resolve("class E(ValueError):\n    def __init__(self): super().__init__('x'); super(E, self).__init__('x')\n")
    assert not _function(result, "E.__init__").get("builtin_super_constructors")


def test_alias_subclass_blocks_exact_property() -> None:
    result = _resolve("class C:\n    @property\n    def value(self): return 1\nAlias = C\nclass D(Alias): pass\n")
    assert _function(result, "C.value")["effect_unresolved"]


@pytest.mark.parametrize("decorator,receiver", [("staticmethod", "self"), ("classmethod", "cls"), ("custom", "self")])
def test_non_instance_calling_convention_cannot_manufacture_getter(decorator: str, receiver: str) -> None:
    result = _resolve(f"class C:\n    @property\n    def value(self): return 1\n    @{decorator}\n    def read({receiver}): return {receiver}.value\n")
    function = _function(result, "C.read")
    assert not function["calls"]
    assert function["effect_unresolved"][-1]["port_eligible"] is False


@pytest.mark.parametrize("header", [
    "def nested(x=(self := other)): pass",
    "deferred = lambda x=(self := other): None",
    "class Nested((self := other)): pass",
    "@replace(self := other)\n        def nested(): pass",
])
def test_eager_nested_header_cannot_preserve_exact_receiver(header: str) -> None:
    source = "class C:\n    @property\n    def value(self): return 1\n    def read(self):\n        " + header + "\n        return self.value\n"
    function = _function(_resolve(source), "C.read")
    assert not function["calls"]
    assert function["effect_unresolved"][-1]["port_eligible"] is False


@pytest.mark.parametrize("attribute", ["__getattribute__", "__getattr__", "__bases__", "__class__", "__build_class__", "__code__"])
def test_dynamic_hook_mro_or_code_rebinding_blocks_exact_getter(attribute: str) -> None:
    result = _resolve("class C:\n    @property\n    def value(self): return 1\n" + f"C.{attribute} = fake\n")
    assert _function(result, "C.value")["effect_unresolved"]


@pytest.mark.parametrize("attribute", ["__getattribute__", "__bases__", "__class__", "__build_class__", "__code__"])
def test_dynamic_hook_mro_or_code_rebinding_blocks_builtin_super(attribute: str) -> None:
    result = _resolve("class E(ValueError):\n    def __init__(self): super().__init__('x')\n" + f"E.{attribute} = fake\n")
    assert not _function(result, "E.__init__").get("builtin_super_constructors")


@pytest.mark.parametrize("prefix", [
    "vars(builtins)['property'] = fake\n",
    "builtins.__dict__['property'] = fake\n",
])
def test_dynamic_builtin_namespace_write_is_not_lexical_builtin_proof(prefix: str) -> None:
    result = _resolve(prefix + "class C:\n    @property\n    def value(self): return 1\n")
    assert _function(result, "C.value")["effect_unresolved"]


@pytest.mark.parametrize("mutation", [
    "vars(builtins)['property'] = fake",
    "builtins.__dict__['property'] = fake",
    "__builtins__['property'] = fake",
    "setattr(builtins, 'property', fake)",
    "setattr(builtins, 'super', fake)",
    "setattr(builtins, 'ValueError', fake)",
    "setattr(C, '__getattribute__', fake)",
    "object.__setattr__(builtins, 'property', fake)",
    "builtins.__setattr__('property', fake)",
    "setter = setattr\nsetter(builtins, 'property', fake)",
    "from builtins import setattr as setter\nsetter(builtins, 'property', fake)",
    "setter = builtins.setattr\nsetter(builtins, 'property', fake)",
])
def test_other_source_namespace_mutation_blocks_getter_and_super(mutation: str) -> None:
    inventory = _inventory("class C:\n    @property\n    def value(self): return 1\nclass E(ValueError):\n    def __init__(self): super().__init__('x')\n")
    inventory["descriptor_syntax"].append(descriptor_source_facts(ast.parse(mutation), path="other.py"))
    resolve_descriptor_dispatch(inventory, module_index={})
    assert _function(inventory, "C.value")["effect_unresolved"]
    assert not _function(inventory, "E.__init__").get("builtin_super_constructors")


def test_unrelated_constant_attribute_write_does_not_rebind_descriptor_cohort() -> None:
    inventory = _inventory("class C:\n    @property\n    def value(self): return 1\n")
    other = "STATE_KEY = 'application_claims'\ndef attach(request, claims): setattr(request.state, STATE_KEY, claims)\n"
    inventory["descriptor_syntax"].append(descriptor_source_facts(ast.parse(other), path="other.py"))
    resolve_descriptor_dispatch(inventory, module_index={})
    assert not _function(inventory, "C.value")["effect_unresolved"]


def test_shadowed_attribute_name_constant_remains_unknown_mutation() -> None:
    inventory = _inventory("class C:\n    @property\n    def value(self): return 1\n")
    other = "STATE_KEY = 'application_claims'\ndef attach(request, STATE_KEY): setattr(request.state, STATE_KEY, fake)\n"
    inventory["descriptor_syntax"].append(descriptor_source_facts(ast.parse(other), path="other.py"))
    resolve_descriptor_dispatch(inventory, module_index={})
    assert _function(inventory, "C.value")["effect_unresolved"]
