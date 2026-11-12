"""Class-bound construction must be observed without changing product semantics."""

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


def _inventory(root: Path, source: str) -> dict:
    path = root / "models.py"
    path.write_text(source)
    return resolve_python_imports(root, discover_python_source(root, [path]), (".",))


@pytest.mark.parametrize("decoration", ["", "@dataclass(slots=True, frozen=True)\n"])
def test_closed_classmethod_construction_retains_exact_owner(
    tmp_path: Path, decoration: str,
) -> None:
    value = _inventory(tmp_path, "from dataclasses import dataclass\n" + decoration
                       + "class Record:\n"
                       "    @classmethod\n"
                       "    def from_payload(cls, payload):\n"
                       "        return cls()\n"
                       "def decode(payload):\n"
                       "    return Record.from_payload(payload)\n")
    facts = [row for row in value["constructors"]
             if row["caller"] == "models.py::Record.from_payload"]
    assert len(facts) == 1
    assert facts[0]["constructed_symbol"] == "models.py::Record"
    assert facts[0]["call_name"] == "cls"


@pytest.mark.parametrize("change", [
    "class Child(Record):\n    pass\n",
    "Record.from_payload = lambda value: value\n",
    "classmethod = lambda value: value\n",
])
def test_ambiguous_class_binding_is_explicitly_unresolved(
    tmp_path: Path, change: str,
) -> None:
    value = _inventory(tmp_path,
                       "class Record:\n"
                       "    @classmethod\n"
                       "    def from_payload(cls, payload):\n"
                       "        return cls()\n" + change)
    assert not any(row["caller"] == "models.py::Record.from_payload"
                   for row in value["constructors"])
    assert any(row["kind"] == "unresolved_class_constructor"
               for row in value["unresolved"])


def test_rebound_class_receiver_cannot_borrow_declaring_class(tmp_path: Path) -> None:
    value = _inventory(tmp_path,
                       "class Record:\n"
                       "    @classmethod\n"
                       "    def from_payload(cls, payload):\n"
                       "        cls = payload\n"
                       "        return cls()\n")
    assert not value["constructors"]
    assert any(row["kind"] == "unresolved_class_constructor"
               for row in value["unresolved"])


def test_custom_metaclass_or_decorator_cannot_claim_exact_class(tmp_path: Path) -> None:
    value = _inventory(tmp_path,
                       "def decorate(value): return value\n"
                       "@decorate\nclass Record:\n"
                       "    @classmethod\n"
                       "    def from_payload(cls, payload):\n"
                       "        return cls()\n")
    assert not value["constructors"]
    assert any(row["kind"] == "unresolved_class_constructor"
               for row in value["unresolved"])


@pytest.mark.parametrize("mutation", [
    "Alias.from_payload = lambda value: value",
    "setattr(Alias, 'from_payload', lambda value: value)",
])
def test_imported_class_replacement_invalidates_class_bound_proof(
    tmp_path: Path, mutation: str,
) -> None:
    _inventory(tmp_path, "class Record:\n"
               "    @classmethod\n"
               "    def from_payload(cls, payload):\n"
               "        return cls()\n")
    (tmp_path / "consumer.py").write_text("from models import Record as Alias\n" + mutation)
    value = resolve_python_imports(tmp_path,
        discover_python_source(tmp_path, sorted(tmp_path.glob("*.py"))), (".",))
    assert not any(row["caller"] == "models.py::Record.from_payload"
                   for row in value["constructors"])
    assert any(row["kind"] == "unresolved_class_constructor"
               for row in value["unresolved"])


@pytest.mark.parametrize("bound", ["Record", "Child"])
def test_classmethod_call_binds_actual_class_without_rewriting_inheritance(
    tmp_path: Path, bound: str,
) -> None:
    value = _inventory(tmp_path,
        "class Record:\n"
        "    @classmethod\n"
        "    def from_payload(cls, payload):\n"
        "        return cls()\n"
        "class Child(Record):\n    pass\n"
        f"def decode(payload):\n    return {bound}.from_payload(payload)\n")
    facts = [row for row in value["constructors"]
             if row["caller"] == "models.py::Record.from_payload"]
    assert len(facts) == 1
    assert facts[0]["constructed_symbol"] == f"models.py::{bound}"
    assert facts[0]["binding_caller"] == "models.py::decode"
    assert not any(row["kind"] == "unresolved_class_constructor"
                   for row in value["unresolved"])


@pytest.mark.parametrize("hook", ["__new__", "__init__", "__post_init__", "__setattr__"])
def test_constructor_hooks_are_not_certified_by_class_or_decorator_spelling(
    tmp_path: Path, hook: str,
) -> None:
    value = _inventory(tmp_path,
        "from dataclasses import dataclass\n@dataclass\nclass Record:\n"
        "    @classmethod\n"
        "    def from_payload(cls, payload):\n        return cls()\n"
        f"    def {hook}(self, *args):\n        raise RuntimeError('hook')\n"
        "def decode(payload):\n    return Record.from_payload(payload)\n")
    assert not any(row["caller"] == "models.py::Record.from_payload"
                   for row in value["constructors"])
    assert any(row["kind"] == "unresolved_class_constructor"
               for row in value["unresolved"])


def test_dataclass_default_factory_requires_explicit_source_obligation(tmp_path: Path) -> None:
    value = _inventory(tmp_path,
        "from dataclasses import dataclass, field\n@dataclass\nclass Record:\n"
        "    value: object = field(default_factory=lambda: print('effect'))\n"
        "    @classmethod\n"
        "    def from_payload(cls, payload):\n        return cls()\n")
    assert any(row["kind"] == "unresolved_class_constructor"
               for row in value["unresolved"])


def test_resolved_base_call_cannot_hide_unsupported_subclass_call(tmp_path: Path) -> None:
    value = _inventory(tmp_path,
        "class Record:\n"
        "    @classmethod\n"
        "    def from_payload(cls, payload):\n        return cls()\n"
        "class Meta(type):\n    pass\n"
        "class Child(Record, metaclass=Meta):\n    pass\n"
        "def good_decode(payload):\n    return Record.from_payload(payload)\n"
        "def bad_decode(payload):\n    return Child.from_payload(payload)\n")
    assert any(row["constructed_symbol"] == "models.py::Record"
               for row in value["constructors"])
    assert any(row["kind"] == "unresolved_class_constructor"
               and row["symbol"] == "models.py::bad_decode"
               for row in value["unresolved"])
    operation = {"id": "decode.v1", "authoritative_read": True,
                 "allowed_read_ports": ["models.py::Child.from_payload"],
                 "allowed_mutation_ports": [], "allowed_authority_ports": [],
                 "non_authoritative_output_effects": []}
    with pytest.raises(SemanticOperationEffectError, match="unresolved"):
        validate_operation_effects(operation, "models.py::bad_decode", value)


@pytest.mark.parametrize("expression", [
    "Record.from_payload.__func__(Record, payload)",
    "getattr(Record, 'from_payload')(payload)",
    "consume(Record.from_payload, payload)",
])
def test_escaped_factory_does_not_disappear_beside_a_direct_call(
    tmp_path: Path, expression: str,
) -> None:
    value = _inventory(tmp_path,
        "class Record:\n"
        "    @classmethod\n"
        "    def from_payload(cls, payload):\n        return cls()\n"
        "def direct(payload):\n    return Record.from_payload(payload)\n"
        f"def indirect(payload):\n    return {expression}\n")
    assert any(row["kind"] == "unresolved_class_constructor"
               for row in value["unresolved"])


@pytest.mark.parametrize("decorator", ["Fake.classmethod", "alias"])
def test_classmethod_spelling_cannot_substitute_for_builtin_binding(
    tmp_path: Path, decorator: str,
) -> None:
    value = _inventory(tmp_path,
        "alias = classmethod\n"
        "class Fake:\n    pass\n"
        "class Record:\n"
        f"    @{decorator}\n"
        "    def from_payload(cls, payload):\n        return cls()\n"
        "def direct(payload):\n    return Record.from_payload(payload)\n")
    assert not any(row["caller"] == "models.py::Record.from_payload"
                   for row in value["constructors"])
    assert any(row["kind"] == "unresolved_class_constructor"
               for row in value["unresolved"])


@pytest.mark.parametrize("instance_first", [False, True])
def test_instance_binding_cannot_borrow_an_independent_class_call(
    tmp_path: Path, instance_first: bool,
) -> None:
    factory = "    @classmethod\n    def from_payload(cls, payload):\n        return cls()\n"
    instance = "    def decode(self, payload):\n        return self.from_payload(payload)\n"
    value = _inventory(tmp_path, "class Record:\n"
        + (instance + factory if instance_first else factory + instance)
        + "def direct(payload):\n    return Record.from_payload(payload)\n")
    assert any(row["constructed_symbol"] == "models.py::Record"
               for row in value["constructors"])
    assert any(row["kind"] == "unresolved_class_constructor"
               and row["symbol"] == "models.py::Record.decode"
               for row in value["unresolved"])


def test_class_parameter_alias_cannot_hide_behind_a_resolved_constructor(tmp_path: Path) -> None:
    value = _inventory(tmp_path,
        "class Record:\n"
        "    @classmethod\n"
        "    def from_payload(cls, payload):\n"
        "        alias = cls\n"
        "        if payload:\n            return cls()\n"
        "        return alias()\n"
        "def direct(payload):\n    return Record.from_payload(payload)\n")
    assert any(row["constructed_symbol"] == "models.py::Record"
               for row in value["constructors"])
    assert any(row["kind"] == "unresolved_class_constructor"
               and row["symbol"] == "models.py::Record.from_payload"
               for row in value["unresolved"])


def test_unknown_standalone_callback_is_not_invented_as_a_class_receiver(tmp_path: Path) -> None:
    value = _inventory(tmp_path,
        "def identity(function):\n    return function\n"
        "@identity\ndef invoke(callback):\n    return callback()\n")
    assert not value["constructors"]
    assert not any(row["kind"] == "unresolved_class_constructor"
                   for row in value["unresolved"])
    operation = {"id": "invoke.v1", "allowed_mutation_ports": [],
                 "allowed_authority_ports": [], "non_authoritative_output_effects": []}
    with pytest.raises(SemanticOperationEffectError, match="unresolved"):
        validate_operation_effects(operation, "models.py::invoke", value)
