"""Authored source discovery controls, UNRUN; input source is never imported."""
import sysconfig
from pathlib import Path
from typing import Any

import pytest

from bcf_governance.tooling.semantic_ownership_inventory import (
    discover_python_source,
    resolve_python_imports,
)
from bcf_governance.tooling.semantic_ownership_registry import Registry, RegistryEntry
from bcf_governance.tooling.semantic_ownership_scan import evaluate_discovery


def inventory(root: Path, source: str) -> dict[str, Any]:
    path = root / "source.py"
    path.write_text(source)
    return resolve_python_imports(root, discover_python_source(root, files=[path]), (".",))


def calls(discovered: dict[str, Any]) -> list[dict[str, Any]]:
    return [call for function in discovered["functions"] for call in function["calls"]]


def test_module_constructor_has_explicit_owning_module(tmp_path: Path) -> None:
    found = inventory(tmp_path, "class Record: pass\nVALUE = Record()\n")
    rows = found["constructors"]
    assert len(rows) == 1
    assert rows[0]["caller"] == "source.py::<module>"
    assert rows[0]["constructed_symbol"] == "source.py::Record"
    assert rows[0]["execution_context"]["phase"] == "module_body"
    assert rows[0]["execution_context"]["runtime_observed"] is False


def test_eager_comprehension_constructor_not_silently_omitted(tmp_path: Path) -> None:
    found = inventory(tmp_path, "class Record: pass\nVALUES = [Record() for _ in range(2)]\n")
    assert len(found["constructors"]) == 1  # lexical site, never invented runtime count
    assert found["constructors"][0]["caller"] == "source.py::<module>"


def test_class_body_constructor_has_distinct_context(tmp_path: Path) -> None:
    found = inventory(tmp_path, "class Record: pass\nclass Container:\n    VALUE = Record()\n")
    assert found["constructors"][0]["caller"] == "source.py::<class-body:Container>"
    assert found["constructors"][0]["execution_context"]["phase"] == "class_body"


def test_default_is_owned_by_definition_site_not_function_invocation(tmp_path: Path) -> None:
    found = inventory(tmp_path, "class Record: pass\ndef use(value=Record()):\n    return value\n")
    assert len(found["constructors"]) == 1
    assert found["constructors"][0]["caller"] == "source.py::<module>"
    assert found["constructors"][0]["execution_context"]["phase"] == "function_default"
    function = next(row for row in found["functions"] if row["symbol"] == "source.py::use")
    assert not function["calls"] and not function["constructors"]


def test_method_default_is_owned_by_class_body(tmp_path: Path) -> None:
    found = inventory(tmp_path, "class Record: pass\nclass Container:\n    def use(self, value=Record()): pass\n")
    assert len(found["constructors"]) == 1
    assert found["constructors"][0]["caller"] == "source.py::<class-body:Container>"


def test_decorator_factory_call_and_application_are_distinct(tmp_path: Path) -> None:
    found = inventory(tmp_path, "def factory(): pass\n@factory()\ndef use(): pass\n")
    row = next(row for row in calls(found) if row["call_name"] == "factory")
    assert row["caller"] == "source.py::<module>"
    assert row["execution_context"]["phase"] == "decorator_expression"
    assert any(row["kind"] == "definition_time_decorator_application" for row in [*found["unresolved"], *found["definition_time_obligations"]])


def test_annotation_calls_require_temporal_contract(tmp_path: Path) -> None:
    found = inventory(tmp_path, "def factory(): pass\ndef use(value: factory()): pass\n")
    assert any(row["kind"] == "definition_time_annotation_contract_required" for row in [*found["unresolved"], *found["definition_time_obligations"]])
    assert not any(row["call_name"] == "factory" and row.get("execution_context", {}).get("phase") == "module_body" for row in calls(found))


def test_generator_body_is_not_claimed_as_eager_module_execution(tmp_path: Path) -> None:
    found = inventory(tmp_path, "class Record: pass\nVALUES = (Record() for _ in range(2))\n")
    assert not found["constructors"]
    assert any(row["kind"] == "definition_time_deferred_generator" for row in [*found["unresolved"], *found["definition_time_obligations"]])


def test_lambda_body_is_not_claimed_as_eager_module_execution(tmp_path: Path) -> None:
    found = inventory(tmp_path, "class Record: pass\nVALUE = lambda: Record()\n")
    assert not found["constructors"]
    assert any(row["kind"] == "definition_time_deferred_lambda" for row in [*found["unresolved"], *found["definition_time_obligations"]])


def test_hidden_module_write_is_visible_without_executing_source(tmp_path: Path) -> None:
    marker = tmp_path / "must-not-exist"
    found = inventory(tmp_path, f"from pathlib import Path\nPath({str(marker)!r}).write_text('forbidden')\n")
    assert not marker.exists()
    assert any(row["call_name"] == "write_text" and row["caller"] == "source.py::<module>" for row in calls(found))
    assert any(row["kind"] == "definition_time_receiver_effect_requires_resolution" for row in [*found["unresolved"], *found["definition_time_obligations"]])


def test_unauthorized_module_constructor_is_causal(tmp_path: Path) -> None:
    healthy = "class Record: pass\ndef create(): return Record()\n"
    owner = "source.py::create"
    entry = RegistryEntry("fixture.record.v1", "record", "enforced", "source.py::Record", owner,
                          frozenset({owner}), frozenset(), True, {})
    registry = Registry("P04", "declared_families_blocking", "fail_closed", ("source.py",), (), (entry,), {})
    def unauthorized(source: str) -> list[dict[str, Any]]:
        report = evaluate_discovery(inventory(tmp_path, source), registry)
        return [row for row in report["violations"] if row["kind"] == "unauthorized_constructor"]
    assert not unauthorized(healthy)
    adverse = unauthorized(healthy + "VALUE = Record()\n")
    assert any(row["symbol"] == "source.py::<module>" for row in adverse)
    assert not unauthorized(healthy)
    # Other implicit-class-dispatch obligations remain unresolved throughout;
    # this isolates the real constructor rule, never claims whole-scan PASS.





def test_default_attribute_access_has_explicit_dispatch_obligation(tmp_path: Path) -> None:
    found = inventory(tmp_path, "def use(value=owner.property): pass\n")
    assert any(row["kind"] == "definition_time_attribute_dispatch_requires_resolution"
               for row in [*found["unresolved"], *found["definition_time_obligations"]])


def test_implicit_class_creation_is_not_assumed_pure(tmp_path: Path) -> None:
    found = inventory(tmp_path, "class Container(metaclass=unknown): pass\n")
    assert any(row["kind"] == "definition_time_implicit_class_dispatch_requires_resolution"
               for row in [*found["unresolved"], *found["definition_time_obligations"]])


def test_bare_decorator_application_cannot_disappear_without_ast_call(tmp_path: Path) -> None:
    found = inventory(tmp_path, "@decorate\ndef use(): pass\n")
    assert any(row["kind"] == "definition_time_decorator_application"
               for row in [*found["unresolved"], *found["definition_time_obligations"]])


def test_nested_runtime_scope_requires_actual_resolution(tmp_path: Path) -> None:
    found = inventory(tmp_path, "def outer():\n    def inner():\n        hidden_write()\n    return inner\n")
    assert any(row["kind"] == "definition_time_nested_runtime_scope_requires_resolution"
               for row in [*found["unresolved"], *found["definition_time_obligations"]])
    assert not any(row["call_name"] == "hidden_write" and row["caller"] == "source.py::outer" for row in calls(found))


@pytest.mark.parametrize("assigned", [True, False])
def test_annotated_target_calls_are_retained_with_optional_value(tmp_path: Path, assigned: bool) -> None:
    source = "target_factory()[key_factory()]: T" + (" = value_factory()" if assigned else "") + "\n"
    found = inventory(tmp_path, source)
    names = {row["call_name"] for row in calls(found)}
    assert {"target_factory", "key_factory"} <= names
    assert ("value_factory" in names) is assigned
    assert any(row["kind"] == "definition_time_annotated_target_contract_required"
               and row["assigned_value_present"] is assigned for row in [*found["unresolved"], *found["definition_time_obligations"]])


@pytest.mark.parametrize("source", [
    "def use[T: bound_factory()](): pass\n",
    "class Container[T: bound_factory()]: pass\n",
])
def test_type_parameter_bounds_have_explicit_deferred_contract(tmp_path: Path, source: str) -> None:
    found = inventory(tmp_path, source)
    assert any(row["kind"] == "definition_time_type_parameter_contract_required" for row in [*found["unresolved"], *found["definition_time_obligations"]])
    assert any(row["call_name"] == "bound_factory" and row["execution_context"]["phase"] == "type_parameter_deferred_contract_required" for row in calls(found))


@pytest.mark.parametrize("expression", ["lambda: hidden_write()", "(hidden_write() for _ in range(1))"])
def test_delayed_runtime_bodies_are_not_outer_invocation_calls(tmp_path: Path, expression: str) -> None:
    found = inventory(tmp_path, "def outer():\n    return " + expression + "\n")
    assert not any(row["call_name"] == "hidden_write" and row["caller"] == "source.py::outer" for row in calls(found))
    assert any(row["kind"] in {"definition_time_deferred_lambda", "definition_time_deferred_generator"} for row in [*found["unresolved"], *found["definition_time_obligations"]])


def test_class_body_effects_are_reachable_from_owning_module(tmp_path: Path) -> None:
    found = inventory(tmp_path, "class Container:\n    hidden_write()\n")
    assert any(row["caller"] == "source.py::<module>"
               and row["called_symbol"] == "source.py::<class-body:Container>"
               and row["implicit"] is True for row in calls(found))
    assert any(row["caller"] == "source.py::<class-body:Container>" and row["call_name"] == "hidden_write" for row in calls(found))


@pytest.mark.parametrize("assigned", [True, False])
def test_local_annotations_are_not_invocation_effects(tmp_path: Path, assigned: bool) -> None:
    source = "def use():\n    local: annotation_factory()" + (" = value_factory()" if assigned else "") + "\n"
    found = inventory(tmp_path, source)
    names = {row["call_name"] for row in calls(found)}
    assert "annotation_factory" not in names
    assert ("value_factory" in names) is assigned


def test_definition_obligation_still_blocks_both_authority_consumers(tmp_path: Path) -> None:
    from bcf_governance.tooling.semantic_operation_effects import (
        SemanticOperationEffectError,
        validate_operation_effects,
    )

    found = inventory(tmp_path, "class Record(metaclass=arbitrary): pass\ndef query(): return 1\n")
    assert found["unresolved"] == []
    assert found["definition_time_obligations"]
    registry = Registry("P04", "declared_families_blocking", "fail_closed", ("source.py",), (), (), {})
    report = evaluate_discovery(found, registry)
    assert report["verdict"] == "non_conformant"
    assert any(row["kind"] == "definition_time_implicit_class_dispatch_requires_resolution"
               for row in report["violations"])
    operation = {"id": "query", "allowed_mutation_ports": [], "allowed_authority_ports": [],
                 "non_authoritative_output_effects": []}
    with pytest.raises(SemanticOperationEffectError, match="definition-time"):
        validate_operation_effects(operation, "source.py::query", found, source_modules=("source.py",))
    # Removing only the new bucket must remove this cause, proving neither
    # consumer is failing on an unrelated syntax or method-dispatch uncertainty.
    for function in found["functions"]:
        function["definition_time_obligations"] = []
    found["definition_time_obligations"] = []
    assert evaluate_discovery(found, registry)["verdict"] == "conformant"
    assert validate_operation_effects(operation, "source.py::query", found, source_modules=("source.py",)) == (0, 0)


def test_plain_empty_class_has_no_unknown_implicit_dispatch(tmp_path: Path) -> None:
    found = inventory(tmp_path, 'class Record:\n    "record documentation"\n    pass\n')
    assert found["definition_time_obligations"] == []
    assert any(row["symbol"] == "source.py::<class-body:Record>" for row in found["functions"])


@pytest.mark.parametrize("source", [
    "class Record(Base): pass\n",
    "class Record(metaclass=Owner): pass\n",
    "@decorate\nclass Record: pass\n",
    "class Record:\n    field = descriptor\n",
    "class Record: pass\nRecord = replacement\n",
    "import builtins\nclass Record: pass\n",
    "globals().update({})\nclass Record: pass\n",
], ids=["base", "metaclass", "decorator", "descriptor", "rebound", "builtin-binding", "namespace"])
def test_empty_class_contract_cannot_hide_custom_dispatch(tmp_path: Path, source: str) -> None:
    found = inventory(tmp_path, source)
    assert any(row["kind"] == "definition_time_implicit_class_dispatch_requires_resolution"
               for row in found["definition_time_obligations"])


def test_stdlib_type_union_records_actual_source_identity(tmp_path: Path) -> None:
    found = inventory(tmp_path, "from email.message import Message\ndef read(value: Message | None): pass\n")
    contracts = [contract for function in found["functions"] for contract in function["definition_time_contracts"]]
    assert len(contracts) == 1
    assert contracts[0]["method"] == "type.__or__"
    assert len(contracts[0]["source_sha256"]) == 64
    assert not found["definition_time_obligations"]


@pytest.mark.parametrize("prefix", [
    "Message = arbitrary\n",
    "from arbitrary import Message\n",
    "getattr(__builtins__, 'setattr')\n",
    "from builtins import setattr as replace\n",
], ids=["rebound", "duplicate-import", "builtin-access", "mutator-alias"])
def test_type_union_contract_rejects_binding_uncertainty(tmp_path: Path, prefix: str) -> None:
    path = tmp_path / "source.py"
    path.write_text("from email.message import Message\n" + prefix + "def read(value: Message | None): pass\n")
    found = discover_python_source(tmp_path, files=[path])
    assert any(row["kind"] == "definition_time_annotation_contract_required"
               for row in found["definition_time_obligations"])


def test_project_module_cannot_borrow_stdlib_union_contract(tmp_path: Path) -> None:
    package = tmp_path / "email"
    package.mkdir()
    fake = package / "message.py"
    fake.write_text("class Meta(type): pass\nclass Message(metaclass=Meta): pass\n")
    caller = tmp_path / "caller.py"
    caller.write_text("from email.message import Message\ndef read(value: Message | None): pass\n")
    found = discover_python_source(tmp_path, files=[fake, caller])
    assert any(row["kind"] == "definition_time_annotation_contract_required"
               for row in found["definition_time_obligations"])


def test_literal_frozen_record_definition_retains_qualified_source_contract(tmp_path: Path) -> None:
    found = inventory(tmp_path, "from __future__ import annotations\nfrom dataclasses import dataclass\n@dataclass(frozen=True)\nclass Result:\n    passed: bool\n    label: str = 'ok'\n")
    assert found["definition_time_obligations"] == []
    contracts = [row for function in found["functions"] for row in function["definition_time_contracts"]]
    assert len(contracts) == 1
    assert contracts[0]["kind"] == "exact_stdlib_literal_record_definition"
    assert len(contracts[0]["source_sha256"]) == 64
    # The factory call remains visible; recognizing class construction does
    # not turn a real call into absent source or grant constructor result types.
    assert any(row["call_name"] == "dataclass" for row in calls(found))


@pytest.mark.parametrize("source", [
    "from dataclasses import dataclass\ndef dataclass(**kw): return arbitrary\n@dataclass(frozen=True)\nclass Result:\n value: str\n",
    "from dataclasses import dataclass\n@dataclass(frozen=True)\nclass Result(Base):\n value: str\n",
    "from dataclasses import dataclass\n@dataclass(frozen=True)\nclass Result:\n value: str = descriptor\n",
    "from dataclasses import dataclass, field\n@dataclass(frozen=True)\nclass Result:\n value: str = field(default_factory=hidden_write)\n",
    "from dataclasses import dataclass\n@dataclass(frozen=True)\nclass Result:\n value: str\n def __set_name__(self, owner, name): hidden_write()\n",
    "from dataclasses import dataclass\nstr = custom_type\n@dataclass(frozen=True)\nclass Result:\n value: str\n",
], ids=["decorator-rebound", "custom-base", "descriptor-default", "default-factory", "class-hook", "field-type-rebound"])
def test_literal_record_contract_does_not_hide_custom_behavior(tmp_path: Path, source: str) -> None:
    found = inventory(tmp_path, source)
    assert any(row["kind"] == "definition_time_decorator_application" for row in found["definition_time_obligations"])
    assert not any(row["kind"] == "exact_stdlib_literal_record_definition"
                   for function in found["functions"] for row in function["definition_time_contracts"])


def test_changed_stdlib_source_cannot_borrow_a_qualified_contract(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    library = tmp_path / "unsupported-runtime"
    (library / "email").mkdir(parents=True)
    (library / "email/message.py").write_text("import plugin\nclass Message: pass\nplugin.patch(__name__)\n")
    (library / "dataclasses.py").write_text("def dataclass(cls=None, **kwargs): return arbitrary(cls)\n")
    monkeypatch.setattr(sysconfig, "get_path", lambda _name: str(library))
    found = inventory(tmp_path, "from email.message import Message\nfrom dataclasses import dataclass\n@dataclass(frozen=True)\nclass Result:\n value: str\ndef read(value: Message | None): pass\n")
    kinds = {row["kind"] for row in found["definition_time_obligations"]}
    assert "definition_time_decorator_application" in kinds
    assert "definition_time_annotation_contract_required" in kinds
