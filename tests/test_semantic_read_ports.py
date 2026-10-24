"""Read declarations classify boundaries without hiding source effects."""

import json
from pathlib import Path

import jsonschema
import pytest

from bcf_governance.tooling.semantic_authority_migrations import _operation_change_kinds

from bcf_governance.tooling.semantic_operation_effects import (
    SemanticOperationEffectError,
    validate_operation_effects,
)


def _operation(**values: object) -> dict:
    return {
        "id": "example.read.v1",
        "authoritative_read": True,
        "allowed_read_ports": ["service.py::self.store.load"],
        "allowed_mutation_ports": [],
        "allowed_authority_ports": [],
        "non_authoritative_output_effects": [],
        **values,
    }


def _inventory(*, call: str = "service.py::self.store.load", eligible: bool = True) -> dict:
    return {"functions": [{
        "symbol": "service.py::Handler.handle",
        "effect_unresolved": [{"port_eligible": eligible}],
        "calls": [{
            "called_symbol": call,
            "call_name": call.rsplit(".", 1)[-1],
            "dispatch_resolution": "unresolved",
            "dispatch_port_eligible": eligible,
        }],
    }]}


def _validate(operation: dict, inventory: dict) -> tuple[int, int]:
    return validate_operation_effects(operation, "service.py::Handler.handle", inventory)


def test_explicit_read_boundary_is_supported_without_output_waiver() -> None:
    assert _validate(_operation(), _inventory()) == (0, 0)


def test_read_declaration_requires_truthful_classification() -> None:
    with pytest.raises(SemanticOperationEffectError, match="authoritative_read"):
        _validate(_operation(authoritative_read=False), _inventory())


@pytest.mark.parametrize("category", [
    "allowed_mutation_ports", "allowed_authority_ports", "non_authoritative_output_effects",
])
def test_read_port_cannot_overlap_other_effect_categories(category: str) -> None:
    with pytest.raises(SemanticOperationEffectError, match="overlap"):
        _validate(_operation(**{category: ["service.py::self.store.load"]}), _inventory())


def test_read_port_must_be_reachable() -> None:
    inventory = {"functions": [{"symbol": "service.py::Handler.handle", "calls": []}]}
    with pytest.raises(SemanticOperationEffectError, match="unreachable"):
        _validate(_operation(), inventory)


def test_read_declaration_does_not_waive_hard_alias() -> None:
    with pytest.raises(SemanticOperationEffectError, match="unresolved effect call path"):
        _validate(_operation(), _inventory(eligible=False))


@pytest.mark.parametrize("name", ["write_text", "publish_status"])
def test_read_declaration_cannot_waive_known_write_or_authority(name: str) -> None:
    target = f"service.py::self.store.{name}"
    with pytest.raises(SemanticOperationEffectError, match="read port.*effect"):
        _validate(_operation(allowed_read_ports=[target]), _inventory(call=target))


@pytest.mark.parametrize("name", ["write_text", "publish_status"])
def test_source_resolved_read_port_is_traversed_for_hidden_effects(name: str) -> None:
    target = "service.py::read_value"
    inventory = {"functions": [
        {"symbol": "service.py::Handler.handle", "calls": [{"called_symbol": target, "call_name": "read_value"}]},
        {"symbol": target, "calls": [{"called_symbol": f"service.py::{name}", "call_name": name}]},
    ]}
    with pytest.raises(SemanticOperationEffectError, match="undeclared (write|authority) effects"):
        _validate(_operation(allowed_read_ports=[target]), inventory)


def test_omitted_read_declaration_preserves_existing_operation_contract() -> None:
    operation = _operation()
    operation.pop("allowed_read_ports")
    inventory = {"functions": [{"symbol": "service.py::Handler.handle", "calls": []}]}
    assert _validate(operation, inventory) == (0, 0)


def test_read_declaration_does_not_change_effect_count_api() -> None:
    target = "service.py::read_value"
    inventory = {"functions": [
        {"symbol": "service.py::Handler.handle", "calls": [{"called_symbol": target, "call_name": "read_value"}]},
        {"symbol": target, "calls": []},
    ]}
    assert _validate(_operation(allowed_read_ports=[target]), inventory) == (0, 0)


def test_nonempty_read_change_requires_existing_effect_migration() -> None:
    previous = _operation(allowed_read_ports=[])
    assert _operation_change_kinds(previous, _operation()) == ("effect_changed",)
    assert _operation_change_kinds(_operation(), previous) == ("effect_changed",)
    previous.pop("allowed_read_ports")
    assert _operation_change_kinds(previous, _operation(allowed_read_ports=[])) == ()


def test_operation_schema_accepts_optional_read_list_and_stays_closed() -> None:
    schema = json.loads((Path(__file__).resolve().parents[1] / "schemas/application-operations.schema.json").read_text())
    validator = jsonschema.Draft202012Validator({"$ref": "#/$defs/operation", "$defs": schema["$defs"]})
    row = {
        **_operation(),
        "population": "native", "population_key": "read", "family": "example",
        "bounded_context": "example", "entrypoints": ["service.py::Handler.handle"],
        "semantic_kind": "query", "authoritative_mutation": False,
        "authority_conferral": False, "produces_projection": True, "model_callable": False,
    }
    validator.validate(row)
    row.pop("allowed_read_ports")
    validator.validate(row)
    with pytest.raises(jsonschema.ValidationError):
        validator.validate({**row, "allowed_read_ports": "not-an-array"})
    with pytest.raises(jsonschema.ValidationError):
        validator.validate({**row, "unknown_read_waiver": []})
