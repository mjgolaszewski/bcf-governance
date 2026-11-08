from __future__ import annotations

import copy
from pathlib import Path

import pytest

from bcf_governance.tooling.semantic_operation_effects import (
    SemanticOperationEffectError, validate_operation_effects,
)
from bcf_governance.tooling.semantic_ownership_inventory import discover_python_source
from bcf_governance.tooling.semantic_operation_registrations import (
    TypedRegistrationError, discover_typed_registrations,
)


PATTERNS = '''from dataclasses import dataclass

@dataclass(frozen=True)
class QuerySpec:
    name: str
    query_factory: object
    dispatch: str = "ask"

    def register(self, server, context):
        register_query(server, context, self)

def register_query(server, context, spec: QuerySpec):
    @server.tool(name=spec.name)
    async def _tool(value):
        return await context.services.mediator.ask(spec.query_factory(value))
'''
TABLE = '''from patterns import QuerySpec
from factories import first, second

TOOLS = (
    QuerySpec(name="first.get", query_factory=first),
    QuerySpec(name="second.get", query_factory=second),
)

def register_tools(server, context):
    for spec in TOOLS:
        spec.register(server, context)
'''


@pytest.fixture
def registered(tmp_path):
    (tmp_path / "patterns.py").write_text(PATTERNS)
    (tmp_path / "table.py").write_text(TABLE)
    (tmp_path / "factories.py").write_text('def first(value):\n    return value\n\ndef second(value):\n    return value\n')
    return tmp_path, {"id": "tools", "adapter": "python_typed_registrations",
                      "source": "table.py", "symbol": "TOOLS", "public_only": True}


def discover(registered):
    root, population = registered
    inventory = discover_python_source(root, sorted(root.glob("*.py")))
    entries, bound = discover_typed_registrations(root, population, inventory)
    return entries, bound, {**inventory, "functions": [*inventory["functions"], *bound]}


def operation():
    return {"id": "first.get.v1", "authoritative_read": True,
            "allowed_read_ports": ["patterns.py::context.services.mediator.ask"],
            "allowed_mutation_ports": [], "allowed_authority_ports": [],
            "non_authoritative_output_effects": []}


def test_each_instance_joins_actual_lexical_handler_factory_and_dispatch(registered):
    entries, bound, inventory = discover(registered)
    assert set(entries) == {"first.get", "second.get"}
    assert len(set(entries.values())) == 2
    for key, fact in zip(("first", "second"), bound, strict=True):
        binding = fact["registration_binding"]
        assert binding["factory"] == f"factories.py::{key}"
        assert binding["lexical_handler"] == "patterns.py::register_query._tool"
        assert binding["dispatch"] == "ask"
        assert any(row["called_symbol"] == f"factories.py::{key}" for row in fact["calls"])
    assert validate_operation_effects(operation(), entries["first.get"], inventory) == (0, 0)


def test_bound_factory_effects_are_followed_instead_of_dto_proxy(registered):
    root, _ = registered
    (root / "factories.py").write_text('def first(value):\n    value.write_text("bad")\n    return value\n\ndef second(value):\n    return value\n')
    entries, _, inventory = discover(registered)
    with pytest.raises(SemanticOperationEffectError, match="undeclared write effects"):
        validate_operation_effects(operation(), entries["first.get"], inventory)


@pytest.mark.parametrize("file,before,after", [
    ("table.py", 'name="second.get"', 'name="first.get"'),
    ("table.py", 'name="first.get"', 'name=operation_name'),
    ("table.py", 'query_factory=first', 'query_factory=factories[0]'),
    ("table.py", 'spec.register(server, context)', 'other.register(server, context)'),
    ("table.py", 'def register_tools', 'TOOLS.append(extra)\n\ndef register_tools'),
    ("table.py", 'def register_tools', 'QuerySpec = replacement\n\ndef register_tools'),
    ("patterns.py", '@dataclass(frozen=True)', '@dataclass(frozen=False)'),
    ("patterns.py", 'register_query(server, context, self)', 'register_query(server, context, other)'),
    ("patterns.py", 'mediator.ask', 'mediator.send'),
    ("patterns.py", 'spec.query_factory(value)', 'other.query_factory(value)'),
    ("patterns.py", 'name=spec.name', 'name="different"'),
    ("patterns.py", 'async def _tool(value):', 'async def _tool(value):\n        spec = other'),
    ("patterns.py", 'def register_query', 'Alias = QuerySpec\nAlias.register = replacement\n\ndef register_query'),
    ("patterns.py", 'def register_query', 'QuerySpec.register = replacement\n\ndef register_query'),
    ("patterns.py", 'def register_query', 'def replace_factory(self):\n    object.__setattr__(self, "query_factory", replacement)\nQuerySpec.__post_init__ = replace_factory\n\ndef register_query'),
    ("patterns.py", '    def register(self, server, context):', '    def __post_init__(self):\n        object.__setattr__(self, "query_factory", replacement)\n\n    def register(self, server, context):'),
    ("patterns.py", '@dataclass(frozen=True)', '@wrapper\n@dataclass(frozen=True)'),
    ("patterns.py", '    @server.tool(name=spec.name)', '    @replacement\n    @server.tool(name=spec.name)'),
    ("table.py", 'def register_tools', 'Alias = QuerySpec\nAlias.register = replacement\n\ndef register_tools'),
])
def test_unknown_duplicate_cross_instance_or_alias_drift_fails_closed(registered, file, before, after):
    root, _ = registered
    path = root / file
    path.write_text(path.read_text().replace(before, after))
    with pytest.raises(TypedRegistrationError):
        discover(registered)


def test_source_changed_after_inventory_cannot_supply_registration(registered):
    root, population = registered
    inventory = discover_python_source(root, sorted(root.glob("*.py")))
    original = copy.deepcopy(inventory)
    path = root / "table.py"
    path.write_text(path.read_text().replace('"first.get"', '"changed.get"'))
    with pytest.raises(TypedRegistrationError, match="source differs"):
        discover_typed_registrations(root, population, inventory)
    assert inventory == original


def payload(registered):
    _, population = registered
    entries, _, _ = discover(registered)
    return {
        "schema_version": "1.1",
        "document": {"kind": "application_operation_registry", "id": "fixture-operations",
                     "version": "1.0.0", "status": "active", "path": "governance/application-operations.yml"},
        "populations": [population], "migrations": [],
        "operations": [{**operation(), "id": key + ".v1", "population": "tools",
                        "population_key": key, "family": "tools", "bounded_context": "orders",
                        "entrypoints": [symbol], "semantic_kind": "query", "authoritative_mutation": False,
                        "authority_conferral": False, "produces_projection": False, "model_callable": True}
                       for key, symbol in entries.items()],
    }


@pytest.mark.parametrize("mutation", [None, "legacy-opt-in", "false-direction", "omitted-operation"])
def test_owner_integrates_actual_handler_effects_and_explicit_opt_in(registered, mutation):
    import shutil
    from bcf_governance.tooling.semantic_authority_contracts import SemanticAuthorityError, _validate_operations

    root, _ = registered
    (root / "schemas").mkdir()
    shutil.copyfile(Path(__file__).resolve().parents[1] / "schemas/application-operations.schema.json",
                    root / "schemas/application-operations.schema.json")
    inventory = discover_python_source(root, sorted(root.glob("*.py")))
    original = copy.deepcopy(inventory)
    value = payload(registered)
    if mutation == "legacy-opt-in":
        value["schema_version"] = "1.0"
        with pytest.raises(SemanticAuthorityError, match="populations.0.adapter"):
            _validate_operations(root, value, inventory)
    elif mutation == "false-direction":
        value["operations"][0]["semantic_kind"] = "command"
        with pytest.raises(SemanticAuthorityError, match="contradicts actual typed dispatch"):
            _validate_operations(root, value, inventory)
    elif mutation == "omitted-operation":
        value["operations"].pop()
        with pytest.raises(SemanticAuthorityError, match="unclassified public application operations"):
            _validate_operations(root, value, inventory)
    else:
        assert len(_validate_operations(root, value, inventory)) == 2
    assert inventory == original


def test_local_dataclasses_shadow_cannot_claim_frozen_contract(registered):
    root, _ = registered
    (root / "dataclasses.py").write_text("def dataclass(**kwargs):\n    return lambda cls: cls\n")
    with pytest.raises(TypedRegistrationError, match="dataclasses shadow"):
        discover(registered)
