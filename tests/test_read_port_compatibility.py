"""Read declarations are source obligations, never write/authority exemptions."""
import copy
import shutil
from pathlib import Path

import pytest
import yaml

from bcf_governance.tooling import semantic_authority_contracts as authority
from bcf_governance.tooling import semantic_authority_migrations as migrations
from bcf_governance.tooling.semantic_operation_effects import (
    SemanticOperationEffectError, validated_operation_effect_inventory, validate_operation_effects,
)
from bcf_governance.tooling.semantic_ownership_inventory import discover_python_source, resolve_python_imports
from bcf_governance.tooling.ci_graph_composition_populations import lifecycle_effect_population
from test_affected_proof_closure import _git

ROOT = Path(__file__).resolve().parents[1]


def source(tmp_path, body="def reader():\n    return 1\n", entry="return reader()"):
    path = tmp_path / "runtime.py"
    path.write_text(body + "\ndef query():\n    " + entry + "\nCOMMANDS = {\"query\": query}\n")
    return resolve_python_imports(tmp_path, discover_python_source(
        tmp_path, files=[path], call_contracts_version="1.0"))


def operation(**changes):
    return dict(id="example.query.v1", population="cli", population_key="query", family="example",
        bounded_context="example", entrypoints=["runtime.py::query"], semantic_kind="query",
        authoritative_read=True, authoritative_mutation=False, authority_conferral=False,
        produces_projection=False, model_callable=False, allowed_mutation_ports=[],
        allowed_authority_ports=[], non_authoritative_output_effects=[],
        allowed_read_ports=["runtime.py::reader"]) | changes


def payload(op):
    return dict(schema_version="1.0", document=dict(kind="application_operation_registry",
        id="example-operations", version="1.0.0", status="active", path="governance/application-operations.yml"),
        populations=[dict(id="cli", adapter="python_mapping", source="runtime.py", symbol="COMMANDS", public_only=True)],
        operations=[op], migrations=[])


def test_public_schema_and_source_inventory_admit_a_pure_read(tmp_path):
    (tmp_path / "schemas").mkdir()
    shutil.copyfile(ROOT / "schemas/application-operations.schema.json",
                    tmp_path / "schemas/application-operations.schema.json")
    facts = source(tmp_path)
    observed = authority._validate_operations(tmp_path, payload(operation()), facts)
    assert observed[0]["effect_ports"] == [
        {"classification": "read", "target_kind": "function", "symbol": "runtime.py::reader"}]
    assert validate_operation_effects(operation(), "runtime.py::query", facts) == (0, 0)


def test_omitted_and_empty_read_lists_preserve_legacy_inventory(tmp_path):
    facts = source(tmp_path)
    omitted = operation()
    omitted.pop("allowed_read_ports")
    assert validated_operation_effect_inventory(omitted, "runtime.py::query", facts) == \
        validated_operation_effect_inventory(operation(allowed_read_ports=[]), "runtime.py::query", facts)


def test_read_ports_require_authoritative_read_semantics():
    with pytest.raises(authority.SemanticAuthorityError, match="read ports require authoritative_read"):
        authority._validate_operation_semantics(operation(authoritative_read=False))


@pytest.mark.parametrize("field", ["allowed_mutation_ports", "allowed_authority_ports", "non_authoritative_output_effects"])
def test_read_port_identity_is_disjoint_from_other_effect_roles(tmp_path, field):
    facts = source(tmp_path)
    with pytest.raises(SemanticOperationEffectError, match="read ports.*disjoint"):
        validated_operation_effect_inventory(operation(**{field:["runtime.py::reader"]}), "runtime.py::query", facts)


@pytest.mark.parametrize("field", ["allowed_mutation_ports", "allowed_authority_ports", "non_authoritative_output_effects"])
def test_read_body_cannot_borrow_command_effect_permissions(tmp_path, field):
    facts = source(tmp_path,
        "def effect():\n    path.write_text('changed')\n"
        "def reader():\n    return effect()\n")
    op = operation(**{field:["runtime.py::effect"]})
    with pytest.raises(SemanticOperationEffectError, match="write|authority|unresolved"):
        validated_operation_effect_inventory(op, "runtime.py::query", facts)


def test_unreachable_read_declaration_refuses(tmp_path):
    facts = source(tmp_path, entry="return 1")
    with pytest.raises(SemanticOperationEffectError, match="unreachable effect ports"):
        validated_operation_effect_inventory(operation(), "runtime.py::query", facts)


@pytest.mark.parametrize("value", [True, "runtime.py::reader", [None], ["runtime.py::reader", "runtime.py::reader"]])
def test_malformed_read_declaration_refuses(tmp_path, value):
    facts = source(tmp_path)
    with pytest.raises(SemanticOperationEffectError, match="read port"):
        validated_operation_effect_inventory(operation(allowed_read_ports=value), "runtime.py::query", facts)


def test_read_alias_cannot_acquire_mutation_permission(tmp_path):
    facts = source(tmp_path, "def reader():\n    return 1\nalias = reader\n")
    op = operation(allowed_read_ports=["runtime.py::alias"], allowed_mutation_ports=["runtime.py::reader"])
    with pytest.raises(SemanticOperationEffectError, match="read port"):
        validated_operation_effect_inventory(op, "runtime.py::query", facts)


def test_lifecycle_projection_retains_read_binding_without_authority():
    port = ("example.query.v1", "read", "function", "runtime.py::reader")
    observed = [{"operation":port[0], "entrypoint":"runtime.py::query",
                 "effect_ports":[dict(classification=port[1], target_kind=port[2], symbol=port[3])],
                 "write_effect_count":0, "authority_effect_count":0}]
    effects = lifecycle_effect_population(observed, expected_entrypoints={port[0]:"runtime.py::query"},
        effect_bindings={port:frozenset({("context","producer","consumer")})})
    assert len(effects) == 1


@pytest.mark.parametrize("field", ["allowed_read_ports", "non_authoritative_output_effects"])
def test_effect_boundary_changes_require_migration(field):
    before = operation()
    after = copy.deepcopy(before)
    after[field] = ["runtime.py::different"]
    assert migrations._operation_change_kinds(before, after) == ("effect_changed",), "read/output boundary change ignored"


def test_empty_read_default_does_not_fabricate_migration():
    before = operation(allowed_read_ports=[])
    after = copy.deepcopy(before)
    before.pop("allowed_read_ports")
    assert migrations._operation_change_kinds(before, after) == ()


def test_real_git_exact_base_read_change_generates_migration(tmp_path):
    _git(tmp_path, "init", "-q")
    _git(tmp_path, "config", "user.name", "Fixture")
    _git(tmp_path, "config", "user.email", "fixture@example.invalid")
    path = tmp_path / "governance/application-operations.yml"
    path.parent.mkdir()
    (tmp_path / "fixture").write_text("migration owner\n")
    before = operation(allowed_read_ports=[])
    path.write_text(yaml.safe_dump(payload(before)))
    _git(tmp_path, "add", ".")
    _git(tmp_path, "commit", "-qm", "exact base")
    base = _git(tmp_path, "rev-parse", "HEAD")
    path.write_text(yaml.safe_dump(payload(operation())))
    rows = migrations.register_operation_migration(tmp_path, base_sha=base,
        subject_id=before["id"], owner="fixture", reason="bind read boundary", apply=False)
    assert len(rows) == 1 and rows[0]["change"] == "effect_changed"
