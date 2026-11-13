"""Complete source blocker diagnostics retain strict operation failure."""
from pathlib import Path
import pytest
from bcf_governance.tooling.semantic_ownership_inventory import discover_python_source, resolve_python_imports
from bcf_governance.tooling.semantic_operation_effects import SemanticOperationEffectError, validate_operation_effects

def inventory(tmp_path: Path, source: str):
    path = tmp_path / "service.py"
    path.write_text(source)
    return resolve_python_imports(tmp_path, discover_python_source(
        tmp_path, files=[path], call_contracts_version="1.0"))

def operation(ports=()):
    return {"id": "population.query.v1", "allowed_mutation_ports": list(ports),
            "allowed_authority_ports": [], "non_authoritative_output_effects": []}

def test_parallel_source_protocol_blockers_are_retained(tmp_path):
    facts = inventory(tmp_path,
        "def left(value):\n    return value[0]\n"
        "def right(value):\n    return value[0]\n"
        "def query(value):\n    left(value)\n    return right(value)\n")
    with pytest.raises(SemanticOperationEffectError) as caught:
        validate_operation_effects(operation(), "service.py::query", facts)
    rows = getattr(caught.value, "effect_obligations", ())
    assert {row[0] for row in rows if row[1] == "runtime_protocol"} == {
        "service.py::left", "service.py::right"}, "parallel source blockers hidden by first failure"
    assert tuple(sorted(set(rows))) == rows

def test_repeated_protocol_sites_keep_distinct_source_identity(tmp_path):
    facts = inventory(tmp_path,
        "def query(value):\n    value[0]\n    return value[0]\n")
    with pytest.raises(SemanticOperationEffectError) as caught:
        validate_operation_effects(operation(), "service.py::query", facts)
    rows = [row for row in getattr(caught.value, "effect_obligations", ())
            if row[0] == "service.py::query" and row[1] == "runtime_protocol"]
    assert len(rows) == 2 and len({row[2] for row in rows}) == 2, "repeated protocol source sites collapsed"

def test_declared_effect_boundary_excludes_its_body_from_diagnostics(tmp_path):
    facts = inventory(tmp_path,
        "def port(value):\n    return value[0]\n"
        "def leaf(value):\n    return value[0]\n"
        "def query(value):\n    port(value)\n    return leaf(value)\n")
    with pytest.raises(SemanticOperationEffectError) as caught:
        validate_operation_effects(operation(("service.py::port",)), "service.py::query", facts)
    rows = getattr(caught.value, "effect_obligations", ())
    assert any(row[0] == "service.py::leaf" for row in rows), "scoped blocker population missing"
    assert not any(row[0] == "service.py::port" for row in rows)

def test_closed_literal_operation_remains_accepted(tmp_path):
    facts = inventory(tmp_path, "def query():\n    return 1\n")
    assert validate_operation_effects(operation(), "service.py::query", facts) == (0, 0)

def test_runtime_protocol_does_not_hide_unreachable_declared_port(tmp_path):
    facts = inventory(tmp_path,
        "def port():\n    return 1\n"
        "def query(value):\n    return value[0]\n")
    with pytest.raises(SemanticOperationEffectError) as caught:
        validate_operation_effects(operation(("service.py::port",)), "service.py::query", facts)
    kinds = {row[1] for row in getattr(caught.value, "effect_obligations", ())}
    assert {"runtime_protocol", "unreachable_port"} <= kinds, "unreachable port hidden behind protocol blocker"

def test_protocol_does_not_hide_separate_source_store_obligation(tmp_path):
    facts = inventory(tmp_path,
        "STATE = 0\n"
        "def query(value):\n    global STATE\n    STATE = 1\n    return value[0]\n")
    with pytest.raises(SemanticOperationEffectError) as caught:
        validate_operation_effects(operation(), "service.py::query", facts)
    kinds = {row[1] for row in getattr(caught.value, "effect_obligations", ())}
    assert "runtime_protocol" in kinds and kinds & {"write", "unresolved_effect"}, "mixed source obligations hidden"

def test_single_protocol_keeps_existing_error_string(tmp_path):
    facts = inventory(tmp_path, "def query(value):\n    return value[0]\n")
    with pytest.raises(SemanticOperationEffectError) as caught:
        validate_operation_effects(operation(), "service.py::query", facts)
    assert str(caught.value) == (
        "operation population.query.v1 contains an unresolved effect runtime protocol at service.py::query")

def test_ambiguous_inventory_aborts_before_diagnostic_credit(tmp_path):
    facts = inventory(tmp_path, "def query():\n    return 1\n")
    facts["functions"].append(dict(facts["functions"][0]))
    with pytest.raises(SemanticOperationEffectError, match="function population is incompatible or ambiguous") as caught:
        validate_operation_effects(operation(), "service.py::query", facts)
    assert getattr(caught.value, "effect_obligations", ()) == ()

def test_failure_note_is_machine_readable_without_runtime_credit(tmp_path):
    import json
    facts = inventory(tmp_path, "def query(value):\n    return value[0]\n")
    with pytest.raises(SemanticOperationEffectError) as caught:
        validate_operation_effects(operation(), "service.py::query", facts)
    notes = getattr(caught.value, "__notes__", ())
    assert len(notes) == 1, "structured failure note missing"
    observation = json.loads(notes[0])
    assert observation["scope"] == "existing_strict_validator_blockers"
    assert observation["authority"] is observation["execution_qualified"] is observation["completeness_qualified"] is False
    assert observation["effect_obligations"] == [list(row) for row in caught.value.effect_obligations]
