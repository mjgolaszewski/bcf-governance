"""Opt-in sibling operation diagnostics cannot authorize runtime effects."""
import copy
import shutil
from pathlib import Path

import pytest

from bcf_governance.tooling import semantic_authority_contracts as owner
from bcf_governance.tooling.semantic_ownership_inventory import discover_python_source


@pytest.fixture
def inputs(tmp_path):
    (tmp_path / "schemas").mkdir()
    shutil.copyfile(Path(__file__).parents[1] / "schemas/application-operations.schema.json",
                    tmp_path / "schemas/application-operations.schema.json")
    path = tmp_path / "runtime.py"
    path.write_text('def left(value):\n    return value[0]\ndef right(value):\n    return value[0]\nCOMMANDS = {"left": left, "right": right}\n')
    payload = dict(schema_version="1.0", document=dict(kind="application_operation_registry",
        id="example-operations", version="1.0.0", status="active", path="governance/application-operations.yml"),
        populations=[dict(id="cli", adapter="python_mapping", source="runtime.py", symbol="COMMANDS", public_only=True)],
        operations=[dict(id="example."+name+".v1", population="cli", population_key=name, family="example",
            bounded_context="example", entrypoints=["runtime.py::"+name], semantic_kind="query",
            authoritative_read=True, authoritative_mutation=False, authority_conferral=False,
            produces_projection=False, model_callable=False, allowed_mutation_ports=[],
            allowed_authority_ports=[], non_authoritative_output_effects=[]) for name in ["left", "right"]],
        migrations=[])
    return tmp_path, path, payload


def inventory(inputs):
    return discover_python_source(inputs[0], files=[inputs[1]], call_contracts_version="1.0")


def failure(inputs, facts=None, **options):
    with pytest.raises(owner.SemanticAuthorityError) as caught:
        owner._validate_operations(inputs[0], inputs[2], inventory(inputs) if facts is None else facts, **options)
    return caught.value


def test_opt_in_captures_both_failing_operation_populations(inputs):
    error = failure(inputs, collect_effect_obligations=True)
    assert error.operation_effect_population == ("example.left.v1", "example.right.v1")
    rows = error.operation_effect_obligations
    assert {row[0] for row in rows} == set(error.operation_effect_population), "sibling operation blockers hidden"
    assert rows == tuple(sorted(set(rows)))
    assert error.effect_context_scope == "admitted_operations_strict_validator_blockers"
    assert error.authority is error.execution_qualified is error.completeness_qualified is False
    assert error.require_runtime_context is True


def test_default_retains_earliest_failure_without_sibling_collection(inputs):
    error = failure(inputs)
    assert str(error) == "operation example.left.v1 contains an unresolved effect runtime protocol at runtime.py::left"
    assert not hasattr(error, "operation_effect_population")


def test_reordering_preserves_canonical_diagnostics_and_first_error_order(inputs):
    first = failure(inputs, collect_effect_obligations=True)
    inputs[2]["operations"].reverse()
    second = failure(inputs, collect_effect_obligations=True)
    assert second.operation_effect_obligations == first.operation_effect_obligations
    assert second.operation_effect_population == first.operation_effect_population
    assert str(second).startswith("operation example.right.v1 ")


def test_successful_sibling_stays_in_admitted_population(inputs):
    inputs[1].write_text(inputs[1].read_text().replace("return value[0]", "return 1", 1))
    error = failure(inputs, collect_effect_obligations=True)
    assert error.operation_effect_population == ("example.left.v1", "example.right.v1")
    assert {row[0] for row in error.operation_effect_obligations} == {"example.right.v1"}


def test_all_valid_operations_return_unchanged_observations(inputs):
    inputs[1].write_text(inputs[1].read_text().replace("return value[0]", "return 1"))
    facts = inventory(inputs)
    before = copy.deepcopy(facts)
    default = owner._validate_operations(inputs[0], inputs[2], facts)
    assert owner._validate_operations(inputs[0], inputs[2], facts, collect_effect_obligations=True) == default
    assert facts == before


def test_malformed_later_observation_aborts_without_completed_population(inputs):
    facts = inventory(inputs)
    right = next(row for row in facts["functions"] if row["symbol"] == "runtime.py::right")
    call = next(row for row in right["calls"] if "implicit_protocol" in row)
    call["implicit_protocol"]["authority"] = True
    error = failure(inputs, facts, collect_effect_obligations=True)
    assert "implicit protocol population is incompatible or ambiguous" in str(error)
    assert not hasattr(error, "operation_effect_population")


def test_unclassified_operation_refuses_before_effect_traversal(inputs, monkeypatch):
    inputs[2]["operations"].pop()
    monkeypatch.setattr(owner, "validated_operation_effect_inventory",
                        lambda *args, **kwargs: pytest.fail("effects traversed before population admission"))
    assert "unclassified public application operations" in str(failure(inputs, collect_effect_obligations=True))


@pytest.mark.parametrize("value", [None, 1, "true"])
def test_diagnostic_option_is_strictly_boolean(inputs, value):
    assert "effect diagnostic option must be boolean" in str(failure(inputs, collect_effect_obligations=value))

def test_source_only_diagnostic_view_retains_unqualified_context(inputs):
    observations = owner._validate_operations(inputs[0], inputs[2], inventory(inputs),
                                              require_runtime_context=False, collect_effect_obligations=True)
    assert len(observations) == 2
    assert all(row["effect_context_scope"] == "source_only_runtime_unqualified" for row in observations)
    assert all(row["unresolved_effect_context_count"] == 1 for row in observations)


def test_diagnostic_option_cannot_waive_required_runtime_context(inputs):
    error = failure(inputs, consumer_owned_schema=True,
                    require_runtime_context=False, collect_effect_obligations=True)
    assert "required operations cannot waive runtime effect context" in str(error)
