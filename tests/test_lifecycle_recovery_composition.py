"""Dormant typed references must close the actual loaded recovery owner."""
from __future__ import annotations

import copy
import hashlib
import json

import pytest

from test_ci_graph_composition import (
    composition, binding_inputs, operation_call_binding_inputs, reconstructed_binding_inputs,
)
from bcf_governance.tooling import ci_recovery_frontier as recovery
from bcf_governance.tooling.ci_graph_composition import (
    _bytes, compile_lifecycle_composition, render_lifecycle_composition,
)
from bcf_governance.tooling.ci_graph_errors import CIGraphError


def typed(composition):
    inputs = copy.deepcopy(composition)
    inputs["payload"]["schema_version"] = "1.2"
    inputs["payload"].pop("source")
    contract = inputs["payload"]["relationships"][0]["contract"]
    contract["recovery_edges"] = [
        {"operation": operation, "state": state}
        for operation, state in sorted(recovery._EDGES)
    ]
    return inputs


def test_typed_recovery_closes_loaded_owner_without_authority(composition):
    inputs = typed(composition)
    original = copy.deepcopy(inputs["payload"])
    compiled = compile_lifecycle_composition(**inputs)
    observation = compiled["recovery_frontier"]
    assert observation["edges_checked"] == len(recovery._EDGES)
    assert observation["authority"] is False
    assert observation["execution_qualified"] is False
    assert observation["context_authority_qualified"] is False
    assert inputs["payload"] == original
    assert {(row["operation"], row["state"]) for row in observation["bindings"]} == recovery._EDGES.keys()


@pytest.mark.parametrize("defect", ["omitted", "invented-state", "invented-operation", "empty", "duplicate"])
def test_typed_recovery_rejects_incomplete_or_invented_population(composition, defect):
    inputs = typed(composition)
    compile_lifecycle_composition(**inputs)
    references = inputs["payload"]["relationships"][0]["contract"]["recovery_edges"]
    if defect == "omitted":
        references.pop()
    elif defect == "empty":
        references.clear()
    elif defect == "invented-state":
        references[0]["state"] = "invented"
    elif defect == "duplicate":
        references.append(dict(references[0]))
    else:
        references[0]["operation"] = "invented"
    pattern = "schema" if defect == "duplicate" else "recovery.*population"
    with pytest.raises(CIGraphError, match=pattern):
        compile_lifecycle_composition(**inputs)


def test_omitted_recovery_edge_and_its_control_cannot_shrink_population(composition):
    inputs = typed(composition)
    contract = inputs["payload"]["relationships"][0]["contract"]
    contract["negative_tests"].append("test_recovery::specific_edge")
    compile_lifecycle_composition(**inputs)
    contract["negative_tests"].remove("test_recovery::specific_edge")
    contract["recovery_edges"].pop()
    with pytest.raises(CIGraphError, match="recovery.*population"):
        compile_lifecycle_composition(**inputs)


def test_recovery_machine_roundtrip_preserves_typed_version_and_order(composition):
    inputs = typed(composition)
    first = compile_lifecycle_composition(**inputs)
    machine = render_lifecycle_composition(first, view="machine")
    inputs["payload"] = json.loads(machine)
    assert inputs["payload"]["schema_version"] == "1.2"
    inputs["payload"]["relationships"].reverse()
    next(row["contract"] for row in inputs["payload"]["relationships"] if row["contract"])["recovery_edges"].reverse()
    second = compile_lifecycle_composition(**inputs)
    assert first == second
    assert render_lifecycle_composition(second, view="machine") == machine
    assert "recovery_edges" in render_lifecycle_composition(second, view="contract")


def test_changed_loaded_recovery_semantics_rejects_cached_snapshot(composition, monkeypatch):
    inputs = typed(composition)
    first = compile_lifecycle_composition(**inputs)
    original_view = render_lifecycle_composition(first, view="contract")
    identity = next(iter(recovery._EDGES))
    monkeypatch.setitem(recovery._EDGES, identity, ("changed_action", recovery._EDGES[identity][1]))
    with pytest.raises(CIGraphError, match="recovery.*(stale|differs)"):
        render_lifecycle_composition(first)
    second = compile_lifecycle_composition(**inputs)
    assert render_lifecycle_composition(second, view="contract") != original_view


def test_recomputed_hash_cannot_launder_recovery_snapshot(composition):
    compiled = compile_lifecycle_composition(**typed(composition))
    compiled["recovery_frontier"]["bindings"].pop()
    compiled["composition_sha256"] = hashlib.sha256(_bytes({
        key: value for key, value in compiled.items() if key != "composition_sha256"
    })).hexdigest()
    with pytest.raises(CIGraphError, match="recovery.*(stale|differs)"):
        render_lifecycle_composition(compiled)


@pytest.mark.parametrize("version", ["1.0", "1.1"])
def test_legacy_versions_cannot_silently_acquire_typed_recovery_fields(composition, version):
    inputs = typed(composition)
    inputs["payload"]["schema_version"] = version
    if version == "1.0":
        inputs["payload"]["source"] = inputs["expected_source"]
    with pytest.raises(CIGraphError, match="schema"):
        compile_lifecycle_composition(**inputs)


def test_candidate_schema_cannot_relax_typed_recovery_admission(composition):
    inputs = typed(composition)
    compile_lifecycle_composition(**inputs)
    inputs["schema"] = {"type": "object", "additionalProperties": True}
    with pytest.raises(CIGraphError, match="owned schema"):
        compile_lifecycle_composition(**inputs)


@pytest.mark.parametrize("cause", ["missing", "malformed"])
def test_typed_recovery_requires_owned_schema_resource(composition, tmp_path, monkeypatch, cause):
    import bcf_governance.tooling.ci_graph_composition as compiler
    inputs = typed(composition)
    compile_lifecycle_composition(**inputs)
    if cause == "malformed":
        path = tmp_path / "schemas/ci-lifecycle-composition.schema.json"
        path.parent.mkdir()
        path.write_text("{invalid")
    monkeypatch.setattr(compiler, "packaged_repo_root", lambda: tmp_path)
    with pytest.raises(CIGraphError, match="owned schema"):
        compile_lifecycle_composition(**inputs)


def test_recovery_consumer_rejects_stale_snapshot_before_source_discovery(
    composition, reconstructed_binding_inputs, monkeypatch,
):
    from bcf_governance.tooling import ci_graph_composition as compiler
    from bcf_governance.tooling import semantic_ownership_inventory as source
    inputs = copy.deepcopy(reconstructed_binding_inputs)
    inputs["compiled"] = compile_lifecycle_composition(**typed(composition))
    result = compiler.validate_reconstructed_lifecycle_bindings(**inputs)
    assert result["recovery_frontier"]["edges_checked"] == len(recovery._EDGES)
    assert result["authority"] is False and result["execution_qualified"] is False
    inputs["compiled"]["recovery_frontier"]["bindings"].pop()
    inputs["compiled"]["composition_sha256"] = hashlib.sha256(_bytes({
        key: value for key, value in inputs["compiled"].items() if key != "composition_sha256"
    })).hexdigest()
    monkeypatch.setattr(source, "discover_python_source",
                        lambda *args, **kwargs: pytest.fail("source discovery before recovery rejection"))
    with pytest.raises(CIGraphError, match="recovery.*differs"):
        compiler.validate_reconstructed_lifecycle_bindings(**inputs)


@pytest.mark.parametrize("version", ["1.0", "1.1"])
def test_cached_version_downgrade_cannot_skip_recovery_validation(composition, version):
    compiled = compile_lifecycle_composition(**typed(composition))
    compiled["schema_version"] = version
    compiled["composition_sha256"] = hashlib.sha256(_bytes({
        key: value for key, value in compiled.items() if key != "composition_sha256"
    })).hexdigest()
    with pytest.raises(CIGraphError, match="recovery.*version"):
        render_lifecycle_composition(compiled)


@pytest.mark.parametrize("version", [None, 1.2, "1.9"])
def test_unknown_version_cannot_borrow_permissive_schema(composition, version):
    inputs = typed(composition)
    compile_lifecycle_composition(**inputs)
    inputs["payload"]["schema_version"] = version
    inputs["schema"] = {}
    with pytest.raises(CIGraphError, match="schema version"):
        compile_lifecycle_composition(**inputs)
