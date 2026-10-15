from __future__ import annotations

import copy
import json
from dataclasses import asdict
from pathlib import Path
from types import SimpleNamespace

import pytest
from jsonschema import Draft202012Validator, ValidationError

from bcf_governance.tooling.ci_graph_composition import (
    compile_lifecycle_composition,
    edge_population_sha256,
    render_lifecycle_composition,
)
from bcf_governance.tooling.ci_graph_edges import EdgeContract
from bcf_governance.tooling.ci_graph_errors import CIGraphError
from bcf_governance.tooling.ci_graph_yaml import load_yaml_path


ROOT = Path(__file__).resolve().parents[1]
SCHEMA = json.loads((ROOT / "schemas/ci-lifecycle-composition.schema.json").read_text())


@pytest.fixture
def composition():
    edge = EdgeContract(
        "build:produce", "verify:consume", True, "workflow_run", None,
        ("exact-assets",), "exact-subject", "provider-artifact", "required",
        (("contents", "read"),), "release", "trusted-consumer", "fail-closed",
    )
    graph = SimpleNamespace(graph_sha256="a" * 64, edge_contracts=(edge,))
    identity = dict(
        repository_id="1207503211", commit_sha="b" * 40, tree_sha="c" * 40,
        controller_commit_sha="d" * 40, policy_sha256="e" * 64,
        graph_sha256=graph.graph_sha256, ci_edges_sha256=edge_population_sha256(graph),
    )
    fact = dict(
        id="exact-assets", producer="build", verifier="protected-verifier",
        subject_binding="repository-commit-tree", proposition="assets-exact",
        authority="provider-build", freshness="exact-at-consumption",
    )
    contract = dict(
        mechanism="provider-artifact", input_schema="release-build-manifest.schema.json",
        output_schema="release-verification.schema.json", cardinality="exactly-one",
        facts=[fact], guards=[dict(fact_id="exact-assets", check="exact_subject")], effects=["verify"],
        successor="verified", rejection="invalid-assets", recovery="bounded-read",
        cleanup="exact-owned-state", freshness="exact-at-consumption",
        cost_boundary="before-verifier-allocation", resource_class="isolated-verifier",
        reuse="independently-applicable-only", implementation=["verifier::verify"],
        positive_tests=["test_verifier::test_exact_assets"],
        negative_tests=["test_verifier::test_substituted_assets"],
        terminal_consumers=["immutable-custody"],
        ci_edges=[dict(producer=edge.producer, consumer=edge.consumer)],
    )
    payload = dict(schema_version="1.0", source=identity, relationships=[
        dict(context="release", producer="build", consumer="verify",
             contract=contract, exclusion=None),
        dict(context="release", producer="verify", consumer="build",
             contract=None, exclusion="no-structural-path"),
    ])
    return dict(
        payload=payload, schema=SCHEMA, compiled_graph=graph,
        expected_source=identity,
        expected_populations={"release": ("build", "verify")},
        expected_relationships={
            ("release", "build", "verify"): None,
            ("release", "verify", "build"): "no-structural-path",
        },
        expected_effects={("release", "build", "verify", "verify")},
    )


def test_valid_composition_has_no_authority_and_is_byte_stable(composition):
    first = compile_lifecycle_composition(**composition)
    composition["payload"]["relationships"].reverse()
    second = compile_lifecycle_composition(**composition)
    assert first == second
    assert first["authority"] is False
    assert first["source"] == composition["expected_source"]
    assert len(first["relationships"]) == 2


def test_removed_relationship_and_its_tests_cannot_hide_population(composition):
    composition["payload"]["relationships"].pop(0)
    with pytest.raises(CIGraphError, match="population"):
        compile_lifecycle_composition(**composition)


@pytest.mark.parametrize("field", ["negative_tests", "positive_tests", "facts", "terminal_consumers"])
def test_missing_binding_rejects_before_composition(composition, field):
    composition["payload"]["relationships"][0]["contract"][field] = []
    with pytest.raises(CIGraphError, match="schema"):
        compile_lifecycle_composition(**composition)


def test_false_exclusion_cannot_erase_reachable_guard_failure(composition):
    row = composition["payload"]["relationships"][0]
    row.update(contract=None, exclusion="no-structural-path")
    with pytest.raises(CIGraphError, match="exclusion"):
        compile_lifecycle_composition(**composition)


def test_omitted_runtime_effect_rejects_independently(composition):
    composition["payload"]["relationships"][0]["contract"]["effects"] = []
    with pytest.raises(CIGraphError, match="effect population"):
        compile_lifecycle_composition(**composition)


@pytest.mark.parametrize("field", ["commit_sha", "tree_sha", "controller_commit_sha", "policy_sha256", "repository_id"])
def test_wrong_authenticated_identity_rejects(composition, field):
    composition["expected_source"] = copy.deepcopy(composition["expected_source"])
    composition["payload"]["source"][field] = "0" * len(composition["payload"]["source"][field])
    with pytest.raises(CIGraphError, match="source identity"):
        compile_lifecycle_composition(**composition)


def test_ci_edge_population_digest_binds_contract_semantics(composition):
    graph = composition["compiled_graph"]
    old = edge_population_sha256(graph)
    fields = asdict(graph.edge_contracts[0])
    fields["custody"] = "different-custody"
    graph.edge_contracts = (EdgeContract(**fields),)
    assert edge_population_sha256(graph) != old
    with pytest.raises(CIGraphError, match="CI edge identity"):
        compile_lifecycle_composition(**composition)


def test_absent_ci_edge_cannot_transport_artifacts(composition):
    composition["payload"]["relationships"][0]["contract"]["ci_edges"][0]["consumer"] = "missing"
    with pytest.raises(CIGraphError, match="CI edge reference"):
        compile_lifecycle_composition(**composition)


def test_duplicate_pair_and_duplicate_effect_reject(composition):
    composition["payload"]["relationships"][0]["contract"]["effects"].append("verify")
    with pytest.raises(CIGraphError, match="schema"):
        compile_lifecycle_composition(**composition)


def test_empty_independent_population_cannot_self_certify(composition):
    composition["expected_relationships"] = {}
    with pytest.raises(CIGraphError, match="population"):
        compile_lifecycle_composition(**composition)


def test_independent_pair_inventory_must_close_the_node_population(composition):
    composition["expected_populations"]["release"] = ("build", "verify", "publish")
    with pytest.raises(CIGraphError, match="population is not closed"):
        compile_lifecycle_composition(**composition)


def test_candidate_cannot_supply_authentication_boolean(composition):
    composition["payload"]["relationships"][0]["contract"]["facts"][0]["authenticated"] = True
    with pytest.raises(CIGraphError, match="schema"):
        compile_lifecycle_composition(**composition)


def test_guard_must_reference_a_uniquely_produced_fact(composition):
    composition["payload"]["relationships"][0]["contract"]["guards"][0]["fact_id"] = "omitted"
    with pytest.raises(CIGraphError, match="undeclared fact"):
        compile_lifecycle_composition(**composition)


def test_conflicting_fact_producers_reject(composition):
    facts = composition["payload"]["relationships"][0]["contract"]["facts"]
    facts.append({**facts[0], "producer": "another-producer"})
    with pytest.raises(CIGraphError, match="ambiguous"):
        compile_lifecycle_composition(**composition)


def test_duplicate_pair_with_different_contract_still_rejects(composition):
    row = copy.deepcopy(composition["payload"]["relationships"][0])
    row["contract"]["recovery"] = "another-recovery"
    composition["payload"]["relationships"].append(row)
    with pytest.raises(CIGraphError, match="duplicate"):
        compile_lifecycle_composition(**composition)


def test_compiled_snapshot_is_detached_from_later_input_changes(composition):
    result = compile_lifecycle_composition(**composition)
    old = json.dumps(result, sort_keys=True)
    composition["payload"]["relationships"][0]["contract"]["facts"][0]["producer"] = "forged"
    assert json.dumps(result, sort_keys=True) == old


def test_source_is_unchanged_and_compiler_performs_no_mutation(composition):
    original = copy.deepcopy(composition["payload"])
    compile_lifecycle_composition(**composition)
    assert composition["payload"] == original


def test_generated_human_view_contains_every_edge_and_contract_field(composition):
    compiled = compile_lifecycle_composition(**composition)
    rendered = render_lifecycle_composition(compiled)
    assert "flowchart TD" in rendered
    assert "no-structural-path" in rendered
    assert "test_verifier::test_substituted_assets" in rendered
    assert "build:produce" in rendered
    for field in composition["payload"]["relationships"][0]["contract"]:
        assert f"| {field} |" in rendered
    composition["payload"]["relationships"].reverse()
    assert render_lifecycle_composition(compile_lifecycle_composition(**composition)) == rendered


def test_projection_rejects_tampered_compiled_snapshot(composition):
    compiled = compile_lifecycle_composition(**composition)
    compiled["relationships"].pop()
    with pytest.raises(CIGraphError, match="projection identity"):
        render_lifecycle_composition(compiled)


def test_projection_escapes_contract_text_without_changing_machine_meaning(composition):
    composition["payload"]["relationships"][0]["contract"]["recovery"] = '<script> | "quoted"\nnext'
    rendered = render_lifecycle_composition(compile_lifecycle_composition(**composition))
    assert "<script>" not in rendered
    assert "&lt;script&gt; &#124; &quot;quoted&quot;<br>next" in rendered


def test_train_inventory_covers_all_identified_requirements_and_workitems():
    plan = load_yaml_path(ROOT / "audits/issue-394/workplan.yml")
    schema = json.loads((ROOT / "audits/issue-394/workplan.schema.json").read_text())
    Draft202012Validator(schema).validate(plan)
    expected = {f"{prefix}{index:02}" for prefix, count in (
        ("I", 32), ("F", 8), ("CP", 10), ("AC", 32),
    ) for index in range(1, count + 1)}
    assert set(plan["requirements"]) == expected
    assert set(plan["canonical_workitem_mapping"]) == set(plan["workitems"])
    for requirement in plan["requirements"].values():
        assert requirement["workitem"] in plan["workitems"]
        assert requirement["terminal_gate"] in plan["workitems"]


@pytest.mark.parametrize("requirement", ["I23", "F06", "CP07", "AC16"])
@pytest.mark.parametrize("defect", ["missing_requirement", "missing_negative_control"])
def test_train_inventory_rejects_unmapped_or_unqualified_requirement(requirement, defect):
    plan = load_yaml_path(ROOT / "audits/issue-394/workplan.yml")
    schema = json.loads((ROOT / "audits/issue-394/workplan.schema.json").read_text())
    if defect == "missing_requirement":
        del plan["requirements"][requirement]
    else:
        del plan["requirements"][requirement]["negative_binding"]
    with pytest.raises(ValidationError):
        Draft202012Validator(schema).validate(plan)


@pytest.fixture
def binding_inputs(composition, tmp_path):
    from bcf_governance.tooling.semantic_ownership_inventory import discover_python_source

    source = tmp_path / 'runtime.py'
    source.write_text('def verify():\n    return True\n\ndef consume():\n    return verify()\n')
    inventory = discover_python_source(tmp_path, files=[source])
    contract = composition['payload']['relationships'][0]['contract']
    contract['implementation'] = ['runtime.py::verify']
    contract['terminal_consumers'] = ['runtime.py::consume']
    contract['positive_tests'] = ['tests/test_runtime.py::test_valid']
    contract['negative_tests'] = ['tests/test_runtime.py::test_wrong_subject']
    compiled = compile_lifecycle_composition(**composition)
    return dict(
        compiled=compiled,
        expected_source=composition['expected_source'],
        source_inventory=inventory,
        collected_selectors=frozenset(contract['positive_tests'] + contract['negative_tests']),
        required_call_edges={('release', 'build', 'verify'): frozenset({('runtime.py::consume', 'runtime.py::verify')})},
        required_negative_controls={
            ('release', 'build', 'verify'): {
                'wrong-subject': 'tests/test_runtime.py::test_wrong_subject',
            },
        },
    )


def _validate_bindings(inputs):
    from bcf_governance.tooling.ci_graph_composition import validate_lifecycle_bindings

    return validate_lifecycle_bindings(**inputs)


def test_binding_conformance_resolves_real_inventory_without_conferring_execution(binding_inputs):
    before = copy.deepcopy(binding_inputs)
    result = _validate_bindings(binding_inputs)
    assert result['authority'] is False
    assert result['execution_qualified'] is False
    assert result['composition_sha256'] == binding_inputs['compiled']['composition_sha256']
    assert result['reachable_relationships'] == 1
    assert result == _validate_bindings(binding_inputs)
    assert binding_inputs == before


@pytest.mark.parametrize('field', ['implementation', 'terminal_consumers'])
def test_binding_conformance_rejects_deleted_function(binding_inputs, field):
    symbol = binding_inputs['compiled']['relationships'][0]['contract'][field][0]
    binding_inputs['source_inventory']['functions'] = [
        row for row in binding_inputs['source_inventory']['functions'] if row['symbol'] != symbol
    ]
    with pytest.raises(CIGraphError, match='runtime function'):
        _validate_bindings(binding_inputs)


@pytest.mark.parametrize('selector', ['tests/test_runtime.py::test_valid', 'tests/test_runtime.py::test_wrong_subject'])
def test_binding_conformance_rejects_uncollected_test(binding_inputs, selector):
    binding_inputs['collected_selectors'] -= {selector}
    with pytest.raises(CIGraphError, match='collected test'):
        _validate_bindings(binding_inputs)


def test_binding_conformance_rejects_ambiguous_function_inventory(binding_inputs):
    binding_inputs['source_inventory']['functions'].append(
        copy.deepcopy(binding_inputs['source_inventory']['functions'][0])
    )
    with pytest.raises(CIGraphError, match='ambiguous'):
        _validate_bindings(binding_inputs)


def test_binding_conformance_rejects_missing_independent_relationship(binding_inputs):
    binding_inputs['required_negative_controls'] = {}
    with pytest.raises(CIGraphError, match='relationship population'):
        _validate_bindings(binding_inputs)


def test_binding_conformance_rejects_missing_cause_even_with_existing_negative(binding_inputs):
    controls = binding_inputs['required_negative_controls'][('release', 'build', 'verify')]
    controls['wrong-authority'] = 'tests/test_runtime.py::test_wrong_authority'
    binding_inputs['collected_selectors'] |= {'tests/test_runtime.py::test_wrong_authority'}
    with pytest.raises(CIGraphError, match='cause-specific'):
        _validate_bindings(binding_inputs)


def test_binding_conformance_rejects_empty_causal_catalogue(binding_inputs):
    binding_inputs['required_negative_controls'][('release', 'build', 'verify')] = {}
    with pytest.raises(CIGraphError, match='cause-specific'):
        _validate_bindings(binding_inputs)


def test_binding_conformance_rejects_tampered_compilation(binding_inputs):
    binding_inputs['compiled']['relationships'][0]['contract']['implementation'] = ['runtime.py::invented']
    with pytest.raises(CIGraphError, match='projection identity'):
        _validate_bindings(binding_inputs)


def test_binding_conformance_rejects_wrong_source(binding_inputs):
    binding_inputs['expected_source'] = {**binding_inputs['expected_source'], 'tree_sha': 'f' * 40}
    with pytest.raises(CIGraphError, match='source identity'):
        _validate_bindings(binding_inputs)


def test_binding_conformance_uses_existing_source_and_pytest_collection_owners(binding_inputs, tmp_path):
    import sys

    from bcf_governance.tooling.test_manifests import collect_selector_map

    tests = tmp_path / 'tests'
    tests.mkdir()
    (tests / 'test_runtime.py').write_text(
        'def test_valid():\n    assert True\n\ndef test_wrong_subject():\n    assert True\n'
    )
    governance = tmp_path / 'governance'
    governance.mkdir()
    (governance / 'gate-contracts.yml').write_text(
        'gates:\n  contract-test:\n    evidence:\n      test_contract:\n'
        '        selectors: [tests/test_runtime.py]\n'
        '        expected_node_manifest: governance/contract-tests.txt\n'
    )
    mapping = collect_selector_map(tmp_path, 'contract-test', python_executable=sys.executable)
    binding_inputs['collected_selectors'] = frozenset(selector for _, selector in mapping.entries)
    assert _validate_bindings(binding_inputs)['execution_qualified'] is False
    (tests / 'test_runtime.py').write_text('def test_valid():\n    assert True\n')
    mapping = collect_selector_map(tmp_path, 'contract-test', python_executable=sys.executable)
    binding_inputs['collected_selectors'] = frozenset(selector for _, selector in mapping.entries)
    with pytest.raises(CIGraphError, match='collected test'):
        _validate_bindings(binding_inputs)


def test_requirement_slice_bindings_resolve_through_canonical_oracle_owner():
    from bcf_governance.tooling.test_manifests import oracle_manifest_index

    plan = load_yaml_path(ROOT / 'audits/issue-394/workplan.yml')
    index = oracle_manifest_index(ROOT)
    for requirement in plan['requirements'].values():
        for slice_id in requirement.get('implementation_slices', []):
            binding = plan['implementation_slices'][slice_id]
            assert binding['id'] == slice_id
            assert binding['workitem'] in plan['canonical_workitem_mapping'].values()
            assert binding['authority'] is False
            assert binding['remaining']
            assert len({control['cause'] for control in binding['negative_controls']}) == len(binding['negative_controls'])
            nodes = binding['positive_tests'] + [control['test'] for control in binding['negative_controls']]
            assert index.resolve(nodes, preferred_gate='test') == 'test'
        assert requirement['evidence_status'] == 'not_executed'


@pytest.mark.parametrize('field', ['negative_controls', 'producer', 'consumer', 'remaining'])
def test_requirement_slice_rejects_missing_qualification_binding(field):
    plan = load_yaml_path(ROOT / 'audits/issue-394/workplan.yml')
    schema = json.loads((ROOT / 'audits/issue-394/workplan.schema.json').read_text())
    slice_id = plan['requirements']['I23']['implementation_slices'][0]
    del plan['implementation_slices'][slice_id][field]
    with pytest.raises(ValidationError):
        Draft202012Validator(schema).validate(plan)


def test_binding_conformance_rejects_removed_call_with_both_functions_present(binding_inputs):
    for function in binding_inputs['source_inventory']['functions']:
        if function['symbol'] == 'runtime.py::consume':
            function['calls'] = []
    with pytest.raises(CIGraphError, match='source call'):
        _validate_bindings(binding_inputs)


def test_binding_conformance_rejects_incomplete_independent_call_population(binding_inputs):
    binding_inputs['required_call_edges'] = {}
    with pytest.raises(CIGraphError, match='call population'):
        _validate_bindings(binding_inputs)


def test_binding_conformance_requires_calls_or_compiled_transport(composition, binding_inputs):
    composition['payload']['relationships'][0]['contract']['ci_edges'] = []
    composition['payload']['relationships'][0]['contract'].update(
        implementation=['runtime.py::verify'], terminal_consumers=['runtime.py::consume'],
        positive_tests=['tests/test_runtime.py::test_valid'],
        negative_tests=['tests/test_runtime.py::test_wrong_subject'],
    )
    binding_inputs['compiled'] = compile_lifecycle_composition(**composition)
    binding_inputs['required_call_edges'] = {('release', 'build', 'verify'): frozenset()}
    with pytest.raises(CIGraphError, match='source call or CI transport'):
        _validate_bindings(binding_inputs)


def test_binding_conformance_traces_actual_compiler_and_projection_calls(composition, binding_inputs):
    from bcf_governance.tooling.semantic_ownership_inventory import discover_python_source

    path = 'bcf_governance/tooling/ci_graph_composition.py'
    symbol = lambda name: path + '::' + name
    contract = composition['payload']['relationships'][0]['contract']
    contract.update(
        implementation=[symbol('compile_lifecycle_composition'), symbol('_canonical_contract')],
        terminal_consumers=[symbol('render_lifecycle_composition'), symbol('_validate_compiled_identity')],
        positive_tests=['tests/test_runtime.py::test_valid'],
        negative_tests=['tests/test_runtime.py::test_wrong_subject'],
    )
    binding_inputs['compiled'] = compile_lifecycle_composition(**composition)
    binding_inputs['source_inventory'] = discover_python_source(ROOT, files=[ROOT / path])
    binding_inputs['required_call_edges'] = {('release', 'build', 'verify'): frozenset({
        (symbol('compile_lifecycle_composition'), symbol('_canonical_contract')),
        (symbol('render_lifecycle_composition'), symbol('_validate_compiled_identity')),
    })}
    assert _validate_bindings(binding_inputs)['authority'] is False


def test_binding_conformance_rejects_unresolved_required_call(binding_inputs):
    for function in binding_inputs['source_inventory']['functions']:
        if function['symbol'] == 'runtime.py::consume':
            function['calls'][0]['dispatch_resolution'] = 'unresolved'
    with pytest.raises(CIGraphError, match='source call is absent or unresolved'):
        _validate_bindings(binding_inputs)


def test_binding_conformance_rejects_call_outside_contract_functions(binding_inputs):
    binding_inputs['required_call_edges'] = {('release', 'build', 'verify'): frozenset({
        ('runtime.py::unbound', 'runtime.py::verify'),
    })}
    with pytest.raises(CIGraphError, match='source call endpoints are unbound'):
        _validate_bindings(binding_inputs)
