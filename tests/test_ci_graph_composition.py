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
    source.write_text('def produce():\n    return b"assets"\n\ndef verify():\n    return True\n\ndef consume():\n    return verify()\n')
    inventory = discover_python_source(tmp_path, files=[source])
    contract = composition['payload']['relationships'][0]['contract']
    contract['facts'][0].update(producer='runtime.py::produce', verifier='runtime.py::verify')
    contract['implementation'] = ['runtime.py::verify']
    contract['terminal_consumers'] = ['runtime.py::consume']
    contract['positive_tests'] = ['tests/test_runtime.py::test_valid']
    contract['negative_tests'] = ['tests/test_runtime.py::test_wrong_subject']
    compiled = compile_lifecycle_composition(**composition)
    return dict(
        compiled=compiled,
        expected_source=composition['expected_source'],
        source_inventory=inventory,
        required_fact_bindings={('release', 'build', 'verify'): tuple(copy.deepcopy(contract['facts']))},
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
    contract['facts'][0].update(producer=symbol('compile_lifecycle_composition'), verifier=symbol('_validate_compiled_identity'))
    binding_inputs['required_fact_bindings'] = {('release', 'build', 'verify'): tuple(copy.deepcopy(contract['facts']))}
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


def test_contract_view_is_stable_across_bound_subjects(composition):
    first = compile_lifecycle_composition(**composition)
    identity = dict(composition['expected_source'])
    identity.update(commit_sha='1' * 40, tree_sha='2' * 40, controller_commit_sha='3' * 40, repository_id='17')
    composition['expected_source'] = identity
    composition['payload']['source'] = dict(identity)
    second = compile_lifecycle_composition(**composition)
    assert first['composition_sha256'] != second['composition_sha256']
    assert render_lifecycle_composition(first) != render_lifecycle_composition(second)
    assert render_lifecycle_composition(first, view='contract') == render_lifecycle_composition(second, view='contract')
    assert identity['commit_sha'] not in render_lifecycle_composition(second, view='contract')


@pytest.mark.parametrize('field', ['policy', 'contract', 'graph', 'ci_edges'])
def test_contract_view_changes_for_semantic_changes(composition, field):
    before = render_lifecycle_composition(compile_lifecycle_composition(**composition), view='contract')
    if field == 'policy':
        identity = dict(composition['expected_source'], policy_sha256='f' * 64)
        composition['expected_source'] = identity
        composition['payload']['source'] = dict(identity)
    elif field == 'contract':
        composition['payload']['relationships'][0]['contract']['recovery'] = 'different-bounded-recovery'
    else:
        graph = composition['compiled_graph']
        if field == 'graph':
            graph.graph_sha256 = 'f' * 64
            identity = dict(composition['expected_source'], graph_sha256=graph.graph_sha256)
        else:
            values = asdict(graph.edge_contracts[0])
            values['custody'] = 'changed-custody'
            graph.edge_contracts = (EdgeContract(**values),)
            identity = dict(composition['expected_source'], ci_edges_sha256=edge_population_sha256(graph))
        composition['expected_source'] = identity
        composition['payload']['source'] = dict(identity)
    after = render_lifecycle_composition(compile_lifecycle_composition(**composition), view='contract')
    assert before != after


def test_contract_view_still_rejects_tampered_bound_identity(composition):
    compiled = compile_lifecycle_composition(**composition)
    compiled['source']['commit_sha'] = '0' * 40
    with pytest.raises(CIGraphError, match='projection identity'):
        render_lifecycle_composition(compiled, view='contract')


def test_renderer_rejects_unknown_view(composition):
    with pytest.raises(CIGraphError, match='view'):
        render_lifecycle_composition(compile_lifecycle_composition(**composition), view='invented')


@pytest.fixture
def effect_population_inputs():
    return dict(
        observations=[dict(
            operation='release.publish.v1', entrypoint='publisher.py::main',
            write_effect_count=0, authority_effect_count=1,
            effect_ports=[dict(classification='authority', target_kind='function', symbol='publisher.py::publish')],
        )],
        expected_entrypoints={'release.publish.v1': 'publisher.py::main'},
        effect_bindings={
            ('release.publish.v1', 'authority', 'function', 'publisher.py::publish'):
                frozenset({('release', 'build', 'verify')}),
        },
    )


def _effect_population(inputs):
    from bcf_governance.tooling.ci_graph_composition import lifecycle_effect_population

    return lifecycle_effect_population(**inputs)


def test_operation_effect_population_closes_actual_compiler_effects(composition, effect_population_inputs):
    effects = _effect_population(effect_population_inputs)
    composition['expected_effects'] = effects
    composition['payload']['relationships'][0]['contract']['effects'] = [next(iter(effects))[-1]]
    assert compile_lifecycle_composition(**composition)['authority'] is False
    composition['payload']['relationships'][0]['contract']['effects'] = []
    with pytest.raises(CIGraphError, match='effect population'):
        compile_lifecycle_composition(**composition)


@pytest.mark.parametrize('defect', ['missing_operation', 'missing_port', 'extra_binding', 'wrong_entrypoint', 'duplicate_operation', 'duplicate_port', 'old_consumer', 'wrong_role_count', 'missing_context', 'unknown_role', 'unknown_kind', 'malformed_port', 'invalid_context', 'empty_expected'])
def test_operation_effect_population_rejects_omitted_or_ambiguous_facts(effect_population_inputs, defect):
    inputs = effect_population_inputs
    row = inputs['observations'][0]
    if defect == 'missing_operation':
        inputs['observations'] = []
    elif defect == 'missing_port':
        row['effect_ports'] = []
        row['authority_effect_count'] = 0
    elif defect == 'extra_binding':
        inputs['effect_bindings'][('foreign.v1', 'authority', 'call', 'api.publish')] = frozenset({('release', 'build', 'verify')})
    elif defect == 'wrong_entrypoint':
        row['entrypoint'] = 'foreign.py::main'
    elif defect == 'duplicate_operation':
        inputs['observations'].append(copy.deepcopy(row))
    elif defect == 'duplicate_port':
        row['effect_ports'].append(copy.deepcopy(row['effect_ports'][0]))
    elif defect == 'old_consumer':
        del row['effect_ports']
    elif defect == 'wrong_role_count':
        row['authority_effect_count'] = False
    elif defect == 'missing_context':
        key = next(iter(inputs['effect_bindings']))
        inputs['effect_bindings'][key] = frozenset()
    elif defect == 'unknown_role':
        row['effect_ports'][0]['classification'] = 'caller-authorized'
    elif defect == 'unknown_kind':
        row['effect_ports'][0]['target_kind'] = 'unchecked'
    elif defect == 'malformed_port':
        row['effect_ports'][0]['authorized'] = True
    elif defect == 'invalid_context':
        key = next(iter(inputs['effect_bindings']))
        inputs['effect_bindings'][key] = frozenset({('release', 'verify', 'verify')})
    else:
        inputs['expected_entrypoints'] = {}
    with pytest.raises(CIGraphError):
        _effect_population(inputs)


def test_discovered_source_authority_port_survives_candidate_effect_omission(composition, tmp_path):
    from bcf_governance.tooling.semantic_operation_effects import validated_operation_effect_inventory
    from bcf_governance.tooling.semantic_ownership_inventory import discover_python_source

    source = tmp_path / 'publisher.py'
    source.write_text('def main():\n    return publish()\n\ndef publish():\n    return True\n')
    inventory = discover_python_source(tmp_path, files=[source])
    operation = dict(id='release.publish.v1', allowed_mutation_ports=[],
                     allowed_authority_ports=['publisher.py::publish'], non_authoritative_output_effects=[])
    ports = validated_operation_effect_inventory(operation, 'publisher.py::main', inventory)
    inputs = dict(
        observations=[dict(operation=operation['id'], entrypoint='publisher.py::main',
                           write_effect_count=0, authority_effect_count=1,
                           effect_ports=[dict(classification=role, target_kind=kind, symbol=symbol) for role, kind, symbol in ports])],
        expected_entrypoints={operation['id']: 'publisher.py::main'},
        effect_bindings={(operation['id'], role, kind, symbol): frozenset({('release', 'build', 'verify')})
                         for role, kind, symbol in ports},
    )
    composition['expected_effects'] = _effect_population(inputs)
    composition['payload']['relationships'][0]['contract']['effects'] = [next(iter(composition['expected_effects']))[-1]]
    assert compile_lifecycle_composition(**composition)['authority'] is False
    composition['payload']['relationships'][0]['contract']['effects'] = []
    with pytest.raises(CIGraphError, match='effect population'):
        compile_lifecycle_composition(**composition)
    composition['payload']['relationships'].pop(0)
    with pytest.raises(CIGraphError, match='population'):
        compile_lifecycle_composition(**composition)


@pytest.mark.parametrize('field', ['id', 'producer', 'verifier', 'subject_binding', 'proposition', 'authority', 'freshness'])
def test_fact_binding_rejects_substitution_from_independent_owner(composition, binding_inputs, field):
    composition['payload']['relationships'][0]['contract']['facts'][0][field] = 'substituted'
    if field == 'id':
        composition['payload']['relationships'][0]['contract']['guards'][0]['fact_id'] = 'substituted'
    binding_inputs['compiled'] = compile_lifecycle_composition(**composition)
    with pytest.raises(CIGraphError, match='fact population'):
        _validate_bindings(binding_inputs)


def test_fact_binding_requires_complete_independent_relationship_population(binding_inputs):
    binding_inputs['required_fact_bindings'] = {}
    with pytest.raises(CIGraphError, match='independent fact relationship population'):
        _validate_bindings(binding_inputs)


@pytest.mark.parametrize('mutation', ['missing', 'duplicate', 'changed'])
def test_fact_binding_rejects_invalid_protected_fact_population(binding_inputs, mutation):
    pair = ('release', 'build', 'verify')
    facts = binding_inputs['required_fact_bindings'][pair]
    if mutation == 'missing':
        facts = ()
    elif mutation == 'duplicate':
        facts = facts + facts
    else:
        facts[0]['authority'] = 'another-authority'
    binding_inputs['required_fact_bindings'][pair] = facts
    with pytest.raises(CIGraphError, match='fact population'):
        _validate_bindings(binding_inputs)


@pytest.mark.parametrize('role', ['producer', 'verifier'])
def test_fact_binding_rejects_orphan_source_owner(binding_inputs, role):
    fact = binding_inputs['required_fact_bindings'][('release', 'build', 'verify')][0]
    binding_inputs['source_inventory']['functions'] = [
        row for row in binding_inputs['source_inventory']['functions'] if row['symbol'] != fact[role]
    ]
    with pytest.raises(CIGraphError, match='fact source runtime function'):
        _validate_bindings(binding_inputs)


def test_machine_contract_round_trip_preserves_every_relationship(composition):
    compiled = compile_lifecycle_composition(**composition)
    text = render_lifecycle_composition(compiled, view='machine')
    authored = json.loads(text)
    assert authored == {'schema_version': '1.1', 'relationships': compiled['relationships']}
    assert text == json.dumps(authored, sort_keys=True, separators=(',', ':')) + '\n'
    composition['payload'] = authored
    rebound = compile_lifecycle_composition(**composition)
    assert rebound['source'] == compiled['source']
    assert rebound['relationships'] == compiled['relationships']
    assert rebound['authority'] is False
    assert render_lifecycle_composition(rebound, view='machine') == text


def test_machine_contract_bytes_are_stable_across_subjects_and_order(composition):
    first = compile_lifecycle_composition(**composition)
    text = render_lifecycle_composition(first, view='machine')
    composition['payload'] = json.loads(text)
    composition['payload']['relationships'].reverse()
    composition['expected_source'] = dict(composition['expected_source'], commit_sha='1' * 40, tree_sha='2' * 40)
    rebound = compile_lifecycle_composition(**composition)
    assert rebound['source'] != first['source']
    assert rebound['composition_sha256'] != first['composition_sha256']
    assert render_lifecycle_composition(rebound, view='machine') == text


def test_authored_machine_contract_cannot_inject_runtime_source(composition):
    composition['payload']['schema_version'] = '1.1'
    with pytest.raises(CIGraphError, match='schema'):
        compile_lifecycle_composition(**composition)


def test_legacy_machine_contract_still_requires_source(composition):
    del composition['payload']['source']
    with pytest.raises(CIGraphError, match='schema'):
        compile_lifecycle_composition(**composition)


@pytest.mark.parametrize('source', [None, {}, {'commit_sha': 'invented'}])
def test_authored_machine_contract_requires_complete_protected_source(composition, source):
    composition['payload'] = json.loads(render_lifecycle_composition(compile_lifecycle_composition(**composition), view='machine'))
    composition['expected_source'] = source
    with pytest.raises(CIGraphError, match='authenticated source identity'):
        compile_lifecycle_composition(**composition)


@pytest.mark.parametrize('field', ['ci_edges_sha256', 'graph_sha256'])
def test_authored_machine_contract_rejects_wrong_current_graph(composition, field):
    composition['payload'] = json.loads(render_lifecycle_composition(compile_lifecycle_composition(**composition), view='machine'))
    composition['expected_source'] = dict(composition['expected_source'], **{field: 'f' * 64})
    with pytest.raises(CIGraphError, match='CI edge identity'):
        compile_lifecycle_composition(**composition)


@pytest.mark.parametrize('omission', ['relationship', 'effect'])
def test_authored_machine_contract_cannot_omit_protected_population(composition, omission):
    composition['payload'] = json.loads(render_lifecycle_composition(compile_lifecycle_composition(**composition), view='machine'))
    if omission == 'relationship':
        composition['payload']['relationships'].pop(0)
    else:
        composition['payload']['relationships'][0]['contract']['effects'] = []
    with pytest.raises(CIGraphError, match='population'):
        compile_lifecycle_composition(**composition)


def test_machine_view_rejects_tampered_bound_envelope(composition):
    compiled = compile_lifecycle_composition(**composition)
    compiled['source']['tree_sha'] = '0' * 40
    with pytest.raises(CIGraphError, match='projection identity'):
        render_lifecycle_composition(compiled, view='machine')


def test_authored_machine_contract_rejects_unknown_schema_version(composition):
    composition['payload'] = json.loads(render_lifecycle_composition(compile_lifecycle_composition(**composition), view='machine'))
    composition['payload']['schema_version'] = '1.2'
    with pytest.raises(CIGraphError, match='schema'):
        compile_lifecycle_composition(**composition)


@pytest.fixture
def operation_call_binding_inputs(binding_inputs, tmp_path):
    from bcf_governance.tooling.semantic_ownership_inventory import discover_python_source
    from bcf_governance.tooling.semantic_operation_effects import source_operation_call_population
    source = tmp_path / "runtime.py"
    source.write_text(source.read_text().replace("return True", "return declared_port()") + "\ndef declared_port():\n    return True\n")
    inventory = discover_python_source(tmp_path, files=[source], call_contracts_version="1.0")
    binding_inputs["source_inventory"] = inventory
    roots = ("runtime.py::produce", "runtime.py::verify", "runtime.py::consume")
    binding_inputs["required_operation_calls"] = {
        ("release", "build", "verify"): {
            root: source_operation_call_population(root, inventory) for root in roots
        }
    }
    return binding_inputs


def test_binding_checks_protected_operation_call_populations(operation_call_binding_inputs):
    before = copy.deepcopy(operation_call_binding_inputs)
    result = _validate_bindings(operation_call_binding_inputs)
    assert result["authority"] is False
    assert result["execution_qualified"] is False
    assert result["operation_call_populations_checked"] == 3
    assert operation_call_binding_inputs == before


def test_binding_rejects_added_call_beyond_retained_declared_endpoint(operation_call_binding_inputs):
    inventory = operation_call_binding_inputs["source_inventory"]
    helper = next(row for row in inventory["functions"] if row["symbol"] == "runtime.py::declared_port")
    call = copy.deepcopy(next(row for row in inventory["functions"] if row["symbol"] == "runtime.py::verify")["calls"][0])
    call.update(caller=helper["symbol"], called_symbol="runtime.py::hidden", call_name="hidden")
    call["call_contract"]["expression_sha256"] = "e" * 64
    helper["calls"].append(call)
    with pytest.raises(CIGraphError, match="operation call population"):
        _validate_bindings(operation_call_binding_inputs)


@pytest.mark.parametrize("defect", ["relationship", "root", "version", "source_file", "extra_root", "malformed_catalogue", "authority_claim"])
def test_binding_rejects_incomplete_or_incompatible_operation_population(operation_call_binding_inputs, defect):
    inputs = operation_call_binding_inputs
    catalogue = inputs["required_operation_calls"]
    pair = ("release", "build", "verify")
    if defect == "relationship":
        del catalogue[pair]
    elif defect == "root":
        del catalogue[pair]["runtime.py::produce"]
    elif defect == "version":
        inputs["source_inventory"]["call_contracts_version"] = "0.9"
    elif defect == "source_file":
        inputs["source_inventory"]["files"][0]["sha256"] = "f" * 64
    elif defect == "extra_root":
        catalogue[pair]["runtime.py::invented"] = {}
    elif defect == "malformed_catalogue":
        catalogue[pair]["runtime.py::produce"] = {"not-json": {1}}
    else:
        catalogue[pair]["runtime.py::produce"]["authority"] = True
    with pytest.raises(CIGraphError, match="operation call population"):
        _validate_bindings(inputs)


def test_legacy_binding_result_does_not_claim_operation_population_checks(binding_inputs):
    assert "operation_call_populations_checked" not in _validate_bindings(binding_inputs)


@pytest.fixture
def path_inputs(composition):
    import hashlib

    contract = composition["payload"]["relationships"][0]["contract"]
    contract.update(successor="ST-OK", rejection="ST-FAIL", recovery="TR-003")
    compiled = compile_lifecycle_composition(**composition)
    pair = ("release", "build", "verify")
    states = [dict(id=identity, owner="existing-owner", authority="none", terminal_class=kind)
              for identity, kind in [("ST-START", "none"), ("ST-OK", "custody"), ("ST-FAIL", "blocked")]]
    transitions = [
        dict(id="TR-001", kind="success", **{"from": "ST-START", "to": "ST-OK"},
             invariants=["INV-RT-001"], rejection_transition="TR-002"),
        dict(id="TR-002", kind="rejection", **{"from": "ST-START", "to": "ST-FAIL"},
             invariants=["INV-RT-001"]),
        dict(id="TR-003", kind="recovery", **{"from": "ST-FAIL", "to": "ST-START"},
             invariants=["INV-RT-001"], retry_of="TR-001", max_attempts=2),
    ]
    guard_refs = ["sha256:" + hashlib.sha256(json.dumps(guard, sort_keys=True, separators=(",", ":")).encode()).hexdigest()
                  for guard in contract["guards"]]
    for transition in transitions:
        transition["guard_refs"] = list(guard_refs)
    backtrace = dict(states=states, transitions=transitions)
    return dict(compiled=compiled, expected_source=dict(composition["expected_source"]), backtrace=backtrace,
                expected_backtrace_sha256=hashlib.sha256(json.dumps(backtrace, sort_keys=True, separators=(",", ":"), allow_nan=False).encode()).hexdigest(),
                required_states={row["id"]: row["terminal_class"] for row in states},
                required_transition_bindings={row["id"]: pair for row in transitions},
                required_recovery_limits={"TR-003": 2})


def _path_query(inputs):
    from bcf_governance.tooling.ci_graph_composition import validate_lifecycle_paths

    return validate_lifecycle_paths(**inputs)


def _refresh_path_digest(inputs):
    import hashlib

    inputs["expected_backtrace_sha256"] = hashlib.sha256(json.dumps(
        inputs["backtrace"], sort_keys=True, separators=(",", ":"), allow_nan=False
    ).encode()).hexdigest()


def test_typed_paths_allow_only_bounded_recovery_outside_attempt_graph(path_inputs):
    before = copy.deepcopy(path_inputs)
    result = _path_query(path_inputs)
    assert result["authority"] is False
    assert result["execution_qualified"] is False
    assert result["transitions_checked"] == 3
    assert result["recoveries_checked"] == 1
    assert result["backtrace_sha256"] == path_inputs["expected_backtrace_sha256"]
    assert path_inputs == before
    path_inputs["backtrace"]["transitions"].reverse()
    _refresh_path_digest(path_inputs)
    assert _path_query(path_inputs)["transitions_checked"] == 3


@pytest.mark.parametrize("defect", [
    "missing-state", "duplicate-state", "wrong-terminal-class", "unknown-terminal-class",
    "missing-transition", "duplicate-transition", "extra-binding", "missing-binding",
    "wrong-relationship", "missing-recovery-limit", "wrong-recovery-limit", "boolean-limit",
    "unbounded-recovery", "wrong-recovery-target", "wrong-recovery-source", "lost-invariant",
    "unknown-rejection", "wrong-rejection-source", "untyped-transition", "unknown-destination",
    "same-attempt-cycle", "wrong-source", "missing-state-population",
])
def test_typed_paths_reject_incomplete_or_unbound_attempts(path_inputs, composition, defect):
    model = path_inputs["backtrace"]
    states = model["states"]
    edges = model["transitions"]
    if defect == "missing-state": states.pop()
    elif defect == "duplicate-state": states.append(copy.deepcopy(states[0]))
    elif defect == "wrong-terminal-class": states[1]["terminal_class"] = "workitem"
    elif defect == "unknown-terminal-class": states[1]["terminal_class"] = "agent-decides"
    elif defect == "missing-transition": edges.pop()
    elif defect == "duplicate-transition": edges.append(copy.deepcopy(edges[0]))
    elif defect == "extra-binding": path_inputs["required_transition_bindings"]["TR-004"] = ("release", "build", "verify")
    elif defect == "missing-binding": path_inputs["required_transition_bindings"].pop("TR-002")
    elif defect == "wrong-relationship": path_inputs["required_transition_bindings"]["TR-003"] = ("release", "verify", "build")
    elif defect == "missing-recovery-limit": path_inputs["required_recovery_limits"].clear()
    elif defect == "wrong-recovery-limit": edges[2]["max_attempts"] = 3
    elif defect == "boolean-limit": edges[2]["max_attempts"] = True
    elif defect == "unbounded-recovery": edges[2]["max_attempts"] = 0
    elif defect == "wrong-recovery-target": edges[2]["to"] = "ST-OK"
    elif defect == "wrong-recovery-source": edges[2]["from"] = "ST-START"
    elif defect == "lost-invariant": edges[2]["invariants"] = []
    elif defect == "unknown-rejection": edges[0]["rejection_transition"] = "TR-999"
    elif defect == "wrong-rejection-source": edges[1]["from"] = "ST-OK"
    elif defect == "untyped-transition": edges[1].pop("kind")
    elif defect == "unknown-destination": edges[0]["to"] = "ST-UNKNOWN"
    elif defect == "same-attempt-cycle":
        edges[0]["to"] = "ST-START"
        composition["payload"]["relationships"][0]["contract"].update(
            successor="ST-START", rejection="ST-FAIL", recovery="TR-003")
        path_inputs["compiled"] = compile_lifecycle_composition(**composition)
    elif defect == "missing-state-population": path_inputs["required_states"].clear()
    _refresh_path_digest(path_inputs)
    if defect == "wrong-source": path_inputs["expected_backtrace_sha256"] = "0" * 64
    match = "concrete attempt contains a cycle" if defect == "same-attempt-cycle" else "lifecycle path"
    with pytest.raises(CIGraphError, match=match):
        _path_query(path_inputs)


@pytest.mark.parametrize("field,value", [("successor", "UNDECLARED"), ("rejection", "UNDECLARED"), ("recovery", "UNDECLARED")])
def test_typed_paths_bind_every_composition_outcome(composition, path_inputs, field, value):
    contract = composition["payload"]["relationships"][0]["contract"]
    contract.update(successor="ST-OK", rejection="ST-FAIL", recovery="TR-003")
    contract[field] = value
    path_inputs["compiled"] = compile_lifecycle_composition(**composition)
    with pytest.raises(CIGraphError, match="lifecycle path"):
        _path_query(path_inputs)


@pytest.mark.parametrize("defect", ["model-list", "states-null", "transitions-null", "bad-terminal-catalogue", "untyped-state", "bad-kind", "wrong-compiled-source"])
def test_typed_paths_reject_malformed_protected_inputs(path_inputs, defect):
    if defect == "wrong-compiled-source": path_inputs["expected_source"]["commit_sha"] = "f" * 40
    elif defect == "model-list": path_inputs["backtrace"] = []
    elif defect == "states-null": path_inputs["backtrace"]["states"] = None
    elif defect == "transitions-null": path_inputs["backtrace"]["transitions"] = None
    elif defect == "bad-terminal-catalogue": path_inputs["required_states"]["ST-OK"] = []
    elif defect == "untyped-state": path_inputs["backtrace"]["states"][0].pop("terminal_class")
    elif defect == "bad-kind": path_inputs["backtrace"]["transitions"][0]["kind"] = []
    _refresh_path_digest(path_inputs)
    with pytest.raises(CIGraphError, match="lifecycle path"):
        _path_query(path_inputs)


def test_typed_paths_allow_explicit_terminal_rejection_without_retry(path_inputs, composition):
    path_inputs["backtrace"]["transitions"].pop()
    path_inputs["required_transition_bindings"].pop("TR-003")
    path_inputs["required_recovery_limits"].clear()
    composition["payload"]["relationships"][0]["contract"].update(
        successor="ST-OK", rejection="ST-FAIL", recovery="none")
    path_inputs["compiled"] = compile_lifecycle_composition(**composition)
    _refresh_path_digest(path_inputs)
    assert _path_query(path_inputs)["recoveries_checked"] == 0


@pytest.mark.parametrize("defect", ["terminal", "kind", "missing-rejection", "missing-retry", "boolean-limit", "zero-limit"])
def test_backtrace_schema_checks_opt_in_typed_paths(defect):
    schema = json.loads((ROOT / "schemas/release-train-backtrace.schema.json").read_text())
    model = load_yaml_path(ROOT / "spec/phase0/release-train-backtrace.yml")
    validator = Draft202012Validator(schema)
    validator.validate(model)
    transition = model["transitions"][0]
    if defect == "terminal": model["states"][0]["terminal_class"] = "agent-decides"
    elif defect == "kind": transition["kind"] = "unknown"
    elif defect == "missing-rejection": transition["kind"] = "success"
    else:
        transition.update(kind="recovery", max_attempts=2)
        if defect != "missing-retry": transition["retry_of"] = "TR-001"
        if defect == "boolean-limit": transition["max_attempts"] = True
        elif defect == "zero-limit": transition["max_attempts"] = 0
    with pytest.raises(ValidationError):
        validator.validate(model)


@pytest.mark.parametrize("field,index", [("rejection_transition", 0), ("retry_of", 2)])
def test_typed_paths_reject_nonstring_transition_references(path_inputs, field, index):
    path_inputs["backtrace"]["transitions"][index][field] = []
    _refresh_path_digest(path_inputs)
    with pytest.raises(CIGraphError, match="typed transition reference"):
        _path_query(path_inputs)


@pytest.mark.parametrize("defect", ["missing-all", "missing-recovery", "changed-recovery", "unknown-all", "duplicate", "malformed", "nonstring"])
def test_typed_paths_reject_dropped_or_poisoned_guard_references(path_inputs, defect):
    edges = path_inputs["backtrace"]["transitions"]
    if defect == "missing-all":
        for row in edges: row.pop("guard_refs")
    elif defect == "missing-recovery": edges[2].pop("guard_refs")
    elif defect == "changed-recovery": edges[2]["guard_refs"] = ["sha256:" + "f" * 64]
    elif defect == "unknown-all":
        for row in edges: row["guard_refs"] = ["sha256:" + "f" * 64]
    elif defect == "duplicate": edges[2]["guard_refs"] *= 2
    elif defect == "malformed": edges[2]["guard_refs"] = ["not-a-guard-reference"]
    elif defect == "nonstring": edges[2]["guard_refs"] = [{}]
    _refresh_path_digest(path_inputs)
    with pytest.raises(CIGraphError, match="guard"):
        _path_query(path_inputs)


def test_typed_paths_cannot_omit_a_compiled_guard_obligation(path_inputs, composition):
    import hashlib

    contract = composition["payload"]["relationships"][0]["contract"]
    contract.update(successor="ST-OK", rejection="ST-FAIL", recovery="TR-003")
    added = dict(fact_id="exact-assets", check="freshness")
    reference = "sha256:" + hashlib.sha256(json.dumps(added, sort_keys=True, separators=(",", ":")).encode()).hexdigest()
    for row in path_inputs["backtrace"]["transitions"]:
        row["guard_refs"].append(reference)
    _refresh_path_digest(path_inputs)
    # Model retains both independently bound obligations, proposed compiled guard
    # population omits one. A source hash alone must not conceal that omission.
    path_inputs["compiled"] = compile_lifecycle_composition(**composition)
    with pytest.raises(CIGraphError, match="guard"):
        _path_query(path_inputs)
    contract["guards"].append(added)
    path_inputs["compiled"] = compile_lifecycle_composition(**composition)
    assert _path_query(path_inputs)["guard_obligations_checked"] == 2


@pytest.mark.parametrize("defect", ["malformed", "duplicate", "empty", "missing-kind"])
def test_backtrace_schema_rejects_invalid_guard_references(defect):
    schema = json.loads((ROOT / "schemas/release-train-backtrace.schema.json").read_text())
    model = load_yaml_path(ROOT / "spec/phase0/release-train-backtrace.yml")
    row = model["transitions"][0]
    row.update(kind="rejection", guard_refs=["sha256:" + "a" * 64])
    validator = Draft202012Validator(schema)
    validator.validate(model)
    if defect == "malformed": row["guard_refs"] = ["arbitrary guard"]
    elif defect == "duplicate": row["guard_refs"] *= 2
    elif defect == "empty": row["guard_refs"] = []
    else: row.pop("kind")
    with pytest.raises(ValidationError):
        validator.validate(model)


@pytest.fixture
def initialization_binding_inputs(operation_call_binding_inputs, tmp_path):
    from bcf_governance.tooling.semantic_ownership_inventory import discover_python_source
    from bcf_governance.tooling.semantic_operation_effects import source_operation_call_population
    source = tmp_path / 'runtime.py'
    source.write_text('initialize()\n' + source.read_text())
    inventory = discover_python_source(tmp_path, files=[source], call_contracts_version='1.0', initialization_contracts_version='1.0')
    operation_call_binding_inputs['source_inventory'] = inventory
    roots = operation_call_binding_inputs['required_operation_calls'][('release', 'build', 'verify')]
    operation_call_binding_inputs['required_operation_calls'] = {
        ('release', 'build', 'verify'): {
            root: source_operation_call_population(root, inventory, include_initialization=True) for root in roots
        }
    }
    return operation_call_binding_inputs


def test_lifecycle_binding_checks_source_initialization_population(initialization_binding_inputs):
    result = _validate_bindings(initialization_binding_inputs)
    assert result['authority'] is False
    assert result['execution_qualified'] is False
    assert result['operation_call_populations_checked'] == 3


@pytest.mark.parametrize('defect', ['removed_module', 'changed_site', 'removed_unknown'])
def test_lifecycle_binding_rejects_initialization_omission_or_substitution(initialization_binding_inputs, defect):
    rows = initialization_binding_inputs['source_inventory']['module_initializers']
    if defect == 'removed_module':
        rows.clear()
    elif defect == 'changed_site':
        rows[0]['sites'][0]['expression_sha256'] = '0' * 64
    else:
        rows[0]['unresolved'].clear()
    with pytest.raises(CIGraphError, match='operation call population'):
        _validate_bindings(initialization_binding_inputs)


@pytest.fixture
def reconstructed_binding_inputs(operation_call_binding_inputs, composition, tmp_path):
    import subprocess
    from bcf_governance.tooling.semantic_ownership_inventory import discover_python_source, resolve_python_imports
    from bcf_governance.tooling.semantic_operation_effects import source_operation_call_population

    def git(*args):
        return subprocess.run(['git', *args], cwd=tmp_path, check=True, capture_output=True, text=True).stdout.strip()
    git('init', '-q')
    git('config', 'user.name', 'Binding Test')
    git('config', 'user.email', 'binding@example.invalid')
    git('add', 'runtime.py')
    git('commit', '-qm', 'source')
    identity = dict(composition['expected_source'], commit_sha=git('rev-parse', 'HEAD'), tree_sha=git('rev-parse', 'HEAD^{tree}'))
    composition['expected_source'] = identity
    composition['payload']['source'] = identity
    inputs = operation_call_binding_inputs
    inputs['compiled'] = compile_lifecycle_composition(**composition)
    inputs['expected_source'] = identity
    subject = {key: identity[key] for key in ('commit_sha', 'tree_sha')}
    inventory = resolve_python_imports(tmp_path, discover_python_source(tmp_path, source_subject=subject, call_contracts_version='1.0', initialization_contracts_version='1.0'))
    pair = ('release', 'build', 'verify')
    inputs['required_operation_calls'] = {pair: {
        root: source_operation_call_population(root, inventory, include_initialization=True)
        for root in inputs['required_operation_calls'][pair]
    }}
    inputs.pop('source_inventory')
    inputs['repo_root'] = tmp_path
    return inputs


def test_reconstructed_source_binding_uses_exact_protected_subject(reconstructed_binding_inputs):
    from bcf_governance.tooling.ci_graph_composition import validate_reconstructed_lifecycle_bindings

    before = copy.deepcopy(reconstructed_binding_inputs)
    result = validate_reconstructed_lifecycle_bindings(**reconstructed_binding_inputs)
    assert result['authority'] is False
    assert result['execution_qualified'] is False
    assert result['operation_call_populations_checked'] == 3
    assert result['source_reconstruction']['subject'] == {
        key: before['expected_source'][key] for key in ('commit_sha', 'tree_sha')
    }
    assert len(result['source_reconstruction']['population_sha256']) == 64
    assert reconstructed_binding_inputs == before
    assert validate_reconstructed_lifecycle_bindings(**reconstructed_binding_inputs) == result


@pytest.mark.parametrize('defect', ['subject', 'root', 'scope', 'catalogue'])
def test_reconstructed_binding_rejects_invalid_inputs_before_discovery(reconstructed_binding_inputs, monkeypatch, defect):
    from bcf_governance.tooling import ci_graph_composition as owner
    from bcf_governance.tooling import semantic_ownership_inventory as source

    inputs = reconstructed_binding_inputs
    populations = inputs['required_operation_calls'][('release', 'build', 'verify')]
    root = next(iter(populations))
    if defect == 'subject':
        inputs['expected_source'] = dict(inputs['expected_source'], commit_sha='a' * 40)
    elif defect == 'root':
        populations.pop(root)
    elif defect == 'scope':
        populations[root]['scope'] = 'discovered_python_functions_only'
    else:
        populations[root] = None
    monkeypatch.setattr(source, 'discover_python_source', lambda *a, **kw: pytest.fail('source discovered before rejecting malformed protected input'))
    with pytest.raises(CIGraphError):
        owner.validate_reconstructed_lifecycle_bindings(**inputs)


@pytest.mark.parametrize('defect', ['dirty', 'untracked', 'missing'])
def test_reconstructed_binding_rejects_source_movement(reconstructed_binding_inputs, defect):
    from bcf_governance.tooling.ci_graph_composition import validate_reconstructed_lifecycle_bindings

    inputs = reconstructed_binding_inputs
    path = inputs['repo_root'] / 'runtime.py'
    if defect == 'dirty':
        path.write_text(path.read_text() + '\nhidden()\n')
    elif defect == 'untracked':
        (path.parent / 'extra.py').write_text('hidden()\n')
    else:
        path.unlink()
    with pytest.raises(CIGraphError, match='source'):
        validate_reconstructed_lifecycle_bindings(**inputs)


@pytest.mark.parametrize('defect', ['expected_source', 'required_negative_controls', 'required_call_edges', 'required_fact_bindings', 'collected_selectors', 'fact_value', 'control_value', 'authority', 'call_endpoint'])
def test_reconstructed_binding_rejects_malformed_declarations_before_io(reconstructed_binding_inputs, monkeypatch, defect):
    from bcf_governance.tooling import ci_graph_composition as owner
    from bcf_governance.tooling import semantic_ownership_inventory as source

    inputs = reconstructed_binding_inputs
    pair = ('release', 'build', 'verify')
    if defect in {'expected_source', 'required_negative_controls', 'required_call_edges', 'required_fact_bindings', 'collected_selectors'}:
        inputs[defect] = None
    elif defect == 'fact_value':
        inputs['required_fact_bindings'][pair] = 1
    elif defect == 'control_value':
        inputs['required_negative_controls'][pair] = 1
    elif defect == 'call_endpoint':
        inputs['required_call_edges'][pair] = frozenset({('runtime.py::unbound', 'runtime.py::verify')})
    else:
        next(iter(inputs['required_operation_calls'][pair].values()))['authority'] = True
    monkeypatch.setattr(source, 'discover_python_source', lambda *a, **kw: pytest.fail('source read before malformed declaration rejection'))
    with pytest.raises(CIGraphError):
        owner.validate_reconstructed_lifecycle_bindings(**inputs)


@pytest.mark.parametrize('roots', [('missing',), ('.', '.'), ('../escape',), (), ('.', 'nested'), ('alias',)])
def test_reconstructed_binding_rejects_invalid_import_resources(reconstructed_binding_inputs, roots, monkeypatch):
    from bcf_governance.tooling.ci_graph_composition import validate_reconstructed_lifecycle_bindings

    from bcf_governance.tooling import semantic_ownership_inventory
    if roots == ('alias',):
        (reconstructed_binding_inputs['repo_root'] / 'alias').symlink_to('.', target_is_directory=True)
    monkeypatch.setattr(semantic_ownership_inventory, 'discover_python_source', lambda *args, **kwargs: pytest.fail('source discovery before import-root rejection'))
    with pytest.raises(CIGraphError, match='source reconstruction'):
        validate_reconstructed_lifecycle_bindings(**reconstructed_binding_inputs, source_import_roots=roots)


def test_reconstructed_binding_accepts_no_caller_inventory(reconstructed_binding_inputs):
    from bcf_governance.tooling.ci_graph_composition import validate_reconstructed_lifecycle_bindings

    with pytest.raises(TypeError, match='source_inventory'):
        validate_reconstructed_lifecycle_bindings(**reconstructed_binding_inputs, source_inventory={'functions': []})


def test_reconstructed_binding_delegates_to_existing_conformance_owner(reconstructed_binding_inputs, monkeypatch):
    from bcf_governance.tooling import ci_graph_composition as owner

    seen = []
    real = owner.validate_lifecycle_bindings
    def observed(*args, **kwargs):
        seen.append(kwargs['source_inventory']['source_population']['subject'])
        return real(*args, **kwargs)
    monkeypatch.setattr(owner, 'validate_lifecycle_bindings', observed)
    result = owner.validate_reconstructed_lifecycle_bindings(**reconstructed_binding_inputs)
    assert seen == [result['source_reconstruction']['subject']]


def test_shared_binding_checks_preserve_legacy_sequence_call_edges(binding_inputs):
    original = _validate_bindings(binding_inputs)
    binding_inputs['required_call_edges'] = {
        pair: [list(edge) for edge in edges]
        for pair, edges in binding_inputs['required_call_edges'].items()
    }
    assert _validate_bindings(binding_inputs) == original


@pytest.fixture
def public_reconstructed_binding_inputs(reconstructed_binding_inputs, composition):
    import hashlib
    import subprocess
    import yaml
    from bcf_governance.tooling.semantic_ownership_inventory import discover_python_source, resolve_python_imports
    from bcf_governance.tooling.semantic_operation_effects import source_operation_call_population

    inputs = reconstructed_binding_inputs
    root = inputs['repo_root']
    source = root / 'runtime.py'
    source.write_text(source.read_text() + '\nCOMMANDS = {"produce": produce}\n')
    operation = dict(id='example.produce.v1', population='cli', population_key='produce', family='example', bounded_context='example', entrypoints=['runtime.py::produce'], semantic_kind='query', authoritative_read=True, authoritative_mutation=False, authority_conferral=False, produces_projection=False, model_callable=False, allowed_mutation_ports=[], allowed_authority_ports=[], non_authoritative_output_effects=[])
    payload = dict(schema_version='1.0', document=dict(kind='application_operation_registry', id='example-operations', version='1.0.0', status='active', path='governance/application-operations.yml'), populations=[dict(id='cli', adapter='python_mapping', source='runtime.py', symbol='COMMANDS', public_only=True)], operations=[operation], migrations=[])
    policy = root / 'governance/application-operations.yml'
    policy.parent.mkdir()
    policy.write_text(yaml.safe_dump(payload))
    def git(*args):
        return subprocess.run(['git', *args], cwd=root, check=True, capture_output=True, text=True).stdout.strip()
    git('add', '.')
    git('commit', '-qm', 'public policy')
    subject = dict(commit_sha=git('rev-parse', 'HEAD'), tree_sha=git('rev-parse', 'HEAD^{tree}'))
    identity = dict(inputs['expected_source'], **subject)
    composition['expected_source'] = composition['payload']['source'] = identity
    inputs['expected_source'] = identity
    inputs['compiled'] = compile_lifecycle_composition(**composition)
    inventory = resolve_python_imports(root, discover_python_source(root, source_subject=subject, call_contracts_version='1.0', initialization_contracts_version='1.0'))
    pair = ('release', 'build', 'verify')
    inputs['required_operation_calls'] = {pair: {symbol: source_operation_call_population(symbol, inventory, include_initialization=True) for symbol in inputs['required_operation_calls'][pair]}}
    inputs['operation_policy_subject'] = subject
    inputs['required_public_operation_relationships'] = {'example.produce.v1': frozenset({pair})}
    return inputs, policy, hashlib.sha256(policy.read_bytes()).hexdigest()


def test_public_operations_bind_to_reconstructed_lifecycle(public_reconstructed_binding_inputs):
    from bcf_governance.tooling.ci_graph_composition import validate_reconstructed_lifecycle_bindings
    inputs, policy, digest = public_reconstructed_binding_inputs
    before = copy.deepcopy(inputs)
    result = validate_reconstructed_lifecycle_bindings(**inputs)
    assert result['public_operation_bindings']['operations_checked'] == 1
    assert result['public_operation_bindings']['registry_sha256'] == digest
    assert result['authority'] is False
    assert result['execution_qualified'] is False
    assert inputs == before


@pytest.mark.parametrize('defect', ['omission', 'empty', 'unknown_pair', 'wrong_operation', 'missing_policy', 'missing_mapping', 'wrong_subject', 'wrong_entrypoint'])
def test_public_operation_declarations_reject_before_source_discovery(public_reconstructed_binding_inputs, monkeypatch, defect):
    from bcf_governance.tooling import ci_graph_composition as owner
    from bcf_governance.tooling import semantic_ownership_inventory
    inputs, policy, digest = public_reconstructed_binding_inputs
    mapping = inputs['required_public_operation_relationships']
    if defect == 'omission':
        mapping.clear()
    elif defect == 'empty':
        mapping['example.produce.v1'] = frozenset()
    elif defect == 'unknown_pair':
        mapping['example.produce.v1'] = frozenset({('other', 'build', 'verify')})
    elif defect == 'wrong_operation':
        mapping['other.operation'] = mapping.pop('example.produce.v1')
    elif defect == 'missing_policy':
        inputs['operation_policy_subject'] = None
    elif defect == 'missing_mapping':
        inputs['required_public_operation_relationships'] = None
    elif defect == 'wrong_subject':
        inputs['operation_policy_subject']['commit_sha'] = 'HEAD'
    else:
        import subprocess
        import yaml
        payload = yaml.safe_load(policy.read_text())
        payload['operations'][0]['entrypoints'] = ['runtime.py::declared_port']
        policy.write_text(yaml.safe_dump(payload))
        def git(*args):
            return subprocess.run(['git', *args], cwd=inputs['repo_root'], check=True, capture_output=True, text=True).stdout.strip()
        git('add', '.')
        git('commit', '-qm', 'unbound policy endpoint')
        inputs['operation_policy_subject'] = dict(commit_sha=git('rev-parse', 'HEAD'), tree_sha=git('rev-parse', 'HEAD^{tree}'))
    monkeypatch.setattr(semantic_ownership_inventory, 'discover_python_source', lambda *args, **kwargs: pytest.fail('source discovery before public-policy rejection'))
    with pytest.raises(CIGraphError):
        owner.validate_reconstructed_lifecycle_bindings(**inputs)


def test_dirty_public_policy_rejects_before_source_discovery(public_reconstructed_binding_inputs, monkeypatch):
    from bcf_governance.tooling import ci_graph_composition as owner
    from bcf_governance.tooling import semantic_ownership_inventory
    inputs, policy, digest = public_reconstructed_binding_inputs
    policy.write_text(policy.read_text() + '# substitution\n')
    monkeypatch.setattr(semantic_ownership_inventory, 'discover_python_source', lambda *args, **kwargs: pytest.fail('source discovery before digest rejection'))
    with pytest.raises(CIGraphError, match='digest'):
        owner.validate_reconstructed_lifecycle_bindings(**inputs)


def test_public_policy_capture_is_not_reread_after_source_reconstruction(public_reconstructed_binding_inputs, monkeypatch):
    from bcf_governance.tooling.ci_graph_composition import validate_reconstructed_lifecycle_bindings
    inputs, policy, digest = public_reconstructed_binding_inputs
    real = Path.read_bytes
    reads = []
    def read(path):
        raw = real(path)
        if path == policy:
            reads.append(raw)
            path.write_text('poisoned after capture')
        return raw
    monkeypatch.setattr(Path, 'read_bytes', read)
    result = validate_reconstructed_lifecycle_bindings(**inputs)
    assert result['public_operation_bindings']['registry_sha256'] == digest
    assert len(reads) == 1


def test_added_public_source_entry_cannot_escape_lifecycle_population(public_reconstructed_binding_inputs, composition):
    import subprocess
    from bcf_governance.tooling.ci_graph_composition import validate_reconstructed_lifecycle_bindings
    from bcf_governance.tooling.semantic_ownership_inventory import discover_python_source, resolve_python_imports
    from bcf_governance.tooling.semantic_operation_effects import source_operation_call_population

    inputs, policy, digest = public_reconstructed_binding_inputs
    root = inputs['repo_root']
    source = root / 'runtime.py'
    source.write_text(source.read_text().replace('COMMANDS = {"produce": produce}', 'COMMANDS = {"produce": produce, "other": produce}'))
    def git(*args):
        return subprocess.run(['git', *args], cwd=root, check=True, capture_output=True, text=True).stdout.strip()
    git('add', '.')
    git('commit', '-qm', 'new public entry')
    subject = dict(commit_sha=git('rev-parse', 'HEAD'), tree_sha=git('rev-parse', 'HEAD^{tree}'))
    identity = dict(inputs['expected_source'], **subject)
    composition['expected_source'] = composition['payload']['source'] = identity
    inputs['expected_source'] = identity
    inputs['compiled'] = compile_lifecycle_composition(**composition)
    inventory = resolve_python_imports(root, discover_python_source(root, source_subject=subject, call_contracts_version='1.0', initialization_contracts_version='1.0'))
    inputs['required_operation_calls'] = {pair: {symbol: source_operation_call_population(symbol, inventory, include_initialization=True) for symbol in roots} for pair, roots in inputs['required_operation_calls'].items()}
    with pytest.raises(CIGraphError, match='unclassified public application operations'):
        validate_reconstructed_lifecycle_bindings(**inputs)


def test_duplicate_protected_operation_identity_rejects_before_source_discovery(public_reconstructed_binding_inputs, monkeypatch):
    import subprocess
    import yaml
    from bcf_governance.tooling import ci_graph_composition as owner
    from bcf_governance.tooling import semantic_ownership_inventory
    inputs, policy, digest = public_reconstructed_binding_inputs
    payload = yaml.safe_load(policy.read_text())
    payload['operations'].append(copy.deepcopy(payload['operations'][0]))
    policy.write_text(yaml.safe_dump(payload))
    def git(*args):
        return subprocess.run(['git', *args], cwd=inputs['repo_root'], check=True, capture_output=True, text=True).stdout.strip()
    git('add', '.')
    git('commit', '-qm', 'duplicate policy identity')
    inputs['operation_policy_subject'] = dict(commit_sha=git('rev-parse', 'HEAD'), tree_sha=git('rev-parse', 'HEAD^{tree}'))
    monkeypatch.setattr(semantic_ownership_inventory, 'discover_python_source', lambda *args, **kwargs: pytest.fail('source discovery before duplicate identity rejection'))
    with pytest.raises(CIGraphError, match='operation IDs must be unique'):
        owner.validate_reconstructed_lifecycle_bindings(**inputs)


def test_import_resource_rejection_precedes_public_policy_capture(public_reconstructed_binding_inputs, monkeypatch):
    from bcf_governance.tooling import ci_graph_composition as owner
    from bcf_governance.tooling import ci_graph_composition_operations
    inputs, policy, digest = public_reconstructed_binding_inputs
    monkeypatch.setattr(ci_graph_composition_operations, 'load_committed_application_operations', lambda *args, **kwargs: pytest.fail('policy capture before import-root rejection'))
    with pytest.raises(CIGraphError, match='Python import root'):
        owner.validate_reconstructed_lifecycle_bindings(**inputs, source_import_roots=('missing',))


def test_reconstructed_binding_passes_import_roots_to_exact_discovery(reconstructed_binding_inputs, monkeypatch):
    from bcf_governance.tooling import ci_graph_composition as owner
    from bcf_governance.tooling import semantic_ownership_inventory
    real = semantic_ownership_inventory.discover_python_source
    seen = []
    def discover(*args, **kwargs):
        seen.append(kwargs.get('import_roots'))
        return real(*args, **kwargs)
    monkeypatch.setattr(semantic_ownership_inventory, 'discover_python_source', discover)
    owner.validate_reconstructed_lifecycle_bindings(**reconstructed_binding_inputs)
    assert seen == [('.',)]


def test_lifecycle_views_match_retained_characterization(composition):
    retained = json.loads((ROOT / 'audits/issue-394/lifecycle-views-before.json').read_text())
    compiled = compile_lifecycle_composition(**composition)
    assert retained['authority'] is False
    assert retained['qualification'] == 'synthetic_fixture_projection_only'
    assert {view: render_lifecycle_composition(compiled, view=view) for view in ('bound', 'contract', 'machine')} == retained['views']


def test_lifecycle_renderer_keeps_public_identity_guard_before_formatting(composition, monkeypatch):
    from bcf_governance.tooling import ci_graph_composition as owner
    from bcf_governance.tooling import ci_graph_composition_views as views
    compiled = compile_lifecycle_composition(**composition)
    seen = []
    def formatter(*args, **kwargs):
        seen.append('formatted')
        return 'view'
    monkeypatch.setattr(views, '_render_lifecycle_composition', formatter)
    assert owner.render_lifecycle_composition(compiled) == 'view'
    assert seen == ['formatted']
    seen.clear()
    compiled['authority'] = True
    with pytest.raises(CIGraphError, match='identity'):
        owner.render_lifecycle_composition(compiled)
    assert seen == []


def test_lifecycle_view_bytes_keep_existing_source_owner():
    from bcf_governance.tooling.semantic_ownership_inventory import discover_python_source, resolve_python_imports
    files = [ROOT / 'bcf_governance/tooling/ci_graph_composition.py', ROOT / 'bcf_governance/tooling/ci_graph_composition_views.py']
    inventory = resolve_python_imports(ROOT, discover_python_source(ROOT, files=files, call_contracts_version='1.0'))
    view = next(row for row in inventory['functions'] if row['symbol'] == 'bcf_governance/tooling/ci_graph_composition_views.py::_render_lifecycle_composition')
    calls = {row['called_symbol'] for row in view['calls']}
    assert 'bcf_governance/tooling/ci_graph_composition.py::_bytes' in calls


def _ci_coverage_inputs(composition, *, second=False, excluded=False, duplicate=False):
    from dataclasses import replace
    edge = composition['compiled_graph'].edge_contracts[0]
    rows = [edge]
    if second:
        rows.append(replace(edge, producer='other:produce', consumer='other:consume'))
    if excluded:
        rows.append(replace(edge, producer=edge.consumer, consumer=edge.producer, reachable=False, exclusion_reason='no-structural-path'))
    if duplicate:
        rows.append(edge)
    composition['compiled_graph'].edge_contracts = tuple(rows)
    source = dict(composition['expected_source'], ci_edges_sha256=edge_population_sha256(composition['compiled_graph']))
    composition['expected_source'] = composition['payload']['source'] = source
    return composition


def _check_ci_coverage(composition):
    from bcf_governance.tooling.ci_graph_composition import validate_lifecycle_ci_edge_coverage
    return validate_lifecycle_ci_edge_coverage(compile_lifecycle_composition(**composition), compiled_graph=composition['compiled_graph'], expected_source=composition['expected_source'])


def test_complete_ci_edge_coverage_is_kernel_derived_stable_and_read_only(composition):
    inputs = _ci_coverage_inputs(composition, second=True, excluded=True)
    contract = inputs['payload']['relationships'][0]['contract']
    contract['ci_edges'].append(dict(producer='other:produce', consumer='other:consume'))
    before = copy.deepcopy(inputs)
    result = _check_ci_coverage(inputs)
    assert result['authority'] is False
    assert result['execution_qualified'] is False
    assert result['reachable_edges_checked'] == 2
    assert result['canonical_exclusions'] == (('verify:consume', 'build:produce', 'no-structural-path'),)
    assert len(result['ci_edge_bindings']) == 2
    assert inputs == before
    inputs['compiled_graph'].edge_contracts = tuple(reversed(inputs['compiled_graph'].edge_contracts))
    contract['ci_edges'].reverse()
    assert _check_ci_coverage(inputs) == result


@pytest.mark.parametrize('omission', ['second_edge', 'edge_and_tests'])
def test_ci_edge_coverage_cannot_be_selected_by_candidate(composition, omission):
    if omission == 'second_edge':
        _ci_coverage_inputs(composition, second=True)
    else:
        contract = composition['payload']['relationships'][0]['contract']
        contract['ci_edges'] = []
        contract['positive_tests'] = ['other::test_irrelevant']
        contract['negative_tests'] = ['other::test_other_cause']
    with pytest.raises(CIGraphError, match='coverage.*incomplete'):
        _check_ci_coverage(composition)


@pytest.mark.parametrize('defect', ['source', 'graph', 'integrity'])
def test_ci_edge_coverage_rejects_wrong_identity(composition, defect):
    from bcf_governance.tooling.ci_graph_composition import validate_lifecycle_ci_edge_coverage
    compiled = compile_lifecycle_composition(**composition)
    expected = dict(composition['expected_source'])
    if defect == 'source':
        expected['repository_id'] = '999'
    elif defect == 'graph':
        composition['compiled_graph'].edge_contracts = ()
    else:
        compiled['authority'] = True
    with pytest.raises(CIGraphError, match='identity|source'):
        validate_lifecycle_ci_edge_coverage(compiled, compiled_graph=composition['compiled_graph'], expected_source=expected)


def test_ci_edge_coverage_rejects_duplicate_canonical_pairs(composition):
    _ci_coverage_inputs(composition, duplicate=True)
    with pytest.raises(CIGraphError, match='duplicate'):
        _check_ci_coverage(composition)


def test_ci_edge_coverage_rejects_resealed_unreachable_reference(composition):
    import hashlib
    from bcf_governance.tooling.ci_graph_composition import validate_lifecycle_ci_edge_coverage
    _ci_coverage_inputs(composition, excluded=True)
    compiled = compile_lifecycle_composition(**composition)
    compiled['relationships'][0]['contract']['ci_edges'] = [dict(producer='verify:consume', consumer='build:produce')]
    unsigned = {key: value for key, value in compiled.items() if key != 'composition_sha256'}
    compiled['composition_sha256'] = hashlib.sha256(json.dumps(unsigned, sort_keys=True, separators=(',', ':'), allow_nan=False).encode()).hexdigest()
    with pytest.raises(CIGraphError, match='absent|unreachable'):
        validate_lifecycle_ci_edge_coverage(compiled, compiled_graph=composition['compiled_graph'], expected_source=composition['expected_source'])


def test_empty_ci_edge_population_does_not_claim_runtime_qualification(composition):
    composition['compiled_graph'].edge_contracts = ()
    composition['payload']['relationships'][0]['contract']['ci_edges'] = []
    source = dict(composition['expected_source'], ci_edges_sha256=edge_population_sha256(composition['compiled_graph']))
    composition['expected_source'] = composition['payload']['source'] = source
    result = _check_ci_coverage(composition)
    assert result['reachable_edges_checked'] == 0
    assert result['authority'] is False
    assert result['execution_qualified'] is False


@pytest.mark.parametrize('reason', [None, '', False])
def test_ci_edge_coverage_rejects_ungrounded_canonical_exclusion(composition, reason):
    from dataclasses import replace
    _ci_coverage_inputs(composition, excluded=True)
    graph = composition['compiled_graph']
    graph.edge_contracts = (graph.edge_contracts[0], replace(graph.edge_contracts[1], exclusion_reason=reason))
    source = dict(composition['expected_source'], ci_edges_sha256=edge_population_sha256(graph))
    composition['expected_source'] = composition['payload']['source'] = source
    with pytest.raises(CIGraphError, match='exclusion'):
        _check_ci_coverage(composition)


def test_ci_edge_coverage_retains_all_context_bindings_without_double_count(composition):
    extra = copy.deepcopy(composition['payload']['relationships'])
    for row in extra:
        row['context'] = 'controller'
    composition['payload']['relationships'].extend(extra)
    composition['expected_populations']['controller'] = ('build', 'verify')
    composition['expected_relationships'].update({('controller', 'build', 'verify'): None, ('controller', 'verify', 'build'): 'no-structural-path'})
    composition['expected_effects'].add(('controller', 'build', 'verify', 'verify'))
    result = _check_ci_coverage(composition)
    assert result['reachable_edges_checked'] == 1
    assert result['ci_edge_bindings'] == (('build:produce', 'verify:consume', (('controller', 'build', 'verify'), ('release', 'build', 'verify'))),)


@pytest.mark.parametrize('version', ['1.0', '1.1'])
def test_zero_source_effects_compile_without_fabricated_effects(composition, version):
    composition['payload']['schema_version'] = version
    if version == '1.1':
        composition['payload'].pop('source')
    composition['payload']['relationships'][0]['contract']['effects'] = []
    composition['expected_effects'] = frozenset()
    assert compile_lifecycle_composition(**composition)['authority'] is False


def test_reconstructed_effects_reject_fabricated_compiled_effect(public_reconstructed_binding_inputs):
    from bcf_governance.tooling.ci_graph_composition import validate_reconstructed_lifecycle_bindings
    inputs, _, _ = public_reconstructed_binding_inputs
    with pytest.raises(CIGraphError, match='reconstructed.*effect population'):
        validate_reconstructed_lifecycle_bindings(**inputs, required_effect_bindings={})


def test_reconstructed_zero_effects_close_existing_schema(public_reconstructed_binding_inputs, composition):
    from bcf_governance.tooling.ci_graph_composition import validate_reconstructed_lifecycle_bindings
    inputs, _, _ = public_reconstructed_binding_inputs
    composition['payload']['relationships'][0]['contract']['effects'] = []
    composition['expected_effects'] = frozenset()
    inputs['compiled'] = compile_lifecycle_composition(**composition)
    result = validate_reconstructed_lifecycle_bindings(**inputs, required_effect_bindings={})
    assert result['source_effect_bindings']['effects_checked'] == 0
    assert result['source_effect_bindings']['authority'] is False
    assert result['execution_qualified'] is False


def test_reconstructed_effects_require_protected_policy_before_discovery(reconstructed_binding_inputs, monkeypatch):
    from bcf_governance.tooling.ci_graph_composition import validate_reconstructed_lifecycle_bindings
    import bcf_governance.tooling.semantic_ownership_inventory as source
    monkeypatch.setattr(source, 'discover_python_source', lambda *a, **kw: pytest.fail('late policy rejection'))
    with pytest.raises(CIGraphError, match='effect binding requires protected public operations'):
        validate_reconstructed_lifecycle_bindings(**reconstructed_binding_inputs, required_effect_bindings={})


@pytest.mark.parametrize('defect', [None, 'missing', 'extra', 'wrong_effect', 'second_entrypoint'])
def test_reconstructed_nonempty_effect_population_uses_existing_owner(composition, effect_population_inputs, defect):
    from bcf_governance.tooling.ci_graph_composition_operations import validate_reconstructed_effects
    effects = _effect_population(effect_population_inputs)
    composition['expected_effects'] = effects
    composition['payload']['relationships'][0]['contract']['effects'] = [next(iter(effects))[-1]]
    compiled = compile_lifecycle_composition(**composition)
    port = ('authority', 'function', 'publisher.py::publish')
    rows = [('release.publish.v1', 'command', 'publisher.py::main', (port,))]
    bindings = dict(effect_population_inputs['effect_bindings'])
    if defect == 'missing':
        bindings.clear()
    elif defect == 'extra':
        bindings[('release.publish.v1', 'mutation', 'call', 'invented')] = frozenset({('release', 'build', 'verify')})
    elif defect == 'wrong_effect':
        rows = [('release.publish.v1', 'command', 'publisher.py::main', ())]
    elif defect == 'second_entrypoint':
        rows.append(('release.publish.v1', 'command', 'publisher.py::alternate', (port,)))
    if defect in {None, 'second_entrypoint'}:
        before = copy.deepcopy((compiled, rows, bindings))
        result = validate_reconstructed_effects(compiled, {'operations': rows}, bindings)
        assert result['effects_checked'] == 1
        assert result['authority'] is False
        assert (compiled, rows, bindings) == before
    else:
        with pytest.raises(CIGraphError, match='effect bindings'):
            validate_reconstructed_effects(compiled, {'operations': rows}, bindings)


@pytest.mark.parametrize('defect', ['unknown_operation', 'unknown_context', 'empty_context', 'mutable_context', 'malformed_port', 'unknown_role', 'unknown_kind'])
def test_reconstructed_effect_contexts_reject_before_discovery(public_reconstructed_binding_inputs, monkeypatch, defect):
    from bcf_governance.tooling.ci_graph_composition import validate_reconstructed_lifecycle_bindings
    import bcf_governance.tooling.semantic_ownership_inventory as source
    inputs, _, _ = public_reconstructed_binding_inputs
    key = ('example.produce.v1', 'authority', 'function', 'runtime.py::produce')
    pairs = frozenset({('release', 'build', 'verify')})
    if defect == 'unknown_operation':
        key = ('unknown', *key[1:])
    elif defect == 'unknown_context':
        pairs = frozenset({('controller', 'build', 'verify')})
    elif defect == 'empty_context':
        pairs = frozenset()
    elif defect == 'mutable_context':
        pairs = set(pairs)
    elif defect == 'malformed_port':
        key = key[:3]
    elif defect == 'unknown_role':
        key = (key[0], 'invented', *key[2:])
    elif defect == 'unknown_kind':
        key = (*key[:2], 'invented', key[3])
    monkeypatch.setattr(source, 'discover_python_source', lambda *a, **kw: pytest.fail('late context rejection'))
    with pytest.raises(CIGraphError, match='effect binding context'):
        validate_reconstructed_lifecycle_bindings(**inputs, required_effect_bindings={key: pairs})


@pytest.fixture
def nonempty_public_effect_inputs(public_reconstructed_binding_inputs, composition):
    import subprocess
    import yaml
    from bcf_governance.tooling.semantic_ownership_inventory import discover_python_source, resolve_python_imports
    from bcf_governance.tooling.semantic_operation_effects import source_operation_call_population
    inputs, policy, _ = public_reconstructed_binding_inputs
    payload = yaml.safe_load(policy.read_text())
    payload['operations'][0]['non_authoritative_output_effects'] = ['runtime.py::declared_port']
    policy.write_text(yaml.safe_dump(payload))
    root = inputs['repo_root']
    source = root / 'runtime.py'
    source.write_text(source.read_text().replace('    return b"assets"', '    declared_port()\n    return b"assets"'))
    def git(*args):
        return subprocess.run(['git', *args], cwd=root, check=True, capture_output=True, text=True).stdout.strip()
    git('add', 'governance/application-operations.yml', 'runtime.py')
    git('commit', '-qm', 'declare protected observation port')
    subject = dict(commit_sha=git('rev-parse', 'HEAD'), tree_sha=git('rev-parse', 'HEAD^{tree}'))
    inputs['expected_source'] = dict(inputs['expected_source'], **subject)
    inputs['operation_policy_subject'] = subject
    pair = ('release', 'build', 'verify')
    port = ('example.produce.v1', 'observation', 'function', 'runtime.py::declared_port')
    encoded = json.dumps(port, sort_keys=True, separators=(',', ':'))
    composition['expected_source'] = composition['payload']['source'] = inputs['expected_source']
    composition['payload']['relationships'][0]['contract']['effects'] = [encoded]
    composition['expected_effects'] = frozenset({(*pair, encoded)})
    inputs['compiled'] = compile_lifecycle_composition(**composition)
    inputs['required_effect_bindings'] = {port: frozenset({pair})}
    inventory = resolve_python_imports(root, discover_python_source(root, source_subject=subject, call_contracts_version='1.0', initialization_contracts_version='1.0'))
    inputs['required_operation_calls'] = {pair: {symbol: source_operation_call_population(symbol, inventory, include_initialization=True) for symbol in inputs['required_operation_calls'][pair]}}
    return inputs


@pytest.mark.parametrize('defect', [None, 'omitted_compiled_effect', 'omitted_crosswalk', 'invented_crosswalk'])
def test_committed_public_port_reconstructs_end_to_end(nonempty_public_effect_inputs, composition, defect):
    from bcf_governance.tooling.ci_graph_composition import validate_reconstructed_lifecycle_bindings
    inputs = nonempty_public_effect_inputs
    inputs['required_ci_graph'] = composition['compiled_graph']
    if defect == 'omitted_compiled_effect':
        composition['payload']['relationships'][0]['contract']['effects'] = []
        composition['expected_effects'] = frozenset()
        inputs['compiled'] = compile_lifecycle_composition(**composition)
    elif defect == 'omitted_crosswalk':
        inputs['required_effect_bindings'] = {}
    elif defect == 'invented_crosswalk':
        inputs['required_effect_bindings'][('example.produce.v1', 'observation', 'call', 'invented')] = frozenset({('release', 'build', 'verify')})
    before = copy.deepcopy(inputs)
    if defect is None:
        result = validate_reconstructed_lifecycle_bindings(**inputs)
        assert result['ci_edge_coverage']['reachable_edges_checked'] == 1
        assert result['source_effect_bindings']['effects_checked'] == 1
        assert result['source_effect_bindings']['bindings'][0][:3] == ('release', 'build', 'verify')
        assert result['public_operation_bindings']['operations'][0][-1] == (('observation', 'function', 'runtime.py::declared_port'),)
        assert result['source_reconstruction']['subject'] == inputs['operation_policy_subject']
        assert result['authority'] is False
        assert result['execution_qualified'] is False
        assert validate_reconstructed_lifecycle_bindings(**inputs) == result
    else:
        with pytest.raises(CIGraphError, match='effect (population|bindings)'):
            validate_reconstructed_lifecycle_bindings(**inputs)
    assert inputs == before



def test_reconstructed_ci_coverage_delegates_to_existing_owner(reconstructed_binding_inputs, composition):
    from bcf_governance.tooling.ci_graph_composition import validate_reconstructed_lifecycle_bindings, validate_lifecycle_ci_edge_coverage
    inputs = reconstructed_binding_inputs
    before = copy.deepcopy(inputs)
    result = validate_reconstructed_lifecycle_bindings(**inputs, required_ci_graph=composition['compiled_graph'])
    assert result['ci_edge_coverage'] == validate_lifecycle_ci_edge_coverage(inputs['compiled'], compiled_graph=composition['compiled_graph'], expected_source=inputs['expected_source'])
    assert result['ci_edge_coverage']['reachable_edges_checked'] == 1
    assert result['authority'] is False
    assert inputs == before
    assert 'ci_edge_coverage' not in validate_reconstructed_lifecycle_bindings(**inputs)


@pytest.mark.parametrize('defect', ['missing_edge', 'stale_graph'])
def test_reconstructed_ci_coverage_rejects_before_policy_and_source(public_reconstructed_binding_inputs, composition, monkeypatch, defect):
    from bcf_governance.tooling.ci_graph_composition import validate_reconstructed_lifecycle_bindings
    from bcf_governance.tooling import semantic_ownership_inventory as source
    from bcf_governance.tooling import ci_graph_composition_operations as operations
    inputs, _, _ = public_reconstructed_binding_inputs
    if defect == 'missing_edge':
        composition['payload']['relationships'][0]['contract']['ci_edges'] = []
        inputs['compiled'] = compile_lifecycle_composition(**composition)
    else:
        composition['compiled_graph'].graph_sha256 = 'f' * 64
    monkeypatch.setattr(source, 'discover_python_source', lambda *a, **kw: pytest.fail('late CI coverage rejection'))
    monkeypatch.setattr(operations, 'capture_public_operation_bindings', lambda *a, **kw: pytest.fail('policy captured before CI coverage rejection'))
    with pytest.raises(CIGraphError, match='CI edge coverage'):
        validate_reconstructed_lifecycle_bindings(**inputs, required_ci_graph=composition['compiled_graph'])



@pytest.mark.parametrize('defect', ['missing_compiled', 'missing_binding', 'invented_binding', 'changed_symbol'])
def test_effect_declaration_contradictions_reject_before_discovery(nonempty_public_effect_inputs, composition, monkeypatch, defect):
    from bcf_governance.tooling.ci_graph_composition import validate_reconstructed_lifecycle_bindings
    import bcf_governance.tooling.semantic_ownership_inventory as source
    inputs = nonempty_public_effect_inputs
    bindings = inputs['required_effect_bindings']
    if defect == 'missing_compiled':
        composition['payload']['relationships'][0]['contract']['effects'] = []
        composition['expected_effects'] = frozenset()
        inputs['compiled'] = compile_lifecycle_composition(**composition)
    elif defect == 'missing_binding':
        bindings.clear()
    elif defect == 'invented_binding':
        bindings[('example.produce.v1', 'observation', 'call', 'invented')] = frozenset({('release', 'build', 'verify')})
    else:
        key, pairs = next(iter(bindings.items()))
        bindings.clear()
        bindings[(*key[:3], 'runtime.py::invented')] = pairs
    monkeypatch.setattr(source, 'discover_python_source', lambda *a, **kw: pytest.fail('late effect declaration rejection'))
    with pytest.raises(CIGraphError, match='reconstructed.*effect population'):
        validate_reconstructed_lifecycle_bindings(**inputs)


def test_matching_effect_omissions_cannot_erase_actual_source(nonempty_public_effect_inputs, composition):
    from bcf_governance.tooling.ci_graph_composition import validate_reconstructed_lifecycle_bindings
    inputs = nonempty_public_effect_inputs
    inputs['required_effect_bindings'] = {}
    composition['payload']['relationships'][0]['contract']['effects'] = []
    composition['expected_effects'] = frozenset()
    inputs['compiled'] = compile_lifecycle_composition(**composition)
    with pytest.raises(CIGraphError, match='source effect bindings'):
        validate_reconstructed_lifecycle_bindings(**inputs)



@pytest.mark.parametrize('consumer', ['references', 'paths'])
def test_recovery_cannot_drop_rejection_path_invariant(path_inputs, consumer):
    from bcf_governance.tooling.ci_graph_composition import validate_backtrace_transition_references
    rows = path_inputs['backtrace']['transitions']
    rows[1]['invariants'].append('INV-RETRY-OUTCOME-AUTHENTICATED')
    _refresh_path_digest(path_inputs)
    with pytest.raises(CIGraphError, match='recovery.*invariants'):
        if consumer == 'references':
            validate_backtrace_transition_references({row['id']: row for row in rows})
        else:
            _path_query(path_inputs)


@pytest.mark.parametrize('mode', ['preserved', 'extra_recovery', 'reordered', 'no_recovery'])
def test_rejection_invariants_preserve_valid_bounded_paths(path_inputs, composition, mode):
    rows = path_inputs['backtrace']['transitions']
    rows[1]['invariants'].append('INV-RETRY-OUTCOME-AUTHENTICATED')
    if mode == 'no_recovery':
        rows.pop()
        path_inputs['required_transition_bindings'].pop('TR-003')
        path_inputs['required_recovery_limits'].clear()
        composition['payload']['relationships'][0]['contract'].update(successor='ST-OK', rejection='ST-FAIL', recovery='none')
        path_inputs['compiled'] = compile_lifecycle_composition(**composition)
    else:
        rows[2]['invariants'].append('INV-RETRY-OUTCOME-AUTHENTICATED')
        if mode == 'extra_recovery':
            rows[2]['invariants'].append('INV-RETRY-LEASE-EXACT')
        elif mode == 'reordered':
            rows.reverse()
    _refresh_path_digest(path_inputs)
    before = copy.deepcopy(path_inputs)
    result = _path_query(path_inputs)
    assert result['recoveries_checked'] == (0 if mode == 'no_recovery' else 1)
    assert result['authority'] is False
    assert result['execution_qualified'] is False
    assert path_inputs == before
