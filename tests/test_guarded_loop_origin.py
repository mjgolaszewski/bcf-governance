"""Qualified guard result origins credit list iteration, never the loop body."""
import copy
import json

import pytest
import yaml

from bcf_governance.tooling import ci_graph_composition_operations as owner
from bcf_governance.tooling.ci_graph_errors import CIGraphError
from tests.runtime_context_factory_support import make_context_inputs, OPERATION, CALLER, CALLEE
from tests.test_runtime_context_consumer_binding import strict_cause


@pytest.fixture
def loop_inputs(tmp_path):
    return make_context_inputs(tmp_path, model_version='1.1')


def test_real_guarded_loop_has_one_exact_qualified_iteration_origin(loop_inputs):
    context = owner.capture_operation_runtime_context(**loop_inputs)
    assert len(context.sites) == 2 and len(context.iteration_sites) == 1
    statement = json.loads(context.statement)
    assert statement['model_version'] == '1.1'
    site = statement['iteration_sites'][0]
    assert site['kind'] == 'native_list_iterator'
    assert site['value_origin'] == 'fresh_exact_list_at_loop_entry'
    assert site['guard_call']['input_origin'] == 'parser_append_vector'
    assert set(site) == {'caller', 'line', 'column', 'expression_sha256', 'occurrence', 'kind', 'value_origin', 'guard_call'}
    summaries = owner.runtime_context_call_summaries(context.public_capture.registry.operations[0], loop_inputs['inventory'], context)
    assert len(summaries) == 3


def test_actual_required_consumer_credits_iteration_but_not_path_or_body(loop_inputs):
    args = loop_inputs
    context = owner.capture_operation_runtime_context(**args)
    site = json.loads(context.iteration_sites[0][0])
    target = f"{CALLER}:iteration:{site['expression_sha256']}:{site['occurrence']}"
    with pytest.raises(CIGraphError) as before:
        owner.validate_public_operation_capture(args['repo_root'], args['inventory'], args['public_capture'])
    assert any(row[1:3] == ('runtime_protocol', target) for row in strict_cause(before.value).effect_obligations)
    with pytest.raises(CIGraphError) as after:
        owner.validate_public_operation_capture(args['repo_root'], args['inventory'], args['public_capture'],
                                                runtime_contexts={OPERATION: context})
    blockers = strict_cause(after.value).effect_obligations
    assert blockers and not any(row[1:3] == ('runtime_protocol', target) for row in blockers)
    assert not any(row[0] == CALLEE for row in blockers)
    assert any(row[0] == CALLER and row[1] in {'construction_context', 'runtime_call', 'runtime_target'} for row in blockers)
    assert any(row[0] == CALLER and row[1] == 'runtime_protocol' for row in blockers)


def test_legacy_model_never_inherits_new_iteration_credit(tmp_path):
    args = make_context_inputs(tmp_path)
    context = owner.capture_operation_runtime_context(**args)
    assert context.iteration_sites == ()
    assert 'iteration_sites' not in json.loads(context.statement)
    assert len(owner.runtime_context_call_summaries(context.public_capture.registry.operations[0], args['inventory'], context)) == 2


@pytest.mark.parametrize('defect', ['missing', 'duplicate', 'extra', 'guard', 'element-claim', 'legacy-version'])
def test_iteration_scope_requires_exact_versioned_canonical_proof(loop_inputs, defect):
    path = loop_inputs['evidence_root'] / 'test.evidence.json'
    receipt = json.loads(path.read_bytes())
    statement = receipt['observations']['runtime_context']
    if defect == 'missing':
        statement.pop('iteration_sites')
    elif defect == 'duplicate':
        statement['iteration_sites'].append(copy.deepcopy(statement['iteration_sites'][0]))
    elif defect == 'extra':
        statement['iteration_sites'].append(dict(statement['iteration_sites'][0], occurrence=99))
    elif defect == 'guard':
        statement['iteration_sites'][0]['guard_call']['input_origin'] = 'untrusted'
    elif defect == 'element-claim':
        statement['iteration_sites'][0]['elements'] = 'always-string'
    else:
        statement['model_version'] = '1.0'
    path.write_text(json.dumps(receipt))
    with pytest.raises(CIGraphError, match='runtime context'):
        owner.capture_operation_runtime_context(**loop_inputs)


def rewrite_source(root, defect):
    path = root / CALLER.split('::')[0]
    text = path.read_text()
    if defect == 'intervening-call':
        text = text.replace('            for raw in adopter_python:', '            touch(adopter_python)\n            for raw in adopter_python:')
    elif defect == 'rebinding':
        text = text.replace('            for raw in adopter_python:', '            adopter_python = replacement\n            for raw in adopter_python:')
    elif defect == 'alternate-iterable':
        text = text.replace('for raw in adopter_python:', 'for raw in args.adopter_python:')
    elif defect == 'unguarded-result':
        text = text.replace('cli_arguments(args.adopter_python)', 'list(args.adopter_python)')
    elif defect == 'continuing-handler':
        text = text.replace('                raise ReleaseQualificationError(\n                    "--adopter-python requires ordinary parsed strings"\n                ) from exc', '                adopter_python = []')
    elif defect == 'global-binding':
        text = text.replace('    argv = cli_arguments(argv)', '    global adopter_python\n    argv = cli_arguments(argv)')
    elif defect == 'finally':
        text = text.replace('            interpreters: dict[str, Path] = {}', '            finally:\n                touch()\n            interpreters: dict[str, Path] = {}')
    else:
        text = text.replace('from __future__ import annotations\n', '')
    assert text != path.read_text()
    path.write_text(text)


@pytest.mark.parametrize('defect', ['intervening-call', 'rebinding', 'alternate-iterable', 'unguarded-result', 'continuing-handler', 'finally', 'eager-annotation', 'global-binding'])
def test_source_flow_changes_cannot_supply_list_origin(tmp_path, defect):
    args = make_context_inputs(tmp_path, model_version='1.1', source_transform=lambda root: rewrite_source(root, defect))
    with pytest.raises(CIGraphError, match='snapshot iteration'):
        owner.capture_operation_runtime_context(**args)


def test_declared_iteration_port_cannot_be_masked_by_model(tmp_path):
    def declare(root):
        path = root / 'governance/application-operations.yml'
        policy = yaml.safe_load(path.read_text())
        policy['operations'][0]['non_authoritative_output_effects'] = ['python-implicit::iteration']
        path.write_text(yaml.safe_dump(policy))
    args = make_context_inputs(tmp_path, model_version='1.1', source_transform=declare)
    context = owner.capture_operation_runtime_context(**args)
    with pytest.raises(CIGraphError) as error:
        owner.validate_public_operation_capture(args['repo_root'], args['inventory'], args['public_capture'],
                                                runtime_contexts={OPERATION: context})
    assert 'runtime model cannot mask a declared effect port' in str(error.value)


def test_iteration_capture_tampering_fails_before_consumption(loop_inputs):
    context = owner.capture_operation_runtime_context(**loop_inputs)
    forged = context._replace(iteration_sites=())
    with pytest.raises(CIGraphError, match='runtime context capture changed'):
        owner.runtime_context_call_summaries(context.public_capture.registry.operations[0], loop_inputs['inventory'], forged)


def test_loop_body_callback_remains_a_required_effect(tmp_path):
    def callback(root):
        path = root / CALLER.split('::')[0]
        text = path.read_text()
        old = '                interpreters[repository] = Path(path)'
        assert text.count(old) == 1
        path.write_text(text.replace(old, '                touch(adopter_python)\n' + old))
    args = make_context_inputs(tmp_path, model_version='1.1', source_transform=callback)
    context = owner.capture_operation_runtime_context(**args)
    assert len(context.iteration_sites) == 1
    with pytest.raises(CIGraphError) as error:
        owner.validate_public_operation_capture(args['repo_root'], args['inventory'], args['public_capture'],
                                                runtime_contexts={OPERATION: context})
    assert any('touch' in row[2] for row in strict_cause(error.value).effect_obligations)


@pytest.mark.parametrize('field,value', [('authority', True), ('execution_qualified', True), ('version', '99.0')])
def test_neutral_protocol_metadata_cannot_become_model_authority(loop_inputs, field, value):
    context = owner.capture_operation_runtime_context(**loop_inputs)
    facts = copy.deepcopy(loop_inputs['inventory'])
    site = json.loads(context.iteration_sites[0][0])
    function = next(row for row in facts['functions'] if row['symbol'] == CALLER)
    row = next(row for row in function['calls'] if row.get('called_symbol') == 'python-implicit::iteration'
               and row['line'] == site['line'] and row['column'] == site['column'])
    row['implicit_protocol'][field] = value
    with pytest.raises(CIGraphError):
        owner.runtime_context_call_summaries(context.public_capture.registry.operations[0], facts, context)
