"""Qualified model applicability for the real CI string snapshot calls."""
import copy
import json

import pytest

from bcf_governance.tooling import ci_graph_composition_operations as owner
from bcf_governance.tooling.ci_graph_errors import CIGraphError
from bcf_governance.tooling.semantic_operation_effects import validated_operation_effect_inventory, SemanticOperationEffectError
from tests.runtime_context_factory_support import context_inputs as context_inputs, OPERATION, CALLER, CALLEE


def test_real_guard_context_constructs_from_exact_qualified_fixture_evidence(context_inputs):
    context=owner.capture_operation_runtime_context(**context_inputs)
    assert context.operation_id==OPERATION
    assert len(context.sites)==2
    operation=context_inputs['public_capture'].registry.operations[0]
    summaries=owner.runtime_context_call_summaries(operation,context_inputs['inventory'],context)
    assert len(summaries)==2 and {row[0] for row in summaries}=={CALLER}


def test_strict_owner_consumes_guard_model_without_waiving_surrounding_cli(context_inputs):
    facts=context_inputs['inventory'];operation=context_inputs['public_capture'].registry.operations[0]
    with pytest.raises(SemanticOperationEffectError) as before:
        validated_operation_effect_inventory(operation,CALLER,facts)
    assert any(row[0]==CALLEE for row in before.value.effect_obligations)
    context=owner.capture_operation_runtime_context(**context_inputs)
    with pytest.raises(SemanticOperationEffectError) as after:
        validated_operation_effect_inventory(operation,CALLER,facts,runtime_context=context)
    assert after.value.effect_obligations
    assert not any(row[0]==CALLEE for row in after.value.effect_obligations)


@pytest.mark.parametrize('field',['implementation_sha256','namespace_sha256'])
def test_wrong_native_scope_cannot_reuse_model_evidence(context_inputs,field):
    arguments=dict(context_inputs,native_subject=dict(context_inputs['native_subject']))
    arguments['native_subject'][field]='f'*64
    with pytest.raises(CIGraphError,match='runtime context'):
        owner.capture_operation_runtime_context(**arguments)


@pytest.mark.parametrize('defect',['missing','diagnostic','forged-qualification','statement','profile','scope','extra-site','duplicate-site'])
def test_wrong_or_missing_model_qualification_stays_blocked(context_inputs,defect):
    path=context_inputs['evidence_root']/'test.evidence.json';receipt=json.loads(path.read_bytes())
    statement=receipt['observations']['runtime_context']
    if defect=='missing':receipt['observations'].pop('runtime_context')
    elif defect=='diagnostic':receipt['qualification']['satisfied']=False
    elif defect=='forged-qualification':receipt['qualification']['control_ids']=[]
    elif defect=='statement':statement['model_version']='99.0'
    elif defect=='profile':statement['target']['profile']='self'
    elif defect=='scope':statement['target']['source_subject']['tree_sha']='f'*40
    elif defect=='extra-site':statement['call_sites'].append(dict(statement['call_sites'][0],occurrence=100))
    else:statement['call_sites'].append(copy.deepcopy(statement['call_sites'][0]))
    path.write_text(json.dumps(receipt))
    with pytest.raises(CIGraphError,match='runtime context'):
        owner.capture_operation_runtime_context(**context_inputs)


@pytest.mark.parametrize('field',['statement','sites','receipts','inventory_sha256','operation_id'])
def test_private_capture_identity_is_not_qualification_authority(context_inputs,field):
    context=owner.capture_operation_runtime_context(**context_inputs)
    replacement={'statement':'{}','sites':(),'receipts':(),'inventory_sha256':'0'*64,'operation_id':'wrong.v1'}[field]
    forged=context._replace(**{field:replacement})
    with pytest.raises(CIGraphError,match='runtime context'):
        owner.runtime_context_call_summaries(context_inputs['public_capture'].registry.operations[0],context_inputs['inventory'],forged)


def test_receipt_movement_invalidates_context_at_consumption(context_inputs):
    context=owner.capture_operation_runtime_context(**context_inputs)
    path=context_inputs['evidence_root']/'test.evidence.json';receipt=json.loads(path.read_bytes())
    receipt['observations']['runtime_context']['target']['native_subject']['namespace_sha256']='f'*64
    path.write_text(json.dumps(receipt))
    with pytest.raises(CIGraphError,match='runtime context'):
        owner.runtime_context_call_summaries(context_inputs['public_capture'].registry.operations[0],context_inputs['inventory'],context)


def test_context_cannot_mask_a_declared_effect_port(context_inputs):
    context=owner.capture_operation_runtime_context(**context_inputs)
    operation=copy.deepcopy(context_inputs['public_capture'].registry.operations[0])
    operation['non_authoritative_output_effects']=[CALLEE]
    with pytest.raises(SemanticOperationEffectError,match='runtime context|runtime model'):
        validated_operation_effect_inventory(operation,CALLER,context_inputs['inventory'],runtime_context=context)


def test_inventory_rewrite_is_not_a_source_context(context_inputs):
    context=owner.capture_operation_runtime_context(**context_inputs)
    facts=copy.deepcopy(context_inputs['inventory'])
    function=next(row for row in facts['functions'] if row['symbol']==CALLER)
    function['calls']=[row for row in function['calls'] if row.get('called_symbol')!=CALLEE]
    with pytest.raises(CIGraphError):
        owner.runtime_context_call_summaries(context_inputs['public_capture'].registry.operations[0],facts,context)


@pytest.mark.parametrize('rewrite', ['guard-builtin', 'guard-import', 'caller-import', 'parser-converter'])
def test_source_model_rejects_rewritten_binding_or_parser(context_inputs, rewrite):
    from bcf_governance.tooling.semantic_ownership_protocols import cli_snapshot_model_sites
    root = context_inputs['repo_root']
    caller = (root / CALLER.split('::')[0]).read_bytes()
    guard = (root / CALLEE.split('::')[0]).read_bytes()
    facts = next(row for row in context_inputs['inventory']['functions'] if row['symbol'] == CALLER)
    if rewrite == 'guard-builtin':
        guard += b'\nlist = object\n'
    elif rewrite == 'guard-import':
        guard += b'\nfrom overrides import list\n'
    elif rewrite == 'caller-import':
        caller += b'\nfrom overrides import cli_arguments\n'
    else:
        caller = caller.replace(b'action="append"', b'action="append", type=str')
        assert caller != (root / CALLER.split('::')[0]).read_bytes()
    with pytest.raises(ValueError, match='snapshot'):
        cli_snapshot_model_sites(caller, guard, guard, caller=CALLER, callee=CALLEE, calls=facts['calls'])
