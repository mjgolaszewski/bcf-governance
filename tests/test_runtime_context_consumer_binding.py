"""A qualified runtime context must match its consuming protected capture."""

import pytest
import yaml

from bcf_governance.tooling import ci_graph_composition_operations as owner
from bcf_governance.tooling.ci_graph_errors import CIGraphError
from bcf_governance.tooling.semantic_operation_effects import SemanticOperationEffectError
from tests.runtime_context_factory_support import context_inputs as context_inputs, OPERATION, CALLER, CALLEE, PAIR, subject
from tests.test_governance_truth import _git


def strict_cause(error):
    while error is not None:
        if isinstance(error, SemanticOperationEffectError):
            return error
        error = error.__cause__
    pytest.fail('required consumer did not reach strict effect owner')


def test_required_public_consumer_uses_only_guard_credit_and_keeps_other_blockers(context_inputs):
    args = context_inputs
    context = owner.capture_operation_runtime_context(**args)
    with pytest.raises(CIGraphError) as before:
        owner.validate_public_operation_capture(args['repo_root'], args['inventory'], args['public_capture'])
    assert any(row[0] == CALLEE for row in strict_cause(before.value).effect_obligations)
    with pytest.raises(CIGraphError) as after:
        owner.validate_public_operation_capture(args['repo_root'], args['inventory'], args['public_capture'],
                                                runtime_contexts={OPERATION: context})
    blockers = strict_cause(after.value).effect_obligations
    assert blockers and not any(row[0] == CALLEE for row in blockers)


def alternate_capture(args, defect):
    public = args['public_capture']
    root = args['repo_root']
    if defect == 'protected-policy':
        path = root / 'governance/gate-contracts.yml'
        policy = yaml.safe_load(path.read_text())
        policy['claim_model']['claims']['test-claim']['truth'] += ' revised protected qualification'
        path.write_text(yaml.safe_dump(policy))
        _git(root, 'add', 'governance/gate-contracts.yml')
        _git(root, 'commit', '-m', 'revise protected claim policy')
        policy_subject = subject(root)
        roots = {PAIR: frozenset({CALLER})}
    else:
        policy_subject = dict(zip(('commit_sha', 'tree_sha'), public.policy_subject))
        roots = {PAIR: frozenset({CALLER, CALLEE})}
    return owner.capture_public_operation_bindings(root, policy_subject=policy_subject,
        runtime_subject=dict(zip(('commit_sha', 'tree_sha'), public.runtime_subject)),
        required_relationships={OPERATION: frozenset({PAIR})}, relationship_roots=roots)


@pytest.mark.parametrize('defect', ['protected-policy', 'relationships'])
def test_context_cannot_cross_a_legitimate_changed_protected_capture(context_inputs, defect):
    args = context_inputs
    context = owner.capture_operation_runtime_context(**args)
    consumer = alternate_capture(args, defect)
    assert consumer != context.public_capture
    assert consumer.registry.operations == context.public_capture.registry.operations
    with pytest.raises(CIGraphError, match='runtime context differs from consuming protected operation capture'):
        owner.validate_public_operation_capture(args['repo_root'], args['inventory'], consumer,
                                                runtime_contexts={OPERATION: context})


@pytest.mark.parametrize('defect', ['wrong-key', 'missing-context', 'forged-context', 'list'])
def test_invalid_context_population_blocks_at_consuming_boundary(context_inputs, defect):
    args = context_inputs
    context = owner.capture_operation_runtime_context(**args)
    population = {OPERATION: context}
    if defect == 'wrong-key':
        population = {'wrong.v1': context}
    elif defect == 'missing-context':
        population[OPERATION] = None
    elif defect == 'forged-context':
        population[OPERATION] = context._replace(operation_id='wrong.v1')
    else:
        population = list(population.items())
    with pytest.raises(CIGraphError, match='runtime context differs from consuming protected operation capture'):
        owner.validate_public_operation_capture(args['repo_root'], args['inventory'], args['public_capture'],
                                                runtime_contexts=population)
