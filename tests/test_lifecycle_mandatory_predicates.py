"""Mandatory predicates cannot silently become contextual acceptance prose."""
import pytest
import yaml

from bcf_governance.tooling.evidence_workitem_lifecycle import (
    WorkitemContractError, active_workitem_entries, validate_bounded_target_authored_ready,
    workitem_observation, workitem_predecessors,
)


MALFORMED = [
    ' requires-workitem-closure:P01-W01',
    '\trequires-workitem-closure:P01-W01',
    '\u00a0requires-workitem-closure:P01-W01',
    'Requires-workitem-closure:P01-W01',
    'requires-workitem-closure :P01-W01',
    'requires-workitem-closure',
    'requires-lifecycle-composition:full',
    'requires-unknown-proof:yes',
    'requires-workitem-closure:P01-W01 ',
]


def _repo(root, predicate, predecessor='TODO'):
    plans = root / 'plans'
    plans.mkdir()
    (plans / 'phase-ledger.yml').write_text(yaml.safe_dump({
        'active_phase': {'id': 'P01', 'workitems': 'plans/items.yml'},
    }))
    entries = [
        {'id': 'P01-W01', 'status': predecessor, 'acceptance_evidence': ['test']},
        {'id': 'P01-W02', 'status': 'DONE', 'acceptance': [predicate],
         'acceptance_evidence': ['test']},
    ]
    (plans / 'items.yml').write_text(yaml.safe_dump({'workitems': entries}))
    return entries


@pytest.mark.parametrize('predicate', MALFORMED)
@pytest.mark.parametrize('consumer', ['decoder', 'active', 'readiness', 'computed'])
def test_mandatory_predicate_never_falls_through_as_prose(tmp_path, predicate, consumer):
    entries = _repo(tmp_path, predicate)
    if consumer == 'computed':
        report = workitem_observation(tmp_path, {}, {'claims': {}}, set(), {})
        assert report['structural_issues'], 'mandatory predicate disappeared from computed truth'
        assert report['closed_ids'] == [] and report['satisfied'] is False
    else:
        with pytest.raises(WorkitemContractError):
            if consumer == 'decoder':
                workitem_predecessors(entries[1])
            elif consumer == 'active':
                active_workitem_entries(tmp_path)
            else:
                validate_bounded_target_authored_ready(tmp_path, 'P01-W02')


def test_exact_dependency_and_contextual_prose_preserve_existing_behavior(tmp_path):
    entries = _repo(tmp_path, 'requires-workitem-closure:P01-W01', predecessor='DONE')
    entries[1]['acceptance'].append('Implementation requires the existing typed consumer')
    (tmp_path / 'plans/items.yml').write_text(yaml.safe_dump({'workitems': entries}))
    assert workitem_predecessors(entries[1]) == ['P01-W01']
    assert active_workitem_entries(tmp_path)[1] == entries
    validate_bounded_target_authored_ready(tmp_path, 'P01-W02')
