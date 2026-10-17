"""Require complete supplemental structure without promoting authored truth."""
import copy

import pytest
import yaml

from test_ci_state_matrix import _repo
from bcf_governance.tooling.governance_validation.ci_state_matrix import (
    CIStateMatrixError, validate_ci_state_matrix,
)


BLOCKS = (
    'release_version_projection_contract', 'adopter_runtime_retirement_contract',
    'phase_retention_validation_projection_contract', 'protected_merge_provider_result_contract',
    'negative_control_fixture_reachability_contract',
)


def _payload(repo):
    return yaml.safe_load((repo / 'spec/phase0/release-train-backtrace.yml').read_text())


def _write(repo, payload):
    (repo / 'spec/phase0/release-train-backtrace.yml').write_text(
        yaml.safe_dump(payload, sort_keys=False),
    )


@pytest.fixture
def version3(tmp_path):
    repo = _repo(tmp_path)
    payload = _payload(repo)
    payload['document']['schema_version'] = 3
    _write(repo, payload)
    report = validate_ci_state_matrix(repo, authored_only=True)
    assert report['authority'] is False and report['execution_qualified'] is False
    return repo, payload


@pytest.mark.parametrize('block', BLOCKS)
@pytest.mark.parametrize('defect', [
    'missing-block', 'empty-states', 'nonboolean-normative', 'empty-inputs',
    'unknown-state-field', 'empty-exclusions',
])
def test_version3_closes_each_supplemental_contract(version3, block, defect):
    repo, payload = version3
    target = payload[block]
    if defect == 'missing-block':
        del payload[block]
    elif defect == 'empty-states':
        target['states'] = []
    elif defect == 'nonboolean-normative':
        target['normative'] = 'yes'
    elif defect == 'empty-inputs':
        target['inputs'] = []
    elif defect == 'unknown-state-field':
        target['states'][0]['invented_authority'] = True
    else:
        target['exclusions'] = []
    _write(repo, payload)
    with pytest.raises(CIStateMatrixError, match='schema violation'):
        validate_ci_state_matrix(repo, authored_only=True)


@pytest.mark.parametrize('block', BLOCKS)
def test_version3_checks_supplemental_primitive_references(version3, block):
    repo, payload = version3
    payload[block]['primitive'] = 'PRIM-UNDECLARED'
    _write(repo, payload)
    with pytest.raises(CIStateMatrixError, match='undeclared supplemental primitive'):
        validate_ci_state_matrix(repo, authored_only=True)


@pytest.mark.parametrize('collection', ['states', 'edge_contracts', 'exclusions'])
def test_version3_rejects_duplicate_supplemental_identity(version3, collection):
    repo, payload = version3
    rows = payload['protected_merge_provider_result_contract'][collection]
    rows.append(copy.deepcopy(rows[0]))
    _write(repo, payload)
    with pytest.raises(CIStateMatrixError, match='duplicate supplemental'):
        validate_ci_state_matrix(repo, authored_only=True)


@pytest.mark.parametrize('defect', ['invented-root', 'missing-session', 'malformed-session'])
def test_version3_root_population_is_closed(version3, defect):
    repo, payload = version3
    if defect == 'invented-root':
        payload['invented_authority_contract'] = {'normative': True}
    elif defect == 'missing-session':
        del payload['same_session_evidence_input_transport']
    else:
        payload['same_session_evidence_input_transport']['contexts'] = []
    _write(repo, payload)
    with pytest.raises(CIStateMatrixError, match='schema violation'):
        validate_ci_state_matrix(repo, authored_only=True)


def test_version2_retains_its_weaker_historical_scope(tmp_path):
    repo = _repo(tmp_path)
    payload = _payload(repo)
    payload['document']['schema_version'] = 2
    payload['invented_authority_contract'] = {'normative': 'historically untyped'}
    payload['release_version_projection_contract']['primitive'] = 'PRIM-UNDECLARED'
    _write(repo, payload)
    report = validate_ci_state_matrix(repo, authored_only=True)
    assert report['authority'] is False and report['execution_qualified'] is False


def test_version3_fact_boundary_edges_are_not_invented_state_edges(version3):
    repo, payload = version3
    block = payload['protected_merge_provider_result_contract']
    state_ids = {row['id'] for row in block['states']}
    assert any(row['from'] not in state_ids for row in block['edge_contracts'])
    assert validate_ci_state_matrix(repo, authored_only=True)['authority'] is False
