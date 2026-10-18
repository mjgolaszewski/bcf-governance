"""Profile normalization preserves exactly the execution bound its caller declares."""
from copy import deepcopy

import pytest

from bcf_governance.tooling.governance_profiles import ProfileContractError, _validate_gate


def gate_rule():
    return {'invocation': {'argv': ['python3', 'gate.py'], 'cwd': '.', 'env': {}, 'required_env': []},
            'evidence': {'kind': 'gate'}, 'negative_controls': [{
                'id': 'gate-must-fail', 'mutation': {'path': 'gate.py', 'search': 'BROKEN = False', 'replace': 'BROKEN = True'},
                'oracle': {'kind': 'diagnostic', 'exit_codes': [1], 'stream': 'stderr', 'regex': 'broken'},
            }]}


@pytest.mark.parametrize('seconds', [1, 30, 600, 21600])
def test_declared_gate_timeout_survives_profile_normalization(seconds):
    rule = gate_rule()
    rule['invocation']['timeout_seconds'] = seconds
    before = deepcopy(rule)
    result = _validate_gate('fixture', rule, command_policy='governance_validation')
    assert result['invocation']['timeout_seconds'] == seconds
    assert rule == before
    assert _validate_gate('fixture', result, command_policy='governance_validation') == result


@pytest.mark.parametrize('seconds', [True, False, 0, -1, '30', 30.0, None, 21601])
def test_invalid_declared_gate_timeout_rejects_at_profile_ingress(seconds):
    rule = gate_rule()
    rule['invocation']['timeout_seconds'] = seconds
    with pytest.raises(ProfileContractError, match='timeout'):
        _validate_gate('fixture', rule, command_policy='governance_validation')


def test_absent_optional_timeout_preserves_legacy_projection():
    rule = gate_rule()
    before = deepcopy(rule)
    result = _validate_gate('fixture', rule, command_policy='governance_validation')
    assert 'timeout_seconds' not in result['invocation']
    assert rule == before
    assert _validate_gate('fixture', result, command_policy='governance_validation') == result
