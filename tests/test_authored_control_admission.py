"""Baseline control defects must reject before normalization effects allocate."""
from contextlib import contextmanager
from pathlib import Path
from types import SimpleNamespace
import sys

import pytest
import yaml

from bcf_governance.tooling import ci_authority_submit as submit
from bcf_governance.tooling import scaffold_governance_artifacts as scaffold
from bcf_governance.tooling.governance_validation import ci_state_matrix
from bcf_governance.tooling.governance_validation.evidence_contracts import _validate_gate_contract_registry


def control_root(root, defect=None):
    governance = root / 'governance'
    governance.mkdir()
    (root / 'check.py').write_text('raise SystemExit(0)\n')
    target = root / 'implementation.py'
    target.write_text('RULE = True\n')
    profile = {'profile_contract_version': '1.0', 'release_gate_profile': {'gates': {
        'test': {'target': 'test', 'status': 'required', 'command_policy': 'automated_tests'},
    }}}
    contract = {'profile_contract_version': '1.0', 'gates': {'test': {
        'invocation': {'argv': ['python3', 'check.py'], 'cwd': '.', 'env': {}, 'required_env': []},
        'negative_controls': [{'id': 'source-rule-must-fail',
            'mutation': {'path': 'implementation.py', 'search': 'RULE = True', 'replace': 'RULE = False'},
            'oracle': {'kind': 'test_node_failure', 'node_ids': ['tests.test_rules::test_rule']}}],
    }}}
    policy = {'gate_overrides': {}}
    for name, value in [('governance-profile.yml', profile), ('governance/gate-contracts.yml', contract),
                        ('governance/evidence-policy.yml', policy)]:
        (root / name).write_text(yaml.safe_dump(value, sort_keys=False))
    if defect == 'absent_search':
        target.write_text('RULE = False\n')
    elif defect == 'ambiguous_search':
        target.write_text('RULE = True\nRULE = True\n')
    elif defect == 'missing_target':
        target.unlink()
    elif defect == 'symlink_target':
        target.rename(root / 'retained.py')
        target.symlink_to(root / 'retained.py')
    return profile, contract, policy


def submit_prerequisites(monkeypatch):
    # Other previously qualified admission owners are outside this control's cause.
    monkeypatch.setattr(submit, 'validate_authored_release_target', lambda *_a: None)
    monkeypatch.setattr(submit, 'gate_timeout_contract', lambda *_a: None)
    monkeypatch.setattr(submit, 'validate_ci_state_matrix', lambda *_a, **_k: None)
    monkeypatch.setattr(submit, 'validate_source_distribution', lambda *_a, **_k: None)
    monkeypatch.setattr(submit, 'validate_authored_test_reference_inventories', lambda *_a, **_k: None)
    monkeypatch.setattr(submit, 'validate_authored_semantic_ownership', lambda *_a: None)


def reconcile_prerequisites(monkeypatch):
    monkeypatch.setattr(scaffold, 'validate_authored_release_target', lambda *_a: None)
    monkeypatch.setattr(scaffold, 'gate_timeout_contract', lambda *_a: None)
    monkeypatch.setattr(ci_state_matrix, 'validate_ci_state_matrix', lambda *_a, **_k: None)
    monkeypatch.setattr(scaffold, 'declared_test_gates', lambda *_a: ('test',))


@pytest.mark.parametrize('defect', ['absent_search', 'ambiguous_search', 'missing_target', 'symlink_target'])
def test_submit_rejects_control_defect_before_lease_or_runner(tmp_path, monkeypatch, defect):
    control_root(tmp_path, defect)
    submit_prerequisites(monkeypatch)
    monkeypatch.setattr(submit, 'local_gate_lease', lambda *_a: pytest.fail('allocated lease before control rejection'))
    with pytest.raises(submit.ProspectiveValidationError, match='negative-control mutations must resolve exactly once'):
        submit._normalize_submission(
            tmp_path, python_executable=Path(sys.executable), execution_id='control-admission',
            semantic_intent=None, runner=lambda *_a, **_k: pytest.fail('allocated normalization runner'),
        )


@pytest.mark.parametrize('mode', ['--check', '--apply'])
@pytest.mark.parametrize('defect', ['absent_search', 'ambiguous_search', 'missing_target', 'symlink_target'])
def test_reconcile_rejects_control_defect_before_runtime_or_shadow(tmp_path, monkeypatch, mode, defect):
    control_root(tmp_path, defect)
    reconcile_prerequisites(monkeypatch)
    monkeypatch.setattr(scaffold, 'ensure_local_project_python', lambda *_a, **_k: pytest.fail('allocated project runtime before control rejection'))
    monkeypatch.setattr(scaffold, 'apply_workflow_authority_transition', lambda *_a, **_k: pytest.fail('allocated shadow before control rejection'))
    with pytest.raises(SystemExit, match='negative-control mutations must resolve exactly once'):
        scaffold.reconcile_main(['--repo-root', str(tmp_path), mode])


@pytest.mark.parametrize('kind', ['governed', 'local', 'local_deadline_policy'])
def test_valid_source_control_uses_existing_registry_and_submission_owner(tmp_path, monkeypatch, kind):
    if kind == 'governed':
        profile, contract, policy = control_root(tmp_path)
        _validate_gate_contract_registry(tmp_path, profile, contract, policy)
    elif kind == 'local_deadline_policy':
        (tmp_path / 'governance').mkdir()
        (tmp_path / 'governance/gate-contracts.yml').write_text(yaml.safe_dump({
            'execution_policy': {'default_timeout_seconds': 60, 'default_cleanup_timeout_seconds': 5},
        }))
    submit_prerequisites(monkeypatch)
    observed = []

    @contextmanager
    def lease(_execution):
        observed.append('lease')
        yield

    def runner(*_args, **_kwargs):
        observed.append('canonical-check')
        return SimpleNamespace(returncode=0)

    monkeypatch.setattr(submit, 'local_gate_lease', lease)
    submit._normalize_submission(
        tmp_path, python_executable=Path(sys.executable), execution_id='valid-control',
        semantic_intent=None, runner=runner,
    )
    assert observed == ['lease', 'canonical-check']


def phase_control_root(root, defect=None):
    profile, contract, policy = control_root(root)
    plans = root / 'plans'
    plans.mkdir()
    phases = root / 'phases'
    phases.mkdir()
    ledger = {'active_phase': {'plan': 'plans/current-plan.yml',
                              'workitems': 'plans/current-workitems.yml',
                              'log': 'phases/current-log.yml'}}
    (plans / 'phase-ledger.yml').write_text(yaml.safe_dump(ledger))
    log = phases / 'current-log.yml'
    log.write_text('document: {status: active}\n')
    # A tempting alternative is not the ledger-selected target.
    (phases / 'old-log.yml').write_text('document: {status: invalid}\n')
    mutation = {'path': '@active_phase_log', 'yaml_path': 'document.status', 'value': 'invalid'}
    if defect == 'stale_yaml_path':
        mutation['yaml_path'] = 'document.missing'
    elif defect == 'already_mutated':
        log.write_text('document: {status: invalid}\n')
    elif defect == 'missing_phase_target':
        log.unlink()
    elif defect == 'symlink_phase_target':
        log.rename(phases / 'retained.yml')
        log.symlink_to(phases / 'retained.yml')
    contract['gates']['test']['negative_controls'][0]['mutation'] = mutation
    (root / 'governance/gate-contracts.yml').write_text(yaml.safe_dump(contract))
    return profile, contract, policy


@pytest.mark.parametrize('defect', ['stale_yaml_path', 'already_mutated', 'missing_phase_target', 'symlink_phase_target'])
def test_complete_registry_checks_ledger_selected_log_mutation_state(tmp_path, defect):
    from bcf_governance.tooling.governance_validation.common import GovernanceValidationError

    profile, contract, policy = phase_control_root(tmp_path, defect)
    with pytest.raises(GovernanceValidationError, match='negative-control mutations must resolve exactly once'):
        _validate_gate_contract_registry(tmp_path, profile, contract, policy)


def test_complete_registry_uses_exact_active_log_and_preserves_valid_mutation(tmp_path):
    profile, contract, policy = phase_control_root(tmp_path)
    _validate_gate_contract_registry(tmp_path, profile, contract, policy)
