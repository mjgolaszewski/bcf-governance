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
    governance.mkdir(exist_ok=True)
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


@pytest.mark.parametrize('relative,duplicate', [
    ('governance-profile.yml', 'profile_contract_version: "1.0"\n'),
    ('governance/gate-contracts.yml', 'profile_contract_version: "1.0"\n'),
    ('governance/evidence-policy.yml', 'gate_overrides: {}\n'),
])
def test_authored_control_population_rejects_duplicate_policy_keys(tmp_path, relative, duplicate):
    from bcf_governance.tooling.governance_validation.common import GovernanceValidationError
    from bcf_governance.tooling.governance_validation.evidence_contracts import validate_authored_gate_controls

    control_root(tmp_path)
    path = tmp_path / relative
    path.write_text(path.read_text() + duplicate)
    with pytest.raises(GovernanceValidationError, match='duplicate'):
        validate_authored_gate_controls(tmp_path)


def test_authored_control_policy_preserves_valid_yaml_alias_and_explicit_merge_override(tmp_path):
    from bcf_governance.tooling.governance_validation.evidence_contracts import validate_authored_gate_controls

    control_root(tmp_path)
    (tmp_path / 'governance-profile.yml').write_text('''profile_contract_version: "1.0"
release_gate_profile:
  gates:
    test:
      <<: &defaults {target: test, status: optional, command_policy: automated_tests}
      status: required
''')
    validate_authored_gate_controls(tmp_path)


def _admission_runtime_module(name):
    import importlib
    from tests.test_scheduled_phase_owners import _owner

    tooling = _owner('evidence_contracts').__package__.rsplit('.', 1)[0]
    return importlib.import_module(f'{tooling}.{name}')


@pytest.mark.parametrize('defect', [None, 'absent_search', 'ambiguous_search', 'missing_target', 'symlink_target'])
def test_authored_control_query_preserves_complete_source_mutation_state(tmp_path, defect):
    owner = _admission_runtime_module('governance_validation.evidence_contracts')
    control_root(tmp_path, defect)
    if defect is None:
        owner.validate_authored_gate_controls(tmp_path)
    else:
        with pytest.raises(owner.GovernanceValidationError, match='negative-control mutations must resolve exactly once'):
            owner.validate_authored_gate_controls(tmp_path)


@pytest.mark.parametrize('poisoned', [False, True])
def test_reconcile_rechecks_generated_control_before_recording_convergence(tmp_path, monkeypatch, poisoned):
    from tests.test_reconcile_governance import _git

    owner = _admission_runtime_module('scaffold_governance_artifacts')
    state = _admission_runtime_module('governance_validation.ci_state_matrix')
    control_root(tmp_path)
    _git(tmp_path, 'init', '--quiet', '--initial-branch=main')
    _git(tmp_path, 'config', 'user.name', 'BCF Test')
    _git(tmp_path, 'config', 'user.email', 'bcf@example.invalid')
    _git(tmp_path, 'add', '--all')
    _git(tmp_path, 'commit', '--quiet', '-m', 'valid controls')
    head = _git(tmp_path, 'rev-parse', 'HEAD')
    monkeypatch.setattr(owner, 'validate_authored_release_target', lambda *_a: None)
    monkeypatch.setattr(owner, 'gate_timeout_contract', lambda *_a: None)
    monkeypatch.setattr(state, 'validate_ci_state_matrix', lambda *_a, **_k: None)
    monkeypatch.setattr(owner, 'declared_test_gates', lambda *_a: ('test',))
    monkeypatch.setattr(owner, 'ensure_local_project_python', lambda *_a, **_k: Path(sys.executable))
    recorded = []
    monkeypatch.setattr(owner, 'record_reconcile_steps', lambda *_a: recorded.append('recorded') or {})

    def generate():
        (tmp_path / 'governance/projected.yml').write_text('generated: true\n')
        if poisoned:
            (tmp_path / 'implementation.py').write_text('RULE = False\n')

    monkeypatch.setattr(owner, 'reconcile_steps', lambda *_a: (
        owner.ReconcileStep('control-projection', lambda: None, generate),
    ))
    if poisoned:
        with pytest.raises(SystemExit, match='negative-control mutations must resolve exactly once'):
            owner.reconcile_main(['--repo-root', str(tmp_path), '--apply'])
        assert recorded == []
    else:
        owner.reconcile_main(['--repo-root', str(tmp_path), '--apply'])
        assert recorded == ['recorded']
    assert _git(tmp_path, 'rev-parse', 'HEAD') == head


@pytest.mark.parametrize('workflow_transition', [False, True])
@pytest.mark.parametrize('poisoned', [False, True])
def test_control_validation_precedes_real_git_shadow_promotion(tmp_path, workflow_transition, poisoned):
    from tests.test_reconcile_governance import (
        _authority_transition_repository, _git, _transition_snapshot, _transition_steps,
    )

    owner = _admission_runtime_module('reconcile_authority_transition')
    fixed_point = _admission_runtime_module('scaffold_governance_artifacts')
    controls = _admission_runtime_module('governance_validation.evidence_contracts')
    root = _authority_transition_repository(tmp_path)
    control_root(root)
    if workflow_transition:
        (root / 'intent').write_text('new\n')
    _git(root, 'add', '--all')
    _git(root, 'commit', '--quiet', '-m', 'valid authored controls')
    controls.validate_authored_gate_controls(root)
    before = (_git(root, 'rev-parse', 'HEAD'), _git(root, 'write-tree'),
              _git(root, 'status', '--porcelain=v1'), _transition_snapshot(root))

    def steps(candidate):
        def generate():
            (candidate / 'governance/projected.yml').write_text('generated: true\n')
            if poisoned:
                (candidate / 'implementation.py').write_text('RULE = False\n')
        return (fixed_point.ReconcileStep('control-projection', lambda: None, generate),
                *_transition_steps(candidate))

    if poisoned:
        with pytest.raises(controls.GovernanceValidationError, match='negative-control mutations must resolve exactly once'):
            owner.apply_workflow_authority_transition(root, step_factory=steps,
                converge=fixed_point.converge, snapshot=_transition_snapshot, commit_projection=True)
        assert (_git(root, 'rev-parse', 'HEAD'), _git(root, 'write-tree'),
                _git(root, 'status', '--porcelain=v1'), _transition_snapshot(root)) == before
        assert not (root / 'governance/projected.yml').exists()
    else:
        result = owner.apply_workflow_authority_transition(root, step_factory=steps,
            converge=fixed_point.converge, snapshot=_transition_snapshot, commit_projection=True)
        assert result is not None
        assert _git(root, 'rev-parse', 'HEAD') == result.authority_commit
        assert _git(root, 'status', '--porcelain=v1') == ''
        controls.validate_authored_gate_controls(root)
        assert (root / 'implementation.py').read_text() == 'RULE = True\n'
