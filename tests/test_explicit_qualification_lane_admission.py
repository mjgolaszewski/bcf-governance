"""Explicit qualification requests require exact custody before lane admission."""
from __future__ import annotations

from dataclasses import replace
import subprocess

import pytest

from bcf_governance.tooling import local_pr_context as owner
from bcf_governance.tooling.governance_install.runtime_custody import (
    RuntimeCustodyError, RuntimeCustodyFailure, RuntimeCustodySnapshot, RuntimeCustodyState,
)
from tests.test_local_pr import _git, _repository


@pytest.fixture
def qualification_subject(tmp_path):
    repo, base = _repository(tmp_path)
    tree = _git(repo, 'rev-parse', f'{base}^{{tree}}')
    context = owner.LocalPRContext('origin', 'main', base,
                                   _git(repo, 'rev-parse', 'HEAD'), 'feature')
    snapshot = RuntimeCustodySnapshot(
        state=RuntimeCustodyState.CANDIDATE_QUALIFICATION_EXACT,
        version='2.5.0', runtime_owned={}, consumer_preserved={}, legacy_overlap=(),
        provenance_claim={'adopter': {'commit_sha': base, 'tree_sha': tree}},
        lock_bytes=b'{}',
    )
    return repo, context, snapshot


def _git_runner(command, **kwargs):
    return subprocess.run(command, capture_output=True, text=True, check=False, **kwargs)


@pytest.mark.parametrize('explicit', [False, True])
def test_exact_adopter_custody_admits_qualification_lane(
    qualification_subject, monkeypatch, explicit,
):
    repo, context, snapshot = qualification_subject
    monkeypatch.setattr(owner, 'inspect_runtime_custody', lambda _root: snapshot)
    lane = owner.LocalValidationLane.ISOLATED_CANDIDATE_QUALIFICATION
    assert owner.derive_local_validation_lane(
        repo, context, requested=lane if explicit else None, runner=_git_runner,
    ) is lane


@pytest.mark.parametrize('defect', ['absent', 'wrong-commit', 'wrong-tree',
                                  'unreadable', 'unavailable-base'])
def test_explicit_qualification_cannot_skip_exact_custody(
    qualification_subject, monkeypatch, defect,
):
    repo, context, snapshot = qualification_subject
    if defect == 'absent':
        snapshot = replace(snapshot, state=RuntimeCustodyState.ABSENT)
    elif defect in ('wrong-commit', 'wrong-tree'):
        adopter = dict(snapshot.provenance_claim['adopter'])
        adopter['commit_sha' if defect == 'wrong-commit' else 'tree_sha'] = 'f' * 40
        snapshot = replace(snapshot, provenance_claim={'adopter': adopter})
    elif defect == 'unavailable-base':
        context = replace(context, base_sha='f' * 40)

    def inspect(_root):
        if defect == 'unreadable':
            raise RuntimeCustodyError(RuntimeCustodyFailure.LOCK_UNREADABLE)
        return snapshot

    monkeypatch.setattr(owner, 'inspect_runtime_custody', inspect)
    with pytest.raises(owner.LocalPRError, match='qualification'):
        owner.derive_local_validation_lane(
            repo, context,
            requested=owner.LocalValidationLane.ISOLATED_CANDIDATE_QUALIFICATION,
            runner=_git_runner,
        )


@pytest.mark.parametrize('defect', ['absent', 'wrong-base'])
def test_public_qualification_rejection_precedes_lease_toolchain_and_provider(
    qualification_subject, monkeypatch, defect,
):
    from bcf_governance.tooling import local_pr

    repo, context, snapshot = qualification_subject
    if defect == 'absent':
        snapshot = replace(snapshot, state=RuntimeCustodyState.ABSENT)
    else:
        snapshot = replace(snapshot, provenance_claim={
            'adopter': {'commit_sha': 'f' * 40, 'tree_sha': 'e' * 40},
        })
    monkeypatch.setattr(owner, 'inspect_runtime_custody', lambda _root: snapshot)
    monkeypatch.setattr(local_pr, 'resolve_local_pr_context', lambda *a, **k: context)
    # Independent authored lifecycle admission has its own causal controls.
    monkeypatch.setattr(local_pr, 'require_clean_candidate_root', lambda root, **k: root)
    monkeypatch.setattr(local_pr, 'validate_evaluation_authored_ready', lambda *a, **k: None)

    def forbidden(*args, **kwargs):
        pytest.fail('qualification custody rejection followed resource/provider admission')

    for name in ('local_gate_lease', 'validate_local_toolchain',
                 'validate_direct_protection_prospective', 'verify_provider_workflow_authority'):
        monkeypatch.setattr(local_pr, name, forbidden)
    with pytest.raises((owner.LocalPRError, owner.ProspectiveValidationError),
                       match='qualification'):
        local_pr.run_prospective_train(
            repo, semantic_intent='pr', evaluation_target=None,
            subject_commit=context.head_sha,
            subject_tree=_git(repo, 'rev-parse', 'HEAD^{tree}'),
            python_executable=repo / '.venv/bin/python',
            validation_lane=owner.LocalValidationLane.ISOLATED_CANDIDATE_QUALIFICATION,
            runner=_git_runner,
        )
