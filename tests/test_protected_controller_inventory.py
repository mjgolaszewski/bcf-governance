"""Real committed target inventory must not be defined by candidate omissions."""
from __future__ import annotations

import os
from pathlib import Path

import pytest

from bcf_governance.tooling import trusted_controller_compatibility as owner
from tests.test_trusted_controller_compatibility import _git, _repository


def _commit(root: Path, message: str) -> str:
    _git(root, 'add', '-A')
    _git(root, 'commit', '--allow-empty', '-q', '-m', message)
    return _git(root, 'rev-parse', 'HEAD')


def _classifier(root: Path, marker: Path, layout: str) -> Path:
    path = (root / owner.INSTALLED_TOPOLOGY_CLASSIFIER if layout == 'source'
            else root / owner.INSTALLED_RUNTIME_ROOT / 'ci_github_membership.py')
    path.parent.mkdir(parents=True, exist_ok=True)
    (path.parent / '__init__.py').touch()
    path.write_text(
        'from pathlib import Path\nfrom types import SimpleNamespace\n'
        'def classify_admission_topology(*args, **kwargs):\n'
        f'    Path({str(marker)!r}).write_text("protected-target-executed")\n'
        '    return SimpleNamespace(state=SimpleNamespace(value="pending_rotation"), reason="fixture")\n'
    )
    return path


def test_confirmed_target_classifier_absence_preserves_legacy_noop(tmp_path: Path, monkeypatch) -> None:
    root, target = _repository(tmp_path)
    before = _git(root, 'worktree', 'list', '--porcelain')
    monkeypatch.setattr(owner, '_candidate_pending_topology', lambda *_: pytest.fail('absent target allocated topology'))
    assert owner._verify_installed_pending_topology(root, target_commit=target) is None
    assert _git(root, 'worktree', 'list', '--porcelain') == before


@pytest.mark.parametrize('fault', ['metadata-denied', 'missing-target'])
def test_failed_target_inventory_cannot_become_confirmed_absence(tmp_path: Path, monkeypatch, fault: str) -> None:
    root, target = _repository(tmp_path)
    metadata = root / '.git'
    previous = metadata.stat().st_mode & 0o777
    if fault == 'metadata-denied':
        metadata.chmod(0)
        assert not os.access(metadata, os.R_OK | os.X_OK), 'fixture requires actual metadata denial'
    else:
        target = 'f' * 40
    monkeypatch.setattr(owner, '_candidate_pending_topology', lambda *_: pytest.fail('unknown target allocated topology'))
    try:
        with pytest.raises(owner.TrustedControllerCompatibilityError):
            owner._verify_installed_pending_topology(root, target_commit=target)
    finally:
        metadata.chmod(previous)


@pytest.mark.parametrize('layout', ['source', 'private'])
def test_target_classifier_executes_despite_committed_candidate_deletion(tmp_path: Path, monkeypatch, layout: str) -> None:
    root, _ = _repository(tmp_path)
    marker = tmp_path / 'protected-evaluator-observation'
    classifier = _classifier(root, marker, layout)
    target = _commit(root, 'protected classifier')
    classifier.unlink()
    _commit(root, 'candidate removes classifier')
    monkeypatch.setattr(owner, '_candidate_pending_topology', lambda *_: ({}, [], {}))
    owner._verify_installed_pending_topology(root, target_commit=target)
    assert marker.is_file(), 'candidate-layout-suppressed-protected-evaluator'
    assert marker.read_text() == 'protected-target-executed'
    assert not _git(root, 'status', '--porcelain')
    assert len([x for x in _git(root, 'worktree', 'list', '--porcelain').splitlines() if x.startswith('worktree ')]) == 1


@pytest.mark.parametrize('unsafe', ['ambiguous', 'symlink'])
def test_unsafe_target_classifier_inventory_blocks_before_execution(tmp_path: Path, monkeypatch, unsafe: str) -> None:
    root, _ = _repository(tmp_path)
    marker = tmp_path / 'forbidden-evaluator-execution'
    source = _classifier(root, marker, 'source')
    if unsafe == 'ambiguous':
        _classifier(root, marker, 'private')
    else:
        outside = tmp_path / 'outside-classifier.py'
        outside.write_bytes(source.read_bytes())
        source.unlink()
        source.symlink_to(outside)
    target = _commit(root, 'unsafe classifier representation')
    monkeypatch.setattr(owner, '_candidate_pending_topology', lambda *_: ({}, [], {}))
    with pytest.raises(owner.TrustedControllerCompatibilityError):
        owner._verify_installed_pending_topology(root, target_commit=target)
    assert not marker.exists(), 'unsafe-target-classifier-was-executed'
    assert len([x for x in _git(root, 'worktree', 'list', '--porcelain').splitlines() if x.startswith('worktree ')]) == 1


@pytest.mark.parametrize('statement', [
    'from .ci_github_api import GitHubAPI\n',
    'from . import ci_github_api\n',
    'from bcf_governance.tooling import ci_github_api\n',
])
def test_committed_candidate_deletion_cannot_hide_target_import_closure(tmp_path: Path, statement: str) -> None:
    root, _ = _repository(tmp_path)
    (root / owner.TRUSTED_ENTRYPOINT).write_text(statement)
    target = _commit(root, 'protected import binding')
    relative = 'bcf_governance/tooling/ci_github_api.py'
    (root / relative).unlink()
    _commit(root, 'candidate deletes required imported module')
    assert relative in owner.trusted_runtime_source_files(root, target_commit=target), 'candidate-deletion-erased-protected-source-population'
    with pytest.raises(owner.TrustedControllerCompatibilityError):
        owner.verify_trusted_controller_compatibility(root, target_commit=target)


def test_uncommitted_runtime_cannot_authorize_current_applicability(tmp_path: Path) -> None:
    root, target = _repository(tmp_path)
    (root / 'bcf_governance/tooling/ci_github_api.py').write_text('class GitHubAPI:\n    uncommitted = True\n')
    assert owner.trusted_runtime_source_files(root)  # Genuinely local authored inventory stays usable.
    with pytest.raises(owner.TrustedControllerCompatibilityError, match='clean|uncommitted'):
        owner.classify_trusted_controller_applicability(root, target_commit=target)


@pytest.mark.parametrize('replacement', ['hide', 'substitute'])
def test_replacement_ref_cannot_hide_or_replace_protected_classifier(tmp_path: Path, monkeypatch, replacement: str) -> None:
    root, _ = _repository(tmp_path)
    original_marker, forged_marker = tmp_path / 'original-target', tmp_path / 'replacement-target'
    classifier = _classifier(root, original_marker, 'source')
    target = _commit(root, 'original protected evaluator')
    if replacement == 'hide':
        classifier.unlink()
    else:
        _classifier(root, forged_marker, 'source')
    substitute = _commit(root, 'replacement evaluator')
    _git(root, 'replace', target, substitute)
    monkeypatch.setattr(owner, '_candidate_pending_topology', lambda *_: ({}, [], {}))
    owner._verify_installed_pending_topology(root, target_commit=target)
    assert original_marker.exists(), 'replacement-ref-hid-protected-evaluator'
    assert not forged_marker.exists(), 'replacement-ref-supplied-evaluator-authority'


def test_checkout_hook_cannot_rewrite_protected_evaluator(tmp_path: Path, monkeypatch) -> None:
    import sys
    root, _ = _repository(tmp_path)
    original_marker, injected_marker = tmp_path / 'original-code', tmp_path / 'hook-code'
    classifier = _classifier(root, original_marker, 'source')
    target = _commit(root, 'protected original evaluator')
    _classifier(root, injected_marker, 'source')
    injected = classifier.read_text()
    _git(root, 'restore', '--', classifier.relative_to(root).as_posix())
    hook = root / '.git/hooks/post-checkout'
    hook_ran = tmp_path / 'unauthorized-hook-ran'
    hook.write_text(f'#!{sys.executable}\nfrom pathlib import Path\nPath({str(hook_ran)!r}).touch()\nPath({str(owner.INSTALLED_TOPOLOGY_CLASSIFIER)!r}).write_text({injected!r})\n')
    hook.chmod(0o700)
    monkeypatch.setattr(owner, '_candidate_pending_topology', lambda *_: ({}, [], {}))
    owner._verify_installed_pending_topology(root, target_commit=target)
    assert original_marker.exists(), 'checkout-hook-replaced-protected-evaluator'
    assert not injected_marker.exists(), 'checkout-hook-code-obtained-authority'
    assert not hook_ran.exists(), 'candidate-hook-executed-during-protected-materialization'


def test_foreign_git_namespace_cannot_authorize_candidate(tmp_path: Path, monkeypatch) -> None:
    import subprocess
    root, target = _repository(tmp_path)
    foreign = tmp_path / 'foreign'
    subprocess.run(['git', 'clone', '-q', '--no-hardlinks', str(root), str(foreign)], check=True)
    (root / 'bcf_governance/tooling/ci_github_api.py').write_text('class GitHubAPI:\n    changed = True\n')
    _commit(root, 'changed candidate runtime')
    monkeypatch.setenv('GIT_DIR', str(foreign / '.git'))
    monkeypatch.setenv('GIT_WORK_TREE', str(foreign))
    with pytest.raises(owner.TrustedControllerCompatibilityError, match='repository|environment|namespace|redirect'):
        owner.classify_trusted_controller_applicability(root, target_commit=target)
