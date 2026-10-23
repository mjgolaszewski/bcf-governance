"""Qualify existing regression detectors against isolated trusted-code faults."""
from __future__ import annotations

import inspect

import pytest

from bcf_governance.tooling import ci_graph_composition_operations as bindings
from bcf_governance.tooling import semantic_authority_contracts as contracts
from bcf_governance.tooling import semantic_operation_python as python_owner
from bcf_governance.tooling.ci_graph_errors import CIGraphError
from tests import test_lifecycle_public_entrypoint_bindings as cases


def _context(root):
    """Reuse the qualified fixture owners, with a distinct real Git repository."""
    root.mkdir()
    composition = cases.composition.__wrapped__()
    inputs = cases.binding_inputs.__wrapped__(composition, root)
    inputs = cases.operation_call_binding_inputs.__wrapped__(inputs, root)
    inputs = cases.reconstructed_binding_inputs.__wrapped__(inputs, composition, root)
    public = cases.public_reconstructed_binding_inputs.__wrapped__(inputs, composition)
    return cases.public_facade_inputs.__wrapped__(public, composition), composition


def _fault(patch, owner, name, search, replacement):
    """Change one exact actual function; never edit repository source bytes."""
    original = getattr(owner, name)
    source = inspect.getsource(original)
    assert source.count(search) == 1, 'fault target must identify exactly one trusted guard'
    namespace = dict(vars(owner))
    exec(compile(source.replace(search, replacement, 1), '<controlled-guard-fault>', 'exec'), namespace)
    patch.setattr(owner, name, namespace[name])
    return namespace[name]


def test_real_runtime_membership_regression_observes_removed_guard(tmp_path, monkeypatch):
    public, composition = _context(tmp_path / 'baseline')
    cases.test_public_facade_cannot_bind_an_unrelated_runtime_function(public, composition)
    public, composition = _context(tmp_path / 'mutant')
    with monkeypatch.context() as patch:
        _fault(patch, bindings, 'validate_public_operation_capture',
               '        if any(runtime_function not in relationship_roots[pair] for pair in relationships[operation]):',
               '        if False:')
        with pytest.raises(pytest.fail.Exception, match='DID NOT RAISE'):
            cases.test_public_facade_cannot_bind_an_unrelated_runtime_function(public, composition)


@pytest.mark.parametrize('path', ['facade.py', 'commands.py'], ids=['facade', 'catalog'])
def test_real_captured_source_regression_observes_unbound_reads(tmp_path, monkeypatch, path):
    public, _ = _context(tmp_path / 'baseline')
    with monkeypatch.context() as patch:
        cases.test_public_facade_uses_captured_source_after_reconstruction(public, patch, path)
    public, _ = _context(tmp_path / 'mutant')
    with monkeypatch.context() as patch:
        mutant = _fault(patch, python_owner, '_operation_source_text',
                        '    if source_subject is None:', '    if True:')
        patch.setattr(contracts, '_operation_source_text', mutant)
        with pytest.raises(CIGraphError, match='public operation source conformance'):
            cases.test_public_facade_uses_captured_source_after_reconstruction(public, patch, path)


def test_real_catalog_regression_observes_late_source_discovery(tmp_path, monkeypatch):
    catalog = 'import facade\nCOMMANDS = {"produce": facade.main, "unclassified": facade.main}\n'
    public, composition = _context(tmp_path / 'baseline')
    with monkeypatch.context() as patch:
        cases.test_public_catalog_changes_reject_before_full_discovery(public, composition, patch, catalog)
    public, composition = _context(tmp_path / 'mutant')
    with monkeypatch.context() as patch:
        _fault(patch, bindings, 'capture_public_operation_bindings',
               '    if classified != {(population, key) for population, entries in populations.items() for key in entries}:',
               '    if False:')
        with pytest.raises(pytest.fail.Exception,
                           match='full source discovered before deterministic public catalog rejection'):
            cases.test_public_catalog_changes_reject_before_full_discovery(public, composition, patch, catalog)
