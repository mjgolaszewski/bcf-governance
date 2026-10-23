"""Public declaration identity must remain distinct from runtime function roots."""
from __future__ import annotations

import copy
import hashlib
import subprocess

import pytest
import yaml

from bcf_governance.tooling.ci_graph_composition import (
    compile_lifecycle_composition,
    validate_reconstructed_lifecycle_bindings,
)
from bcf_governance.tooling.semantic_operation_effects import source_operation_call_population
from bcf_governance.tooling.semantic_ownership_inventory import (
    discover_python_source,
    resolve_python_imports,
)
from tests.test_ci_graph_composition import (
    binding_inputs,
    composition,
    operation_call_binding_inputs,
    public_reconstructed_binding_inputs,
    reconstructed_binding_inputs,
)


def _git(root, *args):
    return subprocess.run(
        ['git', *args], cwd=root, check=True, capture_output=True, text=True,
    ).stdout.strip()


def _capture_subject(inputs, composition):
    root = inputs['repo_root']
    _git(root, 'add', '.')
    _git(root, 'commit', '-qm', 'public facade source')
    subject = dict(commit_sha=_git(root, 'rev-parse', 'HEAD'),
                   tree_sha=_git(root, 'rev-parse', 'HEAD^{tree}'))
    identity = dict(inputs['expected_source'], **subject)
    composition['expected_source'] = composition['payload']['source'] = identity
    inputs['expected_source'] = identity
    inputs['compiled'] = compile_lifecycle_composition(**composition)
    inventory = resolve_python_imports(root, discover_python_source(
        root, source_subject=subject, call_contracts_version='1.0',
        initialization_contracts_version='1.0',
    ))
    pair = ('release', 'build', 'verify')
    inputs['required_operation_calls'] = {pair: {
        symbol: source_operation_call_population(symbol, inventory, include_initialization=True)
        for symbol in inputs['required_operation_calls'][pair]
    }}
    inputs['operation_policy_subject'] = subject
    return subject


@pytest.fixture
def public_facade_inputs(public_reconstructed_binding_inputs, composition):
    inputs, policy, _ = public_reconstructed_binding_inputs
    root = inputs['repo_root']
    source = root / 'runtime.py'
    source.write_text(source.read_text().replace('\nCOMMANDS = {"produce": produce}\n', '\n'))
    (root / 'facade.py').write_text('from runtime import produce as main\n')
    (root / 'commands.py').write_text('import facade\nCOMMANDS = {"produce": facade.main}\n')
    payload = yaml.safe_load(policy.read_text())
    payload['populations'][0]['source'] = 'commands.py'
    payload['operations'][0]['entrypoints'] = ['facade.py::main']
    policy.write_text(yaml.safe_dump(payload))
    _capture_subject(inputs, composition)
    return inputs, policy, hashlib.sha256(policy.read_bytes()).hexdigest()


def test_public_facade_resolves_to_real_lifecycle_function(public_facade_inputs):
    inputs, policy, digest = public_facade_inputs
    before = copy.deepcopy(inputs)
    result = validate_reconstructed_lifecycle_bindings(**inputs)
    observation = result['public_operation_bindings']
    assert observation['operations_checked'] == 1
    assert observation['registry_sha256'] == digest
    assert observation['entrypoint_bindings'] == (
        ('example.produce.v1', 'facade.py::main', 'runtime.py::produce'),
    )
    assert observation['operations'][0][:3] == (
        'example.produce.v1', 'query', 'facade.py::main',
    )
    assert result['operation_call_populations_checked'] == 3
    assert result['authority'] is False
    assert result['execution_qualified'] is False
    assert inputs == before


def test_existing_direct_public_function_keeps_identity(public_reconstructed_binding_inputs):
    inputs, policy, digest = public_reconstructed_binding_inputs
    result = validate_reconstructed_lifecycle_bindings(**inputs)
    observation = result['public_operation_bindings']
    assert observation['registry_sha256'] == digest
    assert observation['operations'][0][:3] == (
        'example.produce.v1', 'query', 'runtime.py::produce',
    )
    assert result['authority'] is False
    assert result['execution_qualified'] is False
# Append to the bounded regression only after authenticating its actual RED.


def test_public_facade_keeps_protected_policy_and_runtime_subjects_distinct(
    public_facade_inputs, composition,
):
    inputs, _, _ = public_facade_inputs
    protected = copy.deepcopy(inputs['operation_policy_subject'])
    # Both functions are genuine existing relationship roots; the public policy
    # keeps its declared facade identity while the runtime alias changes.
    path = inputs['repo_root'] / 'facade.py'
    path.write_text('from runtime import verify as main\n')
    runtime = _capture_subject(inputs, composition)
    inputs['operation_policy_subject'] = protected
    result = validate_reconstructed_lifecycle_bindings(**inputs)
    assert protected != runtime
    assert result['public_operation_bindings']['policy_subject'] == protected
    assert result['source_reconstruction']['subject'] == runtime
    assert result['public_operation_bindings']['entrypoint_bindings'] == (
        ('example.produce.v1', 'facade.py::main', 'runtime.py::verify'),
    )
    assert result['authority'] is False


@pytest.mark.parametrize('catalog', [
    'import facade\nCOMMANDS = {}\n',
    'import facade\nCOMMANDS = {"produce": facade.main, "unclassified": facade.main}\n',
])
def test_public_catalog_changes_reject_before_full_discovery(
    public_facade_inputs, composition, monkeypatch, catalog,
):
    from bcf_governance.tooling import semantic_ownership_inventory as source
    from bcf_governance.tooling.ci_graph_errors import CIGraphError

    inputs, _, _ = public_facade_inputs
    protected = copy.deepcopy(inputs['operation_policy_subject'])
    (inputs['repo_root'] / 'commands.py').write_text(catalog)
    _capture_subject(inputs, composition)
    inputs['operation_policy_subject'] = protected
    monkeypatch.setattr(source, 'discover_python_source', lambda *a, **kw: pytest.fail(
        'full source discovered before deterministic public catalog rejection',
    ))
    with pytest.raises(CIGraphError):
        validate_reconstructed_lifecycle_bindings(**inputs)


@pytest.mark.parametrize('path', ['facade.py', 'commands.py'])
def test_public_facade_rejects_workspace_movement_at_capture(public_facade_inputs, path):
    from bcf_governance.tooling.ci_graph_errors import CIGraphError

    inputs, _, _ = public_facade_inputs
    source = inputs['repo_root'] / path
    source.write_text(source.read_text() + '\nsubstituted()\n')
    with pytest.raises(CIGraphError):
        validate_reconstructed_lifecycle_bindings(**inputs)


def test_public_facade_cannot_bind_an_unrelated_runtime_function(public_facade_inputs, composition):
    from bcf_governance.tooling.ci_graph_errors import CIGraphError

    inputs, _, _ = public_facade_inputs
    (inputs['repo_root'] / 'facade.py').write_text('from runtime import declared_port as main\n')
    _capture_subject(inputs, composition)
    with pytest.raises(CIGraphError, match='lifecycle relationship'):
        validate_reconstructed_lifecycle_bindings(**inputs)


@pytest.mark.parametrize('path', ['facade.py', 'commands.py'])
def test_public_facade_uses_captured_source_after_reconstruction(
    public_facade_inputs, monkeypatch, path,
):
    from bcf_governance.tooling import semantic_ownership_inventory as source

    inputs, _, _ = public_facade_inputs
    actual = source.resolve_python_imports
    def substitute_after_capture(*args, **kwargs):
        inventory = actual(*args, **kwargs)
        (inputs['repo_root'] / path).write_text('raise RuntimeError("must not execute")\n')
        return inventory
    monkeypatch.setattr(source, 'resolve_python_imports', substitute_after_capture)
    result = validate_reconstructed_lifecycle_bindings(**inputs)
    assert result['public_operation_bindings']['entrypoint_bindings'] == (
        ('example.produce.v1', 'facade.py::main', 'runtime.py::produce'),
    )
    assert result['authority'] is False


@pytest.mark.parametrize('facade', [
    'from runtime import missing as main\n',
    'main = lambda: b"unbound"\n',
    'from facade import main\n',
    'from runtime import produce as main\nmain = lambda: b"shadow"\n',
    'from runtime import produce as main\nif True:\n    main = lambda: b"shadow"\n',
])
def test_public_facade_rejects_missing_dynamic_or_shadowed_binding(
    public_facade_inputs, composition, facade,
):
    from bcf_governance.tooling.ci_graph_errors import CIGraphError

    inputs, _, _ = public_facade_inputs
    (inputs['repo_root'] / 'facade.py').write_text(facade)
    _capture_subject(inputs, composition)
    with pytest.raises(CIGraphError, match='public operation'):
        validate_reconstructed_lifecycle_bindings(**inputs)
