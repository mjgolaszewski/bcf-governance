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
