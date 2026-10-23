"""Real installed facade consumers must enforce the authenticated source subject."""
from __future__ import annotations

import json
import subprocess
from pathlib import Path

import pytest

from tests.test_installed_evidence_storage import (
    _environment, installed_consumer, isolated_python,
)
from tests.test_lifecycle_public_entrypoint_bindings import (
    binding_inputs, composition, operation_call_binding_inputs,
    public_facade_inputs, public_reconstructed_binding_inputs,
    reconstructed_binding_inputs,
)


def _encode(value):
    """Transport fixture types explicitly, without importing the SDK or eval."""
    if isinstance(value, Path):
        return ['path', str(value)]
    if isinstance(value, dict):
        return ['dict', [[_encode(k), _encode(v)] for k, v in value.items()]]
    for kind in (list, tuple, frozenset, set):
        if isinstance(value, kind):
            return [kind.__name__, [_encode(v) for v in value]]
    assert value is None or isinstance(value, (str, int, float, bool)), type(value)
    return ['scalar', value]


CONSUMER = """import importlib.util, json, sys
from pathlib import Path
assert importlib.util.find_spec('bcf_governance') is None
consumer = Path.cwd()
sys.path.insert(0, str(consumer / 'scripts'))
from _bcf_runtime import ci_graph_composition as owner
from _bcf_runtime.ci_graph_errors import CIGraphError
assert Path(owner.__file__).resolve().is_relative_to(consumer)
def decode(row):
    kind, value = row
    if kind == 'scalar': return value
    if kind == 'path': return Path(value)
    if kind == 'dict': return {decode(k): decode(v) for k, v in value}
    return {'list': list, 'tuple': tuple, 'frozenset': frozenset, 'set': set}[kind](decode(v) for v in value)
inputs = decode(json.load(sys.stdin))
cause = sys.argv[1]
if cause != 'valid':
    source = inputs['repo_root'] / cause
    source.write_text(source.read_text() + '\\nsubstituted()\\n')
    try:
        owner.validate_reconstructed_lifecycle_bindings(**inputs)
    except CIGraphError as exc:
        assert str(exc) == ('lifecycle binding exact source reconstruction failed: '
                            'exact source bytes or executable mode differ from committed tree')
    else:
        raise AssertionError('installed source guard accepted moved ' + cause)
    print(json.dumps({'authority': False, 'rejected': cause}))
else:
    result = owner.validate_reconstructed_lifecycle_bindings(**inputs)
    assert result['authority'] is False and result['execution_qualified'] is False
    assert result['public_operation_bindings']['entrypoint_bindings'] == (
        ('example.produce.v1', 'facade.py::main', 'runtime.py::produce'),)
    print(json.dumps({'authority': False, 'facade_resolved': True}))
"""


@pytest.mark.parametrize('cause', ['valid', 'facade.py', 'commands.py'])
def test_installed_public_facade_uses_exact_captured_source(
    public_facade_inputs, installed_consumer, isolated_python, cause,
):
    inputs, _, _ = public_facade_inputs
    result = subprocess.run(
        [str(isolated_python), '-I', '-B', '-c', CONSUMER, cause],
        cwd=installed_consumer, env=_environment(), input=json.dumps(_encode(inputs)),
        capture_output=True, text=True, timeout=30,
    )
    assert result.returncode == 0, result.stdout + result.stderr
    observation = json.loads(result.stdout)
    assert observation['authority'] is False
    assert observation == ({'authority': False, 'facade_resolved': True}
                           if cause == 'valid' else {'authority': False, 'rejected': cause})
