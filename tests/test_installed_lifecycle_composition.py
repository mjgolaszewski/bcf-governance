"""Exercise the existing composition contract through source-absent installs."""
from __future__ import annotations

from dataclasses import asdict
import json
import subprocess

from test_ci_graph_composition import composition
from test_installed_evidence_storage import (
    _environment, _record, installed_consumer, isolated_python,
)

from bcf_governance.tooling.ci_graph_composition import compile_lifecycle_composition


def test_installed_composition_preserves_population_and_exclusion_controls(
    installed_consumer, isolated_python, composition,
):
    data = {
        key: composition[key]
        for key in ('payload', 'schema', 'expected_source', 'expected_populations')
    }
    data['relationships'] = list(composition['expected_relationships'].items())
    data['effects'] = sorted(composition['expected_effects'])
    graph = composition['compiled_graph']
    data['graph_sha256'] = graph.graph_sha256
    data['edges'] = [asdict(edge) for edge in graph.edge_contracts]
    expected = compile_lifecycle_composition(**composition)
    code = """import copy, importlib.util, json, sys
from pathlib import Path
from types import SimpleNamespace
assert importlib.util.find_spec('bcf_governance') is None
sys.path.insert(0, str(Path('scripts').resolve()))
from _bcf_runtime.ci_graph_composition import compile_lifecycle_composition
from _bcf_runtime.ci_graph_edges import EdgeContract
from _bcf_runtime.ci_graph_errors import CIGraphError
import _bcf_runtime.ci_graph_composition_populations as owner
assert Path(owner.__file__).resolve().is_relative_to(Path.cwd())
data = json.loads(sys.argv[1])
data['expected_relationships'] = {tuple(k): v for k, v in data.pop('relationships')}
data['expected_effects'] = frozenset(tuple(v) for v in data.pop('effects'))
data['expected_populations'] = {k: tuple(v) for k,v in data['expected_populations'].items()}
data['compiled_graph'] = SimpleNamespace(
    graph_sha256=data.pop('graph_sha256'),
    edge_contracts=tuple(EdgeContract(**v) for v in data.pop('edges')),
)
actual = compile_lifecycle_composition(**data)
rejected = []
for cause in ('omitted-edge-and-tests', 'false-exclusion'):
    mutated = copy.deepcopy(data)
    rows = mutated['payload']['relationships']
    if cause == 'omitted-edge-and-tests':
        rows.pop(0)
    else:
        rows[0].update(contract=None, exclusion='no-structural-path')
    try:
        compile_lifecycle_composition(**mutated)
    except CIGraphError as exc:
        assert ('population' if cause == 'omitted-edge-and-tests' else 'exclusion') in str(exc)
        rejected.append(cause)
    else:
        raise AssertionError('installed compiler accepted ' + cause)
print(json.dumps({'result': actual, 'rejected': rejected}, sort_keys=True))
"""
    result = subprocess.run(
        [str(isolated_python), '-I', '-c', code, json.dumps(data)],
        cwd=installed_consumer, env=_environment(), capture_output=True, text=True,
    )
    assert result.returncode == 0, _record(result)
    assert json.loads(result.stdout) == {
        'result': expected,
        'rejected': ['omitted-edge-and-tests', 'false-exclusion'],
    }
