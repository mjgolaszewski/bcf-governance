"""Qualify the actual installed structural reader with the source SDK absent."""
from pathlib import Path
import hashlib
import json
import subprocess

from test_installed_evidence_storage import (
    _environment, _record, installed_consumer, isolated_python,
)


ROOT = Path(__file__).resolve().parents[1]


def test_installed_backtrace_preserves_versioned_structural_scope(
    installed_consumer, isolated_python,
):
    data = {
        'backtrace': (ROOT / 'spec/phase0/release-train-backtrace.yml').read_text(),
        'schema_sha256': hashlib.sha256(
            (ROOT / 'schemas/release-train-backtrace.schema.json').read_bytes(),
        ).hexdigest(),
    }
    code = """import copy, hashlib, importlib.util, json, sys
from pathlib import Path
import yaml
assert importlib.util.find_spec('bcf_governance') is None
sys.path.insert(0, str(Path('scripts').resolve()))
from _bcf_runtime.governance_validation.ci_state_matrix import (
    CIStateMatrixError, validate_ci_state_matrix,
)
import _bcf_runtime.governance_validation.ci_state_matrix as owner
root = Path.cwd()
assert Path(owner.__file__).resolve().is_relative_to(root)
data = json.loads(sys.stdin.read())
schema = root / 'schemas/release-train-backtrace.schema.json'
assert hashlib.sha256(schema.read_bytes()).hexdigest() == data['schema_sha256']
path = root / 'spec/phase0/release-train-backtrace.yml'
path.parent.mkdir(parents=True, exist_ok=True)
payload = yaml.safe_load(data['backtrace'])
def write(value):
    path.write_text(yaml.safe_dump(value, sort_keys=False))
write(payload)
report = validate_ci_state_matrix(root, authored_only=True)
assert report['authority'] is False and report['execution_qualified'] is False
population = report['machine_backtrace']
assert population['backtrace_schema_version'] == 3
assert (population['supplemental_contracts'], population['supplemental_states'],
        population['supplemental_edges']) == (5, 34, 13)
rejected = []
for cause in ('undeclared-primitive', 'invented-root', 'empty-states'):
    value = copy.deepcopy(payload)
    block = value['release_version_projection_contract']
    if cause == 'undeclared-primitive':
        block['primitive'] = 'PRIM-UNDECLARED'
    elif cause == 'invented-root':
        value['invented_authority_contract'] = {'normative': True}
    else:
        block['states'] = []
    write(value)
    try:
        validate_ci_state_matrix(root, authored_only=True)
    except CIStateMatrixError as exc:
        expected = 'undeclared supplemental primitive' if cause == 'undeclared-primitive' else 'schema violation'
        assert expected in str(exc)
        rejected.append(cause)
    else:
        raise AssertionError('installed validator accepted ' + cause)
legacy = copy.deepcopy(payload)
legacy['document']['schema_version'] = 2
legacy['release_version_projection_contract']['primitive'] = 'PRIM-UNDECLARED'
write(legacy)
old = validate_ci_state_matrix(root, authored_only=True)
assert old['authority'] is False and old['execution_qualified'] is False
assert old['machine_backtrace']['backtrace_schema_version'] == 2
assert old['machine_backtrace']['supplemental_contracts'] == 0
print(json.dumps({'authority': False, 'version3_population': [5, 34, 13],
                  'rejected': rejected, 'legacy_scope_preserved': True,
                  'source_package_absent': True}, sort_keys=True))
"""
    result = subprocess.run(
        [str(isolated_python), '-I', '-c', code], cwd=installed_consumer,
        env=_environment(), input=json.dumps(data), capture_output=True, text=True,
    )
    assert result.returncode == 0, _record(result)
    assert json.loads(result.stdout) == {
        'authority': False, 'version3_population': [5, 34, 13],
        'rejected': ['undeclared-primitive', 'invented-root', 'empty-states'],
        'legacy_scope_preserved': True, 'source_package_absent': True,
    }
