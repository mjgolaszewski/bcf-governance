"""Installed private runtimes retain independently discovered protocol obligations."""
import json
import subprocess

import pytest

from tests.test_implicit_source_coverage import facts_for
from tests.test_independent_call_coverage import payload, work
from tests.test_installed_evidence_storage import (
    _environment, installed_consumer as installed_consumer, isolated_python as isolated_python,
)

PROBE = '''import importlib.util,json,sys
from pathlib import Path
assert importlib.util.find_spec("bcf_governance") is None
sys.path.insert(0,str(Path("scripts").resolve()))
from _bcf_runtime import semantic_authority_operations as owner
from _bcf_runtime.semantic_authority_contracts import SemanticAuthorityError
root,policy,facts=json.load(sys.stdin)
try:owner._validate_operations(Path(root),policy,facts)
except SemanticAuthorityError as error:
 assert "Python source implicit protocol coverage" in str(error),str(error)
else:raise AssertionError("installed omitted implicit protocol accepted")
print("installed-implicit-source-qualified")
'''


def invoke(tmp_path, installed_consumer, isolated_python, mode):
    root = tmp_path / 'source'
    root.mkdir()
    facts = facts_for(root, mode, '1.0')
    work(facts)['calls'] = []
    return subprocess.run([str(isolated_python), '-I', '-B', '-c', PROBE],
        cwd=installed_consumer, env=_environment(),
        input=json.dumps([str(root), payload(), facts]), capture_output=True, text=True)


@pytest.mark.parametrize('mode', ['attribute_read', 'context_manager', 'async_context', 'await'])
def test_installed_implicit_source_coverage(tmp_path, installed_consumer, isolated_python, mode):
    result = invoke(tmp_path, installed_consumer, isolated_python, mode)
    assert result.returncode == 0, result.stdout + result.stderr
    assert result.stdout.strip() == 'installed-implicit-source-qualified'


def test_installed_control_detects_removed_coverage(tmp_path, installed_consumer, isolated_python):
    path = installed_consumer / 'scripts/_bcf_runtime/semantic_authority_operations.py'
    source = path.read_text()
    guard = '            reconcile_protocols(context, symbol, postponed)\n'
    assert source.count(guard) == 1
    path.write_text(source.replace(guard, ''))
    result = invoke(tmp_path, installed_consumer, isolated_python, 'attribute_read')
    assert result.returncode == 1
    assert 'installed omitted implicit protocol accepted' in result.stderr
