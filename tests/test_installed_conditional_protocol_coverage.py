"""Installed consumers retain conditional protocol obligations and exact occurrences."""
import json
import subprocess

import pytest

from tests.conditional_protocol_support import erased
from tests.test_independent_call_coverage import capture, payload, work
from tests.test_installed_evidence_storage import (
    _environment, installed_consumer as installed_consumer, isolated_python as isolated_python,
)

PROBE = '''import importlib.util,json,sys
from pathlib import Path
assert importlib.util.find_spec("bcf_governance") is None
sys.path.insert(0,str(Path("scripts").resolve()))
from _bcf_runtime import semantic_authority_operations as owner
from _bcf_runtime.semantic_authority_contracts import SemanticAuthorityError
root,policy,facts,mode=json.load(sys.stdin)
try:owner._validate_operations(Path(root),policy,facts)
except SemanticAuthorityError as error:
 assert "Python source" in str(error) and "coverage" in str(error),str(error)
else:raise AssertionError("installed conditional identity omission accepted")
print("installed-conditional-protocol-qualified")
'''


def invoke(tmp_path, installed_consumer, isolated_python, mode):
    root = tmp_path / 'source'
    root.mkdir()
    if mode == 'occurrence':
        facts = capture(root, 'def helper():\n    return 1\ndef work():\n'
            '    return helper()\nCOMMANDS={"work":work}\n', '1.0')
        work(facts)['calls'][0]['call_contract']['occurrence'] = 100
    else:
        facts = erased(root, mode)
    return subprocess.run([str(isolated_python), '-I', '-B', '-c', PROBE],
        cwd=installed_consumer, env=_environment(),
        input=json.dumps([str(root), payload(), facts, mode]), capture_output=True, text=True)


@pytest.mark.parametrize('mode', ['truth','operator','for_iteration','dict_collection','subscript','format','occurrence'])
def test_installed_conditional_protocol_coverage(tmp_path, installed_consumer, isolated_python, mode):
    result = invoke(tmp_path, installed_consumer, isolated_python, mode)
    assert result.returncode == 0, result.stdout + result.stderr
    assert result.stdout.strip() == 'installed-conditional-protocol-qualified'


def test_installed_control_detects_removed_context_reconciliation(tmp_path, installed_consumer, isolated_python):
    path = installed_consumer / 'scripts/_bcf_runtime/semantic_authority_operations.py'
    source = path.read_text()
    guard = '            protocol_occurrences = reconcile_protocols(context, symbol, postponed)\n'
    assert source.count(guard) == 1
    path.write_text(source.replace(guard, ''))
    result = invoke(tmp_path, installed_consumer, isolated_python, 'truth')
    assert result.returncode == 1
    assert 'installed conditional identity omission accepted' in result.stderr
