"""Installed consumers bind source callees before granting source traversal."""
import json
import subprocess

import pytest

from tests.test_independent_call_coverage import capture, payload, work
from tests.test_direct_call_binding import SOURCE
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
 if mode!="redirected":raise
 assert "Python source call binding" in str(error),str(error)
else:
 if mode=="redirected":raise AssertionError("installed redirected callee accepted")
print("installed-call-binding-qualified")
'''


def invoke(tmp_path, installed_consumer, isolated_python, mode):
    root = tmp_path / "source"
    root.mkdir()
    facts = capture(root, SOURCE if mode == "redirected" else "def work():\n    return 1\nCOMMANDS={'work':work}\n")
    if mode == "redirected":
        work(facts)['calls'][0]['called_symbol'] = 'runtime.py::safe'
    return subprocess.run([str(isolated_python), "-I", "-B", "-c", PROBE],
        cwd=installed_consumer, env=_environment(),
        input=json.dumps([str(root), payload(), facts, mode]), capture_output=True, text=True)


@pytest.mark.parametrize("mode", ["valid", "redirected"])
def test_installed_direct_source_binding(tmp_path, installed_consumer, isolated_python, mode):
    result = invoke(tmp_path, installed_consumer, isolated_python, mode)
    assert result.returncode == 0, result.stdout + result.stderr
    assert result.stdout.strip() == "installed-call-binding-qualified"


def test_installed_control_detects_removed_binding_guard(tmp_path, installed_consumer, isolated_python):
    path = installed_consumer / "scripts/_bcf_runtime/semantic_authority_operations.py"
    source = path.read_text()
    guard = '''                if (call.get("call_name") != call_name(node)
                        or (direct and call.get("called_symbol") != relative + "::" + node.func.id)):
                    raise SemanticAuthorityError("Python source call binding contradicts exact source")
'''
    assert source.count(guard) == 1
    path.write_text(source.replace(guard, ""))
    result = invoke(tmp_path, installed_consumer, isolated_python, "redirected")
    assert result.returncode == 1
    assert "installed redirected callee accepted" in result.stderr
