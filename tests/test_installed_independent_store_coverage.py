"""SDK-absent consumers reconstruct source rather than trusting paired rows."""
import json
import subprocess

import pytest

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
 if mode!="erased":raise
 assert "Python source store coverage" in str(error),str(error)
else:
 if mode=="erased":raise AssertionError("installed erased store accepted")
print("installed-store-coverage-qualified")
'''


def invoke(tmp_path, installed_consumer, isolated_python, mode):
    root = tmp_path / "source"
    root.mkdir()
    facts = capture(root, "def work():\n    value={}\n    value['v']=1\n    return 1\nCOMMANDS={'work':work}\n")
    if mode == "erased":
        work(facts)["source_store_observations"] = []
    return subprocess.run([str(isolated_python), "-I", "-B", "-c", PROBE],
        cwd=installed_consumer, env=_environment(),
        input=json.dumps([str(root), payload(), facts, mode]), capture_output=True, text=True)


@pytest.mark.parametrize("mode", ["valid", "erased"])
def test_installed_independent_store_coverage(tmp_path, installed_consumer, isolated_python, mode):
    result = invoke(tmp_path, installed_consumer, isolated_python, mode)
    assert result.returncode == 0, result.stdout + result.stderr
    assert result.stdout.strip() == "installed-store-coverage-qualified"


def test_installed_control_detects_removed_guard(tmp_path, installed_consumer, isolated_python):
    path = installed_consumer / "scripts/_bcf_runtime/semantic_authority_operations.py"
    source = path.read_text()
    guard = "            reconcile_stores(context, symbol, postponed)\n"
    assert source.count(guard) == 1
    path.write_text(source.replace(guard, ""))
    result = invoke(tmp_path, installed_consumer, isolated_python, "erased")
    assert result.returncode == 1
    assert "installed erased store accepted" in result.stderr
