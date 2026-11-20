"""Installed private consumers independently reject erased source call rows."""
import inspect
import subprocess

import pytest

import test_independent_call_coverage as cases
import test_installed_evidence_storage as fixtures

installed_consumer = fixtures.installed_consumer
isolated_python = fixtures.isolated_python
PROBE = '''import importlib.util,shutil,sys
from pathlib import Path
assert importlib.util.find_spec("bcf_governance") is None
sys.path.insert(0,str(Path("scripts").resolve()))
from _bcf_runtime import semantic_authority_operations as owner
from _bcf_runtime.semantic_authority_contracts import SemanticAuthorityError
from _bcf_runtime.semantic_ownership_inventory import discover_python_source
from _bcf_runtime.ci_github_authority import packaged_repo_root
''' + inspect.getsource(cases.payload) + '''
root=Path("call-coverage-fixture").resolve();root.mkdir()
(root/"schemas").mkdir()
shutil.copy2(packaged_repo_root()/"schemas/application-operations.schema.json",root/"schemas/application-operations.schema.json")
source="def helper():\\n    return 1\\ndef work():\\n    return helper()\\nCOMMANDS={'work':work}\\n"
(root/"runtime.py").write_bytes(source.encode())
facts=discover_python_source(root,files=[root/"runtime.py"],call_contracts_version="1.0")
assert owner._validate_operations(root,payload(),facts)
entry=next(row for row in facts["functions"] if row["symbol"]=="runtime.py::work")
entry["calls"]=[]
try:owner._validate_operations(root,payload(),facts)
except SemanticAuthorityError as error:assert "Python source call coverage" in str(error),str(error)
else:raise AssertionError("installed omitted source call accepted")
print("installed-independent-call-coverage-qualified")
'''


def invoke(installed_consumer, isolated_python):
    return subprocess.run([str(isolated_python), "-I", "-B", "-c", PROBE],
        cwd=installed_consumer, env=fixtures._environment(), capture_output=True, text=True)


def test_installed_source_call_coverage(installed_consumer, isolated_python):
    result = invoke(installed_consumer, isolated_python)
    assert result.returncode == 0, result.stdout + result.stderr
    assert result.stdout.strip() == "installed-independent-call-coverage-qualified"


@pytest.mark.parametrize("defect", ["guard", "counter"])
def test_installed_independent_detector_fails_removed_guard(installed_consumer, isolated_python, defect):
    path = installed_consumer / "scripts/_bcf_runtime/semantic_authority_operations.py"
    source = path.read_text()
    needle = ("    _validate_python_call_source_coverage(repo_root, inventory, functions, source_subject)\n"
              if defect == "guard" else "if Counter(actual) != Counter(expected.keys()):")
    assert source.count(needle) == 1
    path.write_text(source.replace(needle, "" if defect == "guard" else "if False:"))
    result = invoke(installed_consumer, isolated_python)
    assert result.returncode == 1
    assert "installed omitted source call accepted" in result.stderr
