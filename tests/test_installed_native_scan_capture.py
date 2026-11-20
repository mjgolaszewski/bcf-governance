"""SDK-absent consumers use existing native custody and exact input admission."""
import inspect
import subprocess

import test_installed_evidence_storage as _fixture_owner
from test_installed_evidence_storage import _environment
from test_native_scan_capture import Case

installed_consumer = _fixture_owner.installed_consumer
isolated_python = _fixture_owner.isolated_python
PRELUDE = '''import importlib.util,hashlib,json,sys,tempfile,fcntl
from contextlib import contextmanager
from datetime import datetime,timedelta,timezone
from pathlib import Path
assert importlib.util.find_spec("bcf_governance") is None
sys.path.insert(0,str(Path("scripts").resolve()))
from _bcf_runtime import dependency_assurance as owner
from _bcf_runtime.evidence_process_supervisor import native_lease_custody
def digest(data):return hashlib.sha256(data).hexdigest()
'''
ENDING = '''
with tempfile.TemporaryDirectory() as directory:
 root=Path(directory)
 positive=root/"positive";positive.mkdir()
 case=Case(positive)
 result=case.invoke()
 assert result["status"]=="no_findings",result
 assert case.seen.read_bytes()==case.arguments["sbom_bytes"]
 assert result["authority"] is result["execution_qualified"] is result["security_qualified"] is False
 refused=root/"refused";refused.mkdir()
 case=Case(refused)
 case.arguments["expected_inventory"]=(("pkg:rpm/example/other@1","other","1"),)
 try:case.invoke()
 except owner.DependencyAssuranceError:pass
 else:raise AssertionError("installed unmatched native inventory executed")
 assert not case.seen.exists() and not case.arguments["output_dir"].exists()
print("installed-native-scan-capture-qualified")
'''


def invoke(installed_consumer, isolated_python):
    probe = PRELUDE + inspect.getsource(Case) + ENDING
    return subprocess.run([str(isolated_python), "-I", "-B", "-c", probe],
        cwd=installed_consumer, env=_environment(), capture_output=True, text=True)


def test_installed_exact_native_input_and_owner(installed_consumer, isolated_python):
    result = invoke(installed_consumer, isolated_python)
    assert result.returncode == 0, result.stdout + result.stderr
    assert result.stdout.strip() == "installed-native-scan-capture-qualified"


def test_installed_removed_inventory_predicate_fails_named_control(installed_consumer, isolated_python):
    path = installed_consumer / "scripts/_bcf_runtime/dependency_assurance.py"
    source = path.read_text()
    guard = "if sorted(observed) != sorted(wanted):"
    assert source.count(guard) == 1
    path.write_text(source.replace(guard, "if False:"))
    result = invoke(installed_consumer, isolated_python)
    assert result.returncode == 1
    assert "installed unmatched native inventory executed" in result.stderr
