"""SDK-absent archive/rootfs binding and missing-hash-guard detector."""
import inspect
import subprocess

import test_installed_evidence_storage as fixtures
import test_native_archive_subject as cases

installed_consumer = fixtures.installed_consumer
isolated_python = fixtures.isolated_python
PROBE = '''import gzip,hashlib,io,json,sys,tarfile
from pathlib import Path
assert __import__("importlib.util").util.find_spec("bcf_governance") is None
ROOT=Path.cwd()
sys.path.insert(0,str(ROOT/"scripts"))
from _bcf_runtime import dependency_assurance as owner
''' + inspect.getsource(cases.Case) + '''
case=Case()
result=case.invoke()
assert len(result["layers"])==2 and result["authority"] is result["security_qualified"] is False
case.config["rootfs"]["diff_ids"][0]="sha256:"+"0"*64
try:case.invoke()
except owner.DependencyAssuranceError:pass
else:raise AssertionError("installed substituted rootfs identity was accepted")
print("installed-native-archive-qualified")
'''


def invoke(installed_consumer, isolated_python):
    return subprocess.run([str(isolated_python), "-I", "-B", "-c", PROBE],
        cwd=installed_consumer, env=fixtures._environment(), capture_output=True, text=True)


def test_installed_archive_binding_and_substitution(installed_consumer, isolated_python):
    result = invoke(installed_consumer, isolated_python)
    assert result.returncode == 0, result.stdout + result.stderr
    assert result.stdout.strip() == "installed-native-archive-qualified"


def test_installed_hash_guard_control_detects_weakened_consumer(installed_consumer, isolated_python):
    path = installed_consumer / "scripts/_bcf_runtime/dependency_assurance.py"
    source = path.read_text()
    guard = 'if "sha256:" + hashed.hexdigest() != diff:'
    assert source.count(guard) == 1
    path.write_text(source.replace(guard, "if False:"))
    result = invoke(installed_consumer, isolated_python)
    assert result.returncode == 1
    assert "installed substituted rootfs identity was accepted" in result.stderr
