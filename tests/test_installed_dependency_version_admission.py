"""SDK-absent inventory consumers enforce actual declared dependency versions."""
import subprocess
import test_installed_evidence_storage as _fixture_owner
from test_installed_evidence_storage import _environment

installed_consumer = _fixture_owner.installed_consumer
isolated_python = _fixture_owner.isolated_python
PROBE = '''import importlib.util,sys,tempfile
from pathlib import Path
from types import SimpleNamespace
assert importlib.util.find_spec("bcf_governance") is None
sys.path.insert(0,str(Path("scripts").resolve()))
from _bcf_runtime import dependency_assurance as owner
with tempfile.TemporaryDirectory() as directory:
 root=Path(directory)
 (root/"pyproject.toml").write_text('[build-system]\\nrequires=["example>=2"]\\n')
 (root/"requirements-governance.txt").write_text("")
 row=SimpleNamespace(metadata={"Name":"example"},version="1.0",requires=[])
 owner.metadata.distributions=lambda:iter([row])
 try:owner.collect_installed_inventory(root)
 except owner.DependencyAssuranceError as error:
  assert "violates declared requirement" in str(error)
 else:raise AssertionError("installed incompatible dependency version admitted")
 row.version="2.0"
 assert owner.collect_installed_inventory(root).components[0]["version"]=="2.0"
print("installed-dependency-version-qualified")
'''


def test_installed_dependency_version_rejection(installed_consumer, isolated_python):
    result = subprocess.run([str(isolated_python),"-I","-B","-c",PROBE],
        cwd=installed_consumer,env=_environment(),capture_output=True,text=True)
    assert result.returncode == 0, result.stdout + result.stderr
    assert result.stdout.strip() == "installed-dependency-version-qualified"


def test_installed_removed_version_predicate_fails_named_control(installed_consumer, isolated_python):
    path = installed_consumer / "scripts/_bcf_runtime/dependency_assurance.py"
    source = path.read_text()
    guard = "if not requirement.specifier.contains(installed_version, prereleases=True):"
    assert source.count(guard) == 1
    path.write_text(source.replace(guard,"if False:"))
    result = subprocess.run([str(isolated_python),"-I","-B","-c",PROBE],
        cwd=installed_consumer,env=_environment(),capture_output=True,text=True)
    assert result.returncode == 1
    assert "installed incompatible dependency version admitted" in result.stderr
