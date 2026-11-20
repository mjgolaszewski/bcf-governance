"""Fresh/repaired private release producers enforce selected executable ABI."""
import subprocess
import test_installed_evidence_storage as _fixture_owner
from test_installed_evidence_storage import _environment

installed_consumer = _fixture_owner.installed_consumer
isolated_python = _fixture_owner.isolated_python
PROBE = '''import importlib.util,sys,tempfile,platform
from pathlib import Path
from types import SimpleNamespace
assert importlib.util.find_spec("bcf_governance") is None
sys.path.insert(0,str(Path("scripts").resolve()))
from _bcf_runtime import release_runtime_verification as owner
from _bcf_runtime.ci_github_identity import GitHubControllerError
class NextBoundary(Exception):pass
def reached(*args):raise NextBoundary
owner._extract_sdist=reached
owner.verify_archive=lambda *_:None
owner.verify_wheelhouse=lambda *_:SimpleNamespace(python=platform.python_version(),platform="linux_x86_64",manifest_schema_version="1.1")
with tempfile.TemporaryDirectory() as directory:
 root=Path(directory)
 inputs={name:root/name for name in ["manifest","lock","wheel","sdist"]}
 for path in inputs.values():path.write_bytes(b"admission-only fixture")
 selected=root/"selected-python"
 selected.write_text("#!"+sys.executable+"\\nimport sys\\nsys.abiflags='t'\\nexec(compile(sys.argv[-1],'<actual-native-probe>','exec'))\\n")
 selected.chmod(0o700)
 def invoke(python,output):
  return owner.run_release_runtime_verification(selected_python=python,manifest_path=inputs["manifest"],lock_path=inputs["lock"],wheelhouse=root,wheel=inputs["wheel"],sdist=inputs["sdist"],output_dir=output)
 output=root/"bad-output"
 try:invoke(selected,output)
 except GitHubControllerError as error:assert "interpreter or platform" in str(error)
 except NextBoundary:raise AssertionError("installed incompatible native ABI admitted before allocation")
 else:raise AssertionError("installed incompatible native ABI unexpectedly completed")
 assert not output.exists()
 output=root/"actual-standard-output"
 try:invoke(Path(sys.executable),output)
 except NextBoundary:assert output.is_dir()
 else:raise AssertionError("actual standard native ABI did not reach next boundary")
print("installed-native-abi-admission-qualified")
'''


def test_installed_native_abi_rejection(installed_consumer, isolated_python):
    result = subprocess.run([str(isolated_python),"-I","-B","-c",PROBE],
        cwd=installed_consumer,env=_environment(),capture_output=True,text=True)
    assert result.returncode == 0, result.stdout + result.stderr
    assert result.stdout.strip() == "installed-native-abi-admission-qualified"


def test_installed_disabled_abi_guard_fails_named_control(installed_consumer, isolated_python):
    path = installed_consumer / "scripts/_bcf_runtime/release_runtime_verification.py"
    source = path.read_text()
    guard = "if not native_abi_matches:"
    assert source.count(guard) == 1
    path.write_text(source.replace(guard,"if False:"))
    result = subprocess.run([str(isolated_python),"-I","-B","-c",PROBE],
        cwd=installed_consumer,env=_environment(),capture_output=True,text=True)
    assert result.returncode == 1
    assert "installed incompatible native ABI admitted before allocation" in result.stderr
