"""SDK-absent runtime readers preserve explicit patch-subject ABI admission."""
import subprocess
import test_installed_evidence_storage as _fixture_owner
from test_installed_evidence_storage import _environment

installed_consumer = _fixture_owner.installed_consumer
isolated_python = _fixture_owner.isolated_python
PROBE = '''import importlib.util,sys,tempfile,hashlib
from pathlib import Path
assert importlib.util.find_spec("bcf_governance") is None
sys.path.insert(0,str(Path("scripts").resolve()))
import yaml
from _bcf_runtime.release_closure import verify_release_lock,ReleaseClosureError
with tempfile.TemporaryDirectory() as directory:
 root=Path(directory)
 digest=hashlib.sha256(b"wheel").hexdigest()
 lock=root/"requirements.lock"
 lock.write_text("example==1.0 --hash=sha256:"+digest+"\\n")
 value={"schema_version":"1.1","subject":{"python":"3.12.99","implementation":"CPython","operating_system":"ubuntu-24.04","platform":"linux_x86_64","wheel_platform":"manylinux_2_17_x86_64","abi":"cp312"},"resolution":{"lock_sha256":hashlib.sha256(lock.read_bytes()).hexdigest()},"wheels":{"example-1.0-py3-none-any.whl":digest}}
 manifest=root/"manifest.yml"
 manifest.write_text(yaml.safe_dump(value))
 assert verify_release_lock(manifest,lock).python=="3.12.99"
 value["subject"]["abi"]="cp311"
 manifest.write_text(yaml.safe_dump(value))
 try:verify_release_lock(manifest,lock)
 except ReleaseClosureError:pass
 else:raise AssertionError("installed incompatible runtime ABI accepted")
print("installed-runtime-subject-qualified")
'''


def test_installed_runtime_subject_admission(installed_consumer, isolated_python):
    result = subprocess.run([str(isolated_python), "-I", "-B", "-c", PROBE],
        cwd=installed_consumer, env=_environment(), capture_output=True, text=True)
    assert result.returncode == 0, result.stdout + result.stderr
    assert result.stdout.strip() == "installed-runtime-subject-qualified"


def test_installed_disabled_subject_guard_fails_named_control(installed_consumer, isolated_python):
    path = installed_consumer / "scripts/_bcf_runtime/release_closure.py"
    source = path.read_text()
    guard = "if subject != expected_subject:"
    assert source.count(guard) == 1
    path.write_text(source.replace(guard, "if False:"))
    result = subprocess.run([str(isolated_python), "-I", "-B", "-c", PROBE],
        cwd=installed_consumer, env=_environment(), capture_output=True, text=True)
    assert result.returncode == 1
    assert "installed incompatible runtime ABI accepted" in result.stderr
