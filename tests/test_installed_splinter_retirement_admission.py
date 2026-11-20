"""SDK-absent consumers preserve exact boolean retirement admission."""
import subprocess
import test_installed_evidence_storage as _fixture_owner
from test_installed_evidence_storage import _environment

installed_consumer = _fixture_owner.installed_consumer
isolated_python = _fixture_owner.isolated_python
PROBE = '''import importlib.util,sys,tempfile
from pathlib import Path
assert importlib.util.find_spec("bcf_governance") is None
sys.path.insert(0,str(Path("scripts").resolve()))
from _bcf_runtime.evidence_scheduling import compile_test_splinter_plan
from _bcf_runtime.test_splinter_proofs import write_successful_proof
with tempfile.TemporaryDirectory() as directory:
 root=Path(directory)
 plan=compile_test_splinter_plan({"tests.one::test_a":"tests/one.py::test_a"},{},max_splinters=1,identity={"subject_commit":"a"*40,"subject_tree":"b"*40,"session":"s","policy_sha256":"c"*64,"producer":"test"})
 junit=root/"source.xml"
 junit.write_text('<testsuite><testcase classname="tests.one" name="test_a"/></testsuite>')
 try:
  write_successful_proof(root/"proofs",plan=plan,splinter=plan["splinters"][0],toolchain_sha256="d"*64,junit=junit,observed_nodes=["tests.one::test_a"],execution_state=None,worktree_removed=1,source={"repository":"owner/repo","repository_id":"1","run_id":"2","run_attempt":"1","job":"evidence","shard":"0","session":"s"})
 except ValueError as error:
  assert "proof" in str(error)
 else:
  raise AssertionError("installed nonboolean removal accepted")
 assert not (root/"proofs").exists()
print("installed-splinter-retirement-qualified")
'''


def test_installed_splinter_retirement_rejection(installed_consumer, isolated_python):
    result = subprocess.run([str(isolated_python), "-I", "-B", "-c", PROBE],
        cwd=installed_consumer, env=_environment(), capture_output=True, text=True)
    assert result.returncode == 0, result.stdout + result.stderr
    assert result.stdout.strip() == "installed-splinter-retirement-qualified"


def test_installed_disabled_retirement_guard_fails_named_control(installed_consumer, isolated_python):
    path = installed_consumer / "scripts/_bcf_runtime/test_splinter_proofs.py"
    source = path.read_text()
    guard = "or worktree_removed is not True"
    assert source.count(guard) == 1
    path.write_text(source.replace(guard, "or not worktree_removed"))
    result = subprocess.run([str(isolated_python), "-I", "-B", "-c", PROBE],
        cwd=installed_consumer, env=_environment(), capture_output=True, text=True)
    assert result.returncode == 1
    assert "installed nonboolean removal accepted" in result.stderr
