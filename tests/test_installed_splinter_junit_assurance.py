"""SDK-absent fresh/repaired runtime retains raw JUnit proof qualification."""
import subprocess
import test_installed_evidence_storage as _fixture_owner
from test_installed_evidence_storage import _environment

installed_consumer = _fixture_owner.installed_consumer
isolated_python = _fixture_owner.isolated_python
PROBE = 'import importlib.util,sys,tempfile\nfrom pathlib import Path\nassert importlib.util.find_spec("bcf_governance") is None\nsys.path.insert(0,str(Path("scripts").resolve()))\nfrom _bcf_runtime.evidence_scheduling import compile_test_splinter_plan\nfrom _bcf_runtime.test_splinter_proofs import write_successful_proof\nwith tempfile.TemporaryDirectory() as directory:\n root=Path(directory)\n plan=compile_test_splinter_plan({"tests.one::test_a":"tests/one.py::test_a"},{},max_splinters=1,identity={"subject_commit":"a"*40,"subject_tree":"b"*40,"session":"a"*32,"policy_sha256":"c"*64,"producer":"test"})\n junit=root/"source.xml"\n junit.write_text(\'<testsuite><testcase classname="tests.one" name="test_a"><failure/></testcase></testsuite>\')\n try:\n  write_successful_proof(root/"proofs",plan=plan,splinter=plan["splinters"][0],toolchain_sha256="d"*64,junit=junit,observed_nodes=["tests.one::test_a"],execution_state=None,worktree_removed=True,source={"repository":"owner/repo","repository_id":"1","run_id":"2","run_attempt":"1","job":"evidence","shard":"0","session":"a"*32})\n except ValueError as error:\n  assert "JUnit" in str(error)\n else:\n  raise AssertionError("installed splinter failed JUnit accepted")\n assert not (root/"proofs").exists()\nprint("installed-splinter-junit-qualified")\n'

def test_installed_splinter_junit_rejection(installed_consumer, isolated_python):
    result = subprocess.run([str(isolated_python), "-I", "-B", "-c", PROBE],
                            cwd=installed_consumer, env=_environment(), capture_output=True, text=True)
    assert result.returncode == 0, result.stdout + result.stderr
    assert result.stdout.strip() == "installed-splinter-junit-qualified"


def test_installed_disabled_junit_guard_fails_named_control(installed_consumer, isolated_python):
    path = installed_consumer / "scripts/_bcf_runtime/test_splinter_proofs.py"
    source = path.read_text()
    guard = "if (nodes != sorted(expected)"
    assert source.count(guard) == 1
    path.write_text(source.replace(guard, "if False and (nodes != sorted(expected)"))
    result = subprocess.run([str(isolated_python), "-I", "-B", "-c", PROBE],
                            cwd=installed_consumer, env=_environment(), capture_output=True, text=True)
    assert result.returncode == 1
    assert "installed splinter failed JUnit accepted" in result.stderr
