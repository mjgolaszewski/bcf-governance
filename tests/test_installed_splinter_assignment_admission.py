"""Fresh and repaired SDK-absent consumers enforce exact splinter placement."""
import subprocess
import test_installed_evidence_storage as _fixture_owner
from test_installed_evidence_storage import _environment

installed_consumer = _fixture_owner.installed_consumer
isolated_python = _fixture_owner.isolated_python
PROBE = '''import importlib.util,sys
from pathlib import Path
assert importlib.util.find_spec("bcf_governance") is None
sys.path.insert(0,str(Path("scripts").resolve()))
from _bcf_runtime.evidence_scheduling import compile_test_splinter_plan,validate_test_splinter_results
plan=compile_test_splinter_plan({"tests.one::test_a":"tests/one.py::test_a","tests.two::test_b":"tests/two.py::test_b"},{},max_splinters=2,identity={"subject_commit":"a"*40,"subject_tree":"b"*40,"session":"s","policy_sha256":"c"*64,"producer":"test"})
validate_test_splinter_results(plan,{row["id"]:row["nodes"] for row in plan["splinters"]})
try:
 validate_test_splinter_results(plan,{"splinter-0":plan["splinters"][1]["nodes"],"splinter-1":plan["splinters"][0]["nodes"]})
except ValueError as error:
 assert "assignment" in str(error)
else:
 raise AssertionError("installed swapped splinter results accepted")
print("installed-splinter-assignment-qualified")
'''


def test_installed_splinter_assignment_rejection(installed_consumer, isolated_python):
    result = subprocess.run([str(isolated_python), "-I", "-B", "-c", PROBE],
        cwd=installed_consumer, env=_environment(), capture_output=True, text=True)
    assert result.returncode == 0, result.stdout + result.stderr
    assert result.stdout.strip() == "installed-splinter-assignment-qualified"


def test_installed_disabled_assignment_guard_fails_named_control(installed_consumer, isolated_python):
    path = installed_consumer / "scripts/_bcf_runtime/evidence_scheduling.py"
    source = path.read_text()
    guard = 'if sorted(captured[splinter["id"]]) != splinter["nodes"]:'
    assert source.count(guard) == 1
    path.write_text(source.replace(guard, 'if False:'))
    result = subprocess.run([str(isolated_python), "-I", "-B", "-c", PROBE],
        cwd=installed_consumer, env=_environment(), capture_output=True, text=True)
    assert result.returncode == 1
    assert "installed swapped splinter results accepted" in result.stderr
