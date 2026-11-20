"""Fresh/repaired SDK-absent affected-proof subject controls."""
import subprocess
import test_installed_evidence_storage as _fixture_owner
from test_installed_evidence_storage import _environment

installed_consumer = _fixture_owner.installed_consumer
isolated_python = _fixture_owner.isolated_python
PROBE = 'import importlib.util,sys,tempfile,subprocess\nfrom pathlib import Path\nassert importlib.util.find_spec("bcf_governance") is None\nsys.path.insert(0,str(Path("scripts").resolve()))\nfrom _bcf_runtime import affected_proof_closure as owner\nfrom _bcf_runtime.evidence_execution import EvidenceError\nwith tempfile.TemporaryDirectory() as directory:\n root=Path(directory)\n def git(*args):\n  return subprocess.check_output(["git","-c","core.hooksPath=/dev/null",*args],cwd=root,text=True).strip()\n git("init","-q");git("config","user.name","Fixture");git("config","user.email","fixture@example.invalid")\n (root/"src.py").write_text("VALUE = 1\\n")\n git("add",".");git("commit","-qm","base")\n current={"commit_sha":git("rev-parse","HEAD"),"tree_sha":git("rev-parse","HEAD^{tree}")}\n model={"dependency_sets":{"source":["src.py"],"empty":["never/**"]},"execution_groups":{"test":{"producer":"test","claims":["app-valid"]}},"claims":{"app-valid":{"execution_group":"test","dependencies":{"subject":["source"],"detector":["empty"],"test_population":["empty"],"toolchain":["empty"],"trust":["empty"]}}}}\n def derive(prior):\n  return owner.derive_affected_proof_set(root,model,["app-valid"],current_subject=current,prior_subjects=prior)\n prior=[(current["commit_sha"],current["tree_sha"])]\n assert derive(prior)["classifications"][0]["classification"]=="demonstrably_unaffected"\n git("update-index","--assume-unchanged","src.py")\n (root/"src.py").write_text("VALUE = 2\\n")\n try:\n  derive(prior)\n except EvidenceError as error:\n  assert "affected proof current subject" in str(error)\n else:\n  raise AssertionError("installed dirty source falsely unaffected")\n (root/"src.py").write_text("VALUE = 1\\n")\n assert derive([("HEAD",None)])["classifications"][0]["classification"]=="ambiguous_requires_execution"\n assert derive([("f"*40,current["tree_sha"])])["classifications"][0]["classification"]=="demonstrably_unaffected"\nprint("installed-affected-subject-qualified")\n'
GUARD = '    if (identity.returncode or state["status_entries"]\n            or values != [subject["commit_sha"], subject["tree_sha"]]):'

def test_installed_affected_subject_admission(installed_consumer, isolated_python):
    result = subprocess.run([str(isolated_python), "-I", "-B", "-c", PROBE],
                            cwd=installed_consumer, env=_environment(), capture_output=True, text=True)
    assert result.returncode == 0, result.stdout + result.stderr
    assert result.stdout.strip() == "installed-affected-subject-qualified"


def test_installed_removed_subject_guard_fails_named_control(installed_consumer, isolated_python):
    path = installed_consumer / "scripts/_bcf_runtime/affected_proof_closure.py"
    source = path.read_text()
    assert source.count(GUARD) == 1
    path.write_text(source.replace(GUARD, "    if False:"))
    result = subprocess.run([str(isolated_python), "-I", "-B", "-c", PROBE],
                            cwd=installed_consumer, env=_environment(), capture_output=True, text=True)
    assert result.returncode == 1
    assert "installed dirty source falsely unaffected" in result.stderr
