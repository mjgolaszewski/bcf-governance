"""Fresh/repaired SDK-absent affected-proof subject controls."""
import subprocess
import test_installed_evidence_storage as _fixture_owner
from test_installed_evidence_storage import _environment

installed_consumer = _fixture_owner.installed_consumer
isolated_python = _fixture_owner.isolated_python
PROBE = 'import importlib.util,sys,tempfile,subprocess\nfrom pathlib import Path\nassert importlib.util.find_spec("bcf_governance") is None\nsys.path.insert(0,str(Path("scripts").resolve()))\nfrom _bcf_runtime import truth_receipts as owner\nwith tempfile.TemporaryDirectory() as directory:\n root=Path(directory)\n def git(*args):\n  return subprocess.check_output(["git","-c","core.hooksPath=/dev/null",*args],cwd=root,text=True).strip()\n git("init","-q");git("config","user.name","Fixture");git("config","user.email","fixture@example.invalid")\n (root/"source.py").write_text("VALUE=1\\n")\n git("add",".");git("commit","-qm","base")\n commit=git("rev-parse","HEAD")\n assert owner._changed_paths(root,commit)==[]\n git("update-index","--assume-unchanged","source.py")\n (root/"source.py").write_text("VALUE=2\\n")\n assert owner._changed_paths(root,commit)==["source.py"],"installed receipt hidden source omitted"\n assert owner._changed_paths(root,"f"*40) is None\nprint("installed-receipt-inert-impact-qualified")\n'
GUARD = 'set(paths) | state["working_versions"].keys()'

def test_installed_affected_subject_admission(installed_consumer, isolated_python):
    result = subprocess.run([str(isolated_python), "-I", "-B", "-c", PROBE],
                            cwd=installed_consumer, env=_environment(), capture_output=True, text=True)
    assert result.returncode == 0, result.stdout + result.stderr
    assert result.stdout.strip() == "installed-receipt-inert-impact-qualified"


def test_installed_removed_subject_guard_fails_named_control(installed_consumer, isolated_python):
    path = installed_consumer / "scripts/_bcf_runtime/truth_receipts.py"
    source = path.read_text()
    assert source.count(GUARD) == 1
    path.write_text(source.replace(GUARD, "set(paths)"))
    result = subprocess.run([str(isolated_python), "-I", "-B", "-c", PROBE],
                            cwd=installed_consumer, env=_environment(), capture_output=True, text=True)
    assert result.returncode == 1
    assert "installed receipt hidden source omitted" in result.stderr
