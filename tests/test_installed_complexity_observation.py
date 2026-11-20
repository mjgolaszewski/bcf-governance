"""SDK-absent optional-tool observations remain advisory and detect score loss."""
import subprocess

import test_installed_evidence_storage as _fixture_owner
from test_installed_evidence_storage import _environment
import test_complexity_observation as _radon_fixture_owner

radon_tool = _radon_fixture_owner.radon_tool
installed_consumer = _fixture_owner.installed_consumer
isolated_python = _fixture_owner.isolated_python
PROBE = '''import importlib.metadata,importlib.util,subprocess,sys,tempfile
from pathlib import Path
assert importlib.util.find_spec("bcf_governance") is None
sys.path.insert(0,str(Path("scripts").resolve()))
sys.path.append(sys.argv[1])
from _bcf_runtime import operational_observations as owner
with tempfile.TemporaryDirectory() as directory:
 root=Path(directory)
 (root/"source.py").write_text("def f(x):\\n if x: return 1\\n return 0\\n")
 def git(*args):return subprocess.check_output(["git","-c","core.hooksPath=/dev/null",*args],cwd=root,text=True).strip()
 git("init","-q");git("add",".");git("-c","user.name=Fixture","-c","user.email=fixture@example.invalid","commit","-qm","source")
 subject={"commit_sha":git("rev-parse","HEAD"),"tree_sha":git("rev-parse","HEAD^{tree}")}
 actual_version=importlib.metadata.version
 def missing(name):raise importlib.metadata.PackageNotFoundError(name)
 importlib.metadata.version=missing
 report=owner.python_complexity_observation(root,subject=subject)
 assert report["status"]=="incomplete" and report["functions"]==[],"installed missing calculator became clean"
 importlib.metadata.version=actual_version
 report=owner.python_complexity_observation(root,subject=subject)
 assert report["status"]=="complete",report
 assert [row["complexity"] for row in report["functions"]]==[2],"installed real branch complexity was lost"
 assert report["authority"] is report["execution_qualified"] is False
print("installed-complexity-observation-qualified")
'''


def invoke(installed_consumer, isolated_python, radon_tool):
    tools = radon_tool
    assert tools.is_dir()
    return subprocess.run([str(isolated_python), "-I", "-B", "-c", PROBE, str(tools)],
        cwd=installed_consumer, env=_environment(), capture_output=True, text=True)


def test_installed_missing_and_real_calculator(installed_consumer, isolated_python, radon_tool):
    result = invoke(installed_consumer, isolated_python, radon_tool)
    assert result.returncode == 0, result.stdout + result.stderr
    assert result.stdout.strip() == "installed-complexity-observation-qualified"


def test_installed_score_comparison_control_detects_loss(installed_consumer, isolated_python, radon_tool):
    path = installed_consumer / "scripts/_bcf_runtime/operational_observations.py"
    source = path.read_text()
    assignment = '"complexity": roots[0].complexity,'
    assert source.count(assignment) == 1
    path.write_text(source.replace(assignment, '"complexity": 1,'))
    result = invoke(installed_consumer, isolated_python, radon_tool)
    assert result.returncode == 1
    assert "installed real branch complexity was lost" in result.stderr
