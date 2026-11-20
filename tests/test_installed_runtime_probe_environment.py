"""Private installed producers close the very first native subprocess environment."""
import subprocess

import test_installed_evidence_storage as _fixture_owner
from test_installed_evidence_storage import _environment

installed_consumer = _fixture_owner.installed_consumer
isolated_python = _fixture_owner.isolated_python
PROBE = '''import importlib.util,json,os,sys,tempfile
from pathlib import Path
from types import SimpleNamespace
assert importlib.util.find_spec("bcf_governance") is None
sys.path.insert(0,str(Path("scripts").resolve()))
from _bcf_runtime import release_runtime_verification as owner
class NextBoundary(Exception):pass
def reached(*args):raise NextBoundary
owner._extract_sdist=reached
owner.verify_archive=lambda *_:None
with tempfile.TemporaryDirectory() as directory:
 root=Path(directory)
 paths={name:root/name for name in ["manifest","lock","wheel","sdist"]}
 for path in paths.values():path.write_bytes(b"admission-only fixture")
 capture=root/"child.json"
 selected=root/"selected-python"
 selected.write_text("#!"+sys.executable+" -I\\nimport json,os,sys\\nwith open("+repr(str(capture))+",'w') as stream:json.dump({'env':dict(os.environ),'cwd':os.getcwd()},stream)\\nexec(compile(sys.argv[-1],'<actual-selected-probe>','exec'))\\n")
 selected.chmod(0o700)
 for name in ["GITHUB_TOKEN","ACTIONS_RUNTIME_TOKEN","AWS_SECRET_ACCESS_KEY","SSH_AUTH_SOCK","PYTHONPATH","PYTHONHOME","LD_PRELOAD","LD_LIBRARY_PATH","NODE_OPTIONS","BCF_RELEASE_SDIST_PORTABLE_TEST"]:
  os.environ[name]=str(root/"must-not-inherit")
 for version in ["1.0","1.1"]:
  owner.verify_wheelhouse=lambda *_:SimpleNamespace(python=".".join(str(v) for v in sys.version_info[:3]),platform="linux_x86_64",manifest_schema_version=version)
  output=root/("output-"+version)
  try:owner.run_release_runtime_verification(selected_python=selected,manifest_path=paths["manifest"],lock_path=paths["lock"],wheelhouse=root,wheel=paths["wheel"],sdist=paths["sdist"],output_dir=output)
  except NextBoundary:pass
  else:raise AssertionError("selected probe did not reach next boundary")
  observed=json.loads(capture.read_text())
  assert "GITHUB_TOKEN" not in observed["env"],"installed selected interpreter inherited excluded configuration"
  assert observed["env"]==owner.runtime_environment(home=root)
  assert observed["cwd"]==str(root)
  assert output.is_dir()
print("installed-runtime-probe-environment-qualified")
'''


def test_installed_probe_environment_is_closed(installed_consumer, isolated_python):
    result = subprocess.run([str(isolated_python), "-I", "-B", "-c", PROBE],
        cwd=installed_consumer, env=_environment(), capture_output=True, text=True)
    assert result.returncode == 0, result.stdout + result.stderr
    assert result.stdout.strip() == "installed-runtime-probe-environment-qualified"


def test_installed_removed_environment_binding_fails_named_control(installed_consumer, isolated_python):
    path = installed_consumer / "scripts/_bcf_runtime/release_runtime_verification.py"
    source = path.read_text()
    binding = "cwd=manifest.parent, env=probe_environment,"
    assert source.count(binding) == 2
    path.write_text(source.replace(binding, "cwd=manifest.parent,"))
    result = subprocess.run([str(isolated_python), "-I", "-B", "-c", PROBE],
        cwd=installed_consumer, env=_environment(), capture_output=True, text=True)
    assert result.returncode == 1
    assert "installed selected interpreter inherited excluded configuration" in result.stderr
