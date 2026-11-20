"""Installed public dispatchers retain the same enforced native argv context."""
import json
import subprocess
import pytest
from bcf_governance import cli
import test_installed_evidence_storage as _fixture_owner
from test_installed_evidence_storage import _environment

installed_consumer = _fixture_owner.installed_consumer
isolated_python = _fixture_owner.isolated_python
MODULES = {name:(fn.__module__.replace("bcf_governance.tooling.","_bcf_runtime."),fn.__name__)
           for name,fn in cli.COMMANDS.items()}
PROBE = '''import importlib,importlib.util,sys,json,io,contextlib
from pathlib import Path
assert importlib.util.find_spec("bcf_governance") is None
sys.path.insert(0,str(Path("scripts").resolve()))
from _bcf_runtime import nested_cli_runtime as owner
modules=json.loads(sys.argv[1])
assert len(modules)==21
class Value:
 def __init__(self,events):self.events=events
 def __iter__(self):
  self.events.append("iteration")
  return iter(["--help"])
 def __getitem__(self,key):
  self.events.append("index")
  return ["--help"]
class Word(str):
 def __new__(cls,events):
  value=str.__new__(cls,"--help")
  value.events=events
  return value
 def __hash__(self):
  self.events.append("hash")
  return str.__hash__(self)
 def __getitem__(self,key):
  self.events.append("index")
  return str.__getitem__(self,key)
for name,(module,symbol) in sorted(modules.items()):
 entry=getattr(importlib.import_module(module),symbol)
 for kind in ["sequence","member"]:
  events=[]
  value=Value(events) if kind=="sequence" else [Word(events)]
  try:
   with contextlib.redirect_stdout(io.StringIO()):entry(value)
  except TypeError:pass
  except BaseException:raise AssertionError("installed non-native CLI argument accepted") from None
  else:raise AssertionError("installed non-native CLI argument accepted")
  assert events==[],"installed CLI invoked unqualified argument callback"
 try:
  with contextlib.redirect_stdout(io.StringIO()):entry(("--help",))
 except SystemExit as error:assert error.code==0
 else:raise AssertionError("installed ordinary help did not preserve exit")
values=["ci","--help"]
snapshot=owner.cli_arguments(values)
values[:]=["changed"]
assert snapshot==["ci","--help"] and type(snapshot) is list
print("installed-cli-argument-context-qualified")
'''


def run(installed_consumer, isolated_python):
    return subprocess.run([str(isolated_python),"-I","-B","-c",PROBE,json.dumps(MODULES)],
        cwd=installed_consumer,env=_environment(),capture_output=True,text=True)


def test_installed_public_cli_argument_context(installed_consumer, isolated_python):
    result = run(installed_consumer,isolated_python)
    assert result.returncode == 0, result.stdout + result.stderr
    assert result.stdout.strip() == "installed-cli-argument-context-qualified"


@pytest.mark.parametrize("guard", ["if kind is not list and kind is not tuple:",
    "if any(type(value) is not str for value in values):"])
def test_installed_disabled_argument_predicate_fails_named_control(installed_consumer, isolated_python, guard):
    path = installed_consumer/"scripts/_bcf_runtime/nested_cli_runtime.py"
    source = path.read_text()
    assert source.count(guard) == 1
    path.write_text(source.replace(guard,"if False:"))
    result = run(installed_consumer,isolated_python)
    assert result.returncode == 1
    assert "installed non-native CLI argument accepted" in result.stderr
