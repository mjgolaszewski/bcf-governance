"""Installed ordinary invocation contexts reject native callback laundering."""
import subprocess
import test_installed_evidence_storage as _fixture_owner
from test_installed_evidence_storage import _environment

installed_consumer = _fixture_owner.installed_consumer
isolated_python = _fixture_owner.isolated_python
PROBE = '''import importlib.util,sys,tempfile
from pathlib import Path
assert importlib.util.find_spec("bcf_governance") is None
sys.path.insert(0,str(Path("scripts").resolve()))
from _bcf_runtime.semantic_ownership_inventory import discover_python_source
from _bcf_runtime.semantic_operation_effects import validate_operation_effects,SemanticOperationEffectError
operation={"id":"unbound.query.v1","allowed_mutation_ports":[],"allowed_authority_ports":[],"non_authoritative_output_effects":[]}
with tempfile.TemporaryDirectory() as directory:
 root=Path(directory)
 path=root/"service.py"
 source="def query(value):\\n    return bool(value)\\n"
 path.write_text(source)
 scope={}
 exec(compile(source,str(path),"exec"),scope)
 events=[]
 class Value:
  def __bool__(self):
   events.append("callback")
   return True
 value=Value()
 assert scope["query"](value) is True and events==["callback"]
 facts=discover_python_source(root,files=[path],call_contracts_version="1.0")
 try:validate_operation_effects(operation,"service.py::query",facts)
 except SemanticOperationEffectError as error:
  assert "runtime call context" in str(error)
 else:raise AssertionError("installed native callback accepted without invocation context")
print("installed-unbound-call-qualified")
'''


def test_installed_unbound_call_rejection(installed_consumer, isolated_python):
    result = subprocess.run([str(isolated_python),"-I","-B","-c",PROBE],
        cwd=installed_consumer,env=_environment(),capture_output=True,text=True)
    assert result.returncode == 0, result.stdout + result.stderr
    assert result.stdout.strip() == "installed-unbound-call-qualified"


def test_installed_disabled_native_context_guard_fails_callback_control(installed_consumer, isolated_python):
    path = installed_consumer / "scripts/_bcf_runtime/semantic_operation_effects.py"
    source = path.read_text()
    guard = "if require_runtime_context:\n            reject(caller, \"runtime_call\""
    assert source.count(guard) == 1
    path.write_text(source.replace(guard,"if False:\n            reject(caller, \"runtime_call\""))
    result = subprocess.run([str(isolated_python),"-I","-B","-c",PROBE],
        cwd=installed_consumer,env=_environment(),capture_output=True,text=True)
    assert result.returncode == 1
    assert "installed native callback accepted without invocation context" in result.stderr
