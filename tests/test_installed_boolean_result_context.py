"""Installed strict contexts preserve ordinary nested operand effects."""
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
operation={"id":"boolean.query.v1","allowed_mutation_ports":[],"allowed_authority_ports":[],"non_authoritative_output_effects":[]}
with tempfile.TemporaryDirectory() as directory:
 root=Path(directory)
 path=root/"service.py"
 path.write_text("def query(value):\\n    if value is None:\\n        return True\\n    return False\\n")
 facts=discover_python_source(root,files=[path],call_contracts_version="1.0")
 assert validate_operation_effects(operation,"service.py::query",facts)==(0,0)
 source="def query(value):\\n    return not not value\\n"
 path.write_text(source)
 scope={}
 exec(compile(source,str(path),"exec"),scope)
 events=[]
 class Value:
  def __bool__(self):
   events.append("truth")
   return True
 assert scope["query"](Value()) is True and events==["truth"]
 facts=discover_python_source(root,files=[path],call_contracts_version="1.0")
 try:validate_operation_effects(operation,"service.py::query",facts)
 except SemanticOperationEffectError:pass
 else:raise AssertionError("installed nested operand effect omitted")
print("installed-boolean-result-qualified")
'''


def test_installed_boolean_result_and_operand_contexts(installed_consumer, isolated_python):
    result = subprocess.run([str(isolated_python),"-I","-B","-c",PROBE],
        cwd=installed_consumer,env=_environment(),capture_output=True,text=True)
    assert result.returncode == 0, result.stdout + result.stderr
    assert result.stdout.strip() == "installed-boolean-result-qualified"


def test_installed_disabled_child_descent_fails_native_effect_control(installed_consumer, isolated_python):
    path = installed_consumer / "scripts/_bcf_runtime/semantic_python_calls.py"
    source = path.read_text()
    guard = "        return super().visit(node)"
    assert source.count(guard) == 1
    replacement = "        if isinstance(node, ast.UnaryOp) and isinstance(node.op, ast.Not):\n            return None\n" + guard
    path.write_text(source.replace(guard,replacement))
    result = subprocess.run([str(isolated_python),"-I","-B","-c",PROBE],
        cwd=installed_consumer,env=_environment(),capture_output=True,text=True)
    assert result.returncode == 1
    assert "installed nested operand effect omitted" in result.stderr
