"""Nested definition bodies need distinct source populations and execution phases."""
from pathlib import Path
import os,subprocess,sys
import pytest
from bcf_governance.tooling.semantic_ownership_inventory import discover_python_source,resolve_python_imports
from bcf_governance.tooling.semantic_operation_effects import SemanticOperationEffectError,validate_operation_effects
PREFIX="from pathlib import Path\nSTATE=0\nclass Box: pass\n"
CASES={
"global":("def query():\n    def action():\n        global STATE\n        STATE=1\n    action()\n    return 1\n","assert query()==1 and STATE==1\n","query.<locals>.action"),
"parameter-item":("def query(value):\n    def action():\n        value['v']=1\n    action()\n    return 1\n","value={'v':0}\nassert query(value)==1 and value=={'v':1}\n","query.<locals>.action"),
"parameter-attribute":("def query(value):\n    def action():\n        value.item=1\n    action()\n    return 1\n","value=Box()\nassert query(value)==1 and value.item==1\n","query.<locals>.action"),
"two-level":("def query():\n    def first():\n        def action():\n            global STATE\n            STATE=1\n        action()\n    first()\n    return 1\n","assert query()==1 and STATE==1\n","query.<locals>.first.<locals>.action"),
}
PURE={
"unused-global":"def query():\n    def unused():\n        global STATE\n        STATE=1\n    return 1\n",
"closed-cell":"def query():\n    value=0\n    def action():\n        nonlocal value\n        value+=1\n    action()\n    return value\n",
"unused-write-call":"def query():\n    def unused():\n        Path('state').write_text('changed')\n    return 1\n",
}
def inventory(tmp_path,body):
 path=tmp_path/"service.py";path.write_text(PREFIX+body)
 return resolve_python_imports(tmp_path,discover_python_source(tmp_path,files=[path],call_contracts_version="1.0"))
def operation():
 return {"id":"nested-scope.query.v1","allowed_mutation_ports":[],"allowed_authority_ports":[],"non_authoritative_output_effects":[]}
@pytest.mark.parametrize("case",tuple(CASES))
def test_runtime_named_nested_definition_population_is_not_omitted(tmp_path,case):
 body,_,qualified=CASES[case]
 facts=inventory(tmp_path,body)
 assert "service.py::"+qualified in {row["symbol"] for row in facts["functions"]},"named nested runtime definition omitted"
@pytest.mark.parametrize("case",tuple(CASES))
def test_called_nested_body_cannot_hide_shared_mutation(tmp_path,case):
 body,_,_=CASES[case]
 with pytest.raises(SemanticOperationEffectError,match="(undeclared write|unresolved effect)"):
  validate_operation_effects(operation(),"service.py::query",inventory(tmp_path,body))
@pytest.mark.parametrize("case",tuple(CASES))
def test_fresh_consumer_witnesses_called_nested_mutation(tmp_path,case):
 body,witness,_=CASES[case]
 native(tmp_path,body,witness)
@pytest.mark.parametrize("case",tuple(PURE))
def test_deferred_or_owned_cell_context_remains_pure(tmp_path,case):
 assert validate_operation_effects(operation(),"service.py::query",inventory(tmp_path,PURE[case]))==(0,0)
@pytest.mark.parametrize("case",tuple(PURE))
def test_fresh_consumer_witnesses_pure_nested_context(tmp_path,case):
 native(tmp_path,PURE[case],"assert query()==1 and STATE==0\nassert not Path('state').exists()\n")
def native(tmp_path,body,witness):
 path=tmp_path/"consumer.py";path.write_text(PREFIX+body+"\n"+witness+"print('nested-context-witnessed')\n")
 env={key:value for key,value in os.environ.items() if not key.startswith(("PYTHON","BCF_","GIT_","GITHUB_","AGENTBUS_")) and key not in {"GH_TOKEN","VIRTUAL_ENV"}}
 result=subprocess.run([sys.executable,"-I","-B",str(path)],cwd=tmp_path,env=env,capture_output=True,text=True,timeout=10)
 assert result.returncode==0,result.stderr
 assert result.stdout=="nested-context-witnessed\n" and not result.stderr
