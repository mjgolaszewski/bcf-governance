"""Named lexical scopes retain effects, phases and binding uncertainty."""
import ast,json,os,subprocess,sys
import pytest
from bcf_governance.tooling.semantic_ownership_inventory import discover_python_source,resolve_python_imports
from bcf_governance.tooling.semantic_operation_effects import SemanticOperationEffectError,source_operation_call_population,validate_operation_effects
DATA=json.loads("{\"prefix\":\"from pathlib import Path\\nSTATE=0\\nHELD=[]\\ndef retain(value):\\n    HELD.append(value)\\n\",\"negative\":{\"module-shadow\":{\"body\":\"def action():\\n    return 1\\ndef query():\\n    def action():\\n        global STATE\\n        STATE=1\\n        return 1\\n    return action()\\n\",\"call\":\"query()\",\"witness\":\"STATE==1\"},\"import-shadow\":{\"body\":\"from math import sin as action\\ndef query():\\n    def action():\\n        global STATE\\n        STATE=1\\n        return 1\\n    return action()\\n\",\"call\":\"query()\",\"witness\":\"STATE==1\"},\"alias\":{\"body\":\"def query():\\n    def action():\\n        global STATE\\n        STATE=1\\n        return 1\\n    selected=action\\n    return selected()\\n\",\"call\":\"query()\",\"witness\":\"STATE==1\"},\"rebound\":{\"body\":\"def bad():\\n    global STATE\\n    STATE=1\\n    return 1\\ndef query():\\n    def action():\\n        return 1\\n    action=bad\\n    return action()\\n\",\"call\":\"query()\",\"witness\":\"STATE==1\"},\"conditional\":{\"body\":\"def query():\\n    if True:\\n        def action():\\n            global STATE\\n            STATE=1\\n            return 1\\n    return action()\\n\",\"call\":\"query()\",\"witness\":\"STATE==1\"},\"escape\":{\"body\":\"def query():\\n    value=0\\n    def action():\\n        nonlocal value\\n        value+=1\\n        return value\\n    retain(action)\\n    return action()\\n\",\"call\":\"query()\",\"witness\":\"len(HELD)==1 and HELD[0]()==2\",\"port\":true},\"decorator\":{\"body\":\"def decorate(function):\\n    global STATE\\n    STATE=1\\n    return function\\ndef query():\\n    @decorate\\n    def unused():\\n        return 1\\n    return 1\\n\",\"call\":\"query()\",\"witness\":\"STATE==1\"},\"vararg\":{\"body\":\"def handler():\\n    global STATE\\n    STATE=1\\n    return 1\\ndef query(*values):\\n    return values[0]()\\n\",\"call\":\"query(handler)\",\"witness\":\"STATE==1\"},\"varkw\":{\"body\":\"def handler():\\n    global STATE\\n    STATE=1\\n    return 1\\ndef query(**values):\\n    return values['callback']()\\n\",\"call\":\"query(callback=handler)\",\"witness\":\"STATE==1\"},\"local-class\":{\"body\":\"class Meta(type):\\n    def __new__(meta,name,bases,namespace):\\n        global STATE\\n        STATE=1\\n        return super().__new__(meta,name,bases,namespace)\\ndef query():\\n    class Local(metaclass=Meta):\\n        pass\\n    return 1\\n\",\"call\":\"query()\",\"witness\":\"STATE==1\"},\"lambda-call\":{\"body\":\"def query():\\n    action=lambda: Path('state').write_text('changed')\\n    action()\\n    return 1\\n\",\"call\":\"query()\",\"witness\":\"Path('state').read_text()=='changed'\"},\"default-eager\":{\"body\":\"def write():\\n    global STATE\\n    STATE=1\\n    return 0\\ndef query():\\n    def unused(value=write()):\\n        return value\\n    return 1\\n\",\"call\":\"query()\",\"witness\":\"STATE==1\"},\"import-scope\":{\"body\":\"from bad import perform\\ndef query():\\n    def unused():\\n        from good import perform\\n    return perform()\\n\",\"call\":\"query()\",\"witness\":\"Path('state').read_text()=='changed'\",\"files\":{\"bad.py\":\"from pathlib import Path\\ndef perform():\\n    Path('state').write_text('changed')\\n    return 1\\n\",\"good.py\":\"def perform():\\n    return 1\\n\"}}},\"pure\":{\"named\":{\"body\":\"def query():\\n    def action():\\n        return 1\\n    return action()\\n\",\"call\":\"query()\",\"witness\":\"STATE==0 and not Path('state').exists()\"},\"future\":{\"body\":\"def write():\\n    global STATE\\n    STATE=1\\n    return int\\ndef query():\\n    def unused(value:write()):\\n        return value\\n    return 1\\n\",\"future\":true,\"call\":\"query()\",\"witness\":\"STATE==0 and not Path('state').exists()\"},\"unused-lambda\":{\"body\":\"def query():\\n    unused=lambda: Path('state').write_text('changed')\\n    return 1\\n\",\"call\":\"query()\",\"witness\":\"STATE==0 and not Path('state').exists()\"}}}")
NEGATIVE=DATA["negative"];PURE=DATA["pure"]
def fixture(case):
 row=(NEGATIVE if case in NEGATIVE else PURE)[case]
 source=("from __future__ import annotations\n" if row.get("future") else "")+DATA["prefix"]+row["body"]
 return source,row
def inventory(tmp_path,case):
 source,row=fixture(case)
 path=tmp_path/"service.py";path.write_text(source)
 files=[path]
 for relative,text in row.get("files",{}).items():
  target=tmp_path/relative;target.write_text(text);files.append(target)
 return resolve_python_imports(tmp_path,discover_python_source(tmp_path,files=files,call_contracts_version="1.0"))
def operation(port=False):
 return {"id":"lexical-context.query.v1","allowed_mutation_ports":[],"allowed_authority_ports":[],
         "non_authoritative_output_effects":["service.py::retain"] if port else []}
@pytest.mark.parametrize("case",tuple(NEGATIVE))
def test_lexical_uncertainty_cannot_authorize_shared_effects(tmp_path,case):
 _,row=fixture(case)
 with pytest.raises(SemanticOperationEffectError,match="(undeclared write|unresolved effect)"):
  validate_operation_effects(operation(row.get("port",False)),"service.py::query",inventory(tmp_path,case))
@pytest.mark.parametrize("case",tuple(PURE))
def test_genuinely_unexecuted_or_pure_lexical_context_remains_valid(tmp_path,case):
 assert validate_operation_effects(operation(),"service.py::query",inventory(tmp_path,case))==(0,0)
@pytest.mark.parametrize("case",tuple(NEGATIVE)+tuple(PURE))
def test_ordinary_fresh_consumer_witnesses_lexical_context(tmp_path,case):
 source,row=fixture(case)
 for relative,text in row.get("files",{}).items():(tmp_path/relative).write_text(text)
 path=tmp_path/"consumer.py"
 path.write_text(source+"\nassert "+row["call"]+"==1\nassert "+row["witness"]+"\nprint('lexical-context-witnessed')\n")
 env={key:value for key,value in os.environ.items() if not key.startswith(("PYTHON","BCF_","GIT_","GITHUB_","AGENTBUS_")) and key not in {"GH_TOKEN","VIRTUAL_ENV"}}
 command="import runpy,sys;sys.path.insert(0,sys.argv[1]);runpy.run_path(sys.argv[2],run_name='__main__')"
 result=subprocess.run([sys.executable,"-I","-B","-c",command,str(tmp_path),str(path)],cwd=tmp_path,env=env,capture_output=True,text=True,timeout=10)
 assert result.returncode==0,result.stderr
 assert result.stdout=="lexical-context-witnessed\n" and not result.stderr
@pytest.mark.parametrize("source",(
 "def query(*values):\n    return 1\n",
 "def query(**values):\n    return 1\n",
 "def query(head,/,*values,only=1,**named):\n    return 1\n",
 "async def query(*values,**named):\n    return 1\n",
))
def test_source_parameter_population_includes_every_formal_slot(tmp_path,source):
 path=tmp_path/"service.py";path.write_text(source)
 facts=discover_python_source(tmp_path,files=[path],call_contracts_version="1.0")
 node=ast.parse(source).body[0];args=node.args
 expected={arg.arg for arg in [*args.posonlyargs,*args.args,*args.kwonlyargs,*([args.vararg] if args.vararg else []),*([args.kwarg] if args.kwarg else [])]}
 assert set(facts["functions"][0]["parameters"])==expected,"formal parameter population omitted a slot"

@pytest.mark.parametrize("body,expected",(
 ("def query():\n    def action():\n        return 1\n    return 1\n",{"query","query.<locals>.action"}),
 ("def query():\n    if True:\n        def action():\n            return 1\n    return 1\n",{"query","query.<locals>.action"}),
 ("def query():\n    class Local:\n        def work(self):\n            def inner():\n                return 1\n            return inner()\n    return 1\n",{"query","query.<locals>.Local.work","query.<locals>.Local.work.<locals>.inner"}),
))
def test_named_lexical_source_population_survives_deferred_phases(tmp_path,body,expected):
 path=tmp_path/"service.py";path.write_text(body)
 facts=discover_python_source(tmp_path,files=[path],call_contracts_version="1.0")
 assert {"service.py::"+name for name in expected}<={row["symbol"] for row in facts["functions"]},"named lexical source population omitted"
def test_existing_runtime_scope_facade_preserves_its_default_shape():
 from bcf_governance.tooling.semantic_python_method_identity import runtime_function_scopes
 tree=ast.parse("def query():\n    def inner():\n        return 1\n    return 1\n")
 scopes,missing=runtime_function_scopes(tree,path="service.py",imports={})
 assert missing==[] and [(owner,[node.name for node in nodes]) for owner,nodes in scopes]==[(None,["query"])]
CELL="def query():\n    value=0\n    def action():\n        nonlocal value\n        value+=1\n    action()\n    return value\n"
def cell_inventory(tmp_path):
 path=tmp_path/"service.py";path.write_text(CELL)
 return resolve_python_imports(tmp_path,discover_python_source(tmp_path,files=[path],call_contracts_version="1.0"))
@pytest.mark.parametrize("consumer",("population","effects"))
@pytest.mark.parametrize("defect",("authority","execution","duplicate","owner","digest"))
def test_forged_owned_cell_eligibility_cannot_supply_authority(tmp_path,consumer,defect):
 facts=cell_inventory(tmp_path)
 query=next(row for row in facts["functions"] if row["symbol"]=="service.py::query")
 row=query.get("lexical_scalar_region")
 assert row,"owned cell eligibility omitted"
 if defect=="authority":row["authority"]=True
 elif defect=="execution":row["execution_qualified"]=True
 elif defect=="duplicate":row["cells"]*=2
 elif defect=="owner":row["owner"]="service.py::other"
 else:row["expression_sha256"]="0"
 with pytest.raises(SemanticOperationEffectError,match="lexical scalar region"):
  if consumer=="population":source_operation_call_population("service.py::query",facts)
  else:validate_operation_effects(operation(),"service.py::query",facts)
def test_contextless_nested_entrypoint_is_blocked(tmp_path):
 facts=cell_inventory(tmp_path)
 assert "service.py::query.<locals>.action" in {row["symbol"] for row in facts["functions"]},"named lexical source population omitted"
 with pytest.raises(SemanticOperationEffectError,match="unresolved effect lexical invocation context"):
  validate_operation_effects(operation(),"service.py::query.<locals>.action",facts)
