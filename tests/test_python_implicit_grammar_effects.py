"""Fresh ordinary consumers distinguish implicit grammar from explicit calls."""
import json,os,subprocess,sys
import pytest
from bcf_governance.tooling.semantic_ownership_inventory import discover_python_source
from bcf_governance.tooling.semantic_operation_effects import SemanticOperationEffectError,validate_operation_effects
CASES=json.loads("{\"unary\":{\"prefix\":\"class Value:\\n    def __neg__(self):\\n        STATE.append(1)\\n        return 1\\n\",\"body\":\"return -value\",\"call\":\"query(Value())\"},\"comparison\":{\"prefix\":\"class Value:\\n    def __eq__(self,other):\\n        STATE.append(1)\\n        return True\\n\",\"body\":\"return value == 1\",\"call\":\"query(Value())\"},\"containment\":{\"prefix\":\"class Value:\\n    def __contains__(self,other):\\n        STATE.append(1)\\n        return True\\n\",\"body\":\"return 1 in value\",\"call\":\"query(Value())\"},\"boolean_expression\":{\"prefix\":\"class Value:\\n    def __bool__(self):\\n        STATE.append(1)\\n        return True\\n\",\"body\":\"return value and 1\",\"call\":\"query(Value())\"},\"starred_sequence\":{\"prefix\":\"class Value:\\n    def __iter__(self):\\n        STATE.append(1)\\n        return iter((1,2))\\n\",\"body\":\"return [*value]\",\"call\":\"query(Value())\"},\"unpack_assignment\":{\"prefix\":\"class Value:\\n    def __iter__(self):\\n        STATE.append(1)\\n        return iter((1,2))\\n\",\"body\":\"left,right=value\\nreturn left\",\"call\":\"query(Value())\"},\"raised_class\":{\"prefix\":\"class Value(Exception):\\n    def __init__(self):\\n        STATE.append(1)\\n\",\"body\":\"raise value\",\"call\":\"try:\\n    query(Value)\\nexcept Value:\\n    pass\"},\"await_value\":{\"prefix\":\"class Value:\\n    def __await__(self):\\n        STATE.append(1)\\n        if False:\\n            yield\\n        return 1\\n\",\"body\":\"return await value\",\"async\":true,\"call\":\"import asyncio\\nasyncio.run(query(Value()))\"},\"delegated_generator\":{\"prefix\":\"class Value:\\n    def __iter__(self):\\n        STATE.append(1)\\n        return iter((1,2))\\n\",\"body\":\"yield from value\",\"call\":\"list(query(Value()))\"}}")
def source(case):
 row=CASES[case]
 return "STATE=[]\n"+row["prefix"]+("async def" if row.get("async") else "def")+" query(value):\n    "+row["body"].replace("\n","\n    ")+"\n"
def inventory(tmp_path,text):
 path=tmp_path/"service.py";path.write_text(text)
 return discover_python_source(tmp_path,files=[path],call_contracts_version="1.0")
def operation():
 return {"id":"implicit-grammar.query.v1","allowed_mutation_ports":[],"allowed_authority_ports":[],"non_authoritative_output_effects":[]}
@pytest.mark.parametrize("case",tuple(CASES))
def test_implicit_grammar_cannot_hide_shared_write(tmp_path,case):
 with pytest.raises(SemanticOperationEffectError,match="unresolved effect"):
  validate_operation_effects(operation(),"service.py::query",inventory(tmp_path,source(case)))
def native(tmp_path,text,call,expected):
 path=tmp_path/"consumer.py";path.write_text(text+"\n"+call+"\nassert STATE == "+repr(expected)+"\nprint('implicit-grammar-witnessed')\n")
 env={k:v for k,v in os.environ.items() if not k.startswith(("PYTHON","BCF_","GIT_","GITHUB_","AGENTBUS_")) and k not in {"GH_TOKEN","VIRTUAL_ENV"}}
 result=subprocess.run([sys.executable,"-I","-B",str(path)],cwd=tmp_path,env=env,capture_output=True,text=True,timeout=10)
 assert result.returncode==0,result.stderr
 assert result.stdout=="implicit-grammar-witnessed\n" and not result.stderr
@pytest.mark.parametrize("case",tuple(CASES))
def test_fresh_native_consumer_witnesses_implicit_grammar(tmp_path,case):
 native(tmp_path,source(case),CASES[case]["call"],[1])
def test_closed_literal_grammar_remains_source_valid(tmp_path):
 text="STATE=[]\ndef query():\n    left,right=(1,2)\n    return -1 == 1 and [*(1,2)]\n"
 assert validate_operation_effects(operation(),"service.py::query",inventory(tmp_path,text))==(0,0)
def test_fresh_native_literal_grammar_is_pure(tmp_path):
 native(tmp_path,"STATE=[]\ndef query():\n    left,right=(1,2)\n    return -1 == 1 and [*(1,2)]\n","query()",[])
