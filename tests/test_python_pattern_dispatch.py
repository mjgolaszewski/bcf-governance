"""Native pattern execution must not disappear from strict effect validation."""
import json,os,subprocess,sys
import pytest
from bcf_governance.tooling.semantic_ownership_inventory import discover_python_source
from bcf_governance.tooling.semantic_operation_effects import SemanticOperationEffectError,validate_operation_effects
CASES=json.loads("{\"literal\":{\"prefix\":\"class Value:\\n    def __eq__(self,other):\\n        STATE.append(1)\\n        return True\\n\",\"body\":\"match value:\\n    case 1:\\n        return True\\n    case _:\\n        return False\",\"call\":\"query(Value())\"},\"sequence\":{\"prefix\":\"from collections.abc import Sequence\\nclass Value(Sequence):\\n    def __len__(self):\\n        STATE.append(1)\\n        return 1\\n    def __getitem__(self,index):\\n        if index==0:\\n            return 1\\n        raise IndexError\\n\",\"body\":\"match value:\\n    case [1]:\\n        return True\\n    case _:\\n        return False\",\"call\":\"query(Value())\"},\"mapping\":{\"prefix\":\"class Value(dict):\\n    def get(self,*args):\\n        STATE.append(1)\\n        return super().get(*args)\\n\",\"body\":\"match value:\\n    case {'a': 1}:\\n        return True\\n    case _:\\n        return False\",\"call\":\"query(Value(a=1))\"},\"class_attribute\":{\"prefix\":\"class Value:\\n    @property\\n    def item(self):\\n        STATE.append(1)\\n        return 1\\n\",\"body\":\"match value:\\n    case Value(item=1):\\n        return True\\n    case _:\\n        return False\",\"call\":\"query(Value())\"},\"guard\":{\"prefix\":\"class Value:\\n    def __bool__(self):\\n        STATE.append(1)\\n        return True\\n\",\"body\":\"match 0:\\n    case _ if value:\\n        return True\\n    case _:\\n        return False\",\"call\":\"query(Value())\"}}")
def source(case):
    row=CASES[case]
    return "STATE=[]\n"+row["prefix"]+"def query(value):\n    "+row["body"].replace("\n","\n    ")+"\n"
@pytest.mark.parametrize("case",tuple(CASES))
def test_native_pattern_write_requires_strict_block(tmp_path,case):
    text=source(case);path=tmp_path/"service.py";path.write_text(text)
    consumer=tmp_path/"consumer.py";consumer.write_text(text+"\n"+CASES[case]["call"]+"\nassert STATE==[1],STATE\nprint('pattern-native-write')\n")
    env={key:value for key,value in os.environ.items() if not key.startswith(("PYTHON","BCF_","GIT_","GITHUB_","AGENTBUS_")) and key not in {"GH_TOKEN","VIRTUAL_ENV"}}
    native=subprocess.run([sys.executable,"-I","-B",str(consumer)],cwd=tmp_path,env=env,capture_output=True,text=True,timeout=10)
    assert native.returncode==0,native.stderr
    assert native.stdout=="pattern-native-write\n" and not native.stderr
    inventory=discover_python_source(tmp_path,files=[path],call_contracts_version="1.0")
    operation={"id":"pattern.query.v1","allowed_mutation_ports":[],"allowed_authority_ports":[],"non_authoritative_output_effects":[]}
    try:validate_operation_effects(operation,"service.py::query",inventory)
    except SemanticOperationEffectError as error:
        assert "unresolved effect" in str(error);return
    pytest.fail("native pattern-match write escaped strict effect query")

import ast,copy,hashlib
from pathlib import Path
from jsonschema import Draft202012Validator,ValidationError
from bcf_governance.tooling.semantic_operation_effects import source_operation_call_population
ROOT=Path(__file__).resolve().parents[1]
def facts(tmp_path,case):
    text=source(case);path=tmp_path/"service.py";path.write_text(text)
    return text,discover_python_source(tmp_path,files=[path],call_contracts_version="1.0")
def pattern_row(inventory):
    rows=[call for function in inventory["functions"] if function["symbol"]=="service.py::query" for call in function["calls"] if call.get("implicit_protocol",{}).get("kind")=="pattern_match"]
    assert len(rows)==1,"pattern source edge omitted"
    return rows[0]
def operation():
    return {"id":"pattern.query.v1","allowed_mutation_ports":[],"allowed_authority_ports":[],"non_authoritative_output_effects":[]}
def schema():
    root=json.loads((ROOT/"schemas/semantic-call-contracts.schema.json").read_text())
    return Draft202012Validator({"$defs":root["$defs"],"$ref":"#/$defs/implicit_protocol"})
@pytest.mark.parametrize("case",tuple(CASES))
def test_pattern_span_has_one_neutral_versioned_edge(tmp_path,case):
    text,inventory=facts(tmp_path,case);row=pattern_row(inventory)
    function=next(node for node in ast.parse(text).body if isinstance(node,ast.FunctionDef) and node.name=="query")
    node=next(node for node in ast.walk(function) if isinstance(node,ast.Match))
    digest=hashlib.sha256(ast.dump(node,include_attributes=False).encode()).hexdigest()
    assert row["implicit_protocol"]=={"version":"1.1","authority":False,"execution_qualified":False,"kind":"pattern_match","expression_sha256":digest,"occurrence":0}
    assert row["called_symbol"]=="python-implicit::pattern_match"
    assert row["dispatch_resolution"]=="unresolved" and row["dispatch_port_eligible"] is False
    assert (row["line"],row["column"],row["end_line"],row["end_column"])==(node.lineno,node.col_offset,node.end_lineno,node.end_col_offset)
    assert row["call_contract"]["arguments"]==[]
    schema().validate(row["implicit_protocol"])
    population=source_operation_call_population("service.py::query",inventory)
    assert sum(call[2]==digest and call[4]=="unresolved" for call in population["calls"])==1
    assert population["authority"] is False and population["execution_qualified"] is False
    assert validate_operation_effects(operation(),"service.py::query",inventory,require_runtime_context=False)==(0,0)
@pytest.mark.parametrize("consumer",("schema","population","strict","source-only"))
def test_pattern_marker_cannot_use_legacy_version(tmp_path,consumer):
    _,inventory=facts(tmp_path,"guard");marker=pattern_row(inventory)["implicit_protocol"];marker["version"]="1.0"
    if consumer=="schema":
        with pytest.raises(ValidationError):schema().validate(marker)
    else:
        with pytest.raises(SemanticOperationEffectError,match="implicit protocol population"):
            if consumer=="population":source_operation_call_population("service.py::query",inventory)
            else:validate_operation_effects(operation(),"service.py::query",inventory,require_runtime_context=consumer=="strict")
@pytest.mark.parametrize("scope",(False,True))
def test_pattern_observation_cannot_grant_a_declared_port(tmp_path,scope):
    _,inventory=facts(tmp_path,"guard");pattern_row(inventory);selected=operation()
    selected["non_authoritative_output_effects"]=["python-implicit::pattern_match"]
    with pytest.raises(SemanticOperationEffectError,match="unresolved effect|unreachable effect ports"):
        validate_operation_effects(selected,"service.py::query",inventory,require_runtime_context=scope)
@pytest.mark.parametrize("pattern",("_","captured","None","True","_ if True"))
def test_capture_singleton_and_literal_guard_preserve_no_dispatch(tmp_path,pattern):
    text="STATE=[]\nclass Value:\n    def __eq__(self,other):\n        STATE.append(1)\n        return True\ndef query(value):\n    match value:\n        case "+pattern+":\n            return 1\n"
    path=tmp_path/"service.py";path.write_text(text)
    consumer=tmp_path/"pure.py";consumer.write_text(text+"\nquery(Value())\nassert STATE==[]\n")
    native=subprocess.run([sys.executable,"-I","-B",str(consumer)],cwd=tmp_path,capture_output=True,text=True,timeout=10)
    assert native.returncode==0,native.stderr
    inventory=discover_python_source(tmp_path,files=[path],call_contracts_version="1.0")
    assert validate_operation_effects(operation(),"service.py::query",inventory)==(0,0)
