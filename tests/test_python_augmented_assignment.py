"""Native augmented assignment must not hide in-place/fallback writes."""
import json,os,subprocess,sys
import pytest
from bcf_governance.tooling.semantic_ownership_inventory import discover_python_source
from bcf_governance.tooling.semantic_operation_effects import SemanticOperationEffectError,validate_operation_effects
CASES=json.loads("{\"add\":{\"prefix\":\"class Value:\\n    def __iadd__(self,other):\\n        STATE.append(1)\\n        return self\\n\",\"body\":\"value += 1\\nreturn value\",\"call\":\"query(Value())\"},\"sub\":{\"prefix\":\"class Value:\\n    def __isub__(self,other):\\n        STATE.append(1)\\n        return self\\n\",\"body\":\"value -= 1\\nreturn value\",\"call\":\"query(Value())\"},\"mul\":{\"prefix\":\"class Value:\\n    def __imul__(self,other):\\n        STATE.append(1)\\n        return self\\n\",\"body\":\"value *= 1\\nreturn value\",\"call\":\"query(Value())\"},\"matmul\":{\"prefix\":\"class Value:\\n    def __imatmul__(self,other):\\n        STATE.append(1)\\n        return self\\n\",\"body\":\"value @= 1\\nreturn value\",\"call\":\"query(Value())\"},\"truediv\":{\"prefix\":\"class Value:\\n    def __itruediv__(self,other):\\n        STATE.append(1)\\n        return self\\n\",\"body\":\"value /= 1\\nreturn value\",\"call\":\"query(Value())\"},\"floordiv\":{\"prefix\":\"class Value:\\n    def __ifloordiv__(self,other):\\n        STATE.append(1)\\n        return self\\n\",\"body\":\"value //= 1\\nreturn value\",\"call\":\"query(Value())\"},\"mod\":{\"prefix\":\"class Value:\\n    def __imod__(self,other):\\n        STATE.append(1)\\n        return self\\n\",\"body\":\"value %= 1\\nreturn value\",\"call\":\"query(Value())\"},\"pow\":{\"prefix\":\"class Value:\\n    def __ipow__(self,other):\\n        STATE.append(1)\\n        return self\\n\",\"body\":\"value **= 1\\nreturn value\",\"call\":\"query(Value())\"},\"lshift\":{\"prefix\":\"class Value:\\n    def __ilshift__(self,other):\\n        STATE.append(1)\\n        return self\\n\",\"body\":\"value <<= 1\\nreturn value\",\"call\":\"query(Value())\"},\"rshift\":{\"prefix\":\"class Value:\\n    def __irshift__(self,other):\\n        STATE.append(1)\\n        return self\\n\",\"body\":\"value >>= 1\\nreturn value\",\"call\":\"query(Value())\"},\"bitand\":{\"prefix\":\"class Value:\\n    def __iand__(self,other):\\n        STATE.append(1)\\n        return self\\n\",\"body\":\"value &= 1\\nreturn value\",\"call\":\"query(Value())\"},\"bitxor\":{\"prefix\":\"class Value:\\n    def __ixor__(self,other):\\n        STATE.append(1)\\n        return self\\n\",\"body\":\"value ^= 1\\nreturn value\",\"call\":\"query(Value())\"},\"bitor\":{\"prefix\":\"class Value:\\n    def __ior__(self,other):\\n        STATE.append(1)\\n        return self\\n\",\"body\":\"value |= 1\\nreturn value\",\"call\":\"query(Value())\"},\"fallback_add\":{\"prefix\":\"class Value:\\n    def __add__(self,other):\\n        STATE.append(1)\\n        return self\\n\",\"body\":\"value += 1\\nreturn value\",\"call\":\"query(Value())\"},\"reflected_add\":{\"prefix\":\"class Value:\\n    def __radd__(self,other):\\n        STATE.append(1)\\n        return self\\n\",\"body\":\"left=1\\nleft += value\\nreturn left\",\"call\":\"query(Value())\"}}")
def source(case):
    row=CASES[case]
    return "STATE=[]\n"+row["prefix"]+"def query(value):\n    "+row["body"].replace("\n","\n    ")+"\n"
@pytest.mark.parametrize("case",tuple(CASES))
def test_native_augassign_write_requires_strict_block(tmp_path,case):
    text=source(case);path=tmp_path/"service.py";path.write_text(text)
    consumer=tmp_path/"consumer.py";consumer.write_text(text+"\n"+CASES[case]["call"]+"\nassert STATE==[1],STATE\nprint('augassign-native-write')\n")
    env={key:value for key,value in os.environ.items() if not key.startswith(("PYTHON","BCF_","GIT_","GITHUB_","AGENTBUS_")) and key not in {"GH_TOKEN","VIRTUAL_ENV"}}
    native=subprocess.run([sys.executable,"-I","-B",str(consumer)],cwd=tmp_path,env=env,capture_output=True,text=True,timeout=10)
    assert native.returncode==0,native.stderr
    assert native.stdout=="augassign-native-write\n" and not native.stderr
    inventory=discover_python_source(tmp_path,files=[path],call_contracts_version="1.0")
    operation={"id":"pattern.query.v1","allowed_mutation_ports":[],"allowed_authority_ports":[],"non_authoritative_output_effects":[]}
    try:validate_operation_effects(operation,"service.py::query",inventory)
    except SemanticOperationEffectError as error:
        assert "unresolved effect" in str(error);return
    pytest.fail("native augmented-assignment write escaped strict effect query")

import ast,hashlib
from pathlib import Path
from jsonschema import Draft202012Validator,ValidationError
from bcf_governance.tooling.semantic_operation_effects import source_operation_call_population
ROOT=Path(__file__).resolve().parents[1]
OPERATORS=json.loads("{\"add\":[\"+\",\"__iadd__\"],\"sub\":[\"-\",\"__isub__\"],\"mul\":[\"*\",\"__imul__\"],\"matmul\":[\"@\",\"__imatmul__\"],\"truediv\":[\"/\",\"__itruediv__\"],\"floordiv\":[\"//\",\"__ifloordiv__\"],\"mod\":[\"%\",\"__imod__\"],\"pow\":[\"**\",\"__ipow__\"],\"lshift\":[\"<<\",\"__ilshift__\"],\"rshift\":[\">>\",\"__irshift__\"],\"bitand\":[\"&\",\"__iand__\"],\"bitxor\":[\"^\",\"__ixor__\"],\"bitor\":[\"|\",\"__ior__\"]}")
def facts(tmp_path,case):
    text=source(case);path=tmp_path/"service.py";path.write_text(text)
    return text,discover_python_source(tmp_path,files=[path],call_contracts_version="1.0")
def operator_row(inventory):
    rows=[call for function in inventory["functions"] if function["symbol"]=="service.py::query" for call in function["calls"] if call.get("implicit_protocol",{}).get("kind")=="operator"]
    assert len(rows)==1,"augassign source edge omitted"
    return rows[0]
def operation():
    return {"id":"augassign.query.v1","allowed_mutation_ports":[],"allowed_authority_ports":[],"non_authoritative_output_effects":[]}
def schema():
    root=json.loads((ROOT/"schemas/semantic-call-contracts.schema.json").read_text())
    return Draft202012Validator({"$defs":root["$defs"],"$ref":"#/$defs/implicit_protocol"})
def test_native_cases_cover_current_python_augmented_operator_population():
    observed={type(next(node for node in ast.walk(ast.parse(row["body"])) if isinstance(node,ast.AugAssign)).op) for row in CASES.values()}
    assert observed==set(ast.operator.__subclasses__())
@pytest.mark.parametrize("case",tuple(CASES))
def test_augassign_span_has_one_neutral_existing_operator_edge(tmp_path,case):
    text,inventory=facts(tmp_path,case);row=operator_row(inventory)
    function=next(node for node in ast.parse(text).body if isinstance(node,ast.FunctionDef) and node.name=="query")
    node=next(node for node in ast.walk(function) if isinstance(node,ast.AugAssign))
    digest=hashlib.sha256(ast.dump(node,include_attributes=False).encode()).hexdigest()
    assert row["implicit_protocol"]=={"version":"1.0","authority":False,"execution_qualified":False,"kind":"operator","expression_sha256":digest,"occurrence":0}
    assert row["called_symbol"]=="python-implicit::operator"
    assert row["dispatch_resolution"]=="unresolved" and row["dispatch_port_eligible"] is False
    assert (row["line"],row["column"],row["end_line"],row["end_column"])==(node.lineno,node.col_offset,node.end_lineno,node.end_col_offset)
    assert row["call_contract"]["arguments"]==[]
    schema().validate(row["implicit_protocol"])
    population=source_operation_call_population("service.py::query",inventory)
    assert sum(call[2]==digest and call[4]=="unresolved" for call in population["calls"])==1
    assert population["authority"] is False and population["execution_qualified"] is False
    assert validate_operation_effects(operation(),"service.py::query",inventory,require_runtime_context=False)==(0,0)
@pytest.mark.parametrize("consumer",("schema","population","strict","source-only"))
def test_augassign_operator_cannot_use_wrong_version(tmp_path,consumer):
    _,inventory=facts(tmp_path,"add");operator_row(inventory)["implicit_protocol"]["version"]="1.1"
    if consumer=="schema":
        with pytest.raises(ValidationError):schema().validate(operator_row(inventory)["implicit_protocol"])
    else:
        with pytest.raises(SemanticOperationEffectError,match="implicit protocol population"):
            if consumer=="population":source_operation_call_population("service.py::query",inventory)
            else:validate_operation_effects(operation(),"service.py::query",inventory,require_runtime_context=consumer=="strict")
@pytest.mark.parametrize("scope",(False,True))
def test_augassign_observation_cannot_grant_a_declared_port(tmp_path,scope):
    _,inventory=facts(tmp_path,"add");operator_row(inventory);selected=operation()
    selected["non_authoritative_output_effects"]=["python-implicit::operator"]
    with pytest.raises(SemanticOperationEffectError,match="unresolved effect|unreachable effect ports"):
        validate_operation_effects(selected,"service.py::query",inventory,require_runtime_context=scope)
@pytest.mark.parametrize("case",tuple(name for name in OPERATORS if name!="matmul"))
def test_closed_literal_augassign_preserves_source_and_native_purity(tmp_path,case):
    token=OPERATORS[case][0]
    text="STATE=[]\ndef query():\n    value=8\n    value "+token+"= 2\n    return value\n"
    path=tmp_path/"service.py";path.write_text(text)
    consumer=tmp_path/"pure.py";consumer.write_text(text+"\nquery()\nassert STATE==[]\n")
    native=subprocess.run([sys.executable,"-I","-B",str(consumer)],cwd=tmp_path,capture_output=True,text=True,timeout=10)
    assert native.returncode==0,native.stderr
    inventory=discover_python_source(tmp_path,files=[path],call_contracts_version="1.0")
    assert validate_operation_effects(operation(),"service.py::query",inventory)==(0,0)

CELL="def query():\n    value=0\n    def action():\n        nonlocal value\n        value+=1\n    action()\n    return value\n"
def test_existing_private_closed_cell_frame_remains_pure(tmp_path):
    text="STATE=[]\n"+CELL;path=tmp_path/"service.py";path.write_text(text)
    consumer=tmp_path/"closed.py";consumer.write_text(text+"\nassert query()==1\nassert STATE==[]\n")
    native=subprocess.run([sys.executable,"-I","-B",str(consumer)],cwd=tmp_path,capture_output=True,text=True,timeout=10)
    assert native.returncode==0,native.stderr
    inventory=discover_python_source(tmp_path,files=[path],call_contracts_version="1.0")
    assert validate_operation_effects(operation(),"service.py::query",inventory)==(0,0)
def test_escaping_callback_cannot_inherit_private_cell_proof(tmp_path):
    prefix="STATE=[]\nclass Value:\n    def __iadd__(self,other):\n        STATE.append(1)\n        return self\ndef retain(function):\n    function.__closure__[0].cell_contents=Value()\n"
    text=prefix+CELL.replace("    action()\n","    retain(action)\n    action()\n")
    path=tmp_path/"service.py";path.write_text(text)
    consumer=tmp_path/"escape.py";consumer.write_text(text+"\nquery()\nassert STATE==[1]\n")
    native=subprocess.run([sys.executable,"-I","-B",str(consumer)],cwd=tmp_path,capture_output=True,text=True,timeout=10)
    assert native.returncode==0,native.stderr
    inventory=discover_python_source(tmp_path,files=[path],call_contracts_version="1.0")
    selected=operation();selected["non_authoritative_output_effects"]=["service.py::retain"]
    with pytest.raises(SemanticOperationEffectError,match="write|unresolved effect"):
        validate_operation_effects(selected,"service.py::query",inventory)
