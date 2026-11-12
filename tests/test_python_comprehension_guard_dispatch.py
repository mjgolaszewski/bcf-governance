"""Native comprehension guard execution must not disappear from strict effect validation."""
import json,os,subprocess,sys
import pytest
from bcf_governance.tooling.semantic_ownership_inventory import discover_python_source
from bcf_governance.tooling.semantic_operation_effects import SemanticOperationEffectError,validate_operation_effects
CASES=json.loads("{\"list___bool__\":{\"prefix\":\"class Value:\\n    def __bool__(self):\\n        STATE.append(1)\\n        return True\\n\",\"body\":\"return [item for item in (1,) if value]\",\"call\":\"query(Value())\"},\"list___len__\":{\"prefix\":\"class Value:\\n    def __len__(self):\\n        STATE.append(1)\\n        return 1\\n\",\"body\":\"return [item for item in (1,) if value]\",\"call\":\"query(Value())\"},\"set___bool__\":{\"prefix\":\"class Value:\\n    def __bool__(self):\\n        STATE.append(1)\\n        return True\\n\",\"body\":\"return {item for item in (1,) if value}\",\"call\":\"query(Value())\"},\"set___len__\":{\"prefix\":\"class Value:\\n    def __len__(self):\\n        STATE.append(1)\\n        return 1\\n\",\"body\":\"return {item for item in (1,) if value}\",\"call\":\"query(Value())\"},\"dict___bool__\":{\"prefix\":\"class Value:\\n    def __bool__(self):\\n        STATE.append(1)\\n        return True\\n\",\"body\":\"return {item: 1 for item in (1,) if value}\",\"call\":\"query(Value())\"},\"dict___len__\":{\"prefix\":\"class Value:\\n    def __len__(self):\\n        STATE.append(1)\\n        return 1\\n\",\"body\":\"return {item: 1 for item in (1,) if value}\",\"call\":\"query(Value())\"}}")
def source(case):
    row=CASES[case]
    return "STATE=[]\n"+row["prefix"]+"def query(value):\n    "+row["body"].replace("\n","\n    ")+"\n"
@pytest.mark.parametrize("case",tuple(CASES))
def test_native_comprehension_guard_write_requires_strict_block(tmp_path,case):
    text=source(case);path=tmp_path/"service.py";path.write_text(text)
    consumer=tmp_path/"consumer.py";consumer.write_text(text+"\n"+CASES[case]["call"]+"\nassert STATE==[1],STATE\nprint('comprehension-guard-native-write')\n")
    env={key:value for key,value in os.environ.items() if not key.startswith(("PYTHON","BCF_","GIT_","GITHUB_","AGENTBUS_")) and key not in {"GH_TOKEN","VIRTUAL_ENV"}}
    native=subprocess.run([sys.executable,"-I","-B",str(consumer)],cwd=tmp_path,env=env,capture_output=True,text=True,timeout=10)
    assert native.returncode==0,native.stderr
    assert native.stdout=="comprehension-guard-native-write\n" and not native.stderr
    inventory=discover_python_source(tmp_path,files=[path],call_contracts_version="1.0")
    operation={"id":"pattern.query.v1","allowed_mutation_ports":[],"allowed_authority_ports":[],"non_authoritative_output_effects":[]}
    try:validate_operation_effects(operation,"service.py::query",inventory)
    except SemanticOperationEffectError as error:
        assert "unresolved effect" in str(error);return
    pytest.fail("native comprehension-guard write escaped strict effect query")

import ast,hashlib
from bcf_governance.tooling.semantic_operation_effects import source_operation_call_population
def selected():
    return {"id":"comprehension.query.v1","allowed_mutation_ports":[],"allowed_authority_ports":[],"non_authoritative_output_effects":[]}
def guard_rows(inventory):
    return [call for function in inventory["functions"] if function["symbol"]=="service.py::query" for call in function["calls"] if call.get("implicit_protocol",{}).get("kind")=="truth"]
def guard_inventory(tmp_path,case):
    text=source(case);path=tmp_path/"service.py";path.write_text(text)
    return text,discover_python_source(tmp_path,files=[path],call_contracts_version="1.0")
def one_guard(inventory):
    rows=guard_rows(inventory)
    assert len(rows)==1,"comprehension guard source edge omitted"
    return rows[0]
@pytest.mark.parametrize("case",tuple(CASES))
def test_guard_has_exact_neutral_truth_source_identity(tmp_path,case):
    text,inventory=guard_inventory(tmp_path,case);row=one_guard(inventory)
    query=next(n for n in ast.parse(text).body if isinstance(n,ast.FunctionDef) and n.name=="query")
    node=next(n for n in ast.walk(query) if isinstance(n,ast.comprehension)).ifs[0]
    digest=hashlib.sha256(ast.dump(node,include_attributes=False).encode()).hexdigest()
    assert row["implicit_protocol"]=={"version":"1.0","authority":False,"execution_qualified":False,"kind":"truth","expression_sha256":digest,"occurrence":0}
    assert (row["line"],row["column"],row["end_line"],row["end_column"])==(node.lineno,node.col_offset,node.end_lineno,node.end_col_offset)
    assert row["called_symbol"]=="python-implicit::truth" and row["dispatch_resolution"]=="unresolved" and row["dispatch_port_eligible"] is False
    assert row["call_contract"]["arguments"]==[]
    population=source_operation_call_population("service.py::query",inventory)
    assert sum(call[2]==digest and call[4]=="unresolved" for call in population["calls"])==1
    assert population["authority"] is False and population["execution_qualified"] is False
    assert validate_operation_effects(selected(),"service.py::query",inventory,require_runtime_context=False)==(0,0)
@pytest.mark.parametrize("scope",(False,True))
def test_guard_marker_cannot_acquire_port_credit(tmp_path,scope):
    _,inventory=guard_inventory(tmp_path,"list___bool__");one_guard(inventory)
    operation=selected();operation["non_authoritative_output_effects"]=["python-implicit::truth"]
    with pytest.raises(SemanticOperationEffectError,match="unresolved effect|unreachable effect ports"):
        validate_operation_effects(operation,"service.py::query",inventory,require_runtime_context=scope)
@pytest.mark.parametrize("kind",("list","set","dict"))
@pytest.mark.parametrize("guard",("True","False","item"))
def test_literal_and_closed_iterator_guards_remain_no_dispatch(tmp_path,kind,guard):
    expression={"list":"[item for item in (1,) if "+guard+"]","set":"{item for item in (1,) if "+guard+"}","dict":"{item: 1 for item in (1,) if "+guard+"}"}[kind]
    text="def query(value):\n    return "+expression+"\n";path=tmp_path/"service.py";path.write_text(text)
    consumer=tmp_path/"pure.py";consumer.write_text(text+"\nquery(None)\n")
    native=subprocess.run([sys.executable,"-I","-B",str(consumer)],cwd=tmp_path,capture_output=True,text=True,timeout=10)
    assert native.returncode==0,native.stderr
    inventory=discover_python_source(tmp_path,files=[path],call_contracts_version="1.0")
    assert not guard_rows(inventory)
    assert validate_operation_effects(selected(),"service.py::query",inventory)==(0,0)
def test_repeated_bare_guards_keep_independent_occurrences(tmp_path):
    text="def query(value):\n    return [item for item in (1,) if value if value]\n";path=tmp_path/"service.py";path.write_text(text)
    inventory=discover_python_source(tmp_path,files=[path],call_contracts_version="1.0");rows=guard_rows(inventory)
    assert len(rows)==2,"comprehension guard source edge omitted"
    assert [r["implicit_protocol"]["occurrence"] for r in rows]==[0,1]
    assert rows[0]["implicit_protocol"]["expression_sha256"]==rows[1]["implicit_protocol"]["expression_sha256"]
    assert rows[0]["column"]!=rows[1]["column"]
    with pytest.raises(SemanticOperationEffectError,match="unresolved effect"):
        validate_operation_effects(selected(),"service.py::query",inventory)
