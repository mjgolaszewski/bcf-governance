"""Ordinary implicit-protocol consumers independently witness hidden effects."""
import json,os,subprocess,sys
import pytest
from bcf_governance.tooling.semantic_ownership_inventory import discover_python_source
from bcf_governance.tooling.semantic_operation_effects import SemanticOperationEffectError,validate_operation_effects
CASES=json.loads("{\"dict_literal\":{\"prefix\":\"class Key:\\n    def __hash__(self):\\n        STATE.append(1)\\n        return 7\\n\",\"body\":\"return {value: 1}\",\"call\":\"query(Key())\"},\"set_literal\":{\"prefix\":\"class Key:\\n    def __hash__(self):\\n        STATE.append(1)\\n        return 7\\n\",\"body\":\"return {value}\",\"call\":\"query(Key())\"},\"dict_comprehension\":{\"prefix\":\"class Key:\\n    def __hash__(self):\\n        STATE.append(1)\\n        return 7\\n\",\"body\":\"return {key: 1 for key in value}\",\"call\":\"query([Key()])\"},\"set_comprehension\":{\"prefix\":\"class Key:\\n    def __hash__(self):\\n        STATE.append(1)\\n        return 7\\n\",\"body\":\"return {key for key in value}\",\"call\":\"query([Key()])\"},\"list_comprehension\":{\"prefix\":\"class Value:\\n    def __iter__(self):\\n        STATE.append(1)\\n        return iter((1,))\\n\",\"body\":\"return [item for item in value]\",\"call\":\"query(Value())\"},\"for_iteration\":{\"prefix\":\"class Value:\\n    def __iter__(self):\\n        STATE.append(1)\\n        return iter((1,))\\n\",\"body\":\"for item in value:\\n    pass\\nreturn 1\",\"call\":\"query(Value())\"},\"binary_operator\":{\"prefix\":\"class Value:\\n    def __add__(self, other):\\n        STATE.append(1)\\n        return 1\\n\",\"body\":\"return value + 1\",\"call\":\"query(Value())\"},\"truth_test\":{\"prefix\":\"class Value:\\n    def __bool__(self):\\n        STATE.append(1)\\n        return True\\n\",\"body\":\"if value:\\n    return 1\\nreturn 1\",\"call\":\"query(Value())\"},\"context_manager\":{\"prefix\":\"class Value:\\n    def __enter__(self):\\n        STATE.append(1)\\n        return self\\n    def __exit__(self, *args):\\n        return False\\n\",\"body\":\"with value:\\n    pass\\nreturn 1\",\"call\":\"query(Value())\"},\"formatting\":{\"prefix\":\"class Value:\\n    def __format__(self, spec):\\n        STATE.append(1)\\n        return '1'\\n\",\"body\":\"return f'{value}'\",\"call\":\"query(Value())\"},\"attribute_read\":{\"prefix\":\"class Value:\\n    @property\\n    def item(self):\\n        STATE.append(1)\\n        return 1\\n\",\"body\":\"return value.item\",\"call\":\"query(Value())\"},\"subscript_read\":{\"prefix\":\"class Value:\\n    def __getitem__(self, key):\\n        STATE.append(1)\\n        return 1\\n\",\"body\":\"return value[0]\",\"call\":\"query(Value())\"}}")
PURE=json.loads("{\"literal\":{\"source\":\"STATE=[]\\ndef query():\\n    return {1: 2}\\n\",\"call\":\"query()\"},\"deferred\":{\"source\":\"STATE=[]\\nclass Value:\\n    def __getitem__(self, key):\\n        STATE.append(1)\\n        return 1\\ndef query(value):\\n    unused=lambda: value[0]\\n    return 1\\n\",\"call\":\"query(Value())\"}}")
def fixture(case):
    row=CASES[case]
    return "STATE=[]\n"+row["prefix"]+"def query(value):\n    "+row["body"].replace("\n","\n    ")+"\n"
def inventory(tmp_path,source):
    path=tmp_path/"service.py";path.write_text(source)
    return discover_python_source(tmp_path,files=[path],call_contracts_version="1.0")
def operation():
    return {"id":"implicit-protocol.query.v1","allowed_mutation_ports":[],"allowed_authority_ports":[],"non_authoritative_output_effects":[]}
@pytest.mark.parametrize("case",tuple(CASES))
def test_implicit_protocol_cannot_hide_shared_write(tmp_path,case):
    with pytest.raises(SemanticOperationEffectError,match="unresolved effect"):
        validate_operation_effects(operation(),"service.py::query",inventory(tmp_path,fixture(case)))
def run_consumer(tmp_path,source,call,expected):
    path=tmp_path/"consumer.py"
    path.write_text(source+"\n"+call+"\nassert STATE == "+repr(expected)+"\nprint('implicit-protocol-witnessed')\n")
    env={k:v for k,v in os.environ.items() if not k.startswith(("PYTHON","BCF_","GIT_","GITHUB_","AGENTBUS_")) and k not in {"GH_TOKEN","VIRTUAL_ENV"}}
    result=subprocess.run([sys.executable,"-I","-B",str(path)],cwd=tmp_path,env=env,capture_output=True,text=True,timeout=10)
    assert result.returncode==0,result.stderr
    assert result.stdout=="implicit-protocol-witnessed\n"
    assert not result.stderr
@pytest.mark.parametrize("case",tuple(CASES))
def test_fresh_native_consumer_witnesses_implicit_protocol_write(tmp_path,case):
    run_consumer(tmp_path,fixture(case),CASES[case]["call"],[1])
@pytest.mark.parametrize("case",tuple(PURE))
def test_closed_literal_or_deferred_body_remains_valid(tmp_path,case):
    assert validate_operation_effects(operation(),"service.py::query",inventory(tmp_path,PURE[case]["source"]))==(0,0)
@pytest.mark.parametrize("case",tuple(PURE))
def test_fresh_native_consumer_preserves_pure_context(tmp_path,case):
    run_consumer(tmp_path,PURE[case]["source"],PURE[case]["call"],[])
