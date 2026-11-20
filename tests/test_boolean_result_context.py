"""Boolean result consumption and effectful operand evaluation are distinct."""
import os
import subprocess
import sys

import pytest

from bcf_governance.tooling.semantic_operation_effects import SemanticOperationEffectError, validate_operation_effects
from bcf_governance.tooling.semantic_ownership_inventory import discover_python_source

PURE = {
    "identity_if": ("if value is None:\n    return True\nreturn False", "result is False"),
    "identity_or": ("return value is None or value is False", "result is False"),
    "not_identity": ("return not (value is None)", "result is True"),
    "identity_key": ("return {value is None: 1}", "result == {False: 1}"),
    "not_identity_key": ("return {not (value is None): 1}", "result == {True: 1}"),
    "identity_chain": ("return value is None is False", "result is False"),
    "identity_or_object": ("return value is None or value", "result is value"),
    "identity_guard": ("return [1 for item in [0] if value is not None]", "result == [1]"),
    "identity_set_key": ("return {value is None for item in [0]}", "result == {False}"),
}
UNKNOWN = {
    "double_not": ("return not not value", ["truth"], ["truth"]),
    "if_not": ("if not value:\n    return 1\nreturn 0", ["truth"], ["truth"]),
    "guard_not": ("return [1 for item in [0] if not value]", ["truth"], ["truth"]),
    "property_identity": ("if value.item is None:\n    return 1\nreturn 0", ["attribute_read"], ["attribute"]),
    "rich_comparison": ("return (value == None) or False", ["operator", "truth"], ["eq", "truth"]),
    "unknown_bool_tail": ("if value is None or value:\n    return 1\nreturn 0", ["truth"], ["truth"]),
    "call_identity": ("if effect() is None:\n    return 1\nreturn 0", ["truth"], ["call"]),
}
EXTRA = "\ndef effect():\n    EVENTS.append('call')\n    return None\n"
WITNESSES = '''
EVENTS=[]
class Result:
    def __bool__(self):
        EVENTS.append('truth')
        return True
class Value:
    def __bool__(self):
        EVENTS.append('truth')
        return True
    def __eq__(self, other):
        EVENTS.append('eq')
        return Result()
    @property
    def item(self):
        EVENTS.append('attribute')
        return None
class Explosive:
    def __bool__(self):
        raise AssertionError('unexpected truth callback')
    def __eq__(self, other):
        raise AssertionError('unexpected equality callback')
    def __hash__(self):
        raise AssertionError('unexpected hash callback')
'''


def source(body):
    return "def query(value):\n    " + body.replace("\n", "\n    ") + "\n" + EXTRA


def inventory(tmp_path, body):
    path = tmp_path / "service.py"
    path.write_text(source(body))
    return discover_python_source(tmp_path, files=[path], call_contracts_version="1.0")


def operation():
    return {"id":"boolean-result.query.v1", "allowed_mutation_ports":[],
            "allowed_authority_ports":[], "non_authoritative_output_effects":[]}


def query(facts):
    return next(row for row in facts["functions"] if row["symbol"] == "service.py::query")


def native(tmp_path, body, trailer):
    path = tmp_path / "ordinary_consumer.py"
    path.write_text(WITNESSES + source(body) + trailer + "\nprint('native-boolean-context-witnessed')\n")
    env = {k:v for k,v in os.environ.items() if not k.startswith(("PYTHON","BCF_","GIT_","GITHUB_","AGENTBUS_"))
           and k not in {"GH_TOKEN","VIRTUAL_ENV"}}
    result = subprocess.run([sys.executable,"-I","-B",str(path)],cwd=tmp_path,env=env,capture_output=True,text=True)
    assert result.returncode == 0, result.stdout + result.stderr
    assert result.stdout.strip() == "native-boolean-context-witnessed"


@pytest.mark.parametrize("case", PURE)
def test_supported_identity_body_is_accepted_by_strict_scanner(tmp_path, case):
    assert validate_operation_effects(operation(),"service.py::query",inventory(tmp_path,PURE[case][0])) == (0,0)


@pytest.mark.parametrize("case", PURE)
def test_ordinary_consumer_never_invokes_arbitrary_receiver_hooks(tmp_path, case):
    body, expected = PURE[case]
    native(tmp_path,body,"\nvalue=Explosive()\nresult=query(value)\nassert " + expected + "\nassert EVENTS == []\n")


@pytest.mark.parametrize("case", UNKNOWN)
def test_supported_result_context_retains_operand_or_fallback_obligations(tmp_path, case):
    body, expected, _ = UNKNOWN[case]
    calls = query(inventory(tmp_path,body))["calls"]
    markers = [row["implicit_protocol"] for row in calls if "implicit_protocol" in row]
    assert sorted(row["kind"] for row in markers) == expected
    assert all(row["authority"] is False and row["execution_qualified"] is False for row in markers)


@pytest.mark.parametrize("case", UNKNOWN)
def test_unsupported_operand_context_still_blocks_strict_operation(tmp_path, case):
    with pytest.raises(SemanticOperationEffectError):
        validate_operation_effects(operation(),"service.py::query",inventory(tmp_path,UNKNOWN[case][0]))


@pytest.mark.parametrize("case", UNKNOWN)
def test_ordinary_consumer_independently_witnesses_retained_effects(tmp_path, case):
    body, _, expected = UNKNOWN[case]
    native(tmp_path,body,"\nquery(Value())\nassert EVENTS == " + repr(expected) + "\n")


def test_result_eligibility_cannot_expand_call_free_store_ownership(tmp_path):
    facts = inventory(tmp_path,"data={}\nflag=effect() is None\ndata['key']=value\nreturn flag")
    stores = query(facts)["source_store_observations"]
    assert len(stores) == 1 and stores[0]["disposition"] == "unresolved_object_binding"
    with pytest.raises(SemanticOperationEffectError):
        validate_operation_effects(operation(),"service.py::query",facts)


@pytest.mark.parametrize("body", ["return GLOBAL is None or GLOBAL is False", "global GLOBAL\nreturn value is None or value is False"])
def test_unqualified_global_or_statement_context_keeps_conservative_refusal(tmp_path, body):
    with pytest.raises(SemanticOperationEffectError):
        validate_operation_effects(operation(),"service.py::query",inventory(tmp_path,body))
