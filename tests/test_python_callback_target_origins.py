"""Unknown parameter target facts stay conservative through both consumers."""
from copy import deepcopy
import pytest
from bcf_governance.tooling.semantic_ownership_inventory import discover_python_source, resolve_python_imports
from bcf_governance.tooling.semantic_operation_effects import SemanticOperationEffectError, source_operation_call_population, validate_operation_effects
CASES={
"direct":("def query(callback):\n    return callback()\n","callback"),
"alias":("def query(callback):\n    selected=callback\n    return selected()\n","callback"),
"indexed":("def query(callbacks):\n    return callbacks[0]()\n","callbacks"),
"method":("def query(value):\n    return value.read()\n","value"),
"source-shadow":("def callback():\n    return 1\ndef query(callback):\n    return callback()\n","callback"),
"import-shadow":("from math import sin as callback\ndef query(callback):\n    return callback()\n","callback"),
}
def inventory(tmp_path,case):
    source,_=CASES[case]
    path=tmp_path/"service.py";path.write_text(source)
    return resolve_python_imports(tmp_path,discover_python_source(tmp_path,files=[path],call_contracts_version="1.0"))
def operation():
    return {"id":"runtime-target.query.v1","allowed_mutation_ports":[],"allowed_authority_ports":[],"non_authoritative_output_effects":[]}
@pytest.mark.parametrize("case",tuple(CASES))
def test_parameter_target_population_cannot_gain_source_authority(tmp_path,case):
    facts=inventory(tmp_path,case)
    query=next(row for row in facts["functions"] if row["symbol"]=="service.py::query")
    assert query["calls"][0].get("runtime_target_origins")==["parameter:"+CASES[case][1]],"runtime target origins omitted"
    population=source_operation_call_population("service.py::query",facts)
    assert population["unresolved_calls"]>=1
    assert all(row[4]=="unresolved" for row in population["calls"] if row[0]=="service.py::query")
    assert population["authority"] is population["execution_qualified"] is False
@pytest.mark.parametrize("consumer",("population","effects"))
@pytest.mark.parametrize("defect",("empty","boolean","unknown-parameter","duplicate"))
def test_incompatible_runtime_target_origins_cannot_be_used(tmp_path,consumer,defect):
    facts=inventory(tmp_path,"direct")
    query=next(row for row in facts["functions"] if row["symbol"]=="service.py::query")
    call=query["calls"][0]
    assert call.get("runtime_target_origins"),"runtime target origins omitted"
    call["runtime_target_origins"]={"empty":[],"boolean":True,"unknown-parameter":["parameter:other"],"duplicate":["parameter:callback","parameter:callback"]}[defect]
    with pytest.raises(SemanticOperationEffectError,match="runtime target population"):
        if consumer=="population":
            source_operation_call_population("service.py::query",facts)
        else:
            validate_operation_effects(operation(),"service.py::query",facts)
