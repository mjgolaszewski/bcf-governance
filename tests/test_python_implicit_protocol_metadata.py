"""Versioned implicit observations cannot grant runtime authority or disappear."""
import ast,hashlib
from copy import deepcopy
import pytest
from bcf_governance.tooling.semantic_ownership_inventory import discover_python_source
from bcf_governance.tooling.semantic_operation_effects import SemanticOperationEffectError,source_operation_call_population,validate_operation_effects
SOURCE="def query(value):\n    return value[0]\n"
def inventory(tmp_path):
    path=tmp_path/"service.py";path.write_text(SOURCE)
    return discover_python_source(tmp_path,files=[path],call_contracts_version="1.0")
def operation():
    return {"id":"protocol-metadata.query.v1","allowed_mutation_ports":[],"allowed_authority_ports":[],
            "non_authoritative_output_effects":["python-implicit::subscript_read"]}
def test_independent_ast_protocol_edge_reaches_existing_source_population(tmp_path):
    facts=inventory(tmp_path)
    calls=facts["functions"][0]["calls"]
    node=ast.parse(SOURCE).body[0].body[0].value
    digest=hashlib.sha256(ast.dump(node,include_attributes=False).encode()).hexdigest()
    protocols=[row for row in calls if "implicit_protocol" in row]
    assert len(protocols)==1,"implicit source edge omitted"
    row=protocols[0]
    assert row["implicit_protocol"]["expression_sha256"]==digest
    population=source_operation_call_population("service.py::query",facts)
    assert population["unresolved_calls"]==1
    assert len(population["calls"])==1
    assert population["calls"][0][2]==digest
@pytest.mark.parametrize("consumer",("population","effects","source-only"))
@pytest.mark.parametrize("defect",("authority","execution","version","kind","digest","occurrence","eligible","resolution","callee","caller","marker","contract"))
def test_forged_implicit_protocol_cannot_be_credited_as_a_port(tmp_path,consumer,defect):
    facts=inventory(tmp_path)
    row=next((row for row in facts["functions"][0]["calls"] if "implicit_protocol" in row),None)
    assert row is not None,"implicit source edge omitted"
    marker=row["implicit_protocol"]
    if defect=="authority":marker["authority"]=True
    elif defect=="execution":marker["execution_qualified"]=True
    elif defect=="version":marker["version"]="999"
    elif defect=="kind":marker["kind"]=[]
    elif defect=="digest":marker["expression_sha256"]="0"
    elif defect=="occurrence":marker["occurrence"]=True
    elif defect=="eligible":row["dispatch_port_eligible"]=True
    elif defect=="resolution":row["dispatch_resolution"]="source"
    elif defect=="callee":row["called_symbol"]="service.py::safe"
    elif defect=="caller":row["caller"]="service.py::other"
    elif defect=="marker":row.pop("implicit_protocol")
    else:row["call_contract"]["arguments"]=[{"kind":"positional","slot":0,"expression_sha256":"a"*64}]
    with pytest.raises(SemanticOperationEffectError,match="implicit protocol population"):
        if consumer=="population":source_operation_call_population("service.py::query",facts)
        else:validate_operation_effects(operation(),"service.py::query",facts,require_runtime_context=consumer!="source-only")
