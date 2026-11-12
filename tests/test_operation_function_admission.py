"""Outer operation admission rejects uncertain source identities before filtering."""
import copy
from pathlib import Path
import pytest
from bcf_governance.tooling import semantic_authority_contracts as contracts
from bcf_governance.tooling.semantic_ownership_inventory import discover_python_source
ROOT=Path(__file__).resolve().parents[1]
PAYLOAD="{\"schema_version\":\"1.0\",\"document\":{\"kind\":\"application_operation_registry\",\"id\":\"fixture-operations\",\"version\":\"1.0.0\",\"status\":\"active\",\"path\":\"governance/application-operations.yml\"},\"populations\":[{\"id\":\"fixture\",\"adapter\":\"typescript_exports\",\"source\":\"fixture.ts\",\"symbol\":\"exports\",\"public_only\":true,\"tsconfig\":\"tsconfig.json\",\"package_lock\":\"package-lock.json\",\"node_executable\":\"node\"}],\"operations\":[{\"id\":\"fixture.query.v1\",\"population\":\"fixture\",\"population_key\":\"query\",\"family\":\"fixture\",\"bounded_context\":\"tooling\",\"entrypoints\":[\"service.py::query\"],\"semantic_kind\":\"query\",\"authoritative_read\":false,\"authoritative_mutation\":false,\"authority_conferral\":false,\"produces_projection\":false,\"model_callable\":false,\"allowed_mutation_ports\":[],\"allowed_authority_ports\":[],\"non_authoritative_output_effects\":[]}],\"migrations\":[]}"
def payload():
    import json
    return json.loads(PAYLOAD)
def inventory(tmp_path):
    path=tmp_path/"service.py";path.write_text("def query():\n    return 1\n")
    return discover_python_source(tmp_path,files=[path])
def duplicate(source,conflicting,position):
    row=copy.deepcopy(source["functions"][0])
    if conflicting:row["line"]=999
    source["functions"].insert(position,row)

@pytest.mark.parametrize("conflicting",(False,True))
@pytest.mark.parametrize("position",(0,-1))
def test_filtered_population_cannot_accept_duplicate_functions(tmp_path,conflicting,position):
    source=inventory(tmp_path);duplicate(source,conflicting,position)
    try:
        contracts._validate_operations(ROOT,payload(),source,source_language="python")
    except contracts.SemanticAuthorityError as error:
        assert "function population" in str(error) and "ambiguous" in str(error)
    else:
        pytest.fail("filtered operation population accepted duplicate function identity")

@pytest.mark.parametrize("conflicting",(False,True))
def test_duplicate_functions_reject_before_population_resolver(tmp_path,monkeypatch,conflicting):
    source=inventory(tmp_path);duplicate(source,conflicting,0);entered=[]
    selected=payload();selected["populations"][0]={"id":"fixture","adapter":"python_module_exports","source":"service.py","symbol":"exports","public_only":True}
    def resolver(*args,**kwargs):
        entered.append(True);return {"query":"service.py::query"}
    monkeypatch.setattr(contracts,"_discover_population",resolver)
    with pytest.raises(contracts.SemanticAuthorityError,match="function population.*ambiguous"):
        contracts._validate_operations(ROOT,selected,source)
    assert not entered,"ambiguous function population reached population resolver"

@pytest.mark.parametrize("scope",(False,True))
def test_unique_function_population_retains_ordinary_admission(tmp_path,scope):
    import shutil
    source=inventory(tmp_path);selected=payload();selected["populations"][0]={"id":"fixture","adapter":"python_module_exports","source":"service.py","symbol":"exports","public_only":True}
    (tmp_path/"schemas").mkdir();shutil.copyfile(ROOT/"schemas/application-operations.schema.json",tmp_path/"schemas/application-operations.schema.json")
    before=copy.deepcopy(source)
    observed=contracts._validate_operations(tmp_path,selected,source,require_runtime_context=scope)
    assert [row["operation"] for row in observed]==["fixture.query.v1"]
    assert observed[0]["effect_ports"]==[] and source==before

def test_unique_filtered_population_retains_empty_observation(tmp_path):
    source=inventory(tmp_path);before=copy.deepcopy(source)
    assert contracts._validate_operations(ROOT,payload(),source,source_language="python")==[]
    assert source==before
