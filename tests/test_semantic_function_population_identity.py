"""Every effect consumer rejects ambiguous function identity before traversal."""
import copy
import pytest
from bcf_governance.tooling.semantic_ownership_inventory import discover_python_source
from bcf_governance.tooling.semantic_operation_effects import (
 SemanticOperationEffectError, source_operation_call_population,
 validated_operation_effect_inventory, validate_operation_effects,
)

def facts(tmp_path, source="def query():\n    return 1\ndef unused():\n    return 2\n"):
 path=tmp_path/"service.py";path.write_text(source)
 return discover_python_source(tmp_path,files=[path],call_contracts_version="1.0")

def operation():
 return {"id":"identity.query.v1","allowed_mutation_ports":[],
         "allowed_authority_ports":[],"non_authoritative_output_effects":[]}

@pytest.mark.parametrize("consumer",(validated_operation_effect_inventory,validate_operation_effects))
@pytest.mark.parametrize("scope",(True,False))
@pytest.mark.parametrize("conflicting",(False,True))
@pytest.mark.parametrize("position",(0,-1))
def test_effect_consumers_reject_duplicate_identities_before_resolution(tmp_path,consumer,scope,conflicting,position):
 inventory=facts(tmp_path)
 row=copy.deepcopy(next(v for v in inventory["functions"] if v["symbol"]=="service.py::query"))
 if conflicting:row["line"]=999
 inventory["functions"].insert(position,row)
 with pytest.raises(SemanticOperationEffectError,match="function population.*ambiguous"):
  consumer(operation(),"service.py::query",inventory,require_runtime_context=scope)

@pytest.mark.parametrize("consumer",(validated_operation_effect_inventory,validate_operation_effects))
@pytest.mark.parametrize("scope",(True,False))
def test_unique_function_populations_retain_effect_behavior(tmp_path,consumer,scope):
 inventory=facts(tmp_path);before=copy.deepcopy(inventory)
 expected=() if consumer is validated_operation_effect_inventory else (0,0)
 assert consumer(operation(),"service.py::query",inventory,require_runtime_context=scope)==expected
 assert inventory==before

@pytest.mark.parametrize("conflicting",(False,True))
def test_call_population_retains_duplicate_rejection(tmp_path,conflicting):
 inventory=facts(tmp_path);row=copy.deepcopy(inventory["functions"][0])
 if conflicting:row["line"]=999
 inventory["functions"].append(row)
 with pytest.raises(SemanticOperationEffectError):
  source_operation_call_population("service.py::query",inventory)

def test_unique_source_population_is_order_independent(tmp_path):
 inventory=facts(tmp_path);before=source_operation_call_population("service.py::query",inventory)
 inventory["functions"].reverse()
 assert source_operation_call_population("service.py::query",inventory)==before

def test_explicit_typing_overload_stubs_do_not_duplicate_runtime_identity(tmp_path):
 source="from typing import overload\n@overload\ndef query(value:int)->int: ...\n@overload\ndef query(value:str)->str: ...\ndef query(value):\n    return 1\n"
 inventory=facts(tmp_path,source)
 assert [v["symbol"] for v in inventory["functions"]]==["service.py::query"]
 assert validate_operation_effects(operation(),"service.py::query",inventory)==(0,0)
