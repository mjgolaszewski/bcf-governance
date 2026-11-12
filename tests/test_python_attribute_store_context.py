"""Attribute stores retain source obligations regardless of receiver spelling."""
from pathlib import Path
from copy import deepcopy
import os
import subprocess
import sys
import pytest
from bcf_governance.tooling.semantic_operation_effects import SemanticOperationEffectError, source_operation_call_population, validate_operation_effects
from bcf_governance.tooling.semantic_ownership_inventory import discover_python_source, resolve_python_imports
CASES = {"receiver":["class Service:\n    def query(self):\n        self.value = 1\n        return 1\n","value=Service()\nassert value.query()==1 and value.value==1\n","service.py::Service.query"],"parameter":["class Box: pass\ndef query(value):\n    value.item=1\n    return 1\n","value=Box()\nassert query(value)==1 and value.item==1\n","service.py::query"],"alias":["class Box: pass\ndef query(value):\n    alias=value\n    alias.item=1\n    return 1\n","value=Box()\nassert query(value)==1 and value.item==1\n","service.py::query"],"delete":["class Box: pass\ndef query(value):\n    del value.item\n    return 1\n","value=Box()\nvalue.item=0\nassert query(value)==1 and not hasattr(value,'item')\n","service.py::query"],"augment":["class Box: pass\ndef query(value):\n    value.item+=1\n    return 1\n","value=Box()\nvalue.item=0\nassert query(value)==1 and value.item==1\n","service.py::query"],"descriptor":["STATE=[]\nclass Descriptor:\n    def __set__(self,owner,value):\n        STATE.append(value)\nclass Box:\n    item=Descriptor()\ndef query(value):\n    value.item=1\n    return 1\n","assert query(Box())==1 and STATE==[1]\n","service.py::query"],"fresh-spelling":["HELD=[]\nclass Box:\n    def __new__(cls):\n        return HELD[0]\ndef query():\n    value=Box()\n    value.item=1\n    return 1\n","value=object.__new__(Box)\nHELD.append(value)\nassert query()==1 and value.item==1\n","service.py::query"],"init-spelling":["class Box:\n    def __init__(self,other):\n        other.item=1\n","value=object.__new__(Box)\nother=object.__new__(Box)\nBox.__init__(value,other)\nassert other.item==1\n","service.py::Box.__init__"]}
def inventory(tmp_path, source):
    path=tmp_path/"service.py"
    path.write_text(source)
    return resolve_python_imports(tmp_path,discover_python_source(tmp_path,files=[path],call_contracts_version="1.0"))
def operation():
    return {"id":"attribute-store.query.v1","allowed_mutation_ports":[],"allowed_authority_ports":[],"non_authoritative_output_effects":[]}
@pytest.mark.parametrize("case",tuple(CASES))
def test_attribute_source_population_retains_obligation(tmp_path,case):
    source,_,symbol=CASES[case]
    facts=inventory(tmp_path,source)
    function=next(row for row in facts["functions"] if row["symbol"]==symbol)
    rows=function.get("source_store_observations",[])
    assert rows,"attribute source store observations omitted"
    assert all(row["kind"] in {"attribute_store","attribute_delete"} and row["authority"] is row["execution_qualified"] is False and row["disposition"]=="unresolved_object_binding" for row in rows)
    population=source_operation_call_population(symbol,facts)
    assert len([row for row in population.get("source_stores",()) if row[0]==symbol])==len(rows)
    assert population["authority"] is population["execution_qualified"] is False
@pytest.mark.parametrize("case",tuple(CASES))
def test_effect_consumer_rejects_unqualified_attribute_store(tmp_path,case):
    source,_,symbol=CASES[case]
    with pytest.raises(SemanticOperationEffectError,match="(unresolved effect|source construction|undeclared write)"):
        validate_operation_effects(operation(),symbol,inventory(tmp_path,source))
@pytest.mark.parametrize("case",tuple(CASES))
def test_fresh_consumer_witnesses_attribute_mutation(tmp_path,case):
    source,witness,_=CASES[case]
    path=tmp_path/"consumer.py"
    path.write_text(source+"\n"+witness+"print('attribute-context-witnessed')\n")
    env={key:value for key,value in os.environ.items() if not key.startswith(("PYTHON","BCF_","GIT_","GITHUB_","AGENTBUS_")) and key not in {"GH_TOKEN","VIRTUAL_ENV"}}
    result=subprocess.run([sys.executable,"-I","-B",str(path)],cwd=tmp_path,env=env,capture_output=True,text=True,timeout=10)
    assert result.returncode==0,result.stderr
    assert result.stdout=="attribute-context-witnessed\n" and not result.stderr

@pytest.mark.parametrize("consumer",("population","effects"))
@pytest.mark.parametrize("defect",("authority","execution","local-disposition"))
def test_forged_attribute_store_observation_cannot_grant_authority(tmp_path,consumer,defect):
    source,_,symbol=CASES["parameter"]
    facts=inventory(tmp_path,source)
    function=next(row for row in facts["functions"] if row["symbol"]==symbol)
    rows=function.get("source_store_observations",[])
    assert rows,"attribute source store observations omitted"
    if defect=="authority":
        rows[0]["authority"]=True
    elif defect=="execution":
        rows[0]["execution_qualified"]=True
    else:
        rows[0]["disposition"]="closed_native_literal_region"
        function["effects"]=[]
    with pytest.raises(SemanticOperationEffectError,match="source store population"):
        if consumer=="population":
            source_operation_call_population(symbol,facts)
        else:
            validate_operation_effects(operation(),symbol,facts)
