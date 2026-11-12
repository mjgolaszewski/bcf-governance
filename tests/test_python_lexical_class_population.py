"""Lexical class owners remain source-complete without runtime authority."""
import json
import pytest
from bcf_governance.tooling.semantic_ownership_inventory import discover_python_source
from bcf_governance.tooling.semantic_operation_effects import SemanticOperationEffectError,source_operation_call_population,validate_operation_effects

CASES=json.loads("{\"module\":{\"source\":\"class C:\\n    def read(self):\\n        return 1\\ndef query():\\n    return 1\\n\",\"classes\":[\"C\"],\"methods\":[\"C.read\"]},\"local\":{\"source\":\"def query():\\n    class Local:\\n        def read(self):\\n            return 1\\n    return 1\\n\",\"classes\":[\"query.<locals>.Local\"],\"methods\":[\"query.<locals>.Local.read\"]},\"conditional_local\":{\"source\":\"def query():\\n    if False:\\n        class Local:\\n            def read(self):\\n                return 1\\n    return 1\\n\",\"classes\":[\"query.<locals>.Local\"],\"methods\":[\"query.<locals>.Local.read\"]},\"nested_local\":{\"source\":\"def query():\\n    class Outer:\\n        class Inner:\\n            def read(self):\\n                return 1\\n    return 1\\n\",\"classes\":[\"query.<locals>.Outer\",\"query.<locals>.Outer.Inner\"],\"methods\":[\"query.<locals>.Outer.Inner.read\"]},\"nested_module\":{\"source\":\"class Outer:\\n    class Inner:\\n        def read(self):\\n            return 1\\ndef query():\\n    return 1\\n\",\"classes\":[\"Outer\",\"Outer.Inner\"],\"methods\":[\"Outer.Inner.read\"]},\"conditional_module\":{\"source\":\"if False:\\n    class Conditional:\\n        def read(self):\\n            return 1\\ndef query():\\n    return 1\\n\",\"classes\":[\"Conditional\"],\"methods\":[\"Conditional.read\"]},\"method_local\":{\"source\":\"class Outer:\\n    def run(self):\\n        class Local:\\n            def read(self):\\n                return 1\\n        return 1\\ndef query():\\n    return 1\\n\",\"classes\":[\"Outer\",\"Outer.run.<locals>.Local\"],\"methods\":[\"Outer.run\",\"Outer.run.<locals>.Local.read\"]},\"nested_function\":{\"source\":\"def query():\\n    def inner():\\n        class Local:\\n            def read(self):\\n                return 1\\n        return 1\\n    return 1\\n\",\"classes\":[\"query.<locals>.inner.<locals>.Local\"],\"methods\":[\"query.<locals>.inner.<locals>.Local.read\"]}}")
def inventory(tmp_path,case):
    path=tmp_path/"service.py";path.write_text(CASES[case]["source"])
    return discover_python_source(tmp_path,files=[path],call_contracts_version="1.0")
def operation():
    return {"id":"lexical-class.query.v1","allowed_mutation_ports":[],"allowed_authority_ports":[],"non_authoritative_output_effects":[]}
@pytest.mark.parametrize("case",tuple(CASES))
def test_every_declared_class_and_method_has_its_source_owner(tmp_path,case):
    facts=inventory(tmp_path,case)
    expected={"service.py::"+name for name in CASES[case]["classes"]}
    assert {row["symbol"] for row in facts["classes"]}==expected
    assert set(facts["types"])==expected
    functions={row["symbol"]:row for row in facts["functions"]}
    for method in CASES[case]["methods"]:
        symbol="service.py::"+method
        assert symbol in functions
        assert functions[symbol]["class_symbol"]==symbol.rpartition(".")[0]
    assert all(row.get("class_symbol") is None or row["class_symbol"] in expected for row in facts["functions"])
@pytest.mark.parametrize("case",tuple(CASES))
def test_source_population_keeps_neutral_lexical_classes(tmp_path,case):
    population=source_operation_call_population("service.py::query",inventory(tmp_path,case))
    assert population["authority"] is False
    assert population["execution_qualified"] is False
@pytest.mark.parametrize("consumer",("population","effects"))
@pytest.mark.parametrize("defect",("class","type"))
def test_forged_missing_lexical_class_owner_is_blocked(tmp_path,consumer,defect):
    facts=inventory(tmp_path,"local")
    assert facts["classes"] and facts["types"],"lexical class source population absent"
    if defect=="class":facts["classes"]=[]
    else:facts["types"]=[]
    with pytest.raises(SemanticOperationEffectError,match="class/type population is incomplete"):
        if consumer=="population":source_operation_call_population("service.py::query",facts)
        else:validate_operation_effects(operation(),"service.py::query",facts)
