"""Source-only observations cannot be mistaken for runtime authorization."""
import pytest
from bcf_governance.tooling.semantic_ownership_inventory import discover_python_source
from bcf_governance.tooling.semantic_operation_effects import SemanticOperationEffectError,validated_operation_effect_inventory,validate_operation_effects
def inventory(tmp_path,source="def query(value):\n    return value[0]\n"):
    path=tmp_path/"service.py";path.write_text(source)
    return discover_python_source(tmp_path,files=[path],call_contracts_version="1.0")
def operation():
    return {"id":"source-scope.query.v1","allowed_mutation_ports":[],"allowed_authority_ports":[],"non_authoritative_output_effects":[]}
def test_source_only_view_retains_unknown_without_changing_strict_default(tmp_path):
    facts=inventory(tmp_path)
    ports=validated_operation_effect_inventory(operation(),"service.py::query",facts,require_runtime_context=False)
    assert len(ports)==1 and ports[0][0:2]==("unresolved","implicit_protocol")
    assert validate_operation_effects(operation(),"service.py::query",facts,require_runtime_context=False)==(0,0)
    with pytest.raises(SemanticOperationEffectError,match="unresolved effect runtime protocol"):
        validate_operation_effects(operation(),"service.py::query",facts)
@pytest.mark.parametrize("consumer",(validated_operation_effect_inventory,validate_operation_effects))
@pytest.mark.parametrize("defect",(None,0,"false",{}))
def test_scope_switch_is_typed(tmp_path,consumer,defect):
    with pytest.raises(SemanticOperationEffectError,match="requirement must be boolean"):
        consumer(operation(),"service.py::query",inventory(tmp_path),require_runtime_context=defect)
def test_source_only_view_does_not_excuse_explicit_unowned_write(tmp_path):
    source="STATE=0\ndef query(value):\n    global STATE\n    STATE=1\n    return value[0]\n"
    with pytest.raises(SemanticOperationEffectError,match="undeclared write"):
        validate_operation_effects(operation(),"service.py::query",inventory(tmp_path,source),require_runtime_context=False)
