"""Independent grammar spans and explicit marker-version compatibility."""
import ast,copy,hashlib,json
from pathlib import Path
import pytest
from jsonschema import Draft202012Validator,ValidationError
from bcf_governance.tooling.semantic_ownership_inventory import discover_python_source
from bcf_governance.tooling.semantic_operation_effects import SemanticOperationEffectError,source_operation_call_population,validate_operation_effects
from test_python_implicit_grammar_effects import CASES,source,operation
ROOT=Path(__file__).resolve().parents[1]
EXPECTED={"unary":("UnaryOp","operator","1.0"),"comparison":("Compare","operator","1.0"),"containment":("Compare","operator","1.0"),"boolean_expression":("BoolOp","truth","1.0"),"starred_sequence":("Starred","iteration","1.0"),"unpack_assignment":("Assign","iteration","1.0"),"raised_class":("Raise","exception","1.1"),"await_value":("Await","await","1.1"),"delegated_generator":("YieldFrom","iteration","1.0")}
def facts(tmp_path,text):
 path=tmp_path/"service.py";path.write_text(text)
 return discover_python_source(tmp_path,files=[path],call_contracts_version="1.0")
def schema():
 value=json.loads((ROOT/"schemas/semantic-call-contracts.schema.json").read_text())
 return Draft202012Validator({"$defs":value["$defs"],"$ref":"#/$defs/implicit_protocol"})
@pytest.mark.parametrize("case",tuple(EXPECTED))
def test_every_grammar_span_has_one_neutral_existing_call_edge(tmp_path,case):
 text=source(case);inventory=facts(tmp_path,text)
 syntax,kind,version=EXPECTED[case]
 query=next(node for node in ast.parse(text).body if isinstance(node,(ast.FunctionDef,ast.AsyncFunctionDef)) and node.name=="query")
 nodes=[node for node in ast.walk(query) if type(node).__name__==syntax]
 assert len(nodes)==1
 node=nodes[0];digest=hashlib.sha256(ast.dump(node,include_attributes=False).encode()).hexdigest()
 rows=[call for function in inventory["functions"] if function["symbol"]=="service.py::query" for call in function["calls"] if call.get("implicit_protocol",{}).get("expression_sha256")==digest]
 assert len(rows)==1,"implicit grammar edge omitted"
 row=rows[0];assert row["called_symbol"]=="python-implicit::"+kind
 assert row["dispatch_resolution"]=="unresolved" and row["dispatch_port_eligible"] is False
 assert row["implicit_protocol"]=={"version":version,"authority":False,"execution_qualified":False,"kind":kind,"expression_sha256":digest,"occurrence":0}
 assert (row["line"],row["column"],row["end_line"],row["end_column"])==(node.lineno,node.col_offset,node.end_lineno,node.end_col_offset)
 assert row["call_contract"]["arguments"]==[]
 schema().validate(row["implicit_protocol"])
 population=source_operation_call_population("service.py::query",inventory)
 assert sum(call[2]==digest for call in population["calls"])==1
 assert validate_operation_effects(operation(),"service.py::query",inventory,require_runtime_context=False)==(0,0)
@pytest.mark.parametrize("case",("unary","raised_class","await_value"))
@pytest.mark.parametrize("consumer",("population","strict","source-only","schema"))
def test_cross_version_marker_relabeling_rejects(tmp_path,case,consumer):
 inventory=facts(tmp_path,source(case));kind=EXPECTED[case][1]
 rows=[call for function in inventory["functions"] if function["symbol"]=="service.py::query" for call in function["calls"] if call.get("implicit_protocol",{}).get("kind")==kind]
 assert len(rows)==1,"implicit grammar edge omitted"
 marker=rows[0]["implicit_protocol"];marker["version"]="1.1" if marker["version"]=="1.0" else "1.0"
 if consumer=="schema":
  with pytest.raises(ValidationError):schema().validate(marker)
 else:
  with pytest.raises(SemanticOperationEffectError,match="implicit protocol population"):
   if consumer=="population":source_operation_call_population("service.py::query",inventory)
   else:validate_operation_effects(operation(),"service.py::query",inventory,require_runtime_context=consumer=="strict")
@pytest.mark.parametrize("body",("return value is None","return 0 and value","return 1 or value","return lambda: -value"))
def test_identity_untested_final_operand_and_deferred_lambda_stay_pure(tmp_path,body):
 inventory=facts(tmp_path,"def query(value):\n    "+body+"\n")
 assert validate_operation_effects(operation(),"service.py::query",inventory)==(0,0)
