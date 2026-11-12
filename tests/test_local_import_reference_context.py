"""Ambiguous or future local imports cannot supply a fabricated call reference."""
from pathlib import Path
import pytest
from bcf_governance.tooling.semantic_ownership_inventory import discover_python_source,resolve_python_imports
from bcf_governance.tooling.semantic_operation_effects import SemanticOperationEffectError,validate_operation_effects

NEGATIVE={
 "repeated":("def entry():\n from provider import handler\n handler()\n from other import handler\n handler()\n","entry"),
 "branches":("def entry(flag):\n if flag:\n  from provider import handler\n  handler()\n else:\n  from other import handler\n  handler()\n","entry"),
 "future":("def entry():\n handler()\n from provider import handler\n","entry"),
 "closure":("def entry():\n from provider import handler\n def inner():\n  handler()\n from other import handler\n return inner\n","entry.<locals>.inner"),
}
POSITIVE={
 "module-before":"from provider import handler\ndef entry():\n return handler()\n",
 "module-after":"def entry():\n return handler()\nfrom provider import handler\n",
 "single-local":"def entry():\n from provider import handler\n return handler()\n",
}
def inventory(root,source,resolved):
 paths=[]
 for name,body in (("provider.py","def handler():\n return 1\n"),("other.py","def handler():\n return 2\n"),("entry.py",source)):
  path=root/name;path.write_text(body);paths.append(path)
 observed=discover_python_source(root,files=paths)
 return resolve_python_imports(root,observed) if resolved else observed

@pytest.mark.parametrize("resolved",(False,True))
@pytest.mark.parametrize("case",tuple(NEGATIVE))
def test_local_import_uncertainty_has_no_single_reference(tmp_path,resolved,case):
 source,function=NEGATIVE[case];observed=inventory(tmp_path,source,resolved)
 row=next(row for row in observed["functions"] if row["symbol"]=="entry.py::"+function)
 calls=[call for call in row["calls"] if call["call_name"]=="handler" and not call.get("implicit_protocol")]
 assert calls
 assert all("import_reference" not in call for call in calls),"uncertain local import retained a fabricated single binding"
 assert all(call.get("dispatch_resolution")=="unresolved" and call.get("dispatch_port_eligible") is False for call in calls)
 if resolved:
  with pytest.raises(SemanticOperationEffectError,match="unresolved"):
   validate_operation_effects({"id":"import-context.query.v1","allowed_mutation_ports":[],"allowed_authority_ports":[],"non_authoritative_output_effects":[]},"entry.py::"+function,observed)

@pytest.mark.parametrize("resolved",(False,True))
@pytest.mark.parametrize("case",tuple(POSITIVE))
def test_ordinary_import_reference_preserves_exact_source_binding(tmp_path,resolved,case):
 source=POSITIVE[case];observed=inventory(tmp_path,source,resolved)
 row=next(row for row in observed["functions"] if row["symbol"]=="entry.py::entry")
 call=next(call for call in row["calls"] if call["call_name"]=="handler" and not call.get("implicit_protocol"))
 binding=call["import_reference"]["binding"]
 assert binding["module"]=="provider" and binding["member"]=="handler"
 assert binding["line"]==next(i for i,line in enumerate(source.splitlines(),1) if "from provider import" in line)
