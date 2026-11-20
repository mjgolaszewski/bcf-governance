"""SDK-absent fresh/repaired consumers preserve opt-in blocker populations."""
import subprocess
import test_installed_evidence_storage as _fixture_owner
from test_installed_evidence_storage import _environment

installed_consumer = _fixture_owner.installed_consumer
isolated_python = _fixture_owner.isolated_python
PROBE = 'import importlib.util,sys,shutil,tempfile\nfrom pathlib import Path\nassert importlib.util.find_spec("bcf_governance") is None\nsys.path.insert(0,str(Path("scripts").resolve()))\nfrom _bcf_runtime import semantic_authority_contracts as owner\nfrom _bcf_runtime.semantic_ownership_inventory import discover_python_source\nwith tempfile.TemporaryDirectory() as directory:\n root=Path(directory)\n (root/"schemas").mkdir()\n shutil.copyfile("schemas/application-operations.schema.json",root/"schemas/application-operations.schema.json")\n path=root/"runtime.py"\n path.write_text(\'def left(value):\\n    return value[0]\\ndef right(value):\\n    return value[0]\\nCOMMANDS={"left":left,"right":right}\\n\')\n payload=dict(schema_version="1.0",document=dict(kind="application_operation_registry",id="example-operations",version="1.0.0",status="active",path="governance/application-operations.yml"),populations=[dict(id="cli",adapter="python_mapping",source="runtime.py",symbol="COMMANDS",public_only=True)],operations=[dict(id="example."+name+".v1",population="cli",population_key=name,family="example",bounded_context="example",entrypoints=["runtime.py::"+name],semantic_kind="query",authoritative_read=True,authoritative_mutation=False,authority_conferral=False,produces_projection=False,model_callable=False,allowed_mutation_ports=[],allowed_authority_ports=[],non_authoritative_output_effects=[]) for name in ["left","right"]],migrations=[])\n facts=discover_python_source(root,files=[path],call_contracts_version="1.0")\n try:\n  owner._validate_operations(root,payload,facts,collect_effect_obligations=True)\n except owner.SemanticAuthorityError as error:\n  assert error.operation_effect_population==("example.left.v1","example.right.v1")\n  assert {r[0] for r in error.operation_effect_obligations}==set(error.operation_effect_population),"installed sibling operation blockers hidden"\n  assert error.authority is error.execution_qualified is error.completeness_qualified is False\n else:\n  raise AssertionError("installed unresolved operations falsely accepted")\nprint("installed-operation-blocker-discovery-qualified")\n'

def test_installed_sibling_blocker_population(installed_consumer, isolated_python):
    result = subprocess.run([str(isolated_python), "-I", "-B", "-c", PROBE],
                            cwd=installed_consumer, env=_environment(), capture_output=True, text=True)
    assert result.returncode == 0, result.stdout + result.stderr
    assert result.stdout.strip() == "installed-operation-blocker-discovery-qualified"


def test_installed_removed_blocker_collection_fails_named_control(installed_consumer, isolated_python):
    path = installed_consumer / "scripts/_bcf_runtime/semantic_authority_operations.py"
    source = path.read_text()
    guard = 'effect_blockers.extend((str(operation["id"]), *row) for row in exc.effect_obligations)'
    assert source.count(guard) == 1
    path.write_text(source.replace(guard, "effect_blockers.extend([])"))
    result = subprocess.run([str(isolated_python), "-I", "-B", "-c", PROBE],
                            cwd=installed_consumer, env=_environment(), capture_output=True, text=True)
    assert result.returncode == 1
    assert "installed sibling operation blockers hidden" in result.stderr
