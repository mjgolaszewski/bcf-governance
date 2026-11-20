"""SDK-absent read declarations retain strict source-body permissions."""
import subprocess
import test_installed_evidence_storage as _fixture_owner
from test_installed_evidence_storage import _environment

installed_consumer = _fixture_owner.installed_consumer
isolated_python = _fixture_owner.isolated_python
PROBE = 'import importlib.util,sys,tempfile\nfrom pathlib import Path\nassert importlib.util.find_spec("bcf_governance") is None\nsys.path.insert(0,str(Path("scripts").resolve()))\nfrom _bcf_runtime.semantic_ownership_inventory import discover_python_source,resolve_python_imports\nfrom _bcf_runtime.semantic_operation_effects import validated_operation_effect_inventory,SemanticOperationEffectError\nwith tempfile.TemporaryDirectory() as directory:\n root=Path(directory);path=root/"runtime.py"\n def discover():\n  return resolve_python_imports(root,discover_python_source(root,files=[path],call_contracts_version="1.0"))\n operation={"id":"example.query.v1","allowed_read_ports":["runtime.py::reader"],"allowed_mutation_ports":[],"allowed_authority_ports":[],"non_authoritative_output_effects":[]}\n path.write_text("def reader():\\n    return 1\\ndef query():\\n    return reader()\\n")\n assert validated_operation_effect_inventory(operation,"runtime.py::query",discover())==(("read","function","runtime.py::reader"),)\n path.write_text("def writer():\\n    path.write_text(\'changed\')\\ndef reader():\\n    return writer()\\ndef query():\\n    return reader()\\n")\n operation["allowed_mutation_ports"]=["runtime.py::writer"]\n try:\n  validated_operation_effect_inventory(operation,"runtime.py::query",discover())\n except SemanticOperationEffectError:\n  pass\n else:\n  raise AssertionError("installed read borrowed mutation permission")\nprint("installed-read-port-qualified")\n'

def test_installed_read_port_body_validation(installed_consumer, isolated_python):
    result = subprocess.run([str(isolated_python), "-I", "-B", "-c", PROBE],
                            cwd=installed_consumer, env=_environment(), capture_output=True, text=True)
    assert result.returncode == 0, result.stdout + result.stderr
    assert result.stdout.strip() == "installed-read-port-qualified"


def test_installed_borrowed_permissions_fail_named_control(installed_consumer, isolated_python):
    path = installed_consumer / "scripts/_bcf_runtime/semantic_operation_effects.py"
    source = path.read_text()
    guard = '"id": operation["id"] + ":read", "allowed_mutation_ports": []'
    assert source.count(guard) == 1
    path.write_text(source.replace(guard, '"id": operation["id"] + ":read", "allowed_mutation_ports": operation["allowed_mutation_ports"]'))
    result = subprocess.run([str(isolated_python), "-I", "-B", "-c", PROBE],
                            cwd=installed_consumer, env=_environment(), capture_output=True, text=True)
    assert result.returncode == 1
    assert "installed read borrowed mutation permission" in result.stderr
