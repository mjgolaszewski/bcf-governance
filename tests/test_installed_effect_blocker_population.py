"""Fresh/repaired SDK-absent consumers retain neutral strict blocker diagnostics."""
import subprocess
import test_installed_evidence_storage as _fixture_owner
from test_installed_evidence_storage import _environment
installed_consumer = _fixture_owner.installed_consumer
isolated_python = _fixture_owner.isolated_python
PROBE = 'import importlib.util,json,sys,tempfile\nfrom pathlib import Path\nassert importlib.util.find_spec("bcf_governance") is None\nsys.path.insert(0,str(Path("scripts").resolve()))\nfrom _bcf_runtime.semantic_operation_effects import SemanticOperationEffectError,validate_operation_effects\nfrom _bcf_runtime.semantic_ownership_inventory import discover_python_source,resolve_python_imports\noperation={"id":"installed.query.v1","allowed_mutation_ports":[],"allowed_authority_ports":[],"non_authoritative_output_effects":[]}\nwith tempfile.TemporaryDirectory() as directory:\n root=Path(directory);source=root/"service.py"\n source.write_text("def left(value):\\n    return value[0]\\ndef right(value):\\n    return value[0]\\ndef query(value):\\n    left(value)\\n    return right(value)\\ndef closed():\\n    return 1\\n")\n facts=resolve_python_imports(root,discover_python_source(root,files=[source],call_contracts_version="1.0"))\n try:validate_operation_effects(operation,"service.py::query",facts)\n except SemanticOperationEffectError as error:\n  rows=error.effect_obligations\n  assert {row[0] for row in rows if row[1]=="runtime_protocol"}=={"service.py::left","service.py::right"},"installed parallel blockers hidden"\n  assert rows==tuple(sorted(set(rows))) and all(isinstance(row,tuple) for row in rows)\n  note=json.loads(error.__notes__[0]);assert note["authority"] is note["execution_qualified"] is note["completeness_qualified"] is False\n  assert note["effect_obligations"]==[list(row) for row in rows]\n else:raise AssertionError("installed strict refusal missing")\n assert validate_operation_effects(operation,"service.py::closed",facts)==(0,0)\n facts["functions"].append(dict(facts["functions"][0]))\n try:validate_operation_effects(operation,"service.py::closed",facts)\n except SemanticOperationEffectError as error:\n  assert "ambiguous" in str(error) and error.effect_obligations==()\n else:raise AssertionError("installed ambiguous inventory accepted")\nprint("installed-blocker-diagnostics-qualified")\n'

def test_installed_blocker_diagnostics(installed_consumer, isolated_python):
    result = subprocess.run([str(isolated_python), "-I", "-B", "-c", PROBE], cwd=installed_consumer,
                            env=_environment(), capture_output=True, text=True)
    assert result.returncode == 0, result.stdout + result.stderr
    assert result.stdout.strip() == "installed-blocker-diagnostics-qualified"


def test_installed_removed_rows_fail_named_control(installed_consumer, isolated_python):
    owner = installed_consumer / "scripts/_bcf_runtime/semantic_operation_effects.py"
    source = owner.read_text()
    guard = "error.effect_obligations = tuple(sorted(blockers))"
    assert source.count(guard) == 1
    owner.write_text(source.replace(guard, "error.effect_obligations = ()"))
    result = subprocess.run([str(isolated_python), "-I", "-B", "-c", PROBE], cwd=installed_consumer,
                            env=_environment(), capture_output=True, text=True)
    assert result.returncode == 1
    assert "installed parallel blockers hidden" in result.stderr
