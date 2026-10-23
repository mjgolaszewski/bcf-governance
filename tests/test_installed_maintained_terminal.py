"""Installed private consumers retain exact maintenance declaration assertions."""
import json
import subprocess
from pathlib import Path

from test_installed_evidence_storage import (
    _environment, _record, installed_consumer, isolated_python,
)

PROBE = r'''import ast,importlib.util,json,os,sys,tempfile,unittest
from pathlib import Path
from types import SimpleNamespace
assert importlib.util.find_spec("bcf_governance") is None
root=Path.cwd().resolve()
sys.path.insert(0,str(root/"scripts"))
from _bcf_runtime.governance_validation import supplemental_releases as owner
from _bcf_runtime import ci_github_release_inputs as consumer
from _bcf_runtime import release_versions as versions
for module in (owner,consumer,versions):
 assert Path(module.__file__).resolve().is_relative_to(root/"scripts/_bcf_runtime")
fixture=ast.parse(sys.argv[1])
negative=next(n for n in fixture.body if isinstance(n,ast.FunctionDef) and n.name=="test_maintenance_fallback_rejects_unqualified_catalog")
cases=ast.literal_eval(negative.decorator_list[0].args[1])
assert len(cases)==15 and len(set(cases))==15
body=[]
for node in fixture.body:
 if isinstance(node,ast.Import) and any(a.name=="pytest" for a in node.names):
  assert [a.name for a in node.names]==["pytest"]
  continue
 if isinstance(node,ast.ImportFrom) and node.module and node.module.startswith("bcf_governance.tooling."):
  node.module="_bcf_runtime."+node.module.removeprefix("bcf_governance.tooling.")
 if isinstance(node,ast.FunctionDef):node.decorator_list=[]
 body.append(node)
fixture.body=body
namespace={"pytest":SimpleNamespace(raises=unittest.TestCase().assertRaises)}
exec(compile(ast.fix_missing_locations(fixture),"installed_maintenance_contract_fixture","exec"),namespace)
assert namespace["declared_release_train_terminal"] is owner.declared_release_train_terminal
assert namespace["require_terminal_release_phase_at_main"] is consumer.require_terminal_release_phase_at_main
namespace["test_completed_single_phase_maintenance_patch_retains_declared_terminal"]()
for defect in cases:namespace["test_maintenance_fallback_rejects_unqualified_catalog"](defect)
with tempfile.TemporaryDirectory(dir=root) as temporary:
 try:
  namespace["test_maintained_patch_terminal_uses_exact_main_and_ignores_candidate"](
   Path(temporary),SimpleNamespace(chdir=os.chdir))
 finally:os.chdir(root)
assert importlib.util.find_spec("bcf_governance") is None
print(json.dumps({"source_sdk_absent":True,"private_origins":3,"source_contract_cases":17,"negative_cases":cases,"exact_main_consumer":True}))
'''


def test_installed_maintenance_terminal_preserves_source_contract(installed_consumer, isolated_python):
    source = Path(__file__).with_name("test_maintained_release_terminal.py").read_text()
    result = subprocess.run(
        [str(isolated_python), "-I", "-c", PROBE, source], cwd=installed_consumer,
        env=_environment(), capture_output=True, text=True, timeout=20,
    )
    assert result.returncode == 0, _record(result)
    report = json.loads(result.stdout)
    assert report["source_sdk_absent"] is True
    assert report["private_origins"] == 3
    assert report["source_contract_cases"] == 17
    assert len(report["negative_cases"]) == 15
    assert report["exact_main_consumer"] is True
