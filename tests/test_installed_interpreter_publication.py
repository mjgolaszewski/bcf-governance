"""Fresh and upgraded SDK-absent consumers retain publication freshness checks."""
import json
import subprocess
from pathlib import Path

from test_installed_evidence_storage import (
    _environment, _record, installed_consumer, isolated_python,
)

PROBE = r'''import importlib.util,json,subprocess,sys,tempfile
from pathlib import Path
from unittest.mock import patch
assert importlib.util.find_spec("bcf_governance") is None
root=Path.cwd().resolve()
sys.path.insert(0,str(root/"scripts"))
from _bcf_runtime import interpreter_environment as owner
from _bcf_runtime import interpreter_environment_plan as plan_owner
from _bcf_runtime import profile_yaml as renderer
from _bcf_runtime.runtime_capacity import EXECUTION_STATE_POLICY
import yaml
assert Path(renderer.__file__).resolve().is_relative_to(root/"scripts/_bcf_runtime")
profile_payload=yaml.safe_load((root/"governance/gate-contracts.yml").read_text())
profile_rendered=renderer.render_profile_surface(profile_payload,width=4096)
assert yaml.safe_load(profile_rendered)==profile_payload
assert renderer.render_profile_surface(yaml.safe_load(profile_rendered),width=4096)==profile_rendered
assert Path(owner.__file__).resolve().is_relative_to(root/"scripts/_bcf_runtime")
assert owner.InterpreterEnvironmentPlan is plan_owner.InterpreterEnvironmentPlan
assert owner.InterpreterEnvironmentError is plan_owner.InterpreterEnvironmentError
def _fixture(repo: Path, *, projected: str = "") -> None:
    (repo / "governance").mkdir(parents=True)
    (repo / "governance/gate-contracts.yml").write_text(
        "interpreter_contract: {project_dependencies: true, "
        "build_system_requirements: true, requirements_projection: "
        "requirements-governance.txt, optional_dependency_groups: [dev], "
        "gate_requirements: {test: [pip==26.2.2]}}\n"
        "gates: {test: {}}\n",
        encoding="utf-8",
    )
    runtime_contract = {
        "schema_version": "1.1",
        "runtime_root": ".artifacts/runtime",
        "minimum_free_bytes": 1,
        "maximum_owned_containers": 1,
        "database": {
            "storage": "repository_bind_mount",
            "relative_path": ".artifacts/runtime/database",
        },
        "cleanup": {
            "caller_globs": False,
            "daemon_global_prune": False,
            "exact_owner_revalidation": True,
            "remove_anonymous_volumes": True,
        },
        "execution_state": EXECUTION_STATE_POLICY,
    }
    (repo / "governance/ci-runtime.yml").write_text(
        yaml.safe_dump(runtime_contract, sort_keys=False), encoding="utf-8"
    )
    (repo / "pyproject.toml").write_text(
        "[build-system]\nrequires=['setuptools>=69', 'wheel']\n"
        "build-backend='setuptools.build_meta'\n"
        "[project]\nname='fixture'\nversion='1.0.0'\n"
        "requires-python='>=3.11'\ndependencies=['PyYAML>=6,<7']\n"
        "[project.optional-dependencies]\ndev=['pytest==9.0.3']\n",
        encoding="utf-8",
    )
    (repo / "requirements-governance.txt").write_text(projected, encoding="utf-8")
results=[]
for boundary in ["post-pip","post-inventory"]:
 for moving in ["metadata","projection","registry"]:
  with tempfile.TemporaryDirectory(dir=root) as temporary:
   repo=Path(temporary);_fixture(repo)
   plan=owner.derive_interpreter_environment(repo);assert plan is not None
   projection=owner.apply_interpreter_environment_projection(plan)
   source={"metadata":repo/"pyproject.toml","projection":projection,"registry":repo/"governance/gate-contracts.yml"}[moving]
   commands=[];inventories=[];moves=[]
   def move():
    source.write_text(source.read_text()+"\n# moved at publication consumer\n");moves.append(True)
   def run(argv,**kwargs):
    commands.append(argv)
    if argv[1:3]==["-m","venv"]:
     env=Path(argv[-1]);(env/"bin").mkdir(parents=True);(env/"bin/python").symlink_to(sys.executable);(env/"pyvenv.cfg").write_text("home = exact\n")
    elif argv[1:4]==["-m","pip","install"]:
     assert tuple(argv[argv.index("--disable-pip-version-check")+1:])==plan.requirements
     if boundary=="post-pip":move()
    else:raise AssertionError("unexpected native command")
    return subprocess.CompletedProcess(argv,0,"","")
   def inventory(*args):
    inventories.append(True)
    if boundary=="post-inventory":move()
    return "PyYAML==6.0.3\n"
   with patch.object(owner,"select_materialization_base",lambda *_:Path(sys.executable)),patch.object(owner,"_installed_inventory",inventory),patch.object(subprocess,"run",run):
    try:owner.materialize_interpreter_environment(repo,Path(sys.executable))
    except owner.InterpreterEnvironmentError as error:
     assert "changed after derivation" in str(error) or "projection drift" in str(error)
    else:raise AssertionError("installed consumer published moved source")
   assert moves==[True] and len(commands)==2
   assert len(inventories)==(0 if boundary=="post-pip" else 1)
   assert not list(repo.rglob("environment.json")) and not list(repo.rglob("*.building-*"))
   results.append([boundary,moving])
print(json.dumps({"source_sdk_absent":True,"closed_tuple":True,"private_profile_roundtrip":True,"refused":results}))
'''

def test_installed_interpreter_refuses_moved_source_at_publication(
    installed_consumer, isolated_python,
):
    canonical = Path(__file__).resolve().parents[1] / "bcf_governance/tooling"
    for name in ("interpreter_environment.py", "interpreter_environment_plan.py", "profile_yaml.py"):
        assert (installed_consumer / "scripts/_bcf_runtime" / name).read_bytes() == (
            canonical / name
        ).read_bytes()
    result = subprocess.run(
        [str(isolated_python), "-I", "-c", PROBE],
        cwd=installed_consumer, env=_environment(), capture_output=True, text=True,
    )
    assert result.returncode == 0, _record(result)
    report = json.loads(result.stdout)
    assert report["source_sdk_absent"] is True
    assert report["closed_tuple"] is True
    assert report["private_profile_roundtrip"] is True
    assert report["refused"] == [[boundary, moving]
        for boundary in ("post-pip", "post-inventory")
        for moving in ("metadata", "projection", "registry")]
