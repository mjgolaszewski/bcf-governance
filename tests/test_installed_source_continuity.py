"""Exercise source-continuity observations in fresh and upgraded SDK-absent consumers."""
import json
import subprocess
from pathlib import Path
import test_installed_evidence_storage as _fixture_owner
from test_installed_evidence_storage import _environment, _record
installed_consumer = _fixture_owner.installed_consumer
isolated_python = _fixture_owner.isolated_python
PROBE = r'''import importlib.util,json,os,shlex,subprocess,sys,tempfile,hashlib
from pathlib import Path
assert importlib.util.find_spec("bcf_governance") is None
runtime=Path("scripts").resolve();sys.path.insert(0,str(runtime))
from _bcf_runtime import ci_graph_audit as audit
from _bcf_runtime.semantic_source_paths import _source_git
cases=[]
def git(root,*args):
    env={key:value for key,value in os.environ.items() if not key.startswith("GIT_")}
    return subprocess.run(["git","--no-replace-objects","-c","core.hooksPath=/dev/null","-C",str(root),*args],env=env,capture_output=True,text=True,check=True).stdout.strip()
def repo(root,name="source.py"):
    root.mkdir();git(root,"init","-b","main");git(root,"config","user.name","Fixture");git(root,"config","user.email","fixture@example.invalid")
    (root/name).write_text("VALUE=1\n");git(root,"add",".");git(root,"commit","-m","installed source fixture")
    return root
with tempfile.TemporaryDirectory(prefix="installed-source-continuity-") as directory:
    base=Path(directory)
    root=repo(base/"plain")
    state=audit._repository_state(root);assert state["available"] and state["committed_clean"]
    assert state["source_history"]["authority"] is False and state["source_history"]["retirement_authorized"] is False
    cases.append("plain_clean")
    unusual=repo(base/"unusual","line\nbreak.py");assert audit._tracked(unusual,("*.py",))==["line\nbreak.py"];cases.append("exact_path")
    root=repo(base/"linked");other=base/"peer";git(root,"worktree","add","-b","peer",str(other));(other/"source.py").write_text("VALUE=3\n")
    history=audit._repository_state(root)["source_history"]
    assert history["available"] and {row["path"] for row in history["worktrees"]}=={str(root),str(other)}
    assert next(row for row in history["worktrees"] if row["path"]==str(other))["status_entries"];cases.append("registered_peer")
    root=repo(base/"staged");(root/"source.py").write_text("VALUE=2\n");git(root,"add","source.py");(root/"source.py").write_text("VALUE=1\n")
    history=audit._repository_state(root)["source_history"];assert history["available"]
    observed=history["worktrees"][0]["source_byte_observations"]
    assert observed["index"]["source.py"]["sha256"]==hashlib.sha256(b"VALUE=2\n").hexdigest()
    assert observed["working"]["source.py"]["sha256"]==hashlib.sha256(b"VALUE=1\n").hexdigest();cases.append("staged_working")
    for required in (False,True):
        root=repo(base/("filtered-"+str(required)));marker=base/("filter-marker-"+str(required));hook=base/("clean-filter-"+str(required))
        hook.write_text('#!/bin/sh\ntouch '+shlex.quote(str(marker))+'\ncat\n');hook.chmod(0o700)
        git(root,"config","filter.observe.clean",shlex.quote(str(hook)));git(root,"config","filter.observe.required",str(required).lower())
        (root/".gitattributes").write_text("source.py filter=observe\n");git(root,"add",".gitattributes","source.py");git(root,"commit","-m","filter fixture");marker.unlink(missing_ok=True)
        (root/"source.py").write_text("VALUE=2\n");timestamp=(root/"source.py").stat().st_mtime+5;os.utime(root/"source.py",(timestamp,timestamp))
        git(root,"status","--porcelain");assert marker.exists(),"native installed clean-filter witness absent";marker.unlink()
        config=(root/".git/config").read_bytes();denied=_source_git(root,"status","--porcelain=v1","-z")
        assert denied.returncode!=0 and b"source_git_unqualified_worktree_comparison" in denied.stderr
        state=audit._repository_state(root);assert state["available"] and not state["committed_clean"] and not marker.exists()
        assert (root/".git/config").read_bytes()==config;cases.append("clean_filter_required_"+str(required).lower())
    for flag in ("--assume-unchanged","--skip-worktree"):
        root=repo(base/flag.removeprefix("--"));git(root,"update-index",flag,"source.py");(root/"source.py").write_text("VALUE=8\n")
        assert git(root,"status","--porcelain")==""
        state=audit._repository_state(root);assert state["available"] and not state["committed_clean"];cases.append("hidden_"+flag.removeprefix("--"))
    root=repo(base/"gitlink");head=git(root,"rev-parse","HEAD");git(root,"update-index","--add","--cacheinfo","160000,"+head+",nested")
    assert audit._repository_state(root)=={"available":False,"committed_clean":False};cases.append("gitlink_block")
    root=repo(base/"equal-tree");first=git(root,"rev-parse","HEAD");tree=git(root,"rev-parse","HEAD^{tree}");git(root,"branch","preserved",first);git(root,"commit","--allow-empty","-m","distinct identity")
    second=git(root,"rev-parse","HEAD");assert first!=second
    history=audit._repository_state(root)["source_history"]
    assert any(row["tree_sha"]==tree and row["commits"]==sorted([first,second]) for row in history["same_tree_distinct_commits"]);cases.append("equal_tree_distinct_commits")
    from _bcf_runtime.semantic_authority_contracts import _validate_operations,SemanticAuthorityError
    from _bcf_runtime.semantic_ownership_inventory import discover_python_source
    source=base/"operation.py";source.write_text("def query():\n    return 1\n")
    inventory=discover_python_source(base,files=[source])
    inventory["functions"].append(dict(inventory["functions"][0]))
    operation_payload=json.loads("{\"schema_version\":\"1.0\",\"document\":{\"kind\":\"application_operation_registry\",\"id\":\"fixture-operations\",\"version\":\"1.0.0\",\"status\":\"active\",\"path\":\"governance/application-operations.yml\"},\"populations\":[{\"id\":\"fixture\",\"adapter\":\"typescript_exports\",\"source\":\"fixture.ts\",\"symbol\":\"exports\",\"public_only\":true,\"tsconfig\":\"tsconfig.json\",\"package_lock\":\"package-lock.json\",\"node_executable\":\"node\"}],\"operations\":[{\"id\":\"fixture.query.v1\",\"population\":\"fixture\",\"population_key\":\"query\",\"family\":\"fixture\",\"bounded_context\":\"tooling\",\"entrypoints\":[\"service.py::query\"],\"semantic_kind\":\"query\",\"authoritative_read\":false,\"authoritative_mutation\":false,\"authority_conferral\":false,\"produces_projection\":false,\"model_callable\":false,\"allowed_mutation_ports\":[],\"allowed_authority_ports\":[],\"non_authoritative_output_effects\":[]}],\"migrations\":[]}")
    try:_validate_operations(Path.cwd(),operation_payload,inventory,source_language="python",consumer_owned_schema=True)
    except SemanticAuthorityError as error:assert "function population" in str(error) and "ambiguous" in str(error)
    else:raise AssertionError("installed filtered operation accepted ambiguous functions")
    cases.append("operation_function_identity_admission")
origins={name:str(Path(module.__file__).resolve()) for name,module in list(sys.modules.items()) if name.startswith("_bcf_runtime.") and getattr(module,"__file__",None)}
assert origins and all(Path(value).is_relative_to(runtime) for value in origins.values())
assert len(cases)==11 and len(set(cases))==11
print(json.dumps({"source_package_absent":True,"cases":cases,"private_origins":origins,"authority":False,"retirement_authorized":False},sort_keys=True))
'''

compile(PROBE, "installed-source-continuity", "exec")

def exercise_installed_source_continuity(installed_consumer, isolated_python):
    result = subprocess.run(
        [str(isolated_python), "-I", "-B", "-c", PROBE], cwd=installed_consumer,
        env=_environment(), capture_output=True, text=True, timeout=60,
    )
    assert result.returncode == 0, _record(result)
    actual = json.loads(result.stdout)
    assert actual["source_package_absent"] is True and actual["private_origins"]
    assert len(actual["cases"]) == len(set(actual["cases"])) == 11
    assert actual["authority"] is False and actual["retirement_authorized"] is False
    assert all(Path(value).is_relative_to(installed_consumer.resolve() / "scripts") for value in actual["private_origins"].values())
    return actual

def test_installed_source_continuity(installed_consumer, isolated_python):
    exercise_installed_source_continuity(installed_consumer, isolated_python)
