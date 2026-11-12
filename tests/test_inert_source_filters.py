"""Native Git filter programs must not run during source observations."""
import os,shlex,subprocess
from pathlib import Path
import pytest
from bcf_governance.tooling import ci_graph_audit as audit
from bcf_governance.tooling.semantic_source_paths import _source_git

def git(root,*args):
 env={key:value for key,value in os.environ.items() if not key.startswith("GIT_")}
 return subprocess.run(["git","--no-replace-objects","-c","core.hooksPath=/dev/null","-C",str(root),*args],env=env,capture_output=True,text=True,check=True).stdout.strip()
def repository(root,name="source.py"):
 root.mkdir();git(root,"init","-b","main");git(root,"config","user.name","Fixture");git(root,"config","user.email","fixture@example.invalid")
 (root/name).write_text("VALUE=1\n");git(root,"add",".");git(root,"commit","-m","audit source fixture")
 return root


@pytest.mark.parametrize("consumer",("source_reader","ci_audit"))
@pytest.mark.parametrize("required",(False,True))
def test_source_status_does_not_execute_clean_filter(tmp_path,consumer,required):
    root=repository(tmp_path/"active");marker=tmp_path/"filter-executed";hook=tmp_path/"clean-filter"
    hook.write_text('#!/bin/sh\ntouch '+shlex.quote(str(marker))+'\ncat\n');hook.chmod(0o700)
    git(root,"config","filter.observe.clean",shlex.quote(str(hook)))
    git(root,"config","filter.observe.required",str(required).lower())
    (root/".gitattributes").write_text("source.py filter=observe\n")
    git(root,"add",".gitattributes","source.py");git(root,"commit","-m","native filter fixture")
    marker.unlink(missing_ok=True)
    (root/"source.py").write_text("VALUE=2\n")
    timestamp=(root/"source.py").stat().st_mtime+5;os.utime(root/"source.py",(timestamp,timestamp))
    git(root,"status","--porcelain=v1","--untracked-files=all")
    assert marker.exists(),"native clean-filter witness did not execute";marker.unlink()
    before=(root/".git/config").read_bytes()
    if consumer=="source_reader":
        observed=_source_git(root,"status","--porcelain=v1","-z","--untracked-files=all")
        assert observed.returncode!=0,"source Git comparison did not refuse unsafe working-tree conversion"
        assert b"source_git_unqualified_worktree_comparison" in observed.stderr
    else:
        observed=audit._repository_state(root)
        assert observed["available"] and not observed["committed_clean"]
    assert not marker.exists(),"source query executed candidate clean filter"
    assert (root/".git/config").read_bytes()==before
    assert (root/"source.py").read_text()=="VALUE=2\n"

@pytest.mark.parametrize("flag",("--assume-unchanged","--skip-worktree"))
def test_inert_status_detects_source_hidden_by_index_flags(tmp_path,flag):
    root=repository(tmp_path/"active");git(root,"update-index",flag,"source.py")
    (root/"source.py").write_text("VALUE=8\n")
    assert git(root,"status","--porcelain")=="","native index-flag witness did not hide source"
    observed=audit._repository_state(root)
    assert observed["available"] and not observed["committed_clean"],"source inventory missed index-flag-hidden bytes"

def test_inert_status_blocks_unqualified_gitlink_population(tmp_path):
    root=repository(tmp_path/"active");head=git(root,"rev-parse","HEAD")
    git(root,"update-index","--add","--cacheinfo","160000,"+head+",nested")
    observed=audit._repository_state(root)
    assert observed=={"available":False,"committed_clean":False},"source inventory accepted unresolved Gitlink context"
