"""Registered Git source-history observations never grant retirement authority."""
import hashlib,os,shlex,shutil,subprocess
from pathlib import Path
from bcf_governance.tooling import ci_graph_audit as audit

def git(root,*args):
 env={key:value for key,value in os.environ.items() if not key.startswith("GIT_")}
 return subprocess.run(["git","--no-replace-objects","-c","core.hooksPath=/dev/null","-C",str(root),*args],env=env,capture_output=True,text=True,check=True).stdout.strip()
def repository(root,name="source.py"):
 root.mkdir();git(root,"init","-b","main");git(root,"config","user.name","Fixture");git(root,"config","user.email","fixture@example.invalid")
 (root/name).write_text("VALUE=1\n");git(root,"add",".");git(root,"commit","-m","audit source fixture")
 return root


def history(root):
    observed=audit._repository_state(root)
    assert "source_history" in observed,"CI audit omits registered source-history population"
    result=observed["source_history"]
    assert result["schema_version"]=="1.0"
    assert result["authority"] is False and result["execution_qualified"] is False
    assert result["full_workspace_inventory"] is False and result["retirement_authorized"] is False
    return result

def peer(root,path):
    git(root,"worktree","add","-b","peer",str(path))
    return path

def test_history_captures_exact_active_subject(tmp_path):
    root=repository(tmp_path/"active")
    result=history(root)
    assert result["available"] and result["identity_observation_stable"]
    assert result["subject"]=={"commit_sha":git(root,"rev-parse","HEAD"),"tree_sha":git(root,"rev-parse","HEAD^{tree}"),"branch_ref":"refs/heads/main"}
    assert {row["path"] for row in result["worktrees"]}=={str(root)}

def test_history_includes_dirty_linked_worktree_and_untracked_paths(tmp_path):
    root=repository(tmp_path/"active");other=peer(root,tmp_path/"other")
    (other/"source.py").write_text("VALUE=2\n")
    (other/"unique.py").write_text("UNIQUE=3\n")
    result=history(root)
    row=next(row for row in result["worktrees"] if row["path"]==str(other))
    assert row["available"] and row["status_entries"]
    assert row["untracked_paths"]==["unique.py"]
    assert result["source_byte_custody"]=="unresolved"

def test_history_retains_nonancestor_branch_tip(tmp_path):
    root=repository(tmp_path/"active");base=git(root,"rev-parse","HEAD")
    git(root,"checkout","-b","historical")
    (root/"source.py").write_text("VALUE=7\n");git(root,"commit","-am","historical source")
    tip=git(root,"rev-parse","HEAD");git(root,"checkout","main")
    result=history(root);row=next(row for row in result["branches"] if row["ref"]=="refs/heads/historical")
    assert row["commit_sha"]==tip and row["ancestor_of_subject"] is False
    assert result["subject"]["commit_sha"]==base

def test_history_never_collapses_equal_tree_distinct_commits(tmp_path):
    root=repository(tmp_path/"active");first=git(root,"rev-parse","HEAD");tree=git(root,"rev-parse","HEAD^{tree}")
    git(root,"branch","preserved",first);git(root,"commit","--allow-empty","-m","distinct immutable identity")
    second=git(root,"rev-parse","HEAD");assert first!=second
    result=history(root)
    assert any(row["tree_sha"]==tree and row["commits"]==sorted([first,second]) for row in result["same_tree_distinct_commits"])
    assert {row["commit_sha"] for row in result["branches"]}=={first,second}

def test_history_blocks_stable_observation_claim_when_refs_move(tmp_path,monkeypatch):
    root=repository(tmp_path/"active");original=audit._source_git;moved=False
    def moving(repo,*arguments):
        nonlocal moved
        result=original(repo,*arguments)
        if arguments and arguments[0]=="for-each-ref" and not moved:
            moved=True;git(root,"branch","arrived-during-capture","HEAD")
        return result
    monkeypatch.setattr(audit,"_source_git",moving)
    result=history(root)
    assert moved and result["identity_observation_stable"] is False and result["available"] is False

def test_history_keeps_ambient_foreign_repository_out(tmp_path,monkeypatch):
    root=repository(tmp_path/"active");foreign=repository(tmp_path/"foreign")
    git(foreign,"branch","foreign-only")
    monkeypatch.setenv("GIT_DIR",str(foreign/".git"));monkeypatch.setenv("GIT_WORK_TREE",str(foreign))
    result=history(root)
    assert {row["ref"] for row in result["branches"]}=={"refs/heads/main"}
    assert {row["path"] for row in result["worktrees"]}=={str(root)}

def test_history_never_executes_peer_fsmonitor(tmp_path):
    root=repository(tmp_path/"active");other=peer(root,tmp_path/"other")
    marker=tmp_path/"executed";hook=tmp_path/"monitor"
    hook.write_text('#!/bin/sh\ntouch '+shlex.quote(str(marker))+'\nprintf "token\\0"\n');hook.chmod(0o700)
    git(root,"config","core.fsmonitor",str(hook));git(other,"status","--porcelain")
    assert marker.exists(),"native Git monitor witness did not execute";marker.unlink()
    result=history(root)
    assert result["available"] and not marker.exists(),"source-history query executed candidate monitor"

def test_history_does_not_silently_omit_missing_registered_worktree(tmp_path):
    root=repository(tmp_path/"active");other=peer(root,tmp_path/"other");shutil.rmtree(other)
    result=history(root);row=next(row for row in result["worktrees"] if row["path"]==str(other))
    assert row["available"] is False and result["available"] is False

def test_history_leaves_independent_clone_coverage_unresolved(tmp_path):
    root=repository(tmp_path/"active");clone=tmp_path/"independent"
    subprocess.run(["git","-c","core.hooksPath=/dev/null","clone","--no-hardlinks",str(root),str(clone)],capture_output=True,check=True)
    result=history(root)
    assert result["scope"]=="registered_git_worktrees_and_local_branch_tips"
    assert str(clone) not in {row["path"] for row in result["worktrees"]}
    assert result["independent_clone_discovery"]=="unresolved"

def test_history_observation_never_writes_source_index_or_refs(tmp_path):
    root=repository(tmp_path/"active");(root/"source.py").write_text("VALUE=9\n")
    paths=[root/"source.py",root/".git/index",root/".git/config",root/".git/HEAD",root/".git/refs/heads/main"]
    before={str(path):path.read_bytes() for path in paths}
    result=history(root)
    assert result["available"]
    assert {str(path):path.read_bytes() for path in paths}==before
