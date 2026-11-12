"""Source-byte observations keep index/worktree versions distinct and do not follow links."""
import hashlib,os,shlex,subprocess,sys
from pathlib import Path
import pytest
from bcf_governance.tooling import ci_graph_audit as audit

def git(root,*args):
 env={key:value for key,value in os.environ.items() if not key.startswith("GIT_")}
 return subprocess.run(["git","--no-replace-objects","-c","core.hooksPath=/dev/null","-C",str(root),*args],env=env,capture_output=True,text=True,check=True).stdout.strip()
def repository(root,name="source.py"):
 root.mkdir();git(root,"init","-b","main");git(root,"config","user.name","Fixture");git(root,"config","user.email","fixture@example.invalid")
 (root/name).write_text("VALUE=1\n");git(root,"add",".");git(root,"commit","-m","audit source fixture")
 return root


def reader():
    value=getattr(audit,"_worktree_source_digest",None)
    assert callable(value),"CI audit lacks safe source-byte observation"
    return value

def observations(root):
    result=audit._repository_state(root)["source_history"]
    assert result["available"] and result["identity_observation_stable"]
    row=next(row for row in result["worktrees"] if row["path"]==str(root))
    assert "source_byte_observations" in row,"CI audit omits source-byte versions"
    assert result["source_byte_custody"]=="unresolved" and result["retirement_authorized"] is False
    return row["source_byte_observations"]

def test_source_byte_reader_observes_regular_bytes_without_changes(tmp_path):
    root=repository(tmp_path/"active");before=(root/"source.py").read_bytes()
    assert reader()(root,"source.py")=={"kind":"regular","size":len(before),"sha256":hashlib.sha256(before).hexdigest()}
    assert (root/"source.py").read_bytes()==before

@pytest.mark.parametrize("kind",("leaf","parent","escape"))
def test_source_byte_reader_rejects_links_and_parent_escape(tmp_path,kind):
    root=repository(tmp_path/"active");outside=tmp_path/"outside";outside.mkdir();(outside/"secret.py").write_text("SECRET=3\n")
    if kind=="leaf":(root/"linked.py").symlink_to(outside/"secret.py");name="linked.py"
    elif kind=="parent":(root/"linked").symlink_to(outside,target_is_directory=True);name="linked/secret.py"
    else:name="../outside/secret.py"
    consume=reader()
    with pytest.raises((ValueError,OSError)):consume(root,name)
    assert (outside/"secret.py").read_text()=="SECRET=3\n"

def test_source_byte_reader_refuses_fifo_without_waiting(tmp_path):
    root=repository(tmp_path/"active");os.mkfifo(root/"pipe.py");reader()
    code="from pathlib import Path;from bcf_governance.tooling.ci_graph_audit import _worktree_source_digest\ntry:_worktree_source_digest(Path("+repr(str(root))+"),'pipe.py')\nexcept (OSError,ValueError):pass\nelse:raise AssertionError('FIFO admitted as source')"
    result=subprocess.run([sys.executable,"-B","-c",code],capture_output=True,text=True,timeout=5)
    assert result.returncode==0,result.stderr

def test_source_byte_reader_represents_actual_deletion(tmp_path):
    root=repository(tmp_path/"active");(root/"source.py").unlink()
    assert reader()(root,"source.py")=={"kind":"deleted"}

def test_source_observations_retain_index_and_restored_working_copy(tmp_path):
    root=repository(tmp_path/"active");(root/"source.py").write_text("VALUE=2\n");git(root,"add","source.py");staged=git(root,"rev-parse",":source.py")
    (root/"source.py").write_text("VALUE=1\n")
    result=observations(root)
    assert result["scope"]=="git_reported_index_and_worktree_changes"
    assert result["index"]["source.py"]["blob_oid"]==staged
    assert result["index"]["source.py"]["sha256"]==hashlib.sha256(b"VALUE=2\n").hexdigest()
    assert result["working"]["source.py"]["sha256"]==hashlib.sha256(b"VALUE=1\n").hexdigest()
    assert result["untracked"]=={}

def test_source_observations_retain_untracked_content(tmp_path):
    root=repository(tmp_path/"active");(root/"unique.py").write_text("UNIQUE=4\n")
    result=observations(root)
    assert result["untracked"]["unique.py"]=={"kind":"regular","size":9,"sha256":hashlib.sha256(b"UNIQUE=4\n").hexdigest()}
    assert result["index"]==result["working"]=={}

def test_source_observations_retain_deletion_separately_from_committed_tree(tmp_path):
    root=repository(tmp_path/"active");head=git(root,"rev-parse","HEAD");(root/"source.py").unlink()
    result=observations(root)
    assert result["working"]["source.py"]=={"kind":"deleted"}
    assert git(root,"rev-parse","HEAD")==head

def test_source_byte_movement_with_same_dirty_status_rejects_stability(tmp_path,monkeypatch):
    root=repository(tmp_path/"active");(root/"source.py").write_text("VALUE=2\n");original=audit._source_history_snapshot;moved=False
    def moving(repo):
        nonlocal moved
        result=original(repo)
        if not moved:
            moved=True;(root/"source.py").write_text("VALUE=3\n")
        return result
    monkeypatch.setattr(audit,"_source_history_snapshot",moving)
    result=audit._repository_state(root)["source_history"]
    assert result["available"] is False and result["identity_observation_stable"] is False,"CI audit misses same-status source-byte movement"

def test_source_query_never_executes_configured_external_diff(tmp_path):
    root=repository(tmp_path/"active");(root/"source.py").write_text("VALUE=2\n");git(root,"add","source.py")
    marker=tmp_path/"diff-executed";hook=tmp_path/"external-diff"
    hook.write_text('#!/bin/sh\ntouch '+shlex.quote(str(marker))+'\n');hook.chmod(0o700)
    git(root,"config","diff.external",shlex.quote(str(hook)));git(root,"diff","--cached")
    assert marker.exists(),"native external-diff witness did not execute";marker.unlink()
    result=audit._repository_state(root)["source_history"]
    assert result["available"] and not marker.exists(),"source query executed candidate external diff"
