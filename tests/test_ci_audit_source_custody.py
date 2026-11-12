"""CI audit source reads cannot execute Git programs or borrow another repo."""
import os,shlex,subprocess
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

def test_audit_status_does_not_execute_candidate_fsmonitor(tmp_path):
 root=repository(tmp_path/"candidate repository");marker=tmp_path/"candidate program executed";hook=tmp_path/"candidate fsmonitor"
 hook.write_text('#!/bin/sh\ntouch '+shlex.quote(str(marker))+'\nprintf "token\\0"\n');hook.chmod(0o700)
 git(root,"config","core.fsmonitor",shlex.quote(str(hook)))
 config=(root/".git/config").read_bytes()
 git(root,"status","--porcelain=v1","--untracked-files=all")
 assert marker.exists(),"native Git control did not execute configured monitor"
 marker.unlink()
 observed=audit._repository_state(root)
 assert observed["available"] and observed["committed_clean"]
 assert not marker.exists(),"CI audit executed candidate Git configuration"
 assert (root/".git/config").read_bytes()==config

@pytest.mark.parametrize("consumer",("status","tracked"))
def test_audit_source_reads_reject_ambient_repository_substitution(tmp_path,monkeypatch,consumer):
 active=repository(tmp_path/"active","active.py");foreign=repository(tmp_path/"foreign","foreign.py")
 (foreign/"foreign.py").write_text("VALUE=2\n")
 monkeypatch.setenv("GIT_DIR",str(foreign/".git"));monkeypatch.setenv("GIT_WORK_TREE",str(foreign))
 if consumer=="status":
  observed=audit._repository_state(active)
  assert observed["available"] and observed["committed_clean"],"audit read the ambient foreign repository"
 else:assert audit._tracked(active,("*.py",))==["active.py"],"audit inventoried the ambient foreign repository"
 assert os.environ["GIT_DIR"]==str(foreign/".git")
 assert os.environ["GIT_WORK_TREE"]==str(foreign)

@pytest.mark.parametrize("dirty",(False,True))
def test_audit_retains_actual_requested_repository_status_and_files(tmp_path,dirty):
 root=repository(tmp_path/"actual")
 if dirty:(root/"source.py").write_text("VALUE=2\n")
 result=audit._repository_state(root)
 assert set(result)=={"available","committed_clean","status_entries","status_sha256","source_history"}
 assert result["available"] and result["committed_clean"] is not dirty
 assert bool(result["status_entries"]) is dirty
 assert audit._tracked(root,("*.py",))==["source.py"]

def test_audit_retains_nongit_unavailable_result(tmp_path):
 assert audit._repository_state(tmp_path)=={"available":False,"committed_clean":False}
 assert audit._tracked(tmp_path,("*.py",))==[]
