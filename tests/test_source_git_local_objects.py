"""Native partial-clone object reads must not invoke repository remote helpers."""
import os, shlex, subprocess
from pathlib import Path
import pytest
from bcf_governance.tooling.semantic_source_paths import _source_git

def git(root,*args,check=True):
    environment={key:value for key,value in os.environ.items() if not key.startswith("GIT_")}
    return subprocess.run(["git","--no-replace-objects","-c","core.hooksPath=/dev/null","-C",str(root),*args],env=environment,capture_output=True,text=True,check=check,timeout=10)

@pytest.mark.parametrize("kind",("blob","tree"))
@pytest.mark.parametrize("hostile_ambient",(False,True))
def test_source_object_read_cannot_launch_lazy_fetch(tmp_path,monkeypatch,kind,hostile_ambient):
    root=tmp_path/"source";root.mkdir()
    git(root,"init","-b","main");git(root,"config","user.name","Fixture")
    git(root,"config","user.email","fixture@example.invalid")
    (root/"source.py").write_text("VALUE=1\n")
    git(root,"add",".");git(root,"commit","-m","isolated source fixture")
    subject="HEAD:source.py" if kind=="blob" else "HEAD^{tree}"
    oid=git(root,"rev-parse",subject).stdout.strip()
    arguments=("cat-file","-p",oid) if kind=="blob" else ("ls-tree","-r","-z",oid)
    assert _source_git(root,*arguments).returncode==0
    marker=tmp_path/"remote-helper-executed";binary=tmp_path/"bin";binary.mkdir()
    helper=binary/"git-remote-sourceprobe"
    helper.write_text("#!/bin/sh\ntouch "+shlex.quote(str(marker))+"\nexit 1\n");helper.chmod(0o700)
    monkeypatch.setenv("PATH",str(binary)+os.pathsep+os.environ["PATH"])
    git(root,"config","remote.origin.url","sourceprobe::fixture")
    git(root,"config","remote.origin.promisor","true")
    git(root,"config","extensions.partialClone","origin")
    git(root,"config","protocol.sourceprobe.allow","always")
    objects=root/".git/objects"
    assert objects.is_dir() and not objects.is_symlink()
    assert not (objects/"info/alternates").exists()
    missing=objects/oid[:2]/oid[2:]
    assert missing.is_file() and not missing.is_symlink()
    assert missing.resolve().is_relative_to(objects.resolve())
    missing.unlink()
    assert not marker.exists()
    native=git(root,*arguments,check=False)
    assert native.returncode!=0 and marker.exists(),"native missing-object helper witness did not execute"
    marker.unlink()
    before=(root/".git/config").read_bytes()
    if hostile_ambient:
        monkeypatch.setenv("GIT_NO_LAZY_FETCH","0")
        monkeypatch.setenv("GIT_ALLOW_PROTOCOL","sourceprobe")
    observed=_source_git(root,*arguments)
    assert observed.returncode!=0,"missing local object unexpectedly resolved"
    assert not marker.exists(),"source query executed candidate promisor helper"
    assert (root/".git/config").read_bytes()==before
    assert not missing.exists()
    assert (root/"source.py").read_text()=="VALUE=1\n"
