"""Git audit inventories retain actual UTF-8 path identities."""
import os,subprocess
import pytest
from bcf_governance.tooling import ci_graph_audit as audit
def git(root,*args):
 env={key:value for key,value in os.environ.items() if not key.startswith("GIT_")}
 return subprocess.run(["git","--no-replace-objects","-c","core.hooksPath=/dev/null","-C",str(root),*args],env=env,capture_output=True,text=True,check=True).stdout.strip()
def repository(root,name="source.py"):
 root.mkdir();git(root,"init","-b","main");git(root,"config","user.name","Fixture");git(root,"config","user.email","fixture@example.invalid")
 (root/name).write_text("VALUE=1\n");git(root,"add",".");git(root,"commit","-m","audit source fixture")
 return root


@pytest.mark.parametrize("name",("plain.py","line\nbreak.py","tab\tbreak.py",'quoted"name.py',"back\\slash.py","café.py"))
def test_audit_tracked_inventory_preserves_actual_path_name(tmp_path,name):
    root=repository(tmp_path/"candidate",name)
    git(root,"config","core.quotepath","true")
    before=(root/name).read_bytes()
    assert audit._tracked(root,("*.py",))==[name],"CI audit changed a Git path identity"
    assert (root/name).read_bytes()==before
    assert audit._repository_state(root)["committed_clean"]
