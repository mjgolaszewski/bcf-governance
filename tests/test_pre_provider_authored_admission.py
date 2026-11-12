"""Available authored defects must reject before provider context discovery."""
import json,os,subprocess
from pathlib import Path
from types import SimpleNamespace
import pytest
from bcf_governance.tooling import ci_authority_submit as submit
from bcf_governance.tooling.local_pr import ProspectiveValidationError
CASES={
 "phase":({"plans/product-spec.yml":{"execution_phases":[{"phase_id":"P1","build_block":"a"}]},"plans/build-plan.yml":{"phase_sequence":[{"phase_id":"P2","build_block":"a"}]},"plans/phase-ledger.yml":{},"MEMORY.yml":{}},"same phase identities"),
 "deadline":({"governance/gate-contracts.yml":{"execution_policy":{"default_timeout_seconds":True}}},"gate execution timeout policy is invalid"),
 "controls":({"governance/gate-contracts.yml":{"gates":{}}},"authored control registry requires governance-profile.yml"),
}
def git(root,*args):
 env={k:v for k,v in os.environ.items() if not k.startswith("GIT_")}
 return subprocess.run(["git","-c","core.hooksPath=/dev/null","-c","core.fsmonitor=false","-C",str(root),*args],env=env,capture_output=True,text=True,check=True).stdout.strip()
def committed(root,documents):
 git(root,"init","-b","main");git(root,"config","user.name","Fixture");git(root,"config","user.email","fixture@example.invalid")
 (root/"source.py").write_text("VALUE=1\n")
 for name,value in documents.items():
  path=root/name;path.parent.mkdir(parents=True,exist_ok=True);path.write_text(json.dumps(value)+"\n")
 git(root,"add",".");git(root,"commit","-m","authored admission fixture")
 return git(root,"rev-parse","HEAD"),git(root,"rev-parse","HEAD^{tree}")
@pytest.mark.parametrize("case",tuple(CASES))
@pytest.mark.parametrize("boundary",("submit","normalization"))
def test_real_authored_defect_rejects_before_provider_or_allocation(tmp_path,monkeypatch,case,boundary):
 documents,message=CASES[case];subject=committed(tmp_path,documents);trace=[]
 def provider(*args,**kwargs):
  trace.append("provider");raise RuntimeError("provider discovery reached before authored rejection")
 def forbidden(*args,**kwargs):
  pytest.fail("authored defect allocated normalization or proof")
 monkeypatch.setattr(submit,"resolve_local_pr_context",provider)
 monkeypatch.setattr(submit,"local_gate_lease",forbidden)
 monkeypatch.setattr(submit,"run_prospective_train",forbidden)
 with pytest.raises(ProspectiveValidationError,match=message):
  if boundary=="submit":submit.submit_candidate(tmp_path,python_executable=Path("/unallocated-python"),provider_api=object())
  else:submit._normalize_submission(tmp_path,python_executable=Path("/unallocated-python"),execution_id=subject[0],semantic_intent=None,runner=forbidden)
 assert not trace
 assert (git(tmp_path,"rev-parse","HEAD"),git(tmp_path,"rev-parse","HEAD^{tree}"))==subject
 assert not git(tmp_path,"status","--porcelain")
def test_valid_graphless_source_still_reaches_provider_discovery(tmp_path,monkeypatch):
 subject=committed(tmp_path,{});trace=[]
 def provider(*args,**kwargs):
  trace.append("provider");raise RuntimeError("valid source reached provider")
 monkeypatch.setattr(submit,"resolve_local_pr_context",provider)
 with pytest.raises(RuntimeError,match="valid source reached provider"):
  submit.submit_candidate(tmp_path,python_executable=Path("/unallocated-python"),provider_api=object())
 assert trace==["provider"] and git(tmp_path,"rev-parse","HEAD")==subject[0]
 assert not git(tmp_path,"status","--porcelain")
def test_dirty_subject_rejects_before_authored_and_provider_checks(tmp_path,monkeypatch):
 committed(tmp_path,CASES["controls"][0]);(tmp_path/"source.py").write_text("VALUE=2\n")
 monkeypatch.setattr(submit,"resolve_local_pr_context",lambda *a,**k:pytest.fail("dirty source reached provider"))
 with pytest.raises(ProspectiveValidationError,match="clean committed tree"):
  submit.submit_candidate(tmp_path,python_executable=Path("/unallocated-python"),provider_api=object())
