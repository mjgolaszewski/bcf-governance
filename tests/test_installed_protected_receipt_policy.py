"""Installed canonical receipt owner admits only exact protected policy inputs."""
import copy
import json
import subprocess

import pytest

from tests.test_installed_evidence_storage import (
    _environment, installed_consumer as installed_consumer, isolated_python as isolated_python,
)
from tests.test_installed_public_entrypoint_bindings import _encode
from tests.test_protected_receipt_policy import bundle as bundle

PROBE = '''import importlib.util,json,sys,subprocess
from pathlib import Path
assert importlib.util.find_spec("bcf_governance") is None
sys.path.insert(0,str(Path("scripts").resolve()))
from _bcf_runtime import truth_receipts as owner
from _bcf_runtime import evidence_claim_resolution as claims
assert owner._multi_claim_test_issues is claims._multi_claim_test_issues
assert owner._qualification_issues is claims._qualification_issues
def decode(row):
 kind,value=row
 if kind=="scalar":return value
 if kind=="path":return Path(value)
 if kind=="dict":return {decode(key):decode(item) for key,item in value}
 return {"list":list,"tuple":tuple,"frozenset":frozenset,"set":set}[kind](decode(item) for item in value)
args,subject=decode(json.load(sys.stdin));mode=sys.argv[1];root=args["repo_root"]
if mode=="dirty":
 for name in ["governance-profile.yml","governance/evidence-policy.yml","governance/gate-contracts.yml","schemas/evidence-receipt.schema.json","schemas/evidence-session-v3.schema.json"]:
  (root/name).write_text("false")
if mode=="settings":args["require_session"]=False
if mode=="object":
 oid=subprocess.check_output(["git","--no-replace-objects","-c","core.hooksPath=/dev/null","rev-parse",subject["commit_sha"]+":governance/gate-contracts.yml"],cwd=root,text=True).strip()
 (root/".git/objects"/oid[:2]/oid[2:]).unlink()
if mode in {"settings","object"}:
 try:owner.load_receipts(**args,policy_subject=subject)
 except owner.ReceiptError:pass
 else:raise AssertionError("installed protected receipt policy accepted "+mode)
else:
 result=[row for group in owner.load_receipts(**args,policy_subject=subject).values() for row in group]
 assert result and all(row["result"]=="verified" for row in result),result
 assert all(row["admission_policy"]["subject"]==subject for row in result)
print("installed-protected-receipt-policy-qualified")
'''


@pytest.mark.parametrize('mode', ['valid','dirty','settings','object'])
def test_installed_protected_receipt_policy(bundle, installed_consumer, isolated_python, mode):
    _, _, args, subject = bundle
    result = subprocess.run([str(isolated_python), '-I', '-B', '-c', PROBE, mode],
        cwd=installed_consumer, env=_environment(), input=json.dumps(_encode(copy.deepcopy((args, subject)))),
        capture_output=True, text=True)
    assert result.returncode==0, result.stdout+result.stderr
    assert result.stdout.strip()=='installed-protected-receipt-policy-qualified'
