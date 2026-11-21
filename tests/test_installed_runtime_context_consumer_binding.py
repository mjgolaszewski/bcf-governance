"""Installed protected operation consumer preserves the ambient context binding."""
import json
import subprocess

import pytest

from tests.test_installed_evidence_storage import (
    _environment, installed_consumer as installed_consumer, isolated_python as isolated_python,
)
from tests.test_installed_public_entrypoint_bindings import _encode
from tests.runtime_context_factory_support import context_inputs as context_inputs, OPERATION, CALLER, CALLEE, PAIR

PROBE = '''import importlib.util,json,subprocess,sys,yaml
from pathlib import Path
assert importlib.util.find_spec("bcf_governance") is None
sys.path.insert(0,str(Path("scripts").resolve()))
from _bcf_runtime import ci_graph_composition_operations as owner
from _bcf_runtime.ci_graph_errors import CIGraphError
from _bcf_runtime.semantic_operation_effects import SemanticOperationEffectError
def decode(row):
 kind,value=row
 if kind=="scalar":return value
 if kind=="path":return Path(value)
 if kind=="dict":return {decode(key):decode(item) for key,item in value}
 return {"list":list,"tuple":tuple,"frozenset":frozenset,"set":set}[kind](decode(item) for item in value)
args=decode(json.load(sys.stdin));mode=sys.argv[1]
subject=args.pop("subject");op=args.pop("operation");caller=args.pop("caller");callee=args.pop("callee");pair=args.pop("pair")
def capture(policy,roots):
 return owner.capture_public_operation_bindings(args["repo_root"],policy_subject=policy,runtime_subject=subject,
  required_relationships={op:frozenset({pair})},relationship_roots={pair:frozenset(roots)})
public=capture(subject,[caller]);args["public_capture"]=public
context=owner.capture_operation_runtime_context(**args);population={op:context}
if mode=="relationships":public=capture(subject,[caller,callee])
elif mode=="protected-policy":
 path=args["repo_root"]/"governance/gate-contracts.yml";policy=yaml.safe_load(path.read_text())
 policy["claim_model"]["claims"]["test-claim"]["truth"]+=" revised protected qualification"
 path.write_text(yaml.safe_dump(policy))
 def git(*values):return subprocess.check_output(["git",*values],cwd=args["repo_root"],text=True).strip()
 git("add","governance/gate-contracts.yml");git("commit","-qm","revise protected model policy")
 public=capture(dict(commit_sha=git("rev-parse","HEAD"),tree_sha=git("rev-parse","HEAD^{tree}")),[caller])
elif mode=="missing-context":population[op]=None
try:owner.validate_public_operation_capture(args["repo_root"],args["inventory"],public,runtime_contexts=population)
except CIGraphError as exc:
 if mode!="valid":assert str(exc)=="runtime context differs from consuming protected operation capture",str(exc)
 else:
  cause=exc
  while cause is not None and not isinstance(cause,SemanticOperationEffectError):cause=cause.__cause__
  assert cause is not None and cause.effect_obligations
  assert not any(row[0]==callee for row in cause.effect_obligations)
else:raise AssertionError("surrounding strict CLI obligations waived")
print("installed-runtime-context-consumer-bound")
'''


@pytest.mark.parametrize('mode', ['valid', 'protected-policy', 'relationships', 'missing-context'])
def test_installed_runtime_context_consumer_binding(context_inputs, installed_consumer, isolated_python, mode):
    args = dict(context_inputs)
    public = args.pop('public_capture')
    args.update(subject=dict(zip(('commit_sha', 'tree_sha'), public.runtime_subject)),
                operation=OPERATION, caller=CALLER, callee=CALLEE, pair=PAIR)
    result = subprocess.run([str(isolated_python), '-I', '-B', '-c', PROBE, mode], cwd=installed_consumer,
                            env=_environment(), input=json.dumps(_encode(args)), capture_output=True, text=True)
    assert result.returncode == 0, result.stdout + result.stderr
    assert result.stdout.strip() == 'installed-runtime-context-consumer-bound'
