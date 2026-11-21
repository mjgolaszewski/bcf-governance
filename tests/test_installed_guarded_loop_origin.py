"""Fresh and upgraded SDK-absent consumers preserve versioned loop scope."""
import json
import subprocess

import pytest

from tests.test_installed_evidence_storage import (
    _environment, installed_consumer as installed_consumer, isolated_python as isolated_python,
)
from tests.test_installed_public_entrypoint_bindings import _encode
from tests.runtime_context_factory_support import make_context_inputs, OPERATION, CALLER, PAIR

PROBE = '''import importlib.util,json,sys
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
subject=args.pop("subject");op=args.pop("operation");caller=args.pop("caller");pair=args.pop("pair")
args["public_capture"]=owner.capture_public_operation_bindings(args["repo_root"],policy_subject=subject,
 runtime_subject=subject,required_relationships={op:frozenset({pair})},relationship_roots={pair:frozenset({caller})})
if mode in {"missing-proof","extra-claim"}:
 path=args["evidence_root"]/"test.evidence.json";receipt=json.loads(path.read_bytes())
 if mode=="missing-proof":receipt["observations"]["runtime_context"].pop("iteration_sites")
 else:receipt["observations"]["runtime_context"]["iteration_sites"][0]["elements"]="always-string"
 path.write_text(json.dumps(receipt))
if mode=="wrong-native":args["native_subject"]["namespace_sha256"]="f"*64
try:
 context=owner.capture_operation_runtime_context(**args)
 summaries=owner.runtime_context_call_summaries(context.public_capture.registry.operations[0],args["inventory"],context)
except CIGraphError:
 assert mode in {"missing-proof","extra-claim","wrong-native"}
else:
 assert mode in {"legacy","valid"}
 assert len(summaries)==(2 if mode=="legacy" else 3)
 assert len(context.iteration_sites)==(0 if mode=="legacy" else 1)
 try:owner.validate_public_operation_capture(args["repo_root"],args["inventory"],args["public_capture"],runtime_contexts={op:context})
 except CIGraphError as exc:
  cause=exc
  while cause is not None and not isinstance(cause,SemanticOperationEffectError):cause=cause.__cause__
  assert cause is not None and cause.effect_obligations
  if mode=="valid":
   site=json.loads(context.iteration_sites[0][0]);target=f"{caller}:iteration:{site['expression_sha256']}:{site['occurrence']}"
   assert not any(row[1:3]==("runtime_protocol",target) for row in cause.effect_obligations)
 else:raise AssertionError("whole CLI must remain blocked")
print("installed-guarded-loop-origin-qualified")
'''


@pytest.mark.parametrize('mode', ['legacy', 'valid', 'missing-proof', 'extra-claim', 'wrong-native'])
def test_installed_guarded_loop_origin(tmp_path, installed_consumer, isolated_python, mode):
    args = make_context_inputs(tmp_path, model_version='1.0' if mode == 'legacy' else '1.1')
    public = args.pop('public_capture')
    args.update(subject=dict(zip(('commit_sha', 'tree_sha'), public.runtime_subject)),
                operation=OPERATION, caller=CALLER, pair=PAIR)
    result = subprocess.run([str(isolated_python), '-I', '-B', '-c', PROBE, mode], cwd=installed_consumer,
                            env=_environment(), input=json.dumps(_encode(args)), capture_output=True, text=True)
    assert result.returncode == 0, result.stdout + result.stderr
    assert result.stdout.strip() == 'installed-guarded-loop-origin-qualified'
