"""Installed model factory uses canonical evidence without an installed SDK."""
import json
import subprocess

import pytest

from tests.test_installed_evidence_storage import (
    _environment, installed_consumer as installed_consumer, isolated_python as isolated_python,
)
from tests.test_installed_public_entrypoint_bindings import _encode
from tests.runtime_context_factory_support import context_inputs as context_inputs, OPERATION, CALLER, PAIR

PROBE = '''import importlib.util,json,sys
from pathlib import Path
assert importlib.util.find_spec("bcf_governance") is None
sys.path.insert(0,str(Path("scripts").resolve()))
from _bcf_runtime import ci_graph_composition_operations as owner
from _bcf_runtime.ci_graph_errors import CIGraphError
def decode(row):
 kind,value=row
 if kind=="scalar":return value
 if kind=="path":return Path(value)
 if kind=="dict":return {decode(key):decode(item) for key,item in value}
 return {"list":list,"tuple":tuple,"frozenset":frozenset,"set":set}[kind](decode(item) for item in value)
args=decode(json.load(sys.stdin));mode=sys.argv[1]
subject=args.pop("subject");operation=args.pop("operation");caller=args.pop("caller");pair=args.pop("pair")
args["public_capture"]=owner.capture_public_operation_bindings(args["repo_root"],policy_subject=subject,
 runtime_subject=subject,required_relationships={operation:frozenset({pair})},relationship_roots={pair:frozenset({caller})})
if mode=="wrong-native":args["native_subject"]["namespace_sha256"]="f"*64
if mode=="missing-proof":
 path=args["evidence_root"]/"test.evidence.json";receipt=json.loads(path.read_bytes())
 receipt["observations"].pop("runtime_context");path.write_text(json.dumps(receipt))
try:
 context=owner.capture_operation_runtime_context(**args)
 if mode=="moved-proof":
  path=args["evidence_root"]/"test.evidence.json";receipt=json.loads(path.read_bytes())
  receipt["observations"]["runtime_context"]["model_version"]="99.0";path.write_text(json.dumps(receipt))
 summaries=owner.runtime_context_call_summaries(context.public_capture.registry.operations[0],args["inventory"],context)
except CIGraphError:
 assert mode!="valid"
else:
 assert mode=="valid" and len(summaries)==2
print("installed-runtime-model-factory-qualified")
'''


@pytest.mark.parametrize('mode', ['valid', 'wrong-native', 'missing-proof', 'moved-proof'])
def test_installed_runtime_model_factory(context_inputs, installed_consumer, isolated_python, mode):
    args = dict(context_inputs)
    public = args.pop('public_capture')
    args.update(subject=dict(zip(('commit_sha', 'tree_sha'), public.runtime_subject)),
                operation=OPERATION, caller=CALLER, pair=PAIR)
    result = subprocess.run([str(isolated_python), '-I', '-B', '-c', PROBE, mode],
                            cwd=installed_consumer, env=_environment(), input=json.dumps(_encode(args)),
                            capture_output=True, text=True)
    assert result.returncode == 0, result.stdout + result.stderr
    assert result.stdout.strip() == 'installed-runtime-model-factory-qualified'
