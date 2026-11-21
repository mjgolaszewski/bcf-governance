"""Installed protected qualifier control population and raw-artifact boundaries."""
import copy
import json
import subprocess

import pytest

from tests.test_installed_evidence_storage import (
    _environment, installed_consumer as installed_consumer, isolated_python as isolated_python,
)
from tests.test_installed_public_entrypoint_bindings import _encode
from tests.test_qualifier_control_binding import qualifier as qualifier, mutate

PROBE = '''import importlib.util,json,sys
from pathlib import Path
assert importlib.util.find_spec("bcf_governance") is None
sys.path.insert(0,str(Path("scripts").resolve()))
from _bcf_runtime import truth_receipts as owner
def decode(row):
 kind,value=row
 if kind=="scalar":return value
 if kind=="path":return Path(value)
 if kind=="dict":return {decode(key):decode(item) for key,item in value}
 return {"list":list,"tuple":tuple,"frozenset":frozenset,"set":set}[kind](decode(item) for item in value)
args=decode(json.load(sys.stdin));mode=sys.argv[1]
result=next(row for group in owner.load_receipts(**args).values() for row in group if row["evidence_id"]=="test-evidence")
if mode=="valid":assert result["result"]=="verified",result
else:assert result["result"]=="invalid","installed protected control accepted "+mode
print("installed-qualifier-control-binding-qualified")
'''


def invoke(qualifier, installed_consumer, isolated_python, mode):
    path,args=qualifier
    mutate(path,mode)
    return subprocess.run([str(isolated_python), '-I', '-B', '-c', PROBE, mode],
        cwd=installed_consumer, env=_environment(), input=json.dumps(_encode(copy.deepcopy(args))),
        capture_output=True, text=True)


@pytest.mark.parametrize('mode',['valid','missing','renamed','oracle','unregistered','escape','duplicate','symlink','parent-symlink'])
def test_installed_qualifier_control_binding(qualifier, installed_consumer, isolated_python, mode):
    result=invoke(qualifier,installed_consumer,isolated_python,mode)
    assert result.returncode==0,result.stdout+result.stderr
    assert result.stdout.strip()=='installed-qualifier-control-binding-qualified'


@pytest.mark.parametrize('mode',['renamed','oracle'])
def test_installed_removed_trace_guard_fails_named_control(qualifier, installed_consumer, isolated_python, mode):
    path=installed_consumer / 'scripts/_bcf_runtime/evidence_claim_resolution.py'
    text=path.read_text();guard='        if policy_inputs is not None:\n            controls = {}\n'
    assert text.count(guard)==1
    path.write_text(text.replace(guard,'        if False:\n            controls = {}\n'))
    result=invoke(qualifier,installed_consumer,isolated_python,mode)
    assert result.returncode==1
    assert 'installed protected control accepted '+mode in result.stderr
