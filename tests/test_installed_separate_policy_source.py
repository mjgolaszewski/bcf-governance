"""Installed protected-policy captures reauthenticate before interpretation."""
import copy
import json
import subprocess

import pytest

from tests.test_installed_evidence_storage import (
    _environment, installed_consumer as installed_consumer, isolated_python as isolated_python,
)
from tests.test_installed_public_entrypoint_bindings import _encode
from tests.test_separate_policy_source import arguments, git, roots as roots, subject

PROBE = '''import importlib.util,json,sys
from pathlib import Path
assert importlib.util.find_spec("bcf_governance") is None
sys.path.insert(0,str(Path("scripts").resolve()))
from _bcf_runtime import ci_graph_composition_operations as owner
from _bcf_runtime.ci_graph_errors import CIGraphError
from _bcf_runtime.semantic_ownership_inventory import discover_python_source
def decode(row):
 kind,value=row
 if kind=="scalar":return value
 if kind=="path":return Path(value)
 if kind=="dict":return {decode(key):decode(item) for key,item in value}
 return {"list":list,"tuple":tuple,"frozenset":frozenset,"set":set}[kind](decode(item) for item in value)
args=decode(json.load(sys.stdin));mode=sys.argv[1]
captured=owner.capture_public_operation_bindings(**args)
facts=discover_python_source(args["repo_root"],source_subject=args["runtime_subject"],call_contracts_version="1.0")
if mode=="policy":
 oid=captured[1]["policy_blob_oid"]
 path=args["policy_repo_root"]/".git/objects"/oid[:2]/oid[2:]
 assert path.is_file()
 path.unlink()
elif mode=="subject":facts["source_population"]["subject"]=args["policy_subject"]
if mode=="valid":
 result=owner.validate_public_operation_capture(args["repo_root"],facts,captured)
 assert result["policy_changed"] is True
 assert result["policy_subject"]==args["policy_subject"]
 assert result["runtime_subject"]==args["runtime_subject"]
 assert result["authority"] is False and result["execution_qualified"] is False
else:
 try:owner.validate_public_operation_capture(args["repo_root"],facts,captured)
 except CIGraphError as error:assert "public operation" in str(error),str(error)
 else:raise AssertionError("installed changed "+mode+" accepted")
print("installed-separate-policy-source-qualified")
'''


def invoke(roots, installed_consumer, isolated_python, mode):
    protected, candidate = roots
    expected = subject(protected)
    (candidate / "governance/application-operations.yml").write_text("candidate: is_not_authority\n")
    git(candidate, "add", ".")
    git(candidate, "commit", "-qm", "candidate policy differs")
    args = dict(arguments(candidate, expected), policy_repo_root=protected)
    return subprocess.run([str(isolated_python), "-I", "-B", "-c", PROBE, mode],
        cwd=installed_consumer, env=_environment(), input=json.dumps(_encode(copy.deepcopy(args))),
        capture_output=True, text=True)


@pytest.mark.parametrize("mode", ["valid", "policy", "subject"])
def test_installed_separate_source_roles(roots, installed_consumer, isolated_python, mode):
    result = invoke(roots, installed_consumer, isolated_python, mode)
    assert result.returncode == 0, result.stdout + result.stderr
    assert result.stdout.strip() == "installed-separate-policy-source-qualified"


@pytest.mark.parametrize("mode", ["policy", "subject"])
def test_installed_independent_detector_refuses_removed_reauthentication(roots, installed_consumer, isolated_python, mode):
    path = installed_consumer / "scripts/_bcf_runtime/ci_graph_composition_operations.py"
    source = path.read_text()
    guard = "    registry = _reauthenticate_public_operation_capture(capture, repo_root=repo_root, inventory=inventory)\n"
    assert source.count(guard) == 1
    path.write_text(source.replace(guard, "    registry = capture[0]\n"))
    result = invoke(roots, installed_consumer, isolated_python, mode)
    assert result.returncode == 1
    assert "installed changed " + mode + " accepted" in result.stderr
