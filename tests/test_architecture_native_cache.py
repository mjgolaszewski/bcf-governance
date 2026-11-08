"""Real pytest fixture lifecycle, cache faults and restored runs; authored UNRUN.

The original maintained LOC gate executes in each child. A pytest call hook
observes its real autouse cache then changes a real committed project source or
candidate input data before the original fixture teardown. No query is mocked.
"""
import hashlib
import json
import os
import subprocess
import sys
import xml.etree.ElementTree as ET

import yaml

from bcf_governance.tooling.architecture_candidate_transport import KEY, encode_candidate_inputs
from bcf_governance.tooling.local_pr_context import LocalValidationLane
from test_architecture_candidate_membership import installed_candidate
from test_architecture_native_inventory import commit


_CHILD = r'''
import importlib.util,json,os,pathlib,subprocess,sys
import pytest
root=pathlib.Path(sys.argv[1]);mode=sys.argv[2];state=pathlib.Path(sys.argv[3]);junit=sys.argv[4]
class NativeCacheFault:
    @pytest.hookimpl(hookwrapper=True)
    def pytest_runtest_call(self,item):
        outcome=yield
        assert outcome.excinfo is None,"original native gate must pass before cache fault"
        module=item.module
        assert module._OWNER_TEST_ACTIVE is True and module._OWNERSHIP is not None
        cached=module._OWNERSHIP
        assert module._ownership() is cached
        assert cached.candidate is not None and cached.candidate.authority is False
        assert cached.candidate.publication_authority is False
        record={"mode":mode,"original_native_call_passed":True,"real_autouse_cache_active":True,
                "same_cache_object_reused":True,"candidate_authority":False}
        if mode=="stale-source":
            path=root/"scripts/project_cache_probe.py"
            assert path.read_bytes()==b"VALUE = 1\n"
            path.write_bytes(b"VALUE = 2\n")
            for argv in (["add","scripts/project_cache_probe.py"],["commit","--quiet","-m","cache fault actual committed source"]):
                subprocess.run(["/usr/bin/git","--no-optional-locks","-c","core.hooksPath=/dev/null",
                                "-C",str(root),*argv],check=True,capture_output=True,timeout=15)
            record["actual_source_changed_and_committed_after_cache"]=True
        elif mode=="stale-context":
            value=json.loads(os.environ["BCF_CANDIDATE_MEMBERSHIP_INPUTS"])
            def git(expression):
                return subprocess.run(["/usr/bin/git","--no-optional-locks","-C",str(root),
                    "rev-parse","--verify",expression],check=True,capture_output=True,text=True,timeout=15).stdout.strip()
            value["adopter_commit"]=git("HEAD");value["adopter_tree"]=git("HEAD^{tree}")
            os.environ["BCF_CANDIDATE_MEMBERSHIP_INPUTS"]=json.dumps(value)
            record["actual_context_changed_after_cache"]=True
        else:
            assert mode in {"healthy","restored-source","restored-context"}
        with state.open("x") as stream:json.dump(record,stream)
raise SystemExit(pytest.main([str(root/"backend/tests/architecture/test_boundaries_ast.py")+
    "::test_production_modules_respect_loc_cap","-q","--tb=long","--junitxml="+junit],plugins=[NativeCacheFault()]))
'''


def test_real_native_pytest_cache_healthy_source_context_faults_and_restored(installed_candidate, tmp_path):
    root, inputs = installed_candidate
    config_path = root / "architecture-boundaries.yml"
    original = config_path.read_bytes()
    probe = root / "scripts/project_cache_probe.py"
    assert not probe.exists()
    probe.write_bytes(b"VALUE = 1\n")
    document = yaml.safe_load(original)
    architecture = document["architecture"]
    architecture["bounded_contexts"]["context_root_tokens"].append("scripts")
    architecture["layers"]["tooling"] = {"path_tokens": ["tools"], "required": False,
        "forbidden_import_prefixes": [], "forbidden_layer_imports": [], "forbidden_import_names": []}
    member = "scripts/_bcf_runtime/__init__.py"
    marker = root / "governance/bcf-candidate-qualification.json"
    architecture["source_component_ownership"] = {"version": "1.1", "components": [{
        "id": "runtime-cache", "layer": "tooling", "context": "_bcf_runtime", "rationale": "Exact candidate cache lifecycle",
        "members": {member: hashlib.sha256((root / member).read_bytes()).hexdigest()},
        "managed_pack": {"kind": "candidate_qualification", "path": marker.relative_to(root).as_posix(),
                         "sha256": hashlib.sha256(marker.read_bytes()).hexdigest()},
        "context_authority": {"kind": "independently_inferred_inventory", "version": "1.0", "selector": "_bcf_runtime"},
    }]}
    config_path.write_text(yaml.safe_dump(document))
    commit(root)
    environment = dict(os.environ)
    environment.update({KEY: encode_candidate_inputs(inputs), "BCF_RELEASE_MEMBERSHIP_INPUTS": "",
                        "BCF_VALIDATION_LANE": LocalValidationLane.ISOLATED_CANDIDATE_QUALIFICATION.value,
                        "PYTHONDONTWRITEBYTECODE": "1"})
    modes = ("healthy", "stale-source", "restored-source", "stale-context", "restored-context")
    try:
        for mode in modes:
            state = tmp_path / (mode + ".json")
            junit = tmp_path / (mode + ".xml")
            result = subprocess.run([sys.executable, "-I", "-B", "-c", _CHILD,
                str(root), mode, str(state), str(junit)], cwd=root, env=environment,
                capture_output=True, text=True, timeout=180)
            observed = json.loads(state.read_bytes())
            assert observed["original_native_call_passed"] and observed["real_autouse_cache_active"]
            assert observed["same_cache_object_reused"] and observed["candidate_authority"] is False
            report = ET.parse(junit).getroot()
            failures = report.findall(".//failure")
            errors = report.findall(".//error")
            assert not failures and not report.findall(".//skipped")
            if mode.startswith("stale-"):
                assert result.returncode == 1 and len(errors) == 1
                text = errors[0].text or ""
                assert "reauthenticate_gate_ownership" in text and "architecture_native_gate.py" in text
                assert "SourceComponentError" in text
                if mode == "stale-source":
                    assert "current source or ownership context changed" in text
                    assert observed["actual_source_changed_and_committed_after_cache"]
                    probe.write_bytes(b"VALUE = 1\n")
                    commit(root)
                else:
                    assert "candidate marker does not join the maintained qualification inputs" in text
                    assert observed["actual_context_changed_after_cache"]
            else:
                assert result.returncode == 0 and not errors
                cases = report.findall(".//testcase")
                assert len(cases) == 1 and cases[0].attrib["name"] == "test_production_modules_respect_loc_cap"
    finally:
        probe.unlink()
        config_path.write_bytes(original)
        commit(root)
