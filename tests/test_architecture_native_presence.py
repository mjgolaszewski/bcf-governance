"""Real pytest body-level presence downgrade and restored controls; UNRUN."""
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
import json,pathlib,sys
import pytest,yaml
root=pathlib.Path(sys.argv[1]);mode=sys.argv[2];state=pathlib.Path(sys.argv[3]);junit=sys.argv[4]
class PresenceFault:
    @pytest.hookimpl(hookwrapper=True)
    def pytest_runtest_call(self,item):
        module=item.module
        record={"mode":mode,"real_fixture_active":module._OWNER_TEST_ACTIVE,
                "PRESENT_compiled_before_body":module._OWNERSHIP is not None}
        config=root/"architecture-boundaries.yml"
        original=config.read_bytes()
        if mode.startswith("downgrade"):
            value=yaml.safe_load(original)
            assert "source_component_ownership" in value["architecture"]
            del value["architecture"]["source_component_ownership"]
            config.write_text(yaml.safe_dump(value))
            record["real_config_temporarily_ABSENT_during_body"]=True
        try:
            outcome=yield
            record["original_body_failed"]=outcome.excinfo is not None
        finally:
            config.write_bytes(original)
            record["original_PRESENT_bytes_restored_before_teardown"]=config.read_bytes()==original
            with state.open("x") as stream:json.dump(record,stream)
raise SystemExit(pytest.main([str(root/"backend/tests/architecture/test_boundaries_ast.py")+
    "::test_production_modules_respect_loc_cap","-q","--tb=long","--junitxml="+junit],plugins=[PresenceFault()]))
'''


def test_real_native_PRESENT_admission_cannot_be_downgraded_for_body(installed_candidate, tmp_path):
    root, inputs = installed_candidate
    config = root / "architecture-boundaries.yml"
    original = config.read_bytes()
    document = yaml.safe_load(original)
    architecture = document["architecture"]
    architecture["bounded_contexts"]["context_root_tokens"].append("scripts")
    architecture["layers"]["tooling"] = {"path_tokens":["tools"],"required":False,
        "forbidden_import_prefixes":[],"forbidden_layer_imports":[],"forbidden_import_names":[]}
    member = "scripts/_bcf_runtime/__init__.py"
    marker = root / "governance/bcf-candidate-qualification.json"
    component = {"id":"runtime-presence","layer":"tooling","context":"_bcf_runtime",
        "rationale":"Exact source admission before native body",
        "members":{member:hashlib.sha256((root/member).read_bytes()).hexdigest()},
        "managed_pack":{"kind":"candidate_qualification","path":marker.relative_to(root).as_posix(),
                        "sha256":hashlib.sha256(marker.read_bytes()).hexdigest()},
        "context_authority":{"kind":"independently_inferred_inventory","version":"1.0","selector":"_bcf_runtime"}}
    architecture["source_component_ownership"] = {"version":"1.1","components":[component]}
    valid_raw = yaml.safe_dump(document).encode()
    environment = dict(os.environ)
    environment.update({KEY:encode_candidate_inputs(inputs),"BCF_RELEASE_MEMBERSHIP_INPUTS":"",
        "BCF_VALIDATION_LANE":LocalValidationLane.ISOLATED_CANDIDATE_QUALIFICATION.value,
        "PYTHONDONTWRITEBYTECODE":"1"})
    modes = ("healthy", "downgrade-valid", "restored-valid", "downgrade-invalid", "restored-invalid")
    try:
        for mode in modes:
            if mode == "downgrade-invalid":
                component["members"][member] = "0" * 64
                next_raw = yaml.safe_dump(document).encode()
            else:
                next_raw = valid_raw
            if config.read_bytes() != next_raw:
                config.write_bytes(next_raw)
                commit(root)
            state = tmp_path / (mode + ".json")
            junit = tmp_path / (mode + ".xml")
            result = subprocess.run([sys.executable,"-I","-B","-c",_CHILD,str(root),mode,
                # Keep bounded headroom for concurrent native source admission.
                str(state),str(junit)],cwd=root,env=environment,capture_output=True,text=True,timeout=300)
            report = ET.parse(junit).getroot()
            failures, errors = report.findall(".//failure"), report.findall(".//error")
            assert not report.findall(".//skipped")
            if mode == "downgrade-invalid":
                assert result.returncode == 1 and len(errors) == 1 and not failures
                text = errors[0].text or ""
                assert "SourceComponentError" in text and "_reduce_membership" in text
                assert "declared member is unobserved or stale" in text
                assert not state.exists(), "invalid original PRESENT must refuse before any body hook"
            else:
                observed = json.loads(state.read_bytes())
                assert observed["real_fixture_active"] and observed["PRESENT_compiled_before_body"]
                assert observed["original_PRESENT_bytes_restored_before_teardown"]
                if mode == "downgrade-valid":
                    assert result.returncode == 1 and len(failures) == 1 and not errors
                    text = failures[0].text or ""
                    assert "SourceComponentUnsupportedError" in text and "_admit_configuration" in text
                    assert "native configuration differs from pre-body admission" in text
                    assert observed["real_config_temporarily_ABSENT_during_body"] and observed["original_body_failed"]
                else:
                    assert result.returncode == 0 and not failures and not errors
                    assert observed["original_body_failed"] is False
    finally:
        config.write_bytes(original)
        commit(root)
