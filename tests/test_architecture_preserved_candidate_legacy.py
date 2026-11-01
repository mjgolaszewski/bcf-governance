"""Canonical candidate custody with genuine preservation; authored UNRUN.

The existing maintained upgrade custodian produces the marker. The complete
original thirteen native architecture tests run on ABSENT and restored input;
PRESENT must refuse the unsupported preserved partition with its real cause.
This is native-boundary evidence, not a claim that the whole prospective train
or release qualification has completed.
"""
import hashlib
import json
import os
import shutil
import subprocess
import sys
import xml.etree.ElementTree as ET

import pytest
import yaml

from bcf_governance import __version__
from bcf_governance.tooling import install_governance_pack as installer
from bcf_governance.tooling.architecture_candidate_membership import CandidateQualificationInputs
from bcf_governance.tooling.architecture_candidate_transport import KEY, encode_candidate_inputs
from bcf_governance.tooling.governance_install import release_custody
from bcf_governance.tooling.governance_install.runtime_custody import CANDIDATE_QUALIFICATION_PATH, inspect_runtime_custody, RuntimeCustodyState
from bcf_governance.tooling.local_pr_context import LocalValidationLane
from bcf_governance.tooling.release_adopter_qualification import _release_assets as asset_inventory
from test_architecture_release_membership import installed_release
from test_architecture_native_inventory import commit, git
from test_install_release_custody import _Provider


@pytest.fixture(scope="module")
def canonical_preserved_candidate(installed_release, tmp_path_factory):
    target, assets, template, digests = installed_release
    base = tmp_path_factory.mktemp("canonical_preserved_candidate")
    source = base / "source"
    source_template = source / "bcf_governance/pack/template-repo"
    shutil.copytree(template, source_template)
    git(source, "init", "--quiet")
    git(source, "config", "user.email", "preserved-candidate@example.invalid")
    git(source, "config", "user.name", "Preserved Candidate Fixture")
    commit(source)
    # A genuine existing project-owned schema, retained through the maintained
    # normal-release lock writer and candidate-upgrade preservation path.
    consumer = target / "schemas/consumer.schema.json"
    assert not consumer.exists()
    consumer.write_text('{"title":"Consumer-owned schema"}\n')
    preserved = {consumer.relative_to(target).as_posix(): hashlib.sha256(consumer.read_bytes()).hexdigest()}
    manifest = installer._pack_manifest(template)
    custody = release_custody.prepare_release_custody(assets, installed_version=__version__,
        template_root=template, token="", api=_Provider(digests))
    release_custody.write_runtime_lock(target, custody=custody, manifest_entries=manifest.files,
        upgrade_paths=installer.UPGRADE_REFRESH_PATHS, preserved=preserved,
        placeholder_values={"PLACEHOLDER":"TOKEN"})
    config_path = target / "architecture-boundaries.yml"
    document = yaml.safe_load(config_path.read_bytes())
    document["architecture"]["source_roots"] = ["src"]
    document["architecture"]["package_metadata_ownership"] = []
    config_path.write_text(yaml.safe_dump(document))
    path = target / "src/domain/orders/rules.py"
    path.parent.mkdir(parents=True)
    path.write_text("VALUE = 1\n")
    commit(target)
    prepared = release_custody.prepare_upgrade_release_custody(target, None, True, template,
        candidate_qualification_source=source, manifest_entries=manifest.files,
        retired_files=manifest.retired_files, upgrade_paths=installer.UPGRADE_REFRESH_PATHS)
    assert prepared.preserved == preserved and prepared.candidate is not None
    expected_base = prepared.candidate["adopter"]
    prepared.project(target, manifest_entries=manifest.files, upgrade_paths=installer.UPGRADE_REFRESH_PATHS,
                     placeholder_values={"PLACEHOLDER":"TOKEN"})
    commit(target)
    snapshot = inspect_runtime_custody(target, schema_path=template / "schemas/bcf-runtime-lock.schema.json")
    assert snapshot.state is RuntimeCustodyState.CANDIDATE_QUALIFICATION_EXACT
    assert snapshot.consumer_preserved == preserved
    assert snapshot.runtime_owned.keys() == release_custody.selected_runtime_inventory_paths(
        manifest.files, installer.UPGRADE_REFRESH_PATHS) - preserved.keys()
    marker_raw = (target / CANDIDATE_QUALIFICATION_PATH).read_bytes()
    source_identity = release_custody._clean_git_identity(source, label="preserved candidate source")
    build = base / "build.json"
    build.write_text(json.dumps({"subject":source_identity,"assets":asset_inventory(assets)[1]}))
    inputs = CandidateQualificationInputs(source, assets, build, template,
                                        expected_base["commit_sha"], expected_base["tree_sha"])
    return target, inputs, consumer.read_bytes(), marker_raw


def test_canonical_preserved_candidate_absent_full_native_present_refusal_restored(canonical_preserved_candidate, tmp_path):
    target, inputs, consumer_raw, marker_raw = canonical_preserved_candidate
    config = target / "architecture-boundaries.yml"
    original = config.read_bytes()
    gate = target / "backend/tests/architecture/test_boundaries_ast.py"
    environment = dict(os.environ)
    environment.update({"BCF_VALIDATION_LANE":LocalValidationLane.ISOLATED_CANDIDATE_QUALIFICATION.value,
                        KEY:"", "BCF_RELEASE_MEMBERSHIP_INPUTS":"", "PYTHONDONTWRITEBYTECODE":"1"})
    def run(label, present):
        xml = tmp_path / (label + ".xml")
        selector = str(gate) + ("::test_production_modules_respect_loc_cap" if present else "")
        result = subprocess.run([sys.executable,"-I","-B","-m","pytest",selector,"-q","--tb=long",
                                 "--junitxml="+str(xml)],cwd=target,env=environment,
                                 capture_output=True,text=True,timeout=180)
        root = ET.parse(xml).getroot()
        return result, root
    try:
        healthy, report = run("absent-healthy", False)
        assert healthy.returncode == 0 and len(report.findall(".//testcase")) == 13
        assert not report.findall(".//failure") and not report.findall(".//error")
        document = yaml.safe_load(original)
        member = "src/domain/orders/rules.py"
        document["architecture"]["source_component_ownership"] = {"version":"1.1","components":[{
            "id":"orders", "layer":"domain", "context":"orders", "rationale":"Exact project source request",
            "members":{member:hashlib.sha256((target/member).read_bytes()).hexdigest()},"managed_pack":None,
            "context_authority":{"kind":"independently_inferred_inventory","version":"1.0","selector":"orders"}}]}
        config.write_text(yaml.safe_dump(document))
        commit(target)
        environment[KEY] = encode_candidate_inputs(inputs)
        refused, report = run("present-preservation-refusal", True)
        errors = report.findall(".//error")
        assert refused.returncode == 1 and len(errors) == 1 and not report.findall(".//failure")
        text = errors[0].text or ""
        assert "SourceComponentError" in text and "qualify_candidate_membership" in text
        assert "exact candidate inventory without unqualified preservation required" in text
        config.write_bytes(original)
        commit(target)
        environment[KEY] = ""
        restored, report = run("absent-restored", False)
        assert restored.returncode == 0 and len(report.findall(".//testcase")) == 13
        assert not report.findall(".//failure") and not report.findall(".//error")
        assert (target / "schemas/consumer.schema.json").read_bytes() == consumer_raw
        assert (target / CANDIDATE_QUALIFICATION_PATH).read_bytes() == marker_raw
    finally:
        if config.read_bytes() != original:
            config.write_bytes(original)
            commit(target)
