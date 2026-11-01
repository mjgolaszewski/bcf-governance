"""Real candidate source/build/install joins; authored, UNRUN, no provider mock.

The fixture uses maintained release-asset construction, actual clean Git trees,
canonical projection, and the existing candidate marker inspector. Mutations
are committed and restored; a healthy query follows every expected refusal.
"""
import hashlib
import json
import shutil

import pytest
import yaml

from bcf_governance import __version__
from bcf_governance.tooling import architecture_candidate_membership as owner
from bcf_governance.tooling import architecture_release_membership as released
from bcf_governance.tooling import install_governance_pack as installer
from bcf_governance.tooling.governance_install import release_custody
from bcf_governance.tooling.governance_install.runtime_custody import CANDIDATE_QUALIFICATION_PATH
from bcf_governance.tooling.architecture_source_components import SourceComponentError
from test_install_release_custody import _release_assets, TEMPLATE_ROOT
from test_architecture_native_inventory import commit, git


def _sha(raw):
    return hashlib.sha256(raw).hexdigest()


def _init(root):
    git(root, "init", "--quiet")
    git(root, "config", "user.email", "candidate-membership@example.invalid")
    git(root, "config", "user.name", "Candidate Membership Fixture")
    commit(root)


@pytest.fixture(scope="module")
def installed_candidate(tmp_path_factory):
    base = tmp_path_factory.mktemp("candidate_membership")
    assets, _ = _release_assets(base / "assets")
    source = base / "candidate-source"
    template = source / "bcf_governance/pack/template-repo"
    shutil.copytree(TEMPLATE_ROOT, template)
    _init(source)
    identity = release_custody._clean_git_identity(source, label="fixture candidate")
    from bcf_governance.tooling.release_adopter_qualification import _release_assets as inventory
    build = base / "build.json"
    build.write_text(json.dumps({"subject": identity, "assets": inventory(assets)[1]}))
    target = base / "adopter"
    target.mkdir()
    (target / "README.md").write_text("Pinned candidate adopter base.\n")
    _init(target)
    adopter = release_custody._clean_git_identity(target, label="fixture adopter")
    manifest = installer._pack_manifest(template)
    selected = release_custody.selected_runtime_inventory_paths(manifest.files, installer.UPGRADE_REFRESH_PATHS)
    files = {}
    for relative in sorted(selected):
        path = target / relative
        path.parent.mkdir(parents=True, exist_ok=True)
        raw = release_custody._project_bytes((template / relative).read_bytes(), {"PLACEHOLDER": "TOKEN"})
        path.write_bytes(raw)
        files[relative] = _sha(raw)
    config = yaml.safe_load((template / "architecture-boundaries.yml").read_text())
    config["architecture"]["source_roots"] = ["scripts"]
    config["architecture"]["package_metadata_ownership"] = []
    (target / "architecture-boundaries.yml").write_text(yaml.safe_dump(config))
    marker = target / CANDIDATE_QUALIFICATION_PATH
    marker.parent.mkdir(parents=True, exist_ok=True)
    marker.write_text(json.dumps({
        "schema_version": "1.0", "kind": "candidate_qualification", "non_authoritative": True,
        "runtime_version": __version__,
        "candidate": dict(identity, pack_manifest_sha256=_sha((template / ".bcf-pack-manifest.json").read_bytes())),
        "adopter": adopter, "predecessor_runtime_lock_sha256": "0" * 64,
        "files": files, "preserved_consumer_files": {},
    }))
    commit(target)
    inputs = owner.CandidateQualificationInputs(source, assets, build, template,
                                               adopter["commit_sha"], adopter["tree_sha"])
    return target, inputs


def test_exact_candidate_is_qualified_without_release_authority(installed_candidate):
    target, inputs = installed_candidate
    result = owner.qualify_candidate_membership(target, inputs)
    assert result.domain == "isolated_candidate_qualification"
    assert result.authority is False and result.publication_authority is False
    assert result.classifications and all(row.ownership == "managed" for row in result.classifications)
    with pytest.raises(SourceComponentError, match="candidate qualification has no immutable release authority") as failure:
        released.authenticate_release_membership(target, assets_root=inputs.assets_root,
                                                 template_root=inputs.template_root, token="")
    assert any(entry.name == "authenticate_release_membership" for entry in failure.traceback)


@pytest.mark.parametrize("mutation,diagnostic", [
    ("foreign-candidate", "marker does not join"),
    ("foreign-adopter", "marker does not join"),
    ("false-domain", "marker does not join"),
    ("wrong-version", "marker does not join"),
    ("build-assets", "assets differ"),
    ("build-subject", "assets differ"),
    ("omitted-member", "membership differs"),
    ("edited-and-rehashed", "canonical projection"),
    ("preservation", "without unqualified preservation"),
])
def test_candidate_claims_do_not_replace_fresh_owner_joins(installed_candidate, mutation, diagnostic):
    target, inputs = installed_candidate
    marker_path = target / CANDIDATE_QUALIFICATION_PATH
    originals = {marker_path: marker_path.read_bytes(), inputs.build_manifest: inputs.build_manifest.read_bytes()}
    marker = json.loads(originals[marker_path])
    build = json.loads(originals[inputs.build_manifest])
    if mutation == "foreign-candidate": marker["candidate"]["commit_sha"] = "0" * 40
    elif mutation == "foreign-adopter": marker["adopter"]["commit_sha"] = "0" * 40
    elif mutation == "false-domain": marker["non_authoritative"] = False
    elif mutation == "wrong-version": marker["runtime_version"] = "0.0.0"
    elif mutation == "build-assets": build["assets"][next(iter(build["assets"]))] = "0" * 64
    elif mutation == "build-subject": build["subject"]["commit_sha"] = "0" * 40
    elif mutation == "omitted-member": marker["files"].pop(next(iter(marker["files"])))
    elif mutation == "edited-and-rehashed":
        relative = "scripts/_bcf_runtime/__init__.py"
        path = target / relative
        originals[path] = path.read_bytes()
        path.write_bytes(originals[path] + b"UNQUALIFIED = True\n")
        marker["files"][relative] = _sha(path.read_bytes())
    elif mutation == "preservation":
        relative = next(iter(marker["files"]))
        marker["preserved_consumer_files"][relative] = marker["files"].pop(relative)
    marker_path.write_text(json.dumps(marker))
    inputs.build_manifest.write_text(json.dumps(build))
    commit(target)
    try:
        with pytest.raises(SourceComponentError, match=diagnostic) as failure:
            owner.qualify_candidate_membership(target, inputs)
        assert any(entry.name == "qualify_candidate_membership" for entry in failure.traceback)
    finally:
        for path, raw in originals.items(): path.write_bytes(raw)
        commit(target)
    assert owner.qualify_candidate_membership(target, inputs).authority is False
