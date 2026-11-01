"""Source draft: candidate membership query owned by release qualification.

Candidate qualification is never immutable release authority. The maintained
qualification owner supplies its exact build/source/adopter inputs explicitly;
YAML, a marker, and caller-created result records cannot enable this query.
Production release readers remain separate and refuse candidate installations.
"""
from __future__ import annotations
from dataclasses import dataclass
import hashlib
import json
from pathlib import Path
import re

from .architecture_effective_membership import MemberClassification
from .architecture_native_inventory import build_native_inventory
from .architecture_pack_projection import bound_wheel_manifest
from .architecture_policy_input import _read
from .architecture_source_components import SourceComponentError
from .governance_install.release_custody import (
    _clean_git_identity, _project_bytes, _wheel_template_files,
    selected_runtime_inventory_paths,
)
from .governance_install.runtime_custody import (
    CANDIDATE_QUALIFICATION_PATH, RUNTIME_LOCK_PATH,
    RuntimeCustodyState, inspect_runtime_custody,
)
from .install_governance_pack import UPGRADE_REFRESH_PATHS
from .release_asset_inventory import release_asset_paths
from .runtime_capacity import executing_runtime_version


@dataclass(frozen=True)
class CandidateQualificationInputs:
    source_root: Path
    assets_root: Path
    build_manifest: Path
    template_root: Path
    adopter_commit: str
    adopter_tree: str


@dataclass(frozen=True)
class CandidateMembership:
    classifications: tuple[MemberClassification, ...]
    qualification_sha256: str
    candidate_commit: str
    candidate_tree: str
    wheel_sha256: str
    subject: tuple[tuple[str, object], ...]
    domain: str = "isolated_candidate_qualification"
    authority: bool = False
    publication_authority: bool = False


def _refuse(detail: str) -> None:
    raise SourceComponentError(f"candidate qualification membership: {detail}")


def _sha(raw: bytes) -> str:
    return hashlib.sha256(raw).hexdigest()


def _unique(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            _refuse("duplicate JSON field")
        result[key] = value
    return result


def qualify_candidate_membership(root: Path, inputs: CandidateQualificationInputs) -> CandidateMembership:
    """Freshly rejoin the existing candidate owner's build and installed bytes.

    This is an explicit qualification-owner query, never an automatic fallback
    from failed release authentication. Its result stays non-authoritative.
    """
    from .release_adopter_qualification import _release_assets, _run
    if type(inputs) is not CandidateQualificationInputs:
        _refuse("maintained candidate qualification inputs required")
    if any(re.fullmatch(r"[0-9a-f]{40}", value) is None
           for value in (inputs.adopter_commit, inputs.adopter_tree)):
        _refuse("exact qualification-owner adopter base required")
    native = build_native_inventory(root)
    if (root / RUNTIME_LOCK_PATH).exists() or (root / RUNTIME_LOCK_PATH).is_symlink():
        _refuse("released custody cannot enter the candidate domain")
    marker_path = root / CANDIDATE_QUALIFICATION_PATH
    marker_raw = _read(marker_path)
    marker = json.loads(marker_raw, object_pairs_hook=_unique)
    source = _clean_git_identity(inputs.source_root, label="candidate source")
    build_raw = _read(inputs.build_manifest)
    build = json.loads(build_raw, object_pairs_hook=_unique)
    version, assets, _ = _release_assets(inputs.assets_root)
    if version != executing_runtime_version():
        _refuse("candidate asset version differs from executing runtime")
    if not isinstance(build, dict) or build.get("assets") != assets or build.get("subject") != source:
        _refuse("candidate assets differ from the owner's exact source build")
    base = {"commit_sha": inputs.adopter_commit, "tree_sha": inputs.adopter_tree}
    if (_run(["git", "rev-parse", "--verify", inputs.adopter_commit + "^{tree}"], cwd=root)
            != inputs.adopter_tree):
        _refuse("qualification adopter base tree differs")
    _run(["git", "merge-base", "--is-ancestor", inputs.adopter_commit, "HEAD"], cwd=root)
    manifest_raw = _read(inputs.template_root / ".bcf-pack-manifest.json")
    source_manifest = inputs.source_root / "bcf_governance/pack/template-repo/.bcf-pack-manifest.json"
    if _read(source_manifest) != manifest_raw:
        _refuse("executing candidate template differs from exact source")
    candidate = dict(source, pack_manifest_sha256=_sha(manifest_raw))
    if (not isinstance(marker, dict) or marker.get("kind") != "candidate_qualification"
            or marker.get("non_authoritative") is not True
            or marker.get("candidate") != candidate or marker.get("adopter") != base
            or marker.get("runtime_version") != version):
        _refuse("candidate marker does not join the maintained qualification inputs")
    schema = inputs.template_root / "schemas/bcf-runtime-lock.schema.json"
    schema_raw = _read(schema)
    snapshot = inspect_runtime_custody(root, schema_path=schema)
    if (snapshot.state is not RuntimeCustodyState.CANDIDATE_QUALIFICATION_EXACT
            or snapshot.lock_bytes != marker_raw or snapshot.consumer_preserved):
        _refuse("exact candidate inventory without unqualified preservation required")
    wheels = [path for path in release_asset_paths(inputs.assets_root) if path.suffix == ".whl"]
    if len(wheels) != 1:
        _refuse("one candidate wheel required")
    wheel_sha = assets[wheels[0].name]
    files = _wheel_template_files(wheels[0])
    manifest = bound_wheel_manifest(inputs.assets_root, inputs.template_root, wheel_sha)
    entries = manifest.get("files") if isinstance(manifest, dict) else None
    if not isinstance(entries, dict) or set(entries) != set(files):
        _refuse("complete candidate pack population differs")
    source_template = inputs.source_root / "bcf_governance/pack/template-repo"
    for relative, entry in entries.items():
        # Manifest paths have already passed the maintained wheel owner's
        # canonical-path and duplicate/symlink checks before this lookup.
        if (not isinstance(entry, dict) or entry.get("sha256") != _sha(files[relative])
                or _read(source_template / relative) != files[relative]
                or _read(inputs.template_root / relative) != files[relative]):
            _refuse("candidate wheel, source and executing template bytes differ")
    selected = selected_runtime_inventory_paths(entries, UPGRADE_REFRESH_PATHS)
    if set(snapshot.runtime_owned) != selected:
        _refuse("candidate installed membership differs from maintained selection")
    for relative in sorted(selected):
        projected = _project_bytes(files[relative], {"PLACEHOLDER": "TOKEN"})
        if _read(root / relative) != projected:
            _refuse("candidate installed bytes differ from canonical projection")
    if snapshot.installer_adaptations:
        _refuse("candidate marker cannot assert released installer adaptations")
    classifications = tuple(MemberClassification(
        member.path, member.sha256,
        "managed" if member.path in selected else "project",
    ) for member in native.members)
    if any(member.path.startswith("scripts/_bcf_runtime/") and member.path not in selected
           for member in native.members):
        _refuse("unexplained source inside candidate runtime")
    if (build_native_inventory(root) != native or _read(marker_path) != marker_raw
            or _read(inputs.build_manifest) != build_raw or _read(schema) != schema_raw
            or _clean_git_identity(inputs.source_root, label="candidate source") != source
            or _release_assets(inputs.assets_root)[1] != assets
            or inspect_runtime_custody(root, schema_path=schema) != snapshot):
        _refuse("candidate source, assets or installation changed during qualification")
    return CandidateMembership(classifications, _sha(marker_raw), source["commit_sha"],
                               source["tree_sha"], wheel_sha, native.subject)
