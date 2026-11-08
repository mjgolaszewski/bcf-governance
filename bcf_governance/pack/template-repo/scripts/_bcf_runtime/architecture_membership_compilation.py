"""Fresh native source ownership compilation for project, installed and release contexts.

Installed validation uses local pinned bytes. Explicit release authentication and
candidate qualification retain their separate authority and execution domains."""
from __future__ import annotations

import hashlib
import os
from dataclasses import dataclass, field
from pathlib import Path
from typing import Never

from .architecture_candidate_membership import (
    CandidateMembership,
    CandidateQualificationInputs,
    qualify_candidate_membership,
)
from .architecture_effective_membership import (
    MemberClassification,
    MembershipProjection,
    _reduce_membership,
)
from .architecture_native_inventory import NativeSourceInventory, build_native_inventory
from .architecture_policy_input import _read, load_architecture_mapping
from .architecture_release_membership import (
    InstalledMembership,
    ReleaseMembership,
    authenticate_release_membership,
    inspect_installed_membership,
)
from .architecture_source_components import SourceComponentError, parse_source_components
from .governance_install.release_custody import ReleaseProvider
from .governance_install.runtime_custody import runtime_custody_schema_path


@dataclass(frozen=True)
class NativeReleaseInputs:
    """Inputs only; the existing release owner authenticates them on every call."""

    assets_root: Path
    template_root: Path
    token: str = field(default="", repr=False)
    api: ReleaseProvider | None = field(default=None, repr=False)


@dataclass(frozen=True)
class EffectiveSourceInventory:
    native: NativeSourceInventory
    projection: MembershipProjection | None
    release: ReleaseMembership | None
    scope: str = "Fresh in-process observation; no cached, installed or release acceptance by itself."
    candidate: CandidateMembership | None = None
    installed: InstalledMembership | None = None


def _refuse(detail: str) -> Never:
    raise SourceComponentError(f"native ownership compilation: {detail}")


def _project_classifications(inventory: NativeSourceInventory) -> tuple[MemberClassification, ...]:
    # Independent installation footprints are checked before interpreting a
    # component's managed_pack field. Missing lock alone never means project.
    footprints = (
        "governance/bcf-runtime-lock.json", "governance/bcf-candidate-qualification.json",
        "scripts/_bcf_runtime", "scripts/install_governance_pack.py",
        "governance-profile.yml",
    )
    if any(os.path.lexists(inventory.root / name) for name in footprints):
        _refuse("installed footprint requires explicit native release authentication")
    return tuple(MemberClassification(member.path, member.sha256, "project")
                 for member in inventory.members)


def _build_effective_inventory(root: Path, *,
                               release_inputs: NativeReleaseInputs | None = None,
                               candidate_inputs: CandidateQualificationInputs | None = None) -> EffectiveSourceInventory:
    """Observe first, authenticate managedness, parse requests, reduce, rejoin.

    ABSENT remains the legacy native observation with no component projection.
    PRESENT managed input without the maintained owner's release context fails.
    No context/provider/digest supplied inside architecture YAML grants authority.
    """
    if release_inputs is not None and candidate_inputs is not None:
        _refuse("release and candidate execution domains cannot be combined")
    native = build_native_inventory(root)
    config = root / "architecture-boundaries.yml"
    document = load_architecture_mapping(config, expected_sha256=native.config_sha256)
    architecture = document.get("architecture")
    if not isinstance(architecture, dict):
        _refuse("governed architecture mapping required")
    release = None
    installed = None
    candidate = None
    projection = None
    if "source_component_ownership" in architecture:
        if candidate_inputs is not None:
            candidate = qualify_candidate_membership(root, candidate_inputs)
            if (candidate.subject != native.subject or candidate.authority
                    or candidate.publication_authority
                    or candidate.domain != "isolated_candidate_qualification"):
                _refuse("candidate membership differs from native non-authoritative domain")
            classifications = candidate.classifications
        elif release_inputs is None:
            if os.path.lexists(root / "governance/bcf-runtime-lock.json"):
                installed = inspect_installed_membership(root)
                if installed.subject != native.subject:
                    _refuse("installed membership subject differs from initial native subject")
                classifications = installed.classifications
            else:
                classifications = _project_classifications(native)
        else:
            if type(release_inputs) is not NativeReleaseInputs:
                _refuse("native-owned release inputs required")
            release = authenticate_release_membership(
                root, assets_root=release_inputs.assets_root,
                template_root=release_inputs.template_root,
                token=release_inputs.token, api=release_inputs.api,
            )
            classifications = release.classifications
            if release.subject != native.subject:
                _refuse("release membership subject differs from initial native subject")
        expected = tuple((row.path, row.sha256) for row in native.members)
        if tuple((row.path, row.sha256) for row in classifications) != expected:
            _refuse("independent classification differs from native source population")
        components = parse_source_components(architecture, reader_supported=True)
        projection = _reduce_membership(native, components, classifications,
                                        managed_lock_sha256=(release.lock_sha256 if release else
                                                             installed.lock_sha256 if installed else None),
                                        candidate_qualification_sha256=(
                                            candidate.qualification_sha256 if candidate else None))
    if hashlib.sha256(_read(config)).hexdigest() != native.config_sha256:
        _refuse("configuration changed during native compilation")
    fresh = build_native_inventory(root)
    if fresh != native:
        _refuse("complete native source changed during ownership compilation")
    if release is not None:
        lock = _read(root / "governance/bcf-runtime-lock.json")
        if hashlib.sha256(lock).hexdigest() != release.lock_sha256:
            _refuse("authenticated installed custody changed during compilation")
    if installed is not None:
        if (hashlib.sha256(_read(root / "governance/bcf-runtime-lock.json")).hexdigest() != installed.lock_sha256
                or hashlib.sha256(_read(runtime_custody_schema_path(root))).hexdigest() != installed.schema_sha256):
            _refuse("installed lock or schema changed during compilation")
    if candidate is not None:
        if candidate_inputs is None:
            _refuse("candidate inputs missing during reauthentication")
        if qualify_candidate_membership(root, candidate_inputs) != candidate:
            _refuse("candidate context changed during compilation")
    return EffectiveSourceInventory(native, projection, release, candidate=candidate, installed=installed)


def build_effective_inventory(root: Path, *,
                              release_inputs: NativeReleaseInputs | None = None) -> EffectiveSourceInventory:
    """Production entry: candidate installation never gains release authority."""
    return _build_effective_inventory(root, release_inputs=release_inputs)


def qualify_candidate_effective_inventory(
    root: Path, *, inputs: CandidateQualificationInputs,
) -> EffectiveSourceInventory:
    """Explicit maintained candidate-owner entry, always non-authoritative.

    No environment, declaration or candidate marker selects this entry. The
    release qualification transaction must supply its source-owned exact inputs.
    """
    return _build_effective_inventory(root, candidate_inputs=inputs)


def reauthenticate_effective_inventory(root: Path, inventory: EffectiveSourceInventory, *,
                                       release_inputs: NativeReleaseInputs | None = None) -> None:
    """A cache is compared with a wholly fresh derivation, never consumed as authority."""
    fresh = build_effective_inventory(root, release_inputs=release_inputs)
    if type(inventory) is not EffectiveSourceInventory or inventory != fresh:
        _refuse("cached ownership differs from fresh native compilation")
