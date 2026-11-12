"""Source draft: fresh native ownership compilation for maintained consumers.

Release inputs belong to the execution owner, not configuration declarations.
Neither a serialized projection nor a caller-populated inventory is accepted.
This module is not yet wired into either production architecture reader.
"""
from __future__ import annotations

import ast
from dataclasses import dataclass, field
import hashlib
import os
from pathlib import Path

from .architecture_candidate_membership import (
    CandidateMembership, CandidateQualificationInputs, qualify_candidate_membership,
)
from .architecture_effective_membership import (
    MemberClassification, MembershipProjection, _reduce_membership,
)
from .architecture_native_inventory import NativeSourceInventory, _committed, build_native_inventory
from .architecture_policy_input import _read, load_architecture_mapping
from .architecture_release_membership import ReleaseMembership, authenticate_release_membership
from .architecture_source_components import SourceComponent, SourceComponentError, parse_source_components
from .semantic_ownership_inventory import discover_python_source, resolve_python_imports
from .semantic_ownership_registry import REGISTRY_PATH, SCHEMA_PATH, load_registry
from .semantic_operation_effects import SemanticOperationEffectError, _sdk_decoder_shape
from .governance_install.release_custody import ReleaseProvider


@dataclass(frozen=True)
class NativeReleaseInputs:
    """Inputs only; the existing release owner authenticates them on every call."""

    assets_root: Path
    template_root: Path
    token: str = field(default="", repr=False)
    api: ReleaseProvider | None = field(default=None, repr=False)


@dataclass(frozen=True)
class FunctionRoleObservation:
    selector: str
    profile: str
    member_sha256: str
    sdk_lexical_binding: str
    constructor_lexical_binding: str
    sdk_type_identity: str
    constructor_identity: str
    semantic_inputs: tuple[tuple[str, str], ...] = ()
    qualification: str = "PROVENANCE_AND_OPERATION_WITNESS_REQUIRED"
    authority: bool = False
    raw_findings_retained: bool = True


def _derive_function_role_observations(
    native: NativeSourceInventory, components: tuple[SourceComponent, ...],
) -> tuple[FunctionRoleObservation, ...]:
    """Join shape and neutral source bindings without granting a valid role."""
    requests = tuple(request for component in components for request in component.function_contracts)
    if not requests:
        return ()
    facts = discover_python_source(native.root, files=[native.root / member.path for member in native.members])
    expected = tuple((member.path, member.sha256) for member in native.members)
    if tuple((row["path"], row["sha256"]) for row in facts["files"]) != expected:
        raise SourceComponentError("function roles: semantic population differs from native members")
    members = {member.path: member for member in native.members}
    lexical: dict[str, tuple[str, str]] = {}
    for request in requests:
        rows = [row for row in facts["functions"] if row["symbol"] == request.selector]
        if len(rows) != 1:
            raise SourceComponentError("function roles: selector is absent or ambiguous in independent inventory")
        path, _, qualified = request.selector.partition("::")
        member = members[path]
        if hashlib.sha256(member.raw).hexdigest() != member.sha256:
            raise SourceComponentError("function roles: native member bytes differ from digest")
        tree = ast.parse(member.raw, filename=path)
        parts = qualified.split(".")
        scope = tree.body
        if len(parts) == 2:
            classes = [node for node in scope if isinstance(node, ast.ClassDef) and node.name == parts[0]]
            if len(classes) != 1:
                raise SourceComponentError("function roles: class is absent or ambiguous")
            if classes[0].bases or classes[0].keywords or classes[0].decorator_list:
                raise SourceComponentError("function roles: unsupported class inheritance/metaclass/decorator")
            scope = classes[0].body
        elif len(parts) != 1:
            raise SourceComponentError("function roles: unsupported nested selector scope")
        definitions = [node for node in scope if isinstance(node, ast.FunctionDef) and node.name == parts[-1]]
        if len(definitions) != 1:
            raise SourceComponentError("function roles: runtime function shape is absent or ambiguous")
        try:
            lexical[request.selector] = _sdk_decoder_shape(definitions[0])
        except SemanticOperationEffectError as error:
            raise SourceComponentError(f"function roles: {error}") from error

    # Reuse the sole semantic registry's import-root interpretation if present.
    # Its presence cannot hide members or replace an independently discovered role.
    semantic_inputs: list[tuple[str, str]] = []
    import_roots = (".",)
    if os.path.lexists(native.root / REGISTRY_PATH):
        commit = dict(native.subject).get("commit_sha")
        if not isinstance(commit, str):
            raise SourceComponentError("function roles: exact committed subject required")
        for relative in (REGISTRY_PATH, SCHEMA_PATH):
            raw = _read(native.root / relative)
            _committed(native.root, commit, relative.as_posix(), raw)
            semantic_inputs.append((relative.as_posix(), hashlib.sha256(raw).hexdigest()))
        import_roots = load_registry(native.root).python_import_roots
    resolved = resolve_python_imports(
        native.root, facts, import_roots,
        reference_requests={request.selector: lexical[request.selector] for request in requests},
    )
    observations: list[FunctionRoleObservation] = []
    for request in requests:
        rows = [row for row in resolved["functions"] if row["symbol"] == request.selector]
        if len(rows) != 1:
            raise SourceComponentError("function roles: resolved selector is absent or ambiguous")
        sdk, constructor = lexical[request.selector]
        bindings = rows[0]["requested_reference_symbols"]
        if bindings.get(sdk) != [request.sdk_type] or bindings.get(constructor) != [request.constructor]:
            raise SourceComponentError("function roles: requested identity contradicts source binding")
        path = request.selector.partition("::")[0]
        observations.append(FunctionRoleObservation(
            request.selector, request.profile, members[path].sha256, sdk, constructor,
            request.sdk_type, request.constructor, tuple(semantic_inputs),
        ))
    for relative, digest in semantic_inputs:
        if hashlib.sha256(_read(native.root / relative)).hexdigest() != digest:
            raise SourceComponentError("function roles: semantic import context moved during compilation")
    return tuple(observations)


@dataclass(frozen=True)
class EffectiveSourceInventory:
    native: NativeSourceInventory
    projection: MembershipProjection | None
    release: ReleaseMembership | None
    scope: str = "Fresh in-process observation; no cached, installed or release acceptance by itself."
    candidate: CandidateMembership | None = None
    function_roles: tuple[FunctionRoleObservation, ...] = ()


def _refuse(detail: str) -> None:
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
    candidate = None
    projection = None
    components: tuple[SourceComponent, ...] = ()
    if "source_component_ownership" in architecture:
        if candidate_inputs is not None:
            candidate = qualify_candidate_membership(root, candidate_inputs)
            if (candidate.subject != native.subject or candidate.authority
                    or candidate.publication_authority
                    or candidate.domain != "isolated_candidate_qualification"):
                _refuse("candidate membership differs from native non-authoritative domain")
            classifications = candidate.classifications
        elif release_inputs is None:
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
                                        managed_lock_sha256=release.lock_sha256 if release else None,
                                        candidate_qualification_sha256=(
                                            candidate.qualification_sha256 if candidate else None))
    function_roles = _derive_function_role_observations(native, components)
    if hashlib.sha256(_read(config)).hexdigest() != native.config_sha256:
        _refuse("configuration changed during native compilation")
    fresh = build_native_inventory(root)
    if fresh != native:
        _refuse("complete native source changed during ownership compilation")
    if release is not None:
        lock = _read(root / "governance/bcf-runtime-lock.json")
        if hashlib.sha256(lock).hexdigest() != release.lock_sha256:
            _refuse("authenticated installed custody changed during compilation")
    if candidate is not None:
        if qualify_candidate_membership(root, candidate_inputs) != candidate:
            _refuse("candidate context changed during compilation")
    return EffectiveSourceInventory(native, projection, release, candidate=candidate, function_roles=function_roles)


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
