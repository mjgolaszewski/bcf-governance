"""Private membership reduction; inputs and outputs are data, never authority.

The consuming native owner must freshly authenticate inventory, managedness and
release custody before calling, and rejoin them before using the projection.
Managed projections require the lock join supplied by the native owner;
unsupported context profiles refuse. Existing production readers continue to
refuse PRESENT declarations until their integration is qualified.
Raw observations remain attached in full, including every original finding.
"""
from __future__ import annotations

import ast
from dataclasses import dataclass
import hashlib
import json
import re

from .architecture_native_inventory import NativeSourceInventory
from .architecture_source_components import (
    CandidatePackBinding, ManagedPackBinding, SourceComponent, SourceComponentError,
)
from .architecture_source_observation import Observation


@dataclass(frozen=True)
class MemberClassification:
    """Independent owner's proposed classification; not an authentication token."""

    path: str
    sha256: str
    ownership: str


@dataclass(frozen=True)
class EffectiveMember:
    path: str
    sha256: str
    inferred_layers: tuple[str, ...]
    inferred_contexts: tuple[str, ...]
    effective_layers: tuple[str, ...]
    effective_contexts: tuple[str, ...]
    component_id: str | None
    context_witness_sha256: str | None


@dataclass(frozen=True)
class MembershipProjection:
    members: tuple[EffectiveMember, ...]
    raw_observation: Observation
    scope: str = "Private data projection; no native, release or installed ownership authority."


def _refuse(detail: str) -> None:
    raise SourceComponentError(f"effective source membership: {detail}")


def _object_sha(value: object) -> str:
    return hashlib.sha256(json.dumps(value, sort_keys=True, ensure_ascii=True,
                                    separators=(",", ":")).encode()).hexdigest()


def _context_witness(inventory: NativeSourceInventory, component: SourceComponent,
                     path: str) -> str:
    selector = component.context_authority
    if selector.kind == "maintained_native_context_contract":
        _refuse("maintained native context contract is not implemented")
    if selector.version != "1.0":
        _refuse("unsupported context version")
    bindings = [row for row in inventory.contexts
                if (row.kind, row.version, row.selector) ==
                (selector.kind, selector.version, selector.selector)]
    if len(bindings) != 1 or bindings[0].context != component.context:
        _refuse("context selector does not resolve uniquely to declared context")
    binding = bindings[0]
    if binding.config_sha256 != inventory.config_sha256:
        _refuse("context configuration differs from inventory")
    if binding.subject_sha256 != _object_sha(dict(inventory.subject)):
        _refuse("context subject differs from inventory")
    if selector.kind == "independently_inferred_inventory":
        member = next(row for row in inventory.members if row.path == path)
        if member.inferred_contexts != (component.context,):
            _refuse("context witness cannot be borrowed from another source member")
        witness = tuple((row.path, row.sha256, row.inferred_contexts)
                        for row in inventory.members if component.context in row.inferred_contexts)
    elif selector.kind == "qualified_package_metadata_context":
        if selector.selector != path:
            _refuse("metadata context cannot authorize another member")
        rows = [row for row in inventory.policy.metadata_ownership if row[0] == path]
        if len(rows) != 1 or rows[0] != (path, component.layer, component.context, ("__doc__",)):
            _refuse("metadata declaration differs from native metadata owner")
        member = next(row for row in inventory.members if row.path == path)
        body = ast.parse(member.raw, filename=path).body
        if not (path.endswith("/__init__.py") and len(body) == 1
                and isinstance(body[0], ast.Expr) and isinstance(body[0].value, ast.Constant)
                and isinstance(body[0].value.value, str)):
            _refuse("metadata source must contain only its package docstring")
        witness = (path, member.sha256, component.layer, component.context, ("__doc__",))
    else:
        _refuse("unsupported context kind")
    if binding.member_sha256 != _object_sha(witness):
        _refuse("context witness differs from exact source members")
    return binding.member_sha256


def _reduce_membership(inventory: NativeSourceInventory,
                       components: tuple[SourceComponent, ...],
                       classifications: tuple[MemberClassification, ...], *,
                       managed_lock_sha256: str | None = None,
                       candidate_qualification_sha256: str | None = None) -> MembershipProjection:
    """Reduce exact complete populations without discovering or authenticating them.

    Every observed member survives once, in native order. Unassigned unknown or
    ambiguous ownership survives unchanged. A declaration may fill a missing
    layer, but cannot override even one conflicting inference or borrow context
    authority from unrelated files. Matching inference is corroboration.
    No production caller is activated by this private function.
    """
    if managed_lock_sha256 is not None and candidate_qualification_sha256 is not None:
        _refuse("release and candidate custody domains cannot be combined")
    members = {row.path: row for row in inventory.members}
    if not members or len(members) != len(inventory.members):
        _refuse("nonempty unique native population required")
    expected = tuple((row.path, row.sha256) for row in inventory.members)
    if inventory.observation.source_sha256 != expected:
        _refuse("raw observer population differs from native population")
    for member in inventory.members:
        if hashlib.sha256(member.raw).hexdigest() != member.sha256:
            _refuse("native source bytes differ from their digest")
    ownership = {row.path: row for row in classifications}
    if len(ownership) != len(classifications) or set(ownership) != set(members):
        _refuse("independent managedness population must be complete and unique")
    for path, row in ownership.items():
        if row.sha256 != members[path].sha256 or row.ownership not in {"project", "managed"}:
            _refuse("unresolved or stale independent managedness")
    layers = {name for name, _ in inventory.policy.layer_tokens}
    declared: dict[str, tuple[SourceComponent, str]] = {}
    identifiers: set[str] = set()
    for component in components:
        if component.id in identifiers or not component.members or component.layer not in layers:
            _refuse("duplicate component, empty members or unknown layer")
        identifiers.add(component.id)
        for path, digest in component.members:
            if path not in members or members[path].sha256 != digest:
                _refuse("declared member is unobserved or stale")
            if path in declared:
                _refuse("member assigned by multiple components")
            if ownership[path].ownership == "managed":
                binding = component.managed_pack
                if candidate_qualification_sha256 is not None:
                    if (re.fullmatch(r"[0-9a-f]{64}", candidate_qualification_sha256) is None
                            or type(binding) is not CandidatePackBinding
                            or binding.qualification_path != "governance/bcf-candidate-qualification.json"
                            or binding.qualification_sha256 != candidate_qualification_sha256):
                        _refuse("managed declaration differs from native candidate qualification")
                else:
                    if (managed_lock_sha256 is None or
                            re.fullmatch(r"[0-9a-f]{64}", managed_lock_sha256) is None):
                        _refuse("managed release membership requires the pending custody adapter")
                    if (type(binding) is not ManagedPackBinding
                            or binding.runtime_lock_path != "governance/bcf-runtime-lock.json"
                            or binding.runtime_lock_sha256 != managed_lock_sha256):
                        _refuse("managed declaration differs from native authenticated runtime lock")
            elif component.managed_pack is not None:
                _refuse("project member cannot claim managed release membership")
            member = members[path]
            if member.inferred_layers and member.inferred_layers != (component.layer,):
                _refuse("component conflicts with inferred layers")
            if member.inferred_contexts and member.inferred_contexts != (component.context,):
                _refuse("component conflicts with inferred contexts")
            witness = _context_witness(inventory, component, path)
            declared[path] = (component, witness)
    projected: list[EffectiveMember] = []
    for member in inventory.members:
        assignment = declared.get(member.path)
        component, witness = assignment if assignment else (None, None)
        projected.append(EffectiveMember(
            member.path, member.sha256, member.inferred_layers, member.inferred_contexts,
            (component.layer,) if component else member.inferred_layers,
            (component.context,) if component else member.inferred_contexts,
            component.id if component else None, witness,
        ))
    return MembershipProjection(tuple(projected), inventory.observation)
