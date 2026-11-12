"""Closed source-component declarations; parsing confers no ownership authority."""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import PurePosixPath
import re
from typing import Mapping


class SourceComponentError(ValueError):
    """Refuse unsupported or malformed source-component interpretation."""


@dataclass(frozen=True)
class ContextSelector:
    kind: str
    version: str
    selector: str


@dataclass(frozen=True)
class ManagedPackBinding:
    runtime_lock_path: str
    runtime_lock_sha256: str


@dataclass(frozen=True)
class CandidatePackBinding:
    qualification_path: str
    qualification_sha256: str


@dataclass(frozen=True)
class FunctionContractRequest:
    selector: str
    profile: str
    sdk_type: str
    constructor: str


@dataclass(frozen=True)
class SourceComponent:
    id: str
    layer: str
    context: str
    rationale: str
    members: tuple[tuple[str, str], ...]
    managed_pack: ManagedPackBinding | CandidatePackBinding | None
    context_authority: ContextSelector
    function_contracts: tuple[FunctionContractRequest, ...] = ()


def _mapping(value: object, fields: set[str], label: str) -> dict[str, object]:
    if not isinstance(value, dict) or set(value) != fields:
        raise SourceComponentError(f"{label}: exact fields required")
    if not all(isinstance(key, str) for key in value):
        raise SourceComponentError(f"{label}: string keys required")
    return value


def _text(value: object, label: str) -> str:
    if not isinstance(value, str) or not value or value != value.strip():
        raise SourceComponentError(f"{label}: nonempty unpadded string required")
    if any(ord(character) < 32 or ord(character) == 127 for character in value):
        raise SourceComponentError(f"{label}: control characters prohibited")
    return value


def _digest(value: object, label: str) -> str:
    if not isinstance(value, str) or re.fullmatch(r"[0-9a-f]{64}", value) is None:
        raise SourceComponentError(f"{label}: lowercase SHA256 required")
    return value


def _path(value: object, label: str) -> str:
    path = _text(value, label)
    if (
        path.startswith("/") or "\\" in path or ":" in path
        or any(part in {"", ".", ".."} for part in path.split("/"))
        or any(character in path for character in "*?[]")
        or PurePosixPath(path).as_posix() != path
    ):
        raise SourceComponentError(f"{label}: canonical exact relative path required")
    return path


def _context_binding(value: object, label: str) -> ContextSelector:
    authority = _mapping(value, {"kind", "version", "selector"}, label)
    kind = _text(authority["kind"], f"{label}.kind")
    if kind not in {
        "independently_inferred_inventory", "qualified_package_metadata_context",
        "maintained_native_context_contract",
    }:
        raise SourceComponentError(f"{label}: unsupported context authority")
    if authority["version"] != "1.0":
        raise SourceComponentError(f"{label}: unsupported context owner version")
    selector = _text(authority["selector"], f"{label}.selector")
    if kind == "qualified_package_metadata_context":
        selector = _path(selector, f"{label}.selector")
        if PurePosixPath(selector).name != "__init__.py":
            raise SourceComponentError(f"{label}: package metadata selector required")
    return ContextSelector(kind=kind, version="1.0", selector=selector)


def _managed_binding(value: object, label: str, version: str) -> ManagedPackBinding | CandidatePackBinding | None:
    if value is None:
        return None
    if version in ("1.1", "1.2"):
        binding = _mapping(value, {"kind", "path", "sha256"}, label)
        path = _path(binding["path"], f"{label}.path")
        digest = _digest(binding["sha256"], f"{label}.sha256")
        if binding["kind"] == "authenticated_release" and path == "governance/bcf-runtime-lock.json":
            return ManagedPackBinding(path, digest)
        if binding["kind"] == "candidate_qualification" and path == "governance/bcf-candidate-qualification.json":
            return CandidatePackBinding(path, digest)
        raise SourceComponentError(f"{label}: exact supported custody domain and path required")
    binding = _mapping(value, {"runtime_lock_path", "runtime_lock_sha256"}, label)
    path = _path(binding["runtime_lock_path"], f"{label}.runtime_lock_path")
    if path != "governance/bcf-runtime-lock.json":
        raise SourceComponentError(f"{label}: existing runtime lock owner required")
    return ManagedPackBinding(
        runtime_lock_path=path,
        runtime_lock_sha256=_digest(binding["runtime_lock_sha256"], f"{label}.runtime_lock_sha256"),
    )


def _function_contracts(
    value: object, members: tuple[tuple[str, str], ...], label: str,
) -> tuple[FunctionContractRequest, ...]:
    """Parse requests only; identities and declarations never establish authority."""
    if not isinstance(value, list) or not value:
        raise SourceComponentError(f"{label}: nonempty function contracts required")
    paths = {path for path, _ in members}
    selectors: set[str] = set()
    result: list[FunctionContractRequest] = []
    for index, item in enumerate(value):
        current = f"{label}[{index}]"
        row = _mapping(item, {"selector", "profile", "sdk_type", "constructor"}, current)
        selector = _text(row["selector"], f"{current}.selector")
        path, separator, function = selector.partition("::")
        if not separator or _path(path, f"{current}.selector") not in paths:
            raise SourceComponentError(f"{current}: selector outside exact component members")
        if not function or not all(part.isidentifier() for part in function.split(".")):
            raise SourceComponentError(f"{current}: exact qualified function selector required")
        if selector in selectors:
            raise SourceComponentError(f"{current}: duplicate function selector")
        selectors.add(selector)
        if row["profile"] != "sdk_principal_decoder.v1":
            raise SourceComponentError(f"{current}: unsupported function profile")
        identities: list[str] = []
        for field in ("sdk_type", "constructor"):
            identity = _text(row[field], f"{current}.{field}")
            module, delimiter, symbol = identity.partition("::")
            if not delimiter or not module or not symbol or not all(
                part.isidentifier() for part in symbol.split(".")
            ):
                raise SourceComponentError(f"{current}.{field}: source-qualified identity required")
            identities.append(identity)
        result.append(FunctionContractRequest(selector, "sdk_principal_decoder.v1", identities[0], identities[1]))
    return tuple(result)


def parse_source_components(
    architecture: Mapping[str, object], *, reader_supported: bool,
) -> tuple[SourceComponent, ...]:
    """Parse already bounded, duplicate-key/cycle-checked canonical input.

    Absence is legacy behavior. Presence on an unsupported consumer refuses,
    including null or empty values. Returned records are unresolved requests;
    they cannot classify managedness, authenticate packs, or assign ownership.
    """
    if "source_component_ownership" not in architecture:
        return ()
    if not reader_supported:
        raise SourceComponentError("source_component_ownership: unsupported native consumer")
    declaration = _mapping(architecture["source_component_ownership"],
                           {"version", "components"}, "source_component_ownership")
    if declaration["version"] not in ("1.0", "1.1", "1.2"):
        raise SourceComponentError("source_component_ownership: unsupported version")
    components = declaration["components"]
    if not isinstance(components, list) or not components:
        raise SourceComponentError("source_component_ownership: nonempty components required")
    layers = architecture.get("layers")
    if not isinstance(layers, dict) or not layers:
        raise SourceComponentError("source_component_ownership: existing layers required")
    identifiers: set[str] = set()
    paths: set[str] = set()
    result: list[SourceComponent] = []
    for index, value in enumerate(components):
        label = f"source_component_ownership.components[{index}]"
        fields = {"id", "layer", "context", "rationale", "members",
                  "managed_pack", "context_authority"}
        if declaration["version"] == "1.2" and isinstance(value, dict) and "function_contracts" in value:
            fields.add("function_contracts")
        component = _mapping(value, fields, label)
        identifier = _text(component["id"], f"{label}.id")
        if identifier in identifiers:
            raise SourceComponentError(f"{label}: duplicate component id")
        identifiers.add(identifier)
        layer = _text(component["layer"], f"{label}.layer")
        if layer not in layers:
            raise SourceComponentError(f"{label}: unknown layer")
        members = component["members"]
        if not isinstance(members, dict) or not members:
            raise SourceComponentError(f"{label}: nonempty exact members required")
        admitted: list[tuple[str, str]] = []
        for path, digest in members.items():
            path = _path(path, f"{label}.members")
            if not path.endswith(".py"):
                raise SourceComponentError(f"{label}: Python source member required")
            if path in paths:
                raise SourceComponentError(f"{label}: overlapping member")
            paths.add(path)
            admitted.append((path, _digest(digest, f"{label}.members[{path}]")))
        result.append(SourceComponent(
            id=identifier, layer=layer,
            context=_text(component["context"], f"{label}.context"),
            rationale=_text(component["rationale"], f"{label}.rationale"),
            members=tuple(sorted(admitted)),
            managed_pack=_managed_binding(component["managed_pack"], f"{label}.managed_pack", declaration["version"]),
            context_authority=_context_binding(component["context_authority"], f"{label}.context_authority"),
            function_contracts=(
                _function_contracts(component["function_contracts"], tuple(admitted), f"{label}.function_contracts")
                if "function_contracts" in component else ()
            ),
        ))
    return tuple(result)
