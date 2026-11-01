"""Native current-subject source inventory and maintained metadata-context profile.

Factory results are in-process observations, never deserialized authority.
Managed-pack authentication and effective component ownership are separate.
"""
from __future__ import annotations

import ast
from dataclasses import dataclass
import hashlib
import json
import os
import stat
from pathlib import Path

from .architecture_policy_input import _read
from .architecture_policy_compilation import load_policy
from .architecture_source_observation import Policy, Observation, _contexts, _production_files, observe
from .ci_authority_prospective_lanes import git_blob
from .truth_reporting import current_subject


class ArchitectureInventoryError(ValueError):
    """Refuse an unbound, incomplete or changed native source population."""


@dataclass(frozen=True)
class SourceMember:
    path: str
    sha256: str
    raw: bytes
    inferred_layers: tuple[str, ...]
    inferred_contexts: tuple[str, ...]


@dataclass(frozen=True)
class ContextBinding:
    kind: str
    version: str
    selector: str
    context: str
    subject_sha256: str
    config_sha256: str
    member_sha256: str


@dataclass(frozen=True)
class NativeSourceInventory:
    root: Path
    subject: tuple[tuple[str, object], ...]
    config_sha256: str
    schema_sha256: str
    policy: Policy
    members: tuple[SourceMember, ...]
    contexts: tuple[ContextBinding, ...]
    observation: Observation


def _sha(raw: bytes) -> str:
    return hashlib.sha256(raw).hexdigest()


def _object_sha(value: object) -> str:
    return _sha(json.dumps(value, sort_keys=True, ensure_ascii=True,
                           separators=(",", ":")).encode())


def _source_bytes(path: Path) -> bytes:
    # Reuse the maintained bounded canonical source reader; hardlink aliases
    # additionally cannot become independently owned production members.
    if path.lstat().st_nlink != 1:
        raise ArchitectureInventoryError("production source hardlink alias")
    raw = _read(path)
    if path.lstat().st_nlink != 1:
        raise ArchitectureInventoryError("production source hardlink alias")
    return raw


def _committed(root: Path, commit: str, path: str, raw: bytes) -> None:
    if git_blob(root, ref=commit, path=path) != raw:
        raise ArchitectureInventoryError("source differs from exact committed subject bytes")


def _walk_failed(error: OSError) -> None:
    raise ArchitectureInventoryError("production directory unreadable") from error


def _classify_production_entry(path: Path, children: list[str], names: list[str]) -> str:
    """Refuse suppressed DirEntry errors instead of treating a branch as absent."""
    try:
        metadata = path.lstat()
        if stat.S_ISLNK(metadata.st_mode):
            if path.name in children:
                raise ArchitectureInventoryError("production directory alias")
            raise ArchitectureInventoryError("production source alias or nonregular member")
        if path.resolve(strict=True) != path:
            raise ArchitectureInventoryError("production source alias or nonregular member")
        if stat.S_ISDIR(metadata.st_mode):
            if path.name not in children:
                raise ArchitectureInventoryError("production directory classification disagrees")
            return "directory"
        if not stat.S_ISREG(metadata.st_mode):
            raise ArchitectureInventoryError("production source alias or nonregular member")
        if path.name not in names:
            raise ArchitectureInventoryError("production file classification disagrees")
        return "file"
    except OSError as error:
        raise ArchitectureInventoryError("production member metadata unreadable") from error


def _admitted_production_paths(root: Path, policy: Policy) -> tuple[Path, ...]:
    """Independently census the same governed population before observing it."""
    if not policy.source_roots or len(set(policy.source_roots)) != len(policy.source_roots):
        raise ArchitectureInventoryError("nonempty unique production roots required")
    expected: set[Path] = set()
    for relative in policy.source_roots:
        source_root = root / relative
        if not source_root.is_dir() or source_root.resolve(strict=True) != source_root:
            raise ArchitectureInventoryError("canonical production roots required")
        for directory, children, names in os.walk(source_root, followlinks=False, onerror=_walk_failed):
            children[:] = sorted(name for name in children if name not in policy.excluded_path_tokens)
            for name in sorted(children + names):
                path = Path(directory) / name
                relative_path = path.relative_to(root)
                if set(relative_path.parts).intersection(policy.excluded_path_tokens):
                    continue
                kind = _classify_production_entry(path, children, names)
                if kind == "directory":
                    continue
                if (path.suffix != ".py" or set(relative_path.parts).intersection(policy.excluded_path_tokens)
                        or (policy.excluded_suffixes and path.name.endswith(policy.excluded_suffixes))):
                    continue
                if not path.is_file() or path.is_symlink() or path.resolve(strict=True) != path:
                    raise ArchitectureInventoryError("production source alias or nonregular member")
                if path.lstat().st_nlink != 1:
                    raise ArchitectureInventoryError("production source hardlink alias")
                if path in expected:
                    raise ArchitectureInventoryError("overlapping configured production roots")
                expected.add(path)
    if not expected:
        raise ArchitectureInventoryError("empty production population")
    actual = tuple(_production_files(root, policy))
    if actual != tuple(sorted(expected)):
        raise ArchitectureInventoryError("independent production census differs from source observer")
    return actual


def _reauthenticate_source_bytes(inventory: NativeSourceInventory) -> None:
    """Rejoin whole membership and bytes before returning or consuming a result."""
    root = inventory.root
    if tuple(sorted(current_subject(root).items())) != inventory.subject:
        raise ArchitectureInventoryError("native source subject changed")
    if _sha(_read(root / "architecture-boundaries.yml")) != inventory.config_sha256:
        raise ArchitectureInventoryError("native architecture configuration changed")
    if _sha(_read(root / "schemas/architecture-boundaries.schema.json")) != inventory.schema_sha256:
        raise ArchitectureInventoryError("native architecture schema changed")
    paths = tuple(path.relative_to(root).as_posix() for path in _admitted_production_paths(root, inventory.policy))
    if paths != tuple(member.path for member in inventory.members):
        raise ArchitectureInventoryError("whole production population changed")
    for member in inventory.members:
        if _sha(_source_bytes(root / member.path)) != member.sha256:
            raise ArchitectureInventoryError("native production member changed")
    if tuple(sorted(current_subject(root).items())) != inventory.subject:
        raise ArchitectureInventoryError("native source subject changed during reauthentication")


def build_native_inventory(root: Path) -> NativeSourceInventory:
    """Observe independent production before interpreting component declarations.

    Context authority is derived here from path inference or the maintained
    docstring-only metadata interpretation, not rationale or request digests.
    No component assignment or managed-pack authority is granted here.
    """
    if not root.is_absolute() or root.resolve(strict=True) != root:
        raise ArchitectureInventoryError("canonical native repository root required")
    subject = current_subject(root)
    if not subject["tracked_clean"] or not subject["untracked_clean"]:
        raise ArchitectureInventoryError("clean native source subject required")
    config = root / "architecture-boundaries.yml"
    schema = root / "schemas/architecture-boundaries.schema.json"
    config_raw, schema_raw = _read(config), _read(schema)
    # The exact original bytes are pinned, with no field stripping or self-hash.
    _committed(root, subject["commit_sha"], "architecture-boundaries.yml", config_raw)
    _committed(root, subject["commit_sha"], "schemas/architecture-boundaries.schema.json", schema_raw)
    policy_input = load_policy(config, schema, config_sha256=_sha(config_raw), schema_sha256=_sha(schema_raw))
    policy = policy_input.policy
    members: list[SourceMember] = []
    for path in _admitted_production_paths(root, policy):
        relative = path.relative_to(root)
        raw = _source_bytes(path)
        _committed(root, subject["commit_sha"], relative.as_posix(), raw)
        parent_parts = set(relative.parent.parts)
        layers = tuple(sorted(name for name, tokens in policy.layer_tokens if parent_parts.intersection(tokens)))
        members.append(SourceMember(relative.as_posix(), _sha(raw), raw, layers,
                                    tuple(sorted(_contexts(relative, policy)))))
    if not members:
        raise ArchitectureInventoryError("empty production population")
    by_path = {member.path: member for member in members}
    for metadata in policy_input.metadata_ownership:
        if (not metadata.context or metadata.context != metadata.context.strip()
                or any(ord(character) < 32 or ord(character) == 127 for character in metadata.context)):
            raise ArchitectureInventoryError("canonical metadata context name required")
        if metadata.path not in by_path or Path(metadata.path).name != "__init__.py":
            raise ArchitectureInventoryError("unobserved or unsupported metadata source")
        member = by_path[metadata.path]
        tree = ast.parse(member.raw, filename=member.path)
        if not (len(tree.body) == 1 and isinstance(tree.body[0], ast.Expr)
                and isinstance(tree.body[0].value, ast.Constant)
                and isinstance(tree.body[0].value.value, str)):
            raise ArchitectureInventoryError("metadata source must contain only its docstring")
        if metadata.exports != ("__doc__",):
            raise ArchitectureInventoryError("unsupported metadata exports")
        if member.inferred_layers and member.inferred_layers != (metadata.layer,):
            raise ArchitectureInventoryError("metadata owner conflicts with inferred layers")
        if member.inferred_contexts and member.inferred_contexts != (metadata.context,):
            raise ArchitectureInventoryError("metadata owner conflicts with inferred contexts")
    observed = observe(root, policy)
    if observed.source_sha256 != tuple((member.path, member.sha256) for member in members):
        raise ArchitectureInventoryError("observer source population differs from admitted source")
    subject_sha = _object_sha(subject)
    bindings: list[ContextBinding] = []
    inferred = sorted({context for member in members for context in member.inferred_contexts})
    for context in inferred:
        witnesses = tuple((member.path, member.sha256, member.inferred_contexts)
                          for member in members if context in member.inferred_contexts)
        bindings.append(ContextBinding("independently_inferred_inventory", "1.0", context,
                                       context, subject_sha, _sha(config_raw), _object_sha(witnesses)))
    if set(observed.metadata_modules) != {row.path for row in policy_input.metadata_ownership}:
        raise ArchitectureInventoryError("metadata authority population incomplete")
    for metadata in policy_input.metadata_ownership:
        member = by_path[metadata.path]
        witness = (metadata.path, member.sha256, metadata.layer, metadata.context, metadata.exports)
        bindings.append(ContextBinding("qualified_package_metadata_context", "1.0", metadata.path,
                                       metadata.context, subject_sha, _sha(config_raw), _object_sha(witness)))
    result = NativeSourceInventory(root, tuple(sorted(subject.items())), _sha(config_raw),
                                   _sha(schema_raw), policy, tuple(members), tuple(bindings), observed)
    _reauthenticate_source_bytes(result)
    return result


def reauthenticate_inventory(root: Path, inventory: NativeSourceInventory) -> None:
    """Compare a cache with a fresh native derivation from the explicit root.

    Caller-provided policy, contexts, bytes, observations and populations never
    drive discovery or confer authority. A matching cache is still only data.
    """
    fresh = build_native_inventory(root)
    if type(inventory) is not NativeSourceInventory or inventory != fresh:
        raise ArchitectureInventoryError("cached native inventory differs from fresh native owner")


def resolve_native_context(root: Path, *, kind: str, version: str, selector: str,
                           inventory: NativeSourceInventory | None = None) -> ContextBinding:
    """Resolve only newly derived native facts, optionally comparing a cache."""
    fresh = build_native_inventory(root)
    if inventory is not None and (type(inventory) is not NativeSourceInventory or inventory != fresh):
        raise ArchitectureInventoryError("cached native inventory differs from fresh native owner")
    matches = [binding for binding in fresh.contexts
               if (binding.kind, binding.version, binding.selector) == (kind, version, selector)]
    if len(matches) != 1:
        raise ArchitectureInventoryError("unsupported or unresolved native context selector/version")
    _reauthenticate_source_bytes(fresh)
    return matches[0]
