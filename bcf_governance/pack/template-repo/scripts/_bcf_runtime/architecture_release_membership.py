"""Separate explicit release authentication from ordinary local installed membership.

Provider-backed release qualification is an explicit owner operation. Installed
adopters inspect their pinned local runtime without supplier access or credentials."""
from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass
from pathlib import Path, PurePosixPath
from typing import Any, Never

from .architecture_effective_membership import MemberClassification
from .architecture_native_inventory import build_native_inventory
from .architecture_pack_projection import bound_wheel_manifest
from .architecture_policy_input import _read
from .architecture_source_components import SourceComponentError
from .governance_install.release_custody import (
    ReleaseProvider,
    _project_bytes,
    prepare_release_custody,
    selected_runtime_inventory_paths,
)
from .governance_install.runtime_custody import (
    CANDIDATE_QUALIFICATION_PATH,
    RUNTIME_LOCK_PATH,
    RuntimeCustodyError,
    RuntimeCustodyState,
    inspect_runtime_custody,
    runtime_custody_schema_path,
)
from .install_governance_pack import UPGRADE_REFRESH_PATHS
from .runtime_capacity import executing_runtime_version


@dataclass(frozen=True)
class ReleaseMembership:
    classifications: tuple[MemberClassification, ...]
    lock_sha256: str
    release_version: str
    release_commit: str
    wheel_sha256: str
    subject: tuple[tuple[str, object], ...]
    scope: str = "Fresh query result; consumers must reauthenticate before use."


def _refuse(detail: str) -> Never:
    raise SourceComponentError(f"release source membership: {detail}")


def _sha(raw: bytes) -> str:
    return hashlib.sha256(raw).hexdigest()


def _unique_object(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            _refuse("duplicate JSON field")
        result[key] = value
    return result


def _relative(value: str) -> str:
    path = PurePosixPath(value)
    if (not value or path.is_absolute() or path.as_posix() != value
            or any(part in {"", ".", ".."} for part in value.split("/"))
            or any(character in value for character in "\\:*?[]")):
        _refuse("noncanonical installed source path")
    return value


def authenticate_release_membership(root: Path, *, assets_root: Path,
                                    template_root: Path, token: str,
                                    api: ReleaseProvider | None = None) -> ReleaseMembership:
    """Authenticate independently before parsing source-component declarations.

    Production uses the existing canonical provider. The api port is for native
    owner's closed fixture qualification, never a config-selectable provider.
    Caller-supplied serialized results or cached inventory are not parameters.
    Missing custody always refuses; it never turns installed code project-owned.
    """
    inventory = build_native_inventory(root)
    lock_path = root / RUNTIME_LOCK_PATH
    marker = root / CANDIDATE_QUALIFICATION_PATH
    if marker.exists() or marker.is_symlink():
        _refuse("candidate qualification has no immutable release authority")
    # The bounded canonical reader also refuses missing lock, ancestor aliases,
    # FIFO, leaf symlink and changed named identity before the legacy classifier.
    lock_raw = _read(lock_path)
    payload = json.loads(lock_raw, object_pairs_hook=_unique_object)
    if not isinstance(payload, dict):
        _refuse("runtime lock must be an object")
    for key in ("files", "preserved_consumer_files"):
        mapping = payload.get(key)
        if not isinstance(mapping, dict):
            _refuse("complete installed ownership inventories required")
        for relative, digest in mapping.items():
            raw = _read(root / _relative(relative))
            if _sha(raw) != digest:
                _refuse("installed byte inventory differs from current source")
    schema = template_root / "schemas/bcf-runtime-lock.schema.json"
    schema_raw = _read(schema)
    snapshot = inspect_runtime_custody(root, schema_path=schema)
    if snapshot.state is not RuntimeCustodyState.NORMALIZED_EXACT or snapshot.lock_bytes != lock_raw:
        _refuse("normalized exact installed custody required")
    if snapshot.consumer_preserved:
        _refuse("consumer preservation requires independent maintained authority")
    custody = prepare_release_custody(
        assets_root, installed_version=executing_runtime_version(),
        template_root=template_root, token=token, api=api,
    )
    if custody.released_template_files.get("schemas/bcf-runtime-lock.schema.json") != schema_raw:
        _refuse("runtime lock schema differs from authenticated release")
    expected_provenance = {
        "version": custody.version,
        "source_repository": "mjgolaszewski/bcf-governance",
        "source_repository_id": custody.repository_id,
        "source_commit": custody.source_commit,
        "release_id": custody.release_id,
        "release_url": custody.release_url,
        "wheel_sha256": custody.wheel_sha256,
        "source_archive_sha256": custody.source_archive_sha256,
        "checksum_manifest_sha256": custody.checksum_manifest_sha256,
    }
    if snapshot.provenance_claim != expected_provenance:
        _refuse("persisted release identity differs from existing custodian")
    # Authenticate manifest metadata too, not only its source digest fields.
    # prepare_release_custody bounds the complete wheel and rejects duplicate
    # archive members; its result omits this manifest from released_template_files.
    manifest = bound_wheel_manifest(assets_root, template_root, custody.wheel_sha256)
    entries = manifest.get("files") if isinstance(manifest, dict) else None
    if not isinstance(entries, dict) or set(entries) != set(custody.released_template_files):
        _refuse("authenticated release manifest population differs")
    for relative, entry in entries.items():
        _relative(relative)
        if not isinstance(entry, dict) or entry.get("sha256") != _sha(custody.released_template_files[relative]):
            _refuse("authenticated release manifest byte join differs")
    selected = selected_runtime_inventory_paths(entries, UPGRADE_REFRESH_PATHS)
    if set(snapshot.runtime_owned) != selected:
        _refuse("persisted runtime membership omits or adds maintained release members")
    expected_adaptations = {}
    for relative in sorted(snapshot.runtime_owned):
        released = custody.released_template_files[relative]
        # This is the fixed canonical installer's runtime substitution, not a
        # caller-selected rewrite language. Other token-bearing runtime shapes
        # remain unsupported until their native contracts are maintained.
        projected = _project_bytes(released, {"PLACEHOLDER": "TOKEN"})
        actual = _read(root / relative)
        if actual != projected:
            _refuse("installed runtime differs from canonical installer projection")
        if released != projected:
            expected_adaptations[relative] = (_sha(released), _sha(projected))
    if snapshot.installer_adaptations != expected_adaptations:
        _refuse("installer adaptation inventory differs from exact projection")
    classifications = tuple(MemberClassification(
        member.path, member.sha256,
        "managed" if member.path in snapshot.runtime_owned else "project",
    ) for member in inventory.members)
    # Do not let a new runtime file evade the lock by being labeled project code.
    for member in inventory.members:
        if (member.path.startswith("scripts/_bcf_runtime/")
                and member.path not in snapshot.runtime_owned):
            _refuse("unexplained source inside installed runtime footprint")
    fresh = build_native_inventory(root)
    if fresh != inventory or _read(lock_path) != lock_raw or _read(schema) != schema_raw:
        _refuse("source, configuration or custody changed during authentication")
    if inspect_runtime_custody(root, schema_path=schema) != snapshot:
        _refuse("installed custody changed during authentication")
    return ReleaseMembership(classifications, _sha(lock_raw), custody.version,
                             custody.source_commit, custody.wheel_sha256, inventory.subject)


@dataclass(frozen=True)
class InstalledMembership:
    """Local installed-byte observation, never fresh release/publication authority.

    The adopting repository owns its pinned lock and review boundary. Ordinary
    validation checks that installation locally; it does not contact its supplier.
    """

    classifications: tuple[MemberClassification, ...]
    lock_sha256: str
    subject: tuple[tuple[str, object], ...]
    schema_sha256: str


def inspect_installed_membership(root: Path) -> InstalledMembership:
    """Check the complete current installed inventory without network or secrets."""
    inventory = build_native_inventory(root)
    lock_path = root / RUNTIME_LOCK_PATH
    marker = root / CANDIDATE_QUALIFICATION_PATH
    if marker.exists() or marker.is_symlink():
        _refuse("candidate qualification is not an installed release")
    raw = _read(lock_path)
    payload = json.loads(raw, object_pairs_hook=_unique_object)
    if not isinstance(payload, dict):
        _refuse("runtime lock must be an object")
    schema = runtime_custody_schema_path(root)
    schema_raw = _read(schema)
    try:
        snapshot = inspect_runtime_custody(root, schema_path=schema)
    except RuntimeCustodyError as exc:
        raise SourceComponentError(f"release source membership: invalid installed custody: {exc}") from exc
    if snapshot.state is not RuntimeCustodyState.NORMALIZED_EXACT or snapshot.lock_bytes != raw:
        _refuse("normalized exact installed custody required")
    if snapshot.version != executing_runtime_version():
        _refuse("installed version differs from executing runtime")
    for relative, digest in sorted({**snapshot.runtime_owned, **snapshot.consumer_preserved}.items()):
        if _sha(_read(root / _relative(relative))) != digest:
            _refuse("installed byte inventory differs from current source")
    for member in inventory.members:
        if member.path.startswith("scripts/_bcf_runtime/") and member.path not in snapshot.runtime_owned:
            _refuse("unexplained or consumer-reclassified source inside installed runtime footprint")
    classifications = tuple(MemberClassification(
        member.path, member.sha256,
        "managed" if member.path in snapshot.runtime_owned else "project",
    ) for member in inventory.members)
    if (build_native_inventory(root) != inventory or _read(lock_path) != raw
            or _read(schema) != schema_raw
            or inspect_runtime_custody(root, schema_path=schema) != snapshot):
        _refuse("source, configuration or installed custody changed during local validation")
    return InstalledMembership(classifications, _sha(raw), inventory.subject, _sha(schema_raw))
