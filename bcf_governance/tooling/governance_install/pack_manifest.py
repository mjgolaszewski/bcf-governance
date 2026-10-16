"""Closed decoder for active and retired governance-pack file identities."""

from __future__ import annotations

from dataclasses import dataclass
import hashlib
import json
from pathlib import Path
import re
from typing import Any, Callable, Iterable


@dataclass(frozen=True)
class PackManifest:
    """One exact successor inventory and its content-addressed retirements."""

    files: dict[str, dict[str, Any]]
    retired_files: dict[str, tuple[str, ...]]
    sha256: str


def _safe_relative(value: object) -> Path:
    relative = Path(str(value))
    if relative.is_absolute() or not relative.parts or ".." in relative.parts:
        raise ValueError(f"unsafe pack path: {relative}")
    return relative


def _unique_object(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise ValueError(f"pack manifest duplicates destination {key}")
        result[key] = value
    return result


def load_pack_manifest(
    template_root: Path,
    *,
    iter_template_files: Callable[[Path], Iterable[Path]],
    profile_choices: tuple[str, ...],
) -> PackManifest:
    """Decode and authenticate the complete pack manifest against pack bytes."""

    manifest_path = template_root / ".bcf-pack-manifest.json"
    if not manifest_path.is_file() or manifest_path.is_symlink():
        raise ValueError("template pack is missing .bcf-pack-manifest.json")
    raw = manifest_path.read_bytes()
    try:
        payload = json.loads(raw, object_pairs_hook=_unique_object)
    except (UnicodeError, json.JSONDecodeError) as exc:
        raise ValueError("pack manifest is unreadable") from exc
    if not isinstance(payload, dict):
        raise ValueError("pack manifest must contain a mapping")
    version = payload.get("schema_version")
    allowed_keys = (
        {"schema_version", "files", "generated"}
        if version == "1.0"
        else {"schema_version", "files", "generated", "retired_files"}
        if version == "2.0"
        else set()
    )
    if not allowed_keys or set(payload) != allowed_keys:
        raise ValueError("pack manifest schema version or fields are unsupported")
    raw_files = payload.get("files")
    if not isinstance(raw_files, dict) or not raw_files:
        raise ValueError("pack manifest must declare a non-empty files mapping")
    entries: dict[str, dict[str, Any]] = {}
    for raw_path, raw_entry in raw_files.items():
        relative = _safe_relative(raw_path)
        if not isinstance(raw_entry, dict):
            raise ValueError(f"pack manifest entry for {raw_path} must be a mapping")
        digest = raw_entry.get("sha256")
        if not isinstance(digest, str) or re.fullmatch(r"[a-f0-9]{64}", digest) is None:
            raise ValueError(f"pack manifest has invalid digest for {raw_path}")
        if raw_entry.get("operation") not in {"copy", "merge", "generate", "preserve"}:
            raise ValueError(f"pack manifest has invalid operation for {raw_path}")
        profiles = raw_entry.get("profiles")
        if profiles is not None and (
            not isinstance(profiles, list)
            or not profiles
            or not all(value in profile_choices for value in profiles)
        ):
            raise ValueError(f"pack manifest has invalid profiles for {raw_path}")
        scope = raw_entry.get("installation_scope", "ordinary_adopter")
        if scope not in {"ordinary_adopter", "self_authority"}:
            raise ValueError(f"pack manifest has invalid installation scope for {raw_path}")
        entries[relative.as_posix()] = raw_entry

    retirements: dict[str, tuple[str, ...]] = {}
    raw_retirements = payload.get("retired_files", {})
    if not isinstance(raw_retirements, dict):
        raise ValueError("pack manifest retired_files must be a mapping")
    for raw_path, raw_digests in raw_retirements.items():
        relative = _safe_relative(raw_path).as_posix()
        if relative in entries:
            raise ValueError(f"pack manifest path is both active and retired: {relative}")
        if (
            not isinstance(raw_digests, list)
            or not raw_digests
            or raw_digests != sorted(set(raw_digests))
            or any(
                not isinstance(value, str)
                or re.fullmatch(r"[a-f0-9]{64}", value) is None
                for value in raw_digests
            )
        ):
            raise ValueError(f"pack manifest has invalid retirements for {relative}")
        retirements[relative] = tuple(raw_digests)

    actual = {
        path.relative_to(template_root).as_posix(): hashlib.sha256(path.read_bytes()).hexdigest()
        for path in iter_template_files(template_root)
    }
    expected = {path: str(entry["sha256"]) for path, entry in entries.items()}
    if actual != expected:
        missing = sorted(set(actual) - set(entries))
        stale = sorted(set(entries) - set(actual))
        mismatched = sorted(
            path for path in set(actual) & set(entries) if actual[path] != expected[path]
        )
        raise ValueError(
            "pack manifest mismatch: "
            f"missing={missing}, stale={stale}, digest_mismatch={mismatched}"
        )
    return PackManifest(
        files=entries,
        retired_files=retirements,
        sha256=hashlib.sha256(raw).hexdigest(),
    )
