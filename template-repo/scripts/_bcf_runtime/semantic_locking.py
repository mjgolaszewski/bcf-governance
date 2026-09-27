"""Atomic persistence and stable digest primitives for semantic authority locks."""

from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path
from typing import Any

import yaml  # type: ignore[import-untyped]
from jsonschema import Draft202012Validator
from jsonschema.exceptions import SchemaError


class SemanticLockError(ValueError):
    """A proposed semantic lock cannot be persisted as a valid contract."""


class _NoAliasSafeDumper(yaml.SafeDumper):  # type: ignore[misc]
    def ignore_aliases(self, data: Any) -> bool:
        return True


def _compact_dump(value: Any, *, flow: bool) -> str:
    return yaml.dump(
        value,
        Dumper=_NoAliasSafeDumper,
        sort_keys=False,
        default_flow_style=flow,
        width=1_000_000 if flow else 1000,
    )


def stable_payload_digest(payload: Any) -> str:
    """Return a canonical JSON digest for a semantic value."""
    encoded = json.dumps(payload, sort_keys=True, separators=(",", ":")).encode()
    return hashlib.sha256(encoded).hexdigest()


def sha256_bytes(value: bytes) -> str:
    """Return the SHA-256 digest of exact bytes."""
    return hashlib.sha256(value).hexdigest()


def render_compact_semantic_yaml(payload: dict[str, Any]) -> bytes:
    """Render top-level semantic inventories with one lossless row per list item."""

    segments: list[str] = []
    for key, value in payload.items():
        if not isinstance(value, list):
            segments.append(_compact_dump({key: value}, flow=False))
            continue
        segments.append(f"{key}: []\n" if not value else f"{key}:\n")
        for row in value:
            rendered = _compact_dump(row, flow=True).strip().removesuffix("\n...")
            segments.append(f"- {rendered}\n")
    candidate = "".join(segments).encode("utf-8")
    try:
        decoded = yaml.safe_load(candidate)
    except yaml.YAMLError as exc:
        raise SemanticLockError(f"cannot decode compact semantic contract: {exc}") from exc
    if decoded != payload:
        raise SemanticLockError("compact semantic contract does not preserve its input value")
    return candidate


def prepend_compact_list_rows(
    existing: bytes, key: str, rows: list[dict[str, Any]]
) -> bytes:
    """Add canonical flow rows to one top-level list without rewriting other bytes."""

    if not rows:
        return existing
    populated_marker = f"{key}:\n".encode()
    empty_marker = f"{key}: []\n".encode()
    marker_count = existing.count(populated_marker) + existing.count(empty_marker)
    if marker_count != 1:
        raise SemanticLockError(f"compact semantic contract requires one {key} list")
    try:
        previous = yaml.safe_load(existing)
    except yaml.YAMLError as exc:
        raise SemanticLockError(f"cannot decode compact semantic contract: {exc}") from exc
    if not isinstance(previous, dict) or not isinstance(previous.get(key), list):
        raise SemanticLockError(f"compact semantic contract {key} must be a list")
    rendered = b"".join(
        f"- {_compact_dump(row, flow=True).strip().removesuffix(chr(10) + '...')}\n".encode()
        for row in rows
    )
    marker = populated_marker if populated_marker in existing else empty_marker
    replacement = populated_marker + rendered
    candidate = existing.replace(marker, replacement, 1)
    try:
        decoded = yaml.safe_load(candidate)
    except yaml.YAMLError as exc:
        raise SemanticLockError(f"cannot decode compact semantic contract: {exc}") from exc
    expected = {**previous, key: [*rows, *previous[key]]}
    if decoded != expected:
        raise SemanticLockError("compact semantic row insertion changed unrelated values")
    return candidate


def render_lock_yaml(payload: dict[str, Any]) -> bytes:
    """Render the canonical semantic lock bytes."""
    header = {key: value for key, value in payload.items() if key != "projection_outputs"}
    rendered = yaml.safe_dump(header, sort_keys=False, width=1000)
    rows = payload.get("projection_outputs", [])
    if not isinstance(rows, list):
        raise ValueError("semantic lock projection_outputs must be a list")
    lines = [rendered, "projection_outputs:\n" if rows else "projection_outputs: []\n"]
    for row in rows:
        if not isinstance(row, dict):
            raise ValueError("semantic lock projection output must be an object")
        flow = yaml.safe_dump(
            row,
            sort_keys=False,
            default_flow_style=True,
            width=1000,
        ).strip()
        lines.append(f"- {flow}\n")
    return "".join(lines).encode("utf-8")


def validated_lock_bytes(repo_root: Path, payload: dict[str, Any]) -> bytes:
    """Render, decode, and validate the exact candidate before any replacement."""
    try:
        candidate = render_lock_yaml(payload)
        decoded = yaml.safe_load(candidate)
    except (ValueError, TypeError, yaml.YAMLError) as exc:
        raise SemanticLockError(f"cannot decode semantic lock candidate: {exc}") from exc
    if decoded != payload:
        raise SemanticLockError("semantic lock candidate does not preserve its input value")
    schema_path = repo_root / "schemas/semantic-lock.schema.json"
    try:
        if schema_path.is_symlink() or not schema_path.is_file():
            raise ValueError("schema must be a regular file")
        schema = json.loads(schema_path.read_text(encoding="utf-8"))
        Draft202012Validator.check_schema(schema)
        errors = list(Draft202012Validator(schema).iter_errors(decoded))
    except (OSError, UnicodeError, ValueError, TypeError, SchemaError) as exc:
        raise SemanticLockError(f"cannot load semantic lock schema: {exc}") from exc
    if errors:
        raise SemanticLockError(f"semantic lock candidate violates schema: {errors[0].message}")
    return candidate


def atomic_write(path: Path, content: bytes) -> None:
    """Replace a repository file atomically without following a target symlink."""
    path.parent.mkdir(parents=True, exist_ok=True)
    descriptor = os.open(path.parent, os.O_RDONLY | getattr(os, "O_DIRECTORY", 0))
    try:
        temporary = path.parent / f".{path.name}.{os.getpid()}.tmp"
        flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL
        handle = os.open(temporary, flags, 0o644)
        try:
            with os.fdopen(handle, "wb") as stream:
                stream.write(content)
                stream.flush()
                os.fsync(stream.fileno())
            os.replace(temporary, path)
            os.fsync(descriptor)
        finally:
            if temporary.exists():
                temporary.unlink()
    finally:
        os.close(descriptor)
