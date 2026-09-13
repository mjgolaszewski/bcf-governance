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


def stable_payload_digest(payload: Any) -> str:
    """Return a canonical JSON digest for a semantic value."""
    encoded = json.dumps(payload, sort_keys=True, separators=(",", ":")).encode()
    return hashlib.sha256(encoded).hexdigest()


def sha256_bytes(value: bytes) -> str:
    """Return the SHA-256 digest of exact bytes."""
    return hashlib.sha256(value).hexdigest()


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
