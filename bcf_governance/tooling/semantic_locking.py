"""Atomic persistence and stable digest primitives for semantic authority locks."""

from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path
from typing import Any

import yaml  # type: ignore[import-untyped]


def stable_payload_digest(payload: Any) -> str:
    """Return a canonical JSON digest for a semantic value."""
    encoded = json.dumps(payload, sort_keys=True, separators=(",", ":")).encode()
    return hashlib.sha256(encoded).hexdigest()


def sha256_bytes(value: bytes) -> str:
    """Return the SHA-256 digest of exact bytes."""
    return hashlib.sha256(value).hexdigest()


def render_lock_yaml(payload: dict[str, Any]) -> bytes:
    """Render the canonical semantic lock bytes."""
    return yaml.safe_dump(payload, sort_keys=False, width=1000).encode("utf-8")


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
