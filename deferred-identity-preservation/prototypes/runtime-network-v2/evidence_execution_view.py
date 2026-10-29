"""Materialize actual working bytes for an independently mounted invocation view.

The controller must own the only writer during materialization. A copied tree
is not an immutable execution boundary: admission additionally requires a real
read-only namespace mount, no workload-visible writable alias, and runtime pins.
"""
from __future__ import annotations

from dataclasses import dataclass
import hashlib
import json
import os
import re
from pathlib import Path, PurePosixPath
import stat
from typing import Any

MAX_FILES = 20000
MAX_FILE_BYTES = 64 * 1024 * 1024
MAX_TOTAL_BYTES = 512 * 1024 * 1024


class ExecutionViewError(RuntimeError):
    """The actual source view could not be materialized or independently matched."""


@dataclass(frozen=True)
class WorkingView:
    root: Path
    manifest: tuple[tuple[str, int, int, str], ...]
    digest: str


def _read_regular(path: Path) -> tuple[bytes, int]:
    descriptor = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    try:
        before = os.fstat(descriptor)
        if not stat.S_ISREG(before.st_mode) or before.st_size > MAX_FILE_BYTES:
            raise ExecutionViewError("source input is not a bounded regular file")
        if before.st_mode & (stat.S_ISUID | stat.S_ISGID):
            raise ExecutionViewError("source input has unsupported special permissions")
        with os.fdopen(os.dup(descriptor), "rb") as stream:
            raw = stream.read(MAX_FILE_BYTES + 1)
        after = os.fstat(descriptor)
        fields = ("st_dev", "st_ino", "st_mode", "st_size", "st_mtime_ns", "st_ctime_ns")
        if (len(raw) > MAX_FILE_BYTES or len(raw) != before.st_size
                or any(getattr(before, field) != getattr(after, field) for field in fields)):
            raise ExecutionViewError("source input changed while being read")
        return raw, stat.S_IMODE(before.st_mode)
    finally:
        os.close(descriptor)


def _paths(root: Path, paths: tuple[str, ...]) -> tuple[tuple[str, Path], ...]:
    if not paths or len(paths) > MAX_FILES or len(set(paths)) != len(paths):
        raise ExecutionViewError("source file population is empty duplicated or over budget")
    result = []
    for name in sorted(paths):
        relative = PurePosixPath(name)
        if (not name or relative.is_absolute() or ".." in relative.parts
                or relative.as_posix() != name or "\0" in name):
            raise ExecutionViewError("source path is not a canonical relative path")
        target = root.joinpath(*relative.parts)
        if any(parent.is_symlink() for parent in (target, *target.parents) if parent != root.parent):
            raise ExecutionViewError("source path has a symlink alias")
        result.append((name, target))
    return tuple(result)


def _digest(manifest: tuple[tuple[str, int, int, str], ...]) -> str:
    return hashlib.sha256(json.dumps(manifest, separators=(",", ":"),
                                    ensure_ascii=True).encode("ascii")).hexdigest()


def inspect_view(root: Path, paths: tuple[str, ...]) -> WorkingView:
    rows = []
    total = 0
    for name, source in _paths(root, paths):
        raw, mode = _read_regular(source)
        total += len(raw)
        if total > MAX_TOTAL_BYTES:
            raise ExecutionViewError("source input population exceeds byte budget")
        rows.append((name, mode, len(raw), hashlib.sha256(raw).hexdigest()))
    manifest = tuple(rows)
    return WorkingView(root, manifest, _digest(manifest))


def materialize_view(source: Path, destination: Path, paths: tuple[str, ...]) -> WorkingView:
    """Copy under sole-writer ownership and verify both sides before admission."""
    if not source.is_absolute() or not destination.is_absolute() or destination.exists():
        raise ExecutionViewError("fresh absolute owned destination is required")
    if destination.is_relative_to(source):
        raise ExecutionViewError("source view destination must be outside the working source")
    before = inspect_view(source, paths)
    destination.mkdir(mode=0o700)
    try:
        for name, original in _paths(source, paths):
            raw, mode = _read_regular(original)
            target = destination / name
            target.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
            descriptor = os.open(target, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
            with os.fdopen(descriptor, "wb") as stream:
                stream.write(raw)
                stream.flush()
                os.fchmod(stream.fileno(), mode)
                os.fsync(stream.fileno())
        copied = inspect_view(destination, paths)
        after = inspect_view(source, paths)
        if before.manifest != copied.manifest or before.manifest != after.manifest:
            raise ExecutionViewError("working source or copied view changed during materialization")
        return copied
    except BaseException:
        # Failed bytes remain owned evidence; no unchecked recursive retirement.
        raise


def context_manifest(view: WorkingView, *, runtime: dict[str, Any], producer: str,
                     profile: str, control: str, deadline_ns: int,
                     invocation_nonce: str, controller: dict[str, Any],
                     held_peer: dict[str, Any]) -> bytes:
    """An inventory is input to independent admission, never its receipt."""
    if not all(type(value) is str and value for value in (producer, profile, control)):
        raise ExecutionViewError("actual producer profile and control identities are required")
    if type(deadline_ns) is not int or deadline_ns <= 0:
        raise ExecutionViewError("finite absolute deadline is required")
    if not re.fullmatch("[0-9a-f]{32}", invocation_nonce):
        raise ExecutionViewError("one fresh invocation nonce is required")
    if not controller or not held_peer:
        raise ExecutionViewError("actual controller and held peer observations are required")
    return json.dumps({"schema_version": "1.0", "source_digest": view.digest,
                       "invocation_nonce": invocation_nonce, "controller": controller,
                       "held_peer": held_peer,
                       "files": view.manifest, "runtime": runtime, "producer": producer,
                       "profile": profile, "control": control, "deadline_ns": deadline_ns},
                      sort_keys=True, separators=(",", ":"), allow_nan=False).encode("utf-8")
