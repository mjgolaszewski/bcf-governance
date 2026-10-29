"""Compose actual source and nominated runtime bytes into one bounded image.

Only listed files enter the image. This inventory does not establish semantic
binding, authorize networking, install a backend, or certify that a nominated
runtime contains all dependencies. Missing dependencies must fail closed.
"""
from __future__ import annotations

from dataclasses import dataclass
import hashlib
import os
from pathlib import Path, PurePosixPath
import struct

from .evidence_execution_view import (
    ExecutionViewError, WorkingView, _read_regular, inspect_view,
)

_RESERVED = frozenset({'work', 'proc', 'sys', 'dev', 'tmp', 'run'})
_MAX_FILES = 20000
_MAX_BYTES = 512 * 1024 * 1024


def _absolute_file(value: str) -> str:
    if type(value) is not str:
        raise ExecutionViewError('runtime path must be a canonical absolute file')
    path = PurePosixPath(value)
    if (not path.is_absolute() or path.as_posix() != value or '..' in path.parts
            or len(path.parts) < 2 or '\0' in value):
        raise ExecutionViewError('runtime path must be a canonical absolute file')
    return value[1:]


def _elf_interpreter(raw: bytes) -> str | None:
    # This first profile deliberately supports only the actual Linux x86-64 ABI.
    if (len(raw) < 64 or raw[:7] != b'\x7fELF\x02\x01\x01'
            or struct.unpack_from('<H', raw, 18)[0] != 62):
        raise ExecutionViewError('runtime executable must be Linux x86-64 ELF')
    offset = struct.unpack_from('<Q', raw, 32)[0]
    width, count = struct.unpack_from('<HH', raw, 54)
    if width != 56 or not 1 <= count <= 256 or offset + width * count > len(raw):
        raise ExecutionViewError('runtime executable program headers are invalid')
    found = []
    for index in range(count):
        start = offset + index * width
        if struct.unpack_from('<I', raw, start)[0] != 3:
            continue
        begin = struct.unpack_from('<Q', raw, start + 8)[0]
        size = struct.unpack_from('<Q', raw, start + 32)[0]
        if not 2 <= size <= 512 or begin + size > len(raw):
            raise ExecutionViewError('runtime interpreter path is invalid')
        value = raw[begin:begin + size]
        if value[-1:] != b'\0' or b'\0' in value[:-1]:
            raise ExecutionViewError('runtime interpreter path is invalid')
        try:
            found.append('/' + _absolute_file(value[:-1].decode('ascii')))
        except UnicodeError as error:
            raise ExecutionViewError('runtime interpreter path is invalid') from error
    if len(found) > 1:
        raise ExecutionViewError('runtime executable has multiple interpreters')
    return found[0] if found else None


@dataclass(frozen=True)
class ClosedImageInventory:
    image: WorkingView
    source_digest: str
    runtime_digest: str
    executable: str
    interpreter: str | None

    def recheck(self) -> None:
        actual = inspect_view(self.image.root, tuple(row[0] for row in self.image.manifest))
        if actual != self.image:
            raise ExecutionViewError('composed execution image changed')


def compose_execution_image(source: WorkingView, runtime: WorkingView, *,
                            destination: Path, executable: str) -> ClosedImageInventory:
    """Copy nominated bytes; source owns /work and runtime owns other file paths."""
    if type(source) is not WorkingView or type(runtime) is not WorkingView:
        raise ExecutionViewError('actual source and runtime inventories are required')
    if (not destination.is_absolute() or destination.resolve() != destination
            or destination.exists() or destination.is_symlink()
            or destination.is_relative_to(source.root) or destination.is_relative_to(runtime.root)):
        raise ExecutionViewError('fresh separate owned image destination required')
    selected = _absolute_file(executable)
    runtime_names = {row[0] for row in runtime.manifest}
    if selected not in runtime_names:
        raise ExecutionViewError('runtime executable is outside nominated files')
    names = ['work/' + row[0] for row in source.manifest]
    for name in runtime_names:
        if (PurePosixPath(name).parts[0] in _RESERVED or name.endswith('.pth')
                or _absolute_file('/' + name) != name):
            raise ExecutionViewError('runtime path conflicts with controlled image layout')
    names.extend(row[0] for row in runtime.manifest)
    if (not 1 <= len(names) <= _MAX_FILES or len(set(names)) != len(names)
            or sum(row[2] for view in (source, runtime) for row in view.manifest) > _MAX_BYTES):
        raise ExecutionViewError('composed image exceeds its file or byte budget')
    for view in (source, runtime):
        if inspect_view(view.root, tuple(row[0] for row in view.manifest)) != view:
            raise ExecutionViewError('nominated source or runtime bytes changed')
    executable_raw, mode = _read_regular(runtime.root / selected)
    if not mode & 0o111:
        raise ExecutionViewError('runtime executable lacks executable permissions')
    interpreter = _elf_interpreter(executable_raw)
    if interpreter is not None and interpreter[1:] not in runtime_names:
        raise ExecutionViewError('runtime ELF interpreter is not frozen in the image')
    destination.mkdir(mode=0o700)
    expected = []
    for view, prefix in ((source, 'work/'), (runtime, '')):
        for name, expected_mode, size, digest in view.manifest:
            raw, actual_mode = _read_regular(view.root / name)
            if (actual_mode != expected_mode or len(raw) != size
                    or hashlib.sha256(raw).hexdigest() != digest):
                raise ExecutionViewError('input changed during image composition')
            target = destination / (prefix + name)
            target.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
            descriptor = os.open(target, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
            with os.fdopen(descriptor, 'wb') as stream:
                stream.write(raw)
                stream.flush()
                os.fchmod(stream.fileno(), actual_mode)
                os.fsync(stream.fileno())
            expected.append((prefix + name, actual_mode, size, digest))
    copied = inspect_view(destination, tuple(names))
    if copied.manifest != tuple(sorted(expected)):
        raise ExecutionViewError('composed image differs from nominated bytes')
    for view in (source, runtime):
        if inspect_view(view.root, tuple(row[0] for row in view.manifest)) != view:
            raise ExecutionViewError('input changed before image composition completed')
    return ClosedImageInventory(copied, source.digest, runtime.digest, executable, interpreter)
