"""Independently observe an accepted held workload before any capability grant.

Observations are admission inputs, not provider authority or terminal receipts.
Only the trusted owner creates the listening socket and expected source view.
"""
from __future__ import annotations

from dataclasses import dataclass
import hashlib
import os
import re
from pathlib import Path, PurePosixPath
import socket
import stat
import struct
import time

from .evidence_execution_owner import OwnerAdmissionError, ProcessIdentity
from .evidence_execution_view import MAX_FILES, MAX_FILE_BYTES, MAX_TOTAL_BYTES, WorkingView


@dataclass(frozen=True)
class HeldPeerObservation:
    identity: ProcessIdentity
    supervisor: ProcessIdentity
    source_digest: str
    mount_id: int
    source_device: int
    source_inode: int


def _descends_from(pid: int, supervisor: ProcessIdentity) -> bool:
    current = pid
    seen: set[int] = set()
    for _ in range(32):
        if current == supervisor.pid:
            return ProcessIdentity.observe(current) == supervisor
        if current in seen or current <= 1:
            return False
        seen.add(current)
        try:
            fields = Path("/proc", str(current), "stat").read_bytes().rsplit(b")", 1)[1].split()
            current = int(fields[1])
        except (OSError, IndexError, ValueError):
            return False
    return False


@dataclass
class _InspectionBudget:
    deadline: float
    entries: int = 0
    files: int = 0
    total_bytes: int = 0

    def check(self) -> None:
        if time.monotonic() >= self.deadline:
            raise OwnerAdmissionError("held source inspection deadline exhausted")
        if self.entries > MAX_FILES * 2 or self.files > MAX_FILES or self.total_bytes > MAX_TOTAL_BYTES:
            raise OwnerAdmissionError("held source exceeds finite population budget")


def _actual_files(directory: int, *, budget: _InspectionBudget,
                  prefix: str = "", depth: int = 0) -> list[tuple[str, int, int, str]]:
    budget.check()
    if depth > 64:
        raise OwnerAdmissionError("held source exceeds finite directory depth")
    result: list[tuple[str, int, int, str]] = []
    names = []
    with os.scandir(directory) as entries:
        for entry in entries:
            budget.entries += 1
            budget.check()
            names.append(entry.name)
    for name in sorted(names):
        budget.check()
        relative = prefix + name
        descriptor = os.open(name, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK, dir_fd=directory)
        try:
            info = os.fstat(descriptor)
            if stat.S_ISDIR(info.st_mode):
                result.extend(_actual_files(descriptor, budget=budget,
                                            prefix=relative + "/", depth=depth + 1))
            elif stat.S_ISREG(info.st_mode):
                if info.st_size > MAX_FILE_BYTES or info.st_mode & (stat.S_ISUID | stat.S_ISGID):
                    raise OwnerAdmissionError("held source has an unsupported regular input")
                budget.files += 1
                budget.check()
                digest = hashlib.sha256()
                size = 0
                while raw := os.read(descriptor, 1024 * 1024):
                    size += len(raw)
                    budget.total_bytes += len(raw)
                    budget.check()
                    if size > MAX_FILE_BYTES:
                        raise OwnerAdmissionError("held source exceeds finite file budget")
                    digest.update(raw)
                after = os.fstat(descriptor)
                if (size != info.st_size or any(getattr(info, field) != getattr(after, field)
                        for field in ("st_dev", "st_ino", "st_size", "st_mtime_ns", "st_ctime_ns", "st_mode"))):
                    raise OwnerAdmissionError("held source changed during independent inspection")
                result.append((relative, stat.S_IMODE(info.st_mode), size, digest.hexdigest()))
            else:
                raise OwnerAdmissionError("held source contains a non-regular input")
        finally:
            os.close(descriptor)
    return result


def inspect_held_process(identity: ProcessIdentity, *, expected_view: WorkingView,
                         supervisor: ProcessIdentity, deadline: float,
                         source_mount: str = "/work") -> HeldPeerObservation:
    """Reinspect kernel bytes; callers must authenticate their actual socket peer.

    This query grants no provider authority and accepts no caller JSON as a
    process lifetime. Independent delivery owners compare their accepted socket
    credentials with the original registered lifetime before invoking it.
    """
    if type(identity) is not ProcessIdentity or ProcessIdentity.observe(identity.pid) != identity:
        raise OwnerAdmissionError("held lifetime changed before independent reinspection")
    pid = identity.pid
    mount = PurePosixPath(source_mount)
    if not mount.is_absolute() or ".." in mount.parts or mount.as_posix() != source_mount:
        raise OwnerAdmissionError("held source mount must be a canonical absolute path")
    remaining = deadline - time.monotonic()
    if not 0 < remaining <= 30:
        raise OwnerAdmissionError("held peer observation deadline is invalid")
    if identity.uid != supervisor.uid or not _descends_from(pid, supervisor):
        raise OwnerAdmissionError("held socket peer is outside the registered supervisor")
    own_namespaces = dict(ProcessIdentity.observe(os.getpid()).namespaces)
    actual_namespaces = dict(identity.namespaces)
    if any(actual_namespaces[name] == own_namespaces[name] for name in ("mnt", "pid")):
        raise OwnerAdmissionError("held peer is not in a separate source and PID namespace")
    peer = Path("/proc", str(pid))
    with (peer / "mountinfo").open("rb") as stream:
        mount_bytes = stream.read(131073)
    if len(mount_bytes) > 131072:
        raise OwnerAdmissionError("held mount population exceeds observation budget")
    mounts = [line.split() for line in mount_bytes.decode("utf-8").splitlines()]
    if len(mounts) > 128 or any(len(row) < 7 for row in mounts):
        raise OwnerAdmissionError("held mount population is unsupported")
    matches = [row for row in mounts if row[4] == source_mount]
    if len(matches) != 1 or "ro" not in matches[0][5].split(","):
        raise OwnerAdmissionError("held source is not one independently observed read-only mount")
    def mount_path(value: str) -> PurePosixPath:
        decoded = re.sub(r"\\([0-7]{3})", lambda match: chr(int(match[1], 8)), value)
        path = PurePosixPath(decoded)
        if not path.is_absolute() or ".." in path.parts or path.as_posix() != decoded:
            raise OwnerAdmissionError("held mount path is unsupported")
        return path

    source_device = matches[0][2]
    source_root = mount_path(matches[0][3])
    for row in mounts:
        if "rw" not in row[5].split(","):
            continue
        target = mount_path(row[4])
        backing_root = mount_path(row[3])
        overlaps_source = (row[2] == source_device
            and (source_root.is_relative_to(backing_root) or backing_root.is_relative_to(source_root)))
        if overlaps_source or target.is_relative_to(mount):
            raise OwnerAdmissionError("held view has a writable source alias or submount")
    # The procfs root link is kernel-owned. Descendants use anchored openat
    # and O_NOFOLLOW, never candidate-supplied host paths or symlink chains.
    root = os.open(peer / "root" / source_mount.removeprefix("/"), os.O_RDONLY | os.O_DIRECTORY)
    try:
        info = os.fstat(root)
        expected = expected_view.root.stat()
        if (info.st_dev, info.st_ino) != (expected.st_dev, expected.st_ino):
            raise OwnerAdmissionError("held source mount aliases a different snapshot")
        actual = tuple(sorted(_actual_files(root, budget=_InspectionBudget(deadline))))
    finally:
        os.close(root)
    if actual != expected_view.manifest:
        raise OwnerAdmissionError("held source inventory differs from the actual frozen view")
    if time.monotonic() >= deadline or ProcessIdentity.observe(pid) != identity:
        raise OwnerAdmissionError("held peer changed or observation deadline exhausted")
    observation = HeldPeerObservation(identity, supervisor, expected_view.digest,
                                      int(matches[0][0]), info.st_dev, info.st_ino)
    return observation


def observe_held_namespace(listener: socket.socket, *, expected_view: WorkingView,
                           supervisor: ProcessIdentity, deadline: float,
                           source_mount: str = "/work") -> tuple[socket.socket, HeldPeerObservation]:
    """Accept here, avoiding socketpair creator credentials and claimed PIDs."""
    if (listener.family != socket.AF_UNIX
            or listener.getsockopt(socket.SOL_SOCKET, socket.SO_TYPE) != socket.SOCK_STREAM
            or listener.getsockopt(socket.SOL_SOCKET, socket.SO_ACCEPTCONN) != 1):
        raise OwnerAdmissionError("held peer requires an actual listening Unix socket")
    mount = PurePosixPath(source_mount)
    if not mount.is_absolute() or ".." in mount.parts or mount.as_posix() != source_mount:
        raise OwnerAdmissionError("held source mount must be a canonical absolute path")
    remaining = deadline - time.monotonic()
    if not 0 < remaining <= 30:
        raise OwnerAdmissionError("held peer observation deadline is invalid")
    listener.settimeout(remaining)
    connection, _address = listener.accept()
    try:
        connection.settimeout(max(0.001, deadline - time.monotonic()))
        pid, uid, _gid = struct.unpack("3i", connection.getsockopt(
            socket.SOL_SOCKET, socket.SO_PEERCRED, struct.calcsize("3i")))
        identity = ProcessIdentity.observe(pid)
        observation = inspect_held_process(identity, expected_view=expected_view,
            supervisor=supervisor, deadline=deadline, source_mount=source_mount)
        return connection, observation
    except BaseException:
        connection.close()
        raise
