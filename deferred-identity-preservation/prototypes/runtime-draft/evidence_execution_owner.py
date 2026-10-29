"""Kernel-bound independent-owner transport for a trusted controller bootstrap.

Constructing a registration is not authority. Only an installed trusted launcher
may select it, before candidate execution and outside the candidate namespace.
This transport does not establish source freeze, issuer authority or cleanup.
"""
from __future__ import annotations

import hashlib
import json
import math
import os
import socket
import stat
import struct
import time
from dataclasses import dataclass
from pathlib import Path
from types import TracebackType
from typing import Any

REQUEST_LIMIT = 1024
RESPONSE_LIMIT = 65536


class OwnerAdmissionError(RuntimeError):
    """Owner identity, framing or delivery is not established."""


@dataclass(frozen=True)
class ProcessIdentity:
    pid: int
    uid: int
    start_ticks: int
    boot_id: str
    executable_sha256: str
    command_line_sha256: str
    namespaces: tuple[tuple[str, str], ...]

    @classmethod
    def observe(cls, pid: int) -> ProcessIdentity:
        if type(pid) is not int or pid <= 0:
            raise OwnerAdmissionError("owner peer PID is invalid")
        root = Path("/proc") / str(pid)
        try:
            before = (root / "stat").read_bytes()
            fields = before.rsplit(b")", 1)[1].split()
            start_ticks = int(fields[19])
            status = (root / "status").read_text()
            uid_line = next(line for line in status.splitlines() if line.startswith("Uid:"))
            uids = tuple(int(value) for value in uid_line.split()[1:])
            if len(uids) != 4 or len(set(uids)) != 1:
                raise OwnerAdmissionError("owner peer UID changes are unsupported")
            executable = hashlib.sha256((root / "exe").read_bytes()).hexdigest()
            command_line = hashlib.sha256((root / "cmdline").read_bytes()).hexdigest()
            namespaces = tuple((name, os.readlink(root / "ns" / name))
                               for name in ("pid", "user", "mnt", "net"))
            after = (root / "stat").read_bytes()
            # CPU/accounting fields vary; PID and start identify this lifetime.
            if (int(after.split(b" ", 1)[0]) != pid
                    or int(after.rsplit(b")", 1)[1].split()[19]) != start_ticks):
                raise OwnerAdmissionError("owner peer changed during observation")
            return cls(pid, uids[0], start_ticks,
                       Path("/proc/sys/kernel/random/boot_id").read_text().strip(),
                       executable, command_line, namespaces)
        except (OSError, ValueError, IndexError, StopIteration) as exc:
            raise OwnerAdmissionError("owner peer kernel observation failed") from exc


@dataclass(frozen=True)
class OwnerRegistration:
    endpoint: Path
    owner: ProcessIdentity

    def connect(self, *, deadline: float) -> OwnerSession:
        if (not isinstance(deadline, (int, float)) or isinstance(deadline, bool)
                or not math.isfinite(deadline) or deadline <= time.monotonic()):
            raise OwnerAdmissionError("owner deadline is invalid")
        endpoint = self.endpoint
        if not endpoint.is_absolute() or endpoint.is_symlink():
            raise OwnerAdmissionError("owner endpoint must be an absolute socket")
        try:
            info = endpoint.lstat()
            if (not stat.S_ISSOCK(info.st_mode) or stat.S_IMODE(info.st_mode) != 0o600
                    or info.st_uid != self.owner.uid):
                raise OwnerAdmissionError("owner endpoint permission or ownership mismatch")
            connection = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
            try:
                connection.settimeout(min(30.0, deadline - time.monotonic()))
                connection.connect(str(endpoint))
                pid, uid, _gid = struct.unpack("3i", connection.getsockopt(
                    socket.SOL_SOCKET, socket.SO_PEERCRED, struct.calcsize("3i")))
                if (pid != self.owner.pid or uid != self.owner.uid
                        or ProcessIdentity.observe(pid) != self.owner):
                    raise OwnerAdmissionError("owner socket peer does not match registration")
                return OwnerSession(connection, self.owner, deadline)
            except BaseException:
                connection.close()
                raise
        except (OSError, ValueError) as exc:
            raise OwnerAdmissionError("owner connection or deadline failed") from exc


def _unique_object(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise OwnerAdmissionError("owner response has duplicate fields")
        result[key] = value
    return result


def _invalid_constant(_value: str) -> None:
    raise OwnerAdmissionError("owner response has a non-finite number")


class OwnerSession:
    """One finite authenticated connection; uncertain delivery is never retried."""

    def __init__(self, connection: socket.socket, owner: ProcessIdentity, deadline: float) -> None:
        self._connection = connection
        self.owner = owner
        self.deadline = deadline
        self.delivery_uncertain = False
        self.closed = False
        self._request_deadline: float | None = None

    def __enter__(self) -> OwnerSession:
        return self

    def __exit__(self, _kind: type[BaseException] | None, _error: BaseException | None,
                 _traceback: TracebackType | None) -> None:
        self.close()

    def _timeout(self) -> None:
        deadline = self.deadline if self._request_deadline is None else self._request_deadline
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            raise OwnerAdmissionError("owner deadline exhausted")
        self._connection.settimeout(min(60.0 if self._request_deadline is not None else 30.0, remaining))

    def _receive(self, size: int) -> bytes:
        chunks = bytearray()
        while len(chunks) < size:
            self._timeout()
            part = self._connection.recv(size - len(chunks))
            if not part:
                raise OwnerAdmissionError("owner response ended before complete frame")
            chunks.extend(part)
        return bytes(chunks)

    def request(self, payload: dict[str, Any], *, response_timeout_seconds: int = 30) -> dict[str, Any]:
        if self.closed or self.delivery_uncertain:
            raise OwnerAdmissionError("owner session is closed or delivery is uncertain")
        if type(response_timeout_seconds) is not int or not 1 <= response_timeout_seconds <= 60:
            raise OwnerAdmissionError("owner response window is invalid")
        self._request_deadline = min(self.deadline, time.monotonic() + response_timeout_seconds)
        try:
            raw = json.dumps(payload, separators=(",", ":"), allow_nan=False).encode("utf-8")
        except (ValueError, TypeError) as exc:
            raise OwnerAdmissionError("owner request is not closed JSON") from exc
        if not 0 < len(raw) <= REQUEST_LIMIT:
            raise OwnerAdmissionError("owner request exceeds bounded frame")
        if ProcessIdentity.observe(self.owner.pid) != self.owner:
            raise OwnerAdmissionError("owner peer changed before request")
        self.delivery_uncertain = True
        try:
            self._timeout()
            self._connection.sendall(struct.pack("!I", len(raw)) + raw)
            size, = struct.unpack("!I", self._receive(4))
            if not 0 < size <= RESPONSE_LIMIT:
                raise OwnerAdmissionError("owner response frame is out of bounds")
            response = json.loads(self._receive(size), object_pairs_hook=_unique_object,
                                  parse_constant=_invalid_constant)
            if not isinstance(response, dict):
                raise OwnerAdmissionError("owner response must be a JSON object")
            if ProcessIdentity.observe(self.owner.pid) != self.owner:
                raise OwnerAdmissionError("owner peer changed during response")
            if self._request_deadline is None or time.monotonic() >= self._request_deadline:
                raise OwnerAdmissionError("owner deadline exhausted before authenticated completion")
            self.delivery_uncertain = False
            return response
        except (OSError, UnicodeError, ValueError) as exc:
            raise OwnerAdmissionError("owner response or deadline is unproven") from exc

    def close(self) -> None:
        if not self.closed:
            self._connection.close()
            self.closed = True
