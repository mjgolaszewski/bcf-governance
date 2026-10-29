"""Keep original native lease FDs through kernel and independent-owner cleanup.

The installed trusted controller owns the private control channel. Candidate
stdout and candidate-selected JSON never authorize release. Unknown controller,
process or owner cleanup leaves an observable keeper holding the original OFD.
This module is not an issuer implementation or a complete invocation backend.
"""
from __future__ import annotations

from collections.abc import Mapping
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import re
import select
import socket
import stat
import struct
import subprocess
import sys
from threading import Event, Thread
import time
from typing import Any

MAX_FRAME = 64 * 1024 * 1024


class LeaseCustodyError(RuntimeError):
    """The original lease cannot be released from the available observations."""


def _send(connection: socket.socket, value: Mapping[str, Any]) -> None:
    raw = json.dumps(value, separators=(",", ":"), allow_nan=False).encode("utf-8")
    if not 0 < len(raw) <= MAX_FRAME:
        raise LeaseCustodyError("keeper control frame exceeds its bound")
    connection.sendall(struct.pack("!I", len(raw)) + raw)


def _read(connection: socket.socket, count: int) -> bytes:
    data = bytearray()
    while len(data) < count:
        chunk = connection.recv(count - len(data))
        if not chunk:
            raise EOFError("keeper control channel closed")
        data.extend(chunk)
    return bytes(data)


def _receive(connection: socket.socket) -> dict[str, Any]:
    length, = struct.unpack("!I", _read(connection, 4))
    if not 0 < length <= MAX_FRAME:
        raise LeaseCustodyError("keeper control frame exceeds its bound")
    value = json.loads(_read(connection, length))
    if not isinstance(value, dict):
        raise LeaseCustodyError("keeper control frame is not an object")
    return value


def _journal(root: Path, state: str, metadata: Mapping[str, Any]) -> None:
    path = root / (state + ".json")
    descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
    with os.fdopen(descriptor, "w") as stream:
        json.dump(dict(metadata), stream, sort_keys=True, allow_nan=False)
        stream.write("\n")
        stream.flush()
        os.fsync(stream.fileno())
    directory = os.open(root, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    try:
        os.fsync(directory)
    finally:
        os.close(directory)


def _load_core(expected_digest: str) -> Any:
    path = Path(__file__).with_name("evidence_process_supervisor.py")
    if hashlib.sha256(path.read_bytes()).hexdigest() != expected_digest:
        raise LeaseCustodyError("installed native supervisor changed")
    spec = importlib.util.spec_from_file_location("bcf_installed_guardian_core", path)
    if spec is None or spec.loader is None:
        raise LeaseCustodyError("installed native supervisor is unavailable")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module




class ExecutionLeaseKeeper:
    """A separate trusted keeper, never a candidate registration mechanism."""

    def __init__(self, *, lease_descriptors: tuple[int, ...], context_digest: str | None = None,
                 evidence_root: Path, timeout_seconds: int, cleanup_seconds: int,
                 protected_budget_owner: Any = None,
                 bootstrap_descriptors: tuple[int, ...] = ()) -> None:
        from .evidence_external_custody import require_current_external_custodian

        # A local child of a budgeted controller would die with that controller's
        # native kill tree. Require the separately registered outside coordinator.
        require_current_external_custodian(protected_budget_owner)
        if (not lease_descriptors or (context_digest is not None
                and (type(context_digest) is not str
                     or not re.fullmatch("[0-9a-f]{64}", context_digest)))):
            raise LeaseCustodyError("original leases and actual context digest are required")
        if (type(timeout_seconds) is not int or not 1 <= timeout_seconds <= 21600
                or type(cleanup_seconds) is not int or not 1 <= cleanup_seconds <= 300):
            raise LeaseCustodyError("keeper budgets must be finite positive seconds")
        info = evidence_root.lstat()
        if (not evidence_root.is_absolute() or evidence_root.is_symlink()
                or not stat.S_ISDIR(info.st_mode) or info.st_uid != os.getuid()
                or stat.S_IMODE(info.st_mode) != 0o700):
            raise LeaseCustodyError("keeper evidence root is not privately owned")
        bindings = []
        for descriptor in lease_descriptors:
            lease = os.fstat(descriptor)
            if descriptor <= 2 or not stat.S_ISREG(lease.st_mode):
                raise LeaseCustodyError("original lease descriptor is invalid")
            bindings.append([descriptor, lease.st_dev, lease.st_ino])
        if len(set(lease_descriptors)) != len(lease_descriptors):
            raise LeaseCustodyError("original lease descriptors are duplicated")
        self.context_digest = context_digest
        self.deadline = time.monotonic() + timeout_seconds + cleanup_seconds
        self.connection, inherited = socket.socketpair()
        core_digest = hashlib.sha256(Path(__file__).with_name("evidence_process_supervisor.py").read_bytes()).hexdigest()
        core = _load_core(core_digest)
        core._bootstrap_bindings(bootstrap_descriptors)
        command = [sys.executable, "-I", str(Path(__file__).resolve()), str(inherited.fileno()),
                   str(evidence_root), context_digest if context_digest is not None else "-", str(timeout_seconds), str(cleanup_seconds),
                   core_digest, json.dumps(bindings, separators=(",", ":")),
                   json.dumps(bootstrap_descriptors, separators=(",", ":"))]
        try:
            self.process = subprocess.Popen(command, pass_fds=(inherited.fileno(), *lease_descriptors, *bootstrap_descriptors),
                                            close_fds=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        except BaseException:
            self.connection.close()
            raise
        finally:
            inherited.close()
        self.connection.settimeout(30)
        ready = _receive(self.connection)
        if ready != {"state": "ready", "pid": self.process.pid, "context_digest": context_digest}:
            raise LeaseCustodyError("keeper startup identity is unproven; retain original leases")
        self.started = False
        self.released = False

    def start(self, command: list[str], *, cwd: Path, environment: dict[str, str]) -> None:
        if self.started:
            raise LeaseCustodyError("keeper command may only start once")
        if not command or any(type(value) is not str for value in command):
            raise LeaseCustodyError("keeper command is not a closed argv")
        _send(self.connection, {"operation": "start", "command": command,
                                "cwd": str(cwd), "environment": environment})
        if _receive(self.connection) != {"state": "started"}:
            raise LeaseCustodyError("keeper command start is unproven")
        self.started = True

    def bind_actual_context(self, context_digest: str) -> None:
        """Bind once AFTER actual held-peer birth; pending custody grants nothing."""
        if (not self.started or self.released or self.context_digest is not None
                or type(context_digest) is not str
                or re.fullmatch("[0-9a-f]{64}", context_digest) is None):
            raise LeaseCustodyError("actual keeper context cannot be installed or replaced")
        _send(self.connection, {"operation": "bind_context", "context_digest": context_digest})
        if _receive(self.connection) != {"state": "context_bound", "context_digest": context_digest}:
            raise LeaseCustodyError("actual keeper context binding is unproven")
        self.context_digest = context_digest

    def status(self) -> dict[str, Any]:
        _send(self.connection, {"operation": "status"})
        result = _receive(self.connection)
        if result.get("state") not in {"pending", "native_closed", "HOLD"}:
            raise LeaseCustodyError("keeper terminal state is unproven")
        return result

    def cancel(self) -> None:
        _send(self.connection, {"operation": "cancel"})
        if _receive(self.connection) != {"state": "cancelling"}:
            raise LeaseCustodyError("keeper cancellation is unproven")

    def release_after_owner_cleanup(self, owners: Any) -> None:
        from .evidence_owner_control import OwnerControlPair

        if type(owners) is not OwnerControlPair:
            raise LeaseCustodyError("authenticated independent owner channels are required")
        if self.context_digest is None:
            raise LeaseCustodyError("pending lease custody has no actual execution context")
        issuer, custody = owners.verified_cleanup(self.context_digest)
        _send(self.connection, {"operation": "release", "context_digest": self.context_digest,
                                "issuer": issuer, "custody": custody})
        if _receive(self.connection) != {"state": "released"}:
            raise LeaseCustodyError("keeper has not released original lease custody")
        self.connection.close()
        stdout, stderr = self.process.communicate(timeout=30)
        if self.process.returncode != 0 or stdout or stderr:
            raise LeaseCustodyError("keeper exit and both output EOFs are unproven")
        self.released = True

    def disconnect(self) -> None:
        """Dropping control is a HOLD, never an implicit release or parent wait."""
        self.connection.close()


def _keeper(connection: socket.socket, root: Path, context_digest: str | None,
            timeout_seconds: int, cleanup_seconds: int, core_digest: str,
            leases: list[list[int]], bootstrap_descriptors: tuple[int, ...] = ()) -> None:
    core = _load_core(core_digest)
    core._bootstrap_bindings(bootstrap_descriptors)
    for descriptor, device, inode in leases:
        info = os.fstat(descriptor)
        if (not stat.S_ISREG(info.st_mode) or (info.st_dev, info.st_ino) != (device, inode)
                or not re.search(r"\bFLOCK\s+ADVISORY\s+WRITE\b",
                                 Path(f"/proc/self/fdinfo/{descriptor}").read_text())):
            raise LeaseCustodyError("keeper does not hold the inherited original native lease")
    metadata = {"pid": os.getpid(), "context_digest": context_digest,
                "native_leases": leases, "provider_authority": False}
    _journal(root, "00-started", metadata)
    _send(connection, {"state": "ready", "pid": os.getpid(), "context_digest": context_digest})
    request = _receive(connection)
    if set(request) != {"operation", "command", "cwd", "environment"} or request["operation"] != "start":
        raise LeaseCustodyError("keeper command declaration is invalid")
    command, cwd, environment = request["command"], Path(request["cwd"]), request["environment"]
    if (not isinstance(command, list) or not command or any(type(x) is not str for x in command)
            or not cwd.is_absolute() or not isinstance(environment, dict)
            or any(type(k) is not str or type(v) is not str for k, v in environment.items())):
        raise LeaseCustodyError("keeper command declaration is invalid")
    command_digest = hashlib.sha256(json.dumps(command, separators=(",", ":")).encode()).hexdigest()
    _journal(root, "01-command", {**metadata, "argv_sha256": command_digest})
    cancel = Event()
    done = Event()
    result: dict[str, Any] = {}

    def run() -> None:
        try:
            observed = core.run_owned_command(command, cwd=cwd, env=environment,
                timeout_seconds=timeout_seconds, cleanup_seconds=cleanup_seconds,
                lease_descriptors=tuple(row[0] for row in leases), cancel_event=cancel,
                bootstrap_descriptors=bootstrap_descriptors,
                on_supervisor_ready=lambda pid: result.update({"native_supervisor_pid": pid}))
            result.update({"state": "native_closed", "returncode": observed.returncode,
                           "stdout": observed.stdout, "stderr": observed.stderr})
            _journal(root, "02-native-closed", {**metadata, "returncode": observed.returncode,
                                               "kernel_quiescence_and_both_eof": True})
        except BaseException:
            result.update({"state": "HOLD", "reason": "native_cleanup_unproven"})
            _journal(root, "02-native-HOLD", metadata)
        finally:
            done.set()

    worker = Thread(target=run, daemon=False)
    disconnected = False
    try:
        worker.start()
        _send(connection, {"state": "started"})
        while True:
            if not select.select([connection], [], [], 0.2)[0]:
                continue
            request = _receive(connection)
            operation = request.get("operation")
            if operation == "bind_context":
                actual_context = request.get("context_digest")
                if (set(request) != {"operation", "context_digest"}
                        or context_digest is not None or done.is_set()
                        or type(actual_context) is not str
                        or re.fullmatch("[0-9a-f]{64}", actual_context) is None):
                    _send(connection, {"state": "HOLD"})
                    continue
                _journal(root, "01-context-bound", {**metadata, "context_digest": actual_context,
                         "provider_authority": False})
                context_digest = actual_context
                metadata["context_digest"] = actual_context
                _send(connection, {"state": "context_bound", "context_digest": actual_context})
            elif operation == "status" and set(request) == {"operation"}:
                pending: dict[str, Any] = {"state": "pending"}
                if "native_supervisor_pid" in result:
                    pending["native_supervisor_pid"] = result["native_supervisor_pid"]
                _send(connection, result if done.is_set() else pending)
            elif operation == "cancel" and set(request) == {"operation"}:
                cancel.set()
                _send(connection, {"state": "cancelling"})
            elif operation == "release":
                issuer, custody = request.get("issuer"), request.get("custody")
                closed = (context_digest is not None
                          and set(request) == {"operation", "context_digest", "issuer", "custody"}
                          and done.is_set() and result.get("state") == "native_closed"
                          and request.get("context_digest") == context_digest
                          and isinstance(issuer, dict) and isinstance(custody, dict)
                          and issuer.get("role") == "issuer" and custody.get("role") == "custody"
                          and issuer.get("owner_pid") != custody.get("owner_pid")
                          and all(receipt.get("context_digest") == context_digest
                                  for receipt in (issuer, custody)))
                if not closed:
                    _send(connection, {"state": "HOLD"})
                    continue
                # This records authorization only. The caller must still observe
                # keeper exit/reap and EOF, then close its own OFDs and probe the
                # physical fence. A failed response can still leave this keeper HOLD.
                _journal(root, "03-release-authorized", {**metadata, "issuer": issuer,
                         "custody": custody, "keeper_reap_required": True})
                _send(connection, {"state": "released"})
                worker.join()
                return
            else:
                raise LeaseCustodyError("keeper operation is outside its closed protocol")
    except BaseException:
        disconnected = True
        cancel.set()
    finally:
        if disconnected:
            _journal(root, "03-controller-HOLD", metadata)
            # No expiry, lost parent or candidate result may retire these OFDs.
            # Original finite cancellation budget remains enforced by the core.
            while True:
                time.sleep(1)


if __name__ == "__main__":
    try:
        with socket.socket(fileno=int(sys.argv[1])) as _channel:
            _keeper(_channel, Path(sys.argv[2]), None if sys.argv[3] == "-" else sys.argv[3], int(sys.argv[4]),
                    int(sys.argv[5]), sys.argv[6], json.loads(sys.argv[7]),
                    tuple(json.loads(sys.argv[8])) if len(sys.argv) > 8 else ())
    except BaseException:
        # The child already inherited original locked OFDs at process birth.
        # Even pre-start/core/transport failure cannot establish that independent
        # issuer and custody obligations were never staged. Preserve custody.
        try:
            _journal(Path(sys.argv[2]), "00-bootstrap-HOLD",
                     {"pid": os.getpid(), "state": "HOLD",
                      "reason": "bootstrap_or_control_unproven"})
        except BaseException:
            pass  # An unavailable journal cannot authorize descriptor release.
        while True:
            time.sleep(1)
