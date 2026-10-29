"""Ephemeral Linux child-tree custody for one evidence command, not a scheduler."""
from __future__ import annotations

import ctypes
import fcntl
from collections.abc import Callable
import fcntl
import re
import stat
import json
import locale
import math
import os
from pathlib import Path
import selectors
import signal
import socket
import subprocess
import sys
import time
from threading import Event
from typing import Any


class _CancellationRequested(RuntimeError):
    """A trusted controller requested bounded cancellation."""


class OwnedProcessError(RuntimeError):
    """Kernel child custody or its terminal observation is unresolved."""


def _send(connection: socket.socket, value: dict[str, Any]) -> None:
    connection.sendall(json.dumps(value, separators=(',', ':')).encode() + b'\n')


def _receive(connection: socket.socket, deadline: float) -> dict[str, Any]:
    data = b''
    while b'\n' not in data:
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            raise OwnedProcessError('supervisor readiness exhausted the command deadline')
        connection.settimeout(remaining)
        chunk = connection.recv(65536)
        if not chunk:
            raise OwnedProcessError('supervisor channel closed without a message')
        data += chunk
        if len(data) > 4 * 1024 * 1024:
            raise OwnedProcessError('supervisor message exceeds the transport bound')
    line, remainder = data.split(b'\n', 1)
    if remainder:
        raise OwnedProcessError('unexpected extra supervisor message')
    value = json.loads(line)
    if not isinstance(value, dict):
        raise OwnedProcessError("supervisor frame must be an object")
    return value


def _terminal_result(value: Any, supervisor_pid: int) -> dict[str, Any]:
    if (not isinstance(value, dict)
            or type(value.get('supervisor_pid')) is not int
            or value['supervisor_pid'] != supervisor_pid
            or value.get('quiescent') is not True or type(value.get('returncode')) is not int):
        raise OwnedProcessError('child cleanup completion is missing or unauthenticated')
    if value.get('type') == 'not-started':
        if (value.get('command_pid') is not None or 'command_pid' not in value
                or value.get('reason') != 'launch-error' or value['returncode'] != 126
                or not isinstance(value.get('detail'), str)):
            raise OwnedProcessError('unstarted child cleanup completion is unauthenticated')
    elif (value.get('type') != 'complete' or type(value.get('command_pid')) is not int
            or value['command_pid'] <= 0
            or value.get('reason') not in {'exit', 'timeout', 'descendants', 'cancelled'}):
        raise OwnedProcessError('exact child cleanup completion is unauthenticated')
    return value


def _observe(process: subprocess.Popen[bytes], connection: socket.socket, selector: selectors.BaseSelector, buffers: dict[str, list[bytes]], deadline: float, cancel_event: Event | None = None) -> dict[str, Any]:
    data = b''
    terminal = None
    while True:
        if cancel_event is not None and cancel_event.is_set():
            raise _CancellationRequested()
        ended = os.waitid(os.P_PID, process.pid, os.WEXITED | os.WNOHANG | os.WNOWAIT)
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            raise OwnedProcessError('child cleanup exceeded its composed command deadline')
        if ended is not None and not selector.get_map():
            if data:
                raise OwnedProcessError('partial extra child cleanup frame contradicts completion')
            value = _terminal_result(terminal, process.pid)
            if process.wait(timeout=0) != 0:
                raise OwnedProcessError('supervisor failed after child cleanup')
            return value
        for key, _events in selector.select(min(0.02, remaining)):
            chunk = os.read(key.fd, 65536)
            if not chunk:
                selector.unregister(key.fileobj)
                continue
            if key.data != 'control':
                buffers[key.data].append(chunk)
                continue
            data += chunk
            if len(data) > 65536:
                raise OwnedProcessError('child cleanup message exceeds its bound')
            while b'\n' in data:
                line, data = data.split(b'\n', 1)
                if terminal is not None:
                    raise OwnedProcessError('duplicate child cleanup completion')
                terminal = _terminal_result(json.loads(line), process.pid)


def _bootstrap_bindings(descriptors: tuple[int, ...]) -> list[list[int]]:
    """Only a source directory and its mount/user namespace may reach bootstrap.

    Original leases, ordinary files and sockets never enter the workload.
    NS_GET_NSTYPE is the Linux nsfs ioctl, not caller-provided type metadata.
    """
    if not descriptors:
        return []
    if len(descriptors) != 3 or len(set(descriptors)) != 3:
        raise OwnedProcessError('bootstrap requires three distinct source capabilities')
    bindings = []
    for offset, descriptor in enumerate(descriptors):
        if type(descriptor) is not int or descriptor <= 2:
            raise OwnedProcessError('bootstrap capability descriptor is invalid')
        info = os.fstat(descriptor)
        if offset == 0:
            if not stat.S_ISDIR(info.st_mode):
                raise OwnedProcessError('bootstrap source is not a directory')
            kind = 0
        else:
            kind = fcntl.ioctl(descriptor, 0xb703)
            if kind != (0x00020000 if offset == 1 else 0x10000000):
                raise OwnedProcessError('bootstrap namespace type is incorrect')
        bindings.append([descriptor, info.st_dev, info.st_ino, kind])
    return bindings


def run_owned_command(command: list[str], *, cwd: Path, env: dict[str, str] | None, timeout_seconds: float, cleanup_seconds: float, lease_descriptors: tuple[int, ...] = (), cancel_event: Event | None = None, bootstrap_descriptors: tuple[int, ...] = (), on_supervisor_ready: Callable[[int], None] | None = None, absolute_body_deadline: float | None = None, absolute_cleanup_deadline: float | None = None) -> subprocess.CompletedProcess[str]:
    """Hold the supervisor unreaped until its child proof and both output EOFs."""
    for value in (timeout_seconds, cleanup_seconds):
        if type(value) not in (int, float) or not math.isfinite(value) or value <= 0:
            raise OwnedProcessError("command and cleanup deadlines must be finite positive seconds")
    leases: list[list[int]] = []
    for descriptor in lease_descriptors:
        if type(descriptor) is not int or descriptor <= 2:
            raise OwnedProcessError("native lease descriptor is invalid")
        identity = os.fstat(descriptor)
        if (not stat.S_ISREG(identity.st_mode)
                or not re.search(r"\bFLOCK\s+ADVISORY\s+WRITE\b",
                                 Path(f"/proc/self/fdinfo/{descriptor}").read_text())):
            raise OwnedProcessError("native lease is not a regular locked descriptor")
        leases.append([descriptor, identity.st_dev, identity.st_ino])
    if len(set(lease_descriptors)) != len(lease_descriptors):
        raise OwnedProcessError("native lease descriptors are duplicated")
    bootstrap = _bootstrap_bindings(bootstrap_descriptors)
    if set(lease_descriptors).intersection(bootstrap_descriptors):
        raise OwnedProcessError('original leases cannot become bootstrap inputs')
    lease_arguments = [str(value) for lease in leases for value in lease]
    start = time.monotonic()
    body_deadline = start + timeout_seconds
    if (absolute_body_deadline is None) != (absolute_cleanup_deadline is None):
        raise OwnedProcessError('both original absolute deadlines are required together')
    if absolute_body_deadline is not None and absolute_cleanup_deadline is not None:
        if (any(type(value) not in (int, float) or not math.isfinite(value)
                for value in (absolute_body_deadline, absolute_cleanup_deadline))
                or not start < absolute_body_deadline < absolute_cleanup_deadline):
            raise OwnedProcessError('original absolute execution window is invalid or expired')
        body_deadline = min(body_deadline, absolute_body_deadline)
        # Both native termination and descendant/EOF cleanup share this cap.
        cleanup_seconds = min(body_deadline + cleanup_seconds,
                              absolute_cleanup_deadline) - body_deadline
    connection, inherited = socket.socketpair()
    process = None
    quiescent = False
    buffers: dict[str, list[bytes]] = {'stdout': [], 'stderr': []}
    try:
        try:
            process = subprocess.Popen(
                [sys.executable, '-I', str(Path(__file__).resolve()), str(inherited.fileno()),
                 str(body_deadline), str(cleanup_seconds), *lease_arguments],
                cwd=cwd, env=env, pass_fds=(inherited.fileno(), *lease_descriptors, *bootstrap_descriptors),
                stdout=subprocess.PIPE, stderr=subprocess.PIPE, start_new_session=True,
            )
        except OSError as exc:
            return subprocess.CompletedProcess(command, 126, '',
                f'bcf execution infrastructure failure: {exc}')
        inherited.close()
        ready = _receive(connection, body_deadline)
        expected_ready: dict[str, Any] = {'type': 'ready', 'supervisor_pid': process.pid}
        if leases:
            expected_ready['native_leases'] = leases
        if (not isinstance(ready, dict) or type(ready.get('supervisor_pid')) is not int
                or ready != expected_ready):
            raise OwnedProcessError('child supervisor could not establish exclusive custody')
        if on_supervisor_ready is not None:
            on_supervisor_ready(process.pid)
        declaration: dict[str, Any] = {'command': command}
        if bootstrap:
            declaration['bootstrap_inputs'] = bootstrap
        _send(connection, declaration)
        connection.setblocking(False)
        with selectors.DefaultSelector() as selector:
            selector.register(connection, selectors.EVENT_READ, 'control')
            for name in buffers:
                selector.register(getattr(process, name), selectors.EVENT_READ, name)
            try:
                result = _observe(process, connection, selector, buffers,
                                  body_deadline + cleanup_seconds, cancel_event)
                quiescent = True
            except _CancellationRequested:
                recovery_deadline = min(body_deadline + cleanup_seconds,
                                        time.monotonic() + cleanup_seconds)
                remaining = recovery_deadline - time.monotonic()
                if remaining <= 0:
                    raise OwnedProcessError('no declared cleanup budget remains') from None
                connection.settimeout(remaining)
                _send(connection, {'cancel': True})
                connection.setblocking(False)
                result = _observe(process, connection, selector, buffers, recovery_deadline)
                quiescent = True
            except BaseException:
                # Cancellation uses the same owner; never kill an unknown child tree.
                try:
                    recovery_deadline = min(body_deadline + cleanup_seconds,
                                            time.monotonic() + cleanup_seconds)
                    remaining = recovery_deadline - time.monotonic()
                    if remaining <= 0:
                        raise OwnedProcessError('no declared cleanup budget remains')
                    connection.settimeout(remaining)
                    _send(connection, {'cancel': True})
                    connection.setblocking(False)
                    _observe(process, connection, selector, buffers, recovery_deadline)
                except BaseException as exc:
                    raise OwnedProcessError('interrupted child cleanup remains unresolved') from exc
                raise
        if result['reason'] == 'launch-error':
            return subprocess.CompletedProcess(command, 126, '',
                'bcf execution infrastructure failure: ' + result['detail'])
        if result['reason'] != 'exit':
            reason = {'timeout': 'command timed out', 'descendants': 'command left live descendants',
                      'cancelled': 'command was interrupted'}[result['reason']]
            return subprocess.CompletedProcess(command, 126, '',
                'bcf execution infrastructure failure: ' + reason)
        # Match subprocess text-mode decoding and universal newline semantics.
        encoding = 'utf-8' if sys.flags.utf8_mode else locale.getencoding()
        output = [b''.join(buffers[name]).decode(encoding).replace('\r\n', '\n').replace('\r', '\n')
                  for name in ('stdout', 'stderr')]
        return subprocess.CompletedProcess(command, result['returncode'], *output)
    except OwnedProcessError:
        raise
    except UnicodeError as exc:
        if quiescent:
            raise
        raise OwnedProcessError('child cleanup could not be authenticated') from exc
    except Exception as exc:
        raise OwnedProcessError('child cleanup could not be authenticated') from exc
    finally:
        inherited.close()
        connection.close()
        if process is not None:
            for stream in (process.stdout, process.stderr):
                if stream is not None:
                    stream.close()


def _subreaper() -> None:
    if signal.getsignal(signal.SIGCHLD) != signal.SIG_DFL:
        raise OwnedProcessError('supervisor requires default SIGCHLD')
    if len(list(Path('/proc/self/task').iterdir())) != 1:
        raise OwnedProcessError('supervisor requires an exclusive single-threaded waiter')
    libc = ctypes.CDLL(None, use_errno=True)
    enabled = ctypes.c_int()
    # Linux uapi/linux/prctl.h: PR_SET_CHILD_SUBREAPER=36, PR_GET_CHILD_SUBREAPER=37.
    if (libc.prctl(36, 1, 0, 0, 0) != 0
            or libc.prctl(37, ctypes.byref(enabled), 0, 0, 0) != 0 or enabled.value != 1):
        raise OwnedProcessError('kernel child subreaper custody is unavailable')


def _reap(command: subprocess.Popen[bytes]) -> bool:
    """ECHILD is kernel proof of an empty owned tree, including adopted orphans."""
    while True:
        try:
            result = os.waitid(os.P_ALL, 0, os.WEXITED | os.WNOHANG)
        except ChildProcessError:
            return True
        if result is None:
            return False
        if result.si_pid == command.pid:
            command.returncode = (result.si_status if result.si_code == os.CLD_EXITED
                                  else -result.si_status)


def _kill_owned_children() -> None:
    # This supervisor has exactly one thread and owns every listed unreaped child.
    # Unlike a host-wide PID scan, foreign process births cannot affect this list.
    raw = Path(f'/proc/self/task/{os.getpid()}/children').read_text()
    children = [int(pid) for pid in raw.split()]
    if not children:
        raise OwnedProcessError('kernel child inventory contradicted live wait ownership')
    for pid in children:
        os.waitid(os.P_PID, pid, os.WEXITED | os.WNOHANG | os.WNOWAIT)
        # Exclusive waiting holds this child identity; no PID can recycle here.
        try:
            os.kill(pid, signal.SIGKILL)
        except ProcessLookupError:
            pass


def _supervise(connection: socket.socket, body_deadline: float, cleanup_seconds: float, native_leases: tuple[tuple[int, int, int], ...] = ()) -> None:
    _subreaper()
    ready: dict[str, Any] = {'type': 'ready', 'supervisor_pid': os.getpid()}
    for descriptor, device, inode in native_leases:
        identity = os.fstat(descriptor)
        if (descriptor <= 2 or descriptor == connection.fileno()
                or not stat.S_ISREG(identity.st_mode)
                or (identity.st_dev, identity.st_ino) != (device, inode)
                or not re.search(r"\bFLOCK\s+ADVISORY\s+WRITE\b",
                                 Path(f"/proc/self/fdinfo/{descriptor}").read_text())):
            raise OwnedProcessError("inherited original native lease is not authenticated")
    if native_leases:
        ready['native_leases'] = [list(row) for row in native_leases]
    _send(connection, ready)
    request = _receive(connection, body_deadline)
    if set(request) not in ({'command'}, {'command', 'bootstrap_inputs'}):
        raise OwnedProcessError('owned command declaration has unexpected fields')
    bootstrap = request.get('bootstrap_inputs', [])
    if (type(bootstrap) is not list or any(type(row) is not list or len(row) != 4
            or any(type(value) is not int for value in row) for row in bootstrap)):
        raise OwnedProcessError('bootstrap descriptor declaration is malformed')
    bootstrap_descriptors = tuple(row[0] for row in bootstrap)
    if _bootstrap_bindings(bootstrap_descriptors) != bootstrap:
        raise OwnedProcessError('inherited bootstrap capabilities changed')
    if {row[0] for row in native_leases}.intersection(bootstrap_descriptors):
        raise OwnedProcessError('original leases cannot enter the workload')
    command = request['command']
    if not isinstance(command, list) or not command or not all(isinstance(x, str) for x in command):
        raise OwnedProcessError('invalid owned command')
    if time.monotonic() >= body_deadline:
        raise OwnedProcessError('command deadline expired before allocation')
    try:
        process = subprocess.Popen(command, start_new_session=True, close_fds=True, pass_fds=bootstrap_descriptors)
    except OSError as exc:
        try:
            os.waitid(os.P_ALL, 0, os.WEXITED | os.WNOHANG)
        except ChildProcessError:
            _send(connection, {'type': 'not-started', 'supervisor_pid': os.getpid(),
                'command_pid': None, 'quiescent': True, 'returncode': 126,
                'reason': 'launch-error', 'detail': str(exc)})
            return
        raise OwnedProcessError('failed exec left unresolved child custody') from exc
    connection.setblocking(False)
    reason = 'exit'
    cleanup_deadline = None
    while True:
        empty = _reap(process)
        if empty:
            if process.returncode is None:
                raise OwnedProcessError('exact command termination was not observed')
            if reason == 'exit' and time.monotonic() >= body_deadline:
                reason = 'timeout'
            _send(connection, {'type': 'complete', 'supervisor_pid': os.getpid(),
                'command_pid': process.pid, 'quiescent': True,
                'returncode': process.returncode, 'reason': reason})
            return
        if cleanup_deadline is None:
            try:
                message = connection.recv(65536)
            except BlockingIOError:
                message = None
            if message is not None:
                reason = 'cancelled'
            elif process.returncode is not None:
                reason = 'descendants'
            elif time.monotonic() >= body_deadline:
                reason = 'timeout'
            if reason != 'exit':
                cleanup_deadline = min(body_deadline + cleanup_seconds,
                                       time.monotonic() + cleanup_seconds)
        if cleanup_deadline is not None:
            if time.monotonic() >= cleanup_deadline:
                raise OwnedProcessError('owned child cleanup deadline exhausted')
            _kill_owned_children()
        time.sleep(0.005)


def _retain_native_custody() -> None:
    """Observe only after the cleanup budget; never extend signalling authority."""
    while True:
        try:
            os.waitid(os.P_ALL, 0, os.WEXITED | os.WNOHANG)
        except ChildProcessError:
            return
        except OSError:
            pass
        time.sleep(0.05)


if __name__ == '__main__':
    with socket.socket(fileno=int(sys.argv[1])) as _connection:
        try:
            if (len(sys.argv) - 4) % 3:
                raise OwnedProcessError('inherited native lease binding is incomplete')
            _leases = tuple((int(sys.argv[offset]), int(sys.argv[offset + 1]), int(sys.argv[offset + 2]))
                            for offset in range(4, len(sys.argv), 3))
            _supervise(_connection, float(sys.argv[2]), float(sys.argv[3]), _leases)
        except BaseException:
            if len(sys.argv) > 4:
                _retain_native_custody()
            sys.exit(126)
