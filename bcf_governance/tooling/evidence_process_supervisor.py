"""Ephemeral Linux child-tree custody for one evidence command, not a scheduler."""
from __future__ import annotations

from contextlib import contextmanager
import ctypes
import json
import locale
import os
from pathlib import Path
import selectors
import signal
import socket
import subprocess
import sys
import time
import threading


class OwnedProcessError(RuntimeError):
    """Kernel child custody or its terminal observation is unresolved."""


_native_lease = None
_native_lease_binding = threading.Lock()


@contextmanager
def native_lease_custody(descriptor):
    """Bind the acquired lease to native commands in this invoking thread."""
    global _native_lease
    if not _native_lease_binding.acquire(blocking=False):
        raise OwnedProcessError('native lease binding is already active in this process')
    try:
        identity = os.fstat(descriptor)
        _native_lease = (descriptor, threading.get_ident(), identity.st_dev, identity.st_ino)
        yield
    finally:
        _native_lease = None
        _native_lease_binding.release()


def _send(connection, value):
    connection.sendall(json.dumps(value, separators=(',', ':')).encode() + b'\n')


def _receive(connection, deadline):
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
    return json.loads(line)


def _terminal_result(value, supervisor_pid):
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


def _observe(process, connection, selector, buffers, deadline):
    data = b''
    terminal = None
    while True:
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


def run_owned_command(command, *, cwd, env, timeout_seconds, cleanup_seconds):
    """Hold the supervisor unreaped until its child proof and both output EOFs."""
    lease = _native_lease
    if lease is not None and lease[1] != threading.get_ident():
        raise OwnedProcessError('native command cannot consume another thread native lease')
    lease_arguments = [] if lease is None else [str(lease[0]), str(lease[2]), str(lease[3])]
    inherited_descriptors = () if lease is None else (lease[0],)
    start = time.monotonic()
    body_deadline = start + timeout_seconds
    connection, inherited = socket.socketpair()
    process = None
    quiescent = False
    buffers = {'stdout': [], 'stderr': []}
    try:
        try:
            process = subprocess.Popen(
                [sys.executable, '-I', str(Path(__file__).resolve()), str(inherited.fileno()),
                 str(body_deadline), str(cleanup_seconds), *lease_arguments],
                cwd=cwd, env=env, pass_fds=(inherited.fileno(), *inherited_descriptors),
                stdout=subprocess.PIPE, stderr=subprocess.PIPE, start_new_session=True,
            )
        except OSError as exc:
            return subprocess.CompletedProcess(command, 126, '',
                f'bcf execution infrastructure failure: {exc}')
        inherited.close()
        ready = _receive(connection, body_deadline)
        expected_ready = {'type': 'ready', 'supervisor_pid': process.pid}
        if lease is not None:
            expected_ready['native_lease'] = [lease[0], lease[2], lease[3]]
        if (not isinstance(ready, dict) or type(ready.get('supervisor_pid')) is not int
                or ready != expected_ready):
            raise OwnedProcessError('child supervisor could not establish exclusive custody')
        _send(connection, {'command': command})
        connection.setblocking(False)
        with selectors.DefaultSelector() as selector:
            selector.register(connection, selectors.EVENT_READ, 'control')
            for name in buffers:
                selector.register(getattr(process, name), selectors.EVENT_READ, name)
            try:
                result = _observe(process, connection, selector, buffers,
                                  body_deadline + cleanup_seconds)
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
                stream.close()


def _subreaper():
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


def _reap(command):
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


def _kill_owned_children():
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


def _supervise(connection, body_deadline, cleanup_seconds, native_lease=None):
    _subreaper()
    ready = {'type': 'ready', 'supervisor_pid': os.getpid()}
    if native_lease is not None:
        descriptor, device, inode = native_lease
        identity = os.fstat(descriptor)
        if (identity.st_dev, identity.st_ino) != (device, inode):
            raise OwnedProcessError('inherited native lease identity is contradictory')
        ready['native_lease'] = list(native_lease)
    _send(connection, ready)
    request = _receive(connection, body_deadline)
    command = request['command']
    if not isinstance(command, list) or not command or not all(isinstance(x, str) for x in command):
        raise OwnedProcessError('invalid owned command')
    if time.monotonic() >= body_deadline:
        raise OwnedProcessError('command deadline expired before allocation')
    try:
        process = subprocess.Popen(command, start_new_session=True, close_fds=True)
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


def _retain_native_custody():
    """Observe only: exhausted cleanup grants no further signalling authority."""
    while True:
        try:
            os.waitid(os.P_ALL, 0, os.WEXITED | os.WNOHANG)
        except ChildProcessError:
            return
        except OSError:
            # An uncertain observation cannot establish an empty child tree.
            pass
        time.sleep(0.05)


if __name__ == '__main__':
    with socket.socket(fileno=int(sys.argv[1])) as _connection:
        try:
            _lease = tuple(int(value) for value in sys.argv[4:]) or None
            _supervise(_connection, float(sys.argv[2]), int(sys.argv[3]), _lease)
        except BaseException:
            # Keep the inherited open-file-description lock until kernel proof
            # of no owned children. A failed report remains failure at the caller.
            if len(sys.argv) > 4:
                _retain_native_custody()
            sys.exit(126)
