"""Ephemeral Linux child-tree custody for one evidence command, not a scheduler."""
from __future__ import annotations

from contextlib import contextmanager
import ctypes
import fcntl
import json
import locale
import math
import os
from pathlib import Path
import selectors
import signal
import socket
import stat
import subprocess
import sys
import time
import threading


class OwnedProcessError(RuntimeError):
    """Kernel child custody or its terminal observation is unresolved."""


_native_lease = None
_native_lease_binding = threading.RLock()
# Linux UAPI (linux/fcntl.h), independent of CPython build-header exports.
# Applying and reading these seals on the actual memfd is the kernel proof.
_INPUT_ADD_SEALS = 1033
_INPUT_GET_SEALS = 1034
_INPUT_REQUIRED_SEALS = 0x000F  # SEAL | SHRINK | GROW | WRITE


@contextmanager
def native_lease_custody(descriptor, *, timeout_seconds, cleanup_seconds):
    """Bind the acquired lease to native commands in this invoking thread."""
    global _native_lease
    if not _native_lease_binding.acquire(blocking=False):
        raise OwnedProcessError('native lease binding is already active in this process')
    previous = _native_lease
    try:
        identity = os.fstat(descriptor)
        _native_lease = (descriptor, threading.get_ident(), identity.st_dev, identity.st_ino, previous, timeout_seconds, cleanup_seconds)
        yield
    finally:
        _native_lease = previous
        _native_lease_binding.release()


def run_admitted_command(command, *, unbound_runner=None, **kwargs):
    """Use existing native custody when bound; preserve ordinary unbound runners."""
    lease = _native_lease
    if lease is None:
        runner = subprocess.run if unbound_runner is None else unbound_runner
        return runner(command, **kwargs)
    if lease[1] != threading.get_ident():
        raise OwnedProcessError('native command cannot consume another thread native lease')
    options = dict(kwargs)
    check = options.pop('check', False)
    capture = options.pop('capture_output', False)
    text = options.pop('text', False)
    cwd = options.pop('cwd', None)
    env = options.pop('env', None)
    timeout = options.pop('timeout', None)
    supplied_input = options.pop('input', None)
    if options or capture is not True or type(text) is not bool or type(check) is not bool:
        raise OwnedProcessError('bound native invocation options require explicit custody support')
    input_options = {}
    if supplied_input is not None:
        if text:
            if not isinstance(supplied_input, str):
                raise TypeError('bound text input must be a string')
            encoding = 'utf-8' if sys.flags.utf8_mode else locale.getencoding()
            supplied_input = supplied_input.encode(encoding)
        elif not isinstance(supplied_input, (bytes, bytearray, memoryview)):
            raise TypeError('bound binary input must be bytes-like')
        input_options['input_bytes'] = bytes(supplied_input)
    body = lease[5]
    cleanup = lease[6]
    while lease[4] is not None:
        lease = lease[4]
        body = min(body, lease[5])
        cleanup = min(cleanup, lease[6])
    if timeout is not None:
        if (isinstance(timeout, bool) or not isinstance(timeout, (int, float))
                or (isinstance(timeout, float) and not math.isfinite(timeout)) or timeout <= 0):
            raise OwnedProcessError('bound native timeout must be finite positive seconds')
        body = min(body, timeout)
    result = run_owned_command(command, cwd=cwd, env=env, timeout_seconds=body,
                               cleanup_seconds=cleanup, text=text,
                               timeout_raises=True, raise_launch_errors=True, **input_options)
    if check:
        result.check_returncode()
    return result


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


def _stage_command_input(data, deadline):
    """Seal finite command stdin before allocation without a writable pipe wait."""
    if not isinstance(data, bytes):
        raise TypeError('owned command input requires bytes')
    descriptor = os.memfd_create('bcf-owned-command-input', os.MFD_CLOEXEC | os.MFD_ALLOW_SEALING)
    try:
        offset = 0
        view = memoryview(data)
        while offset < len(view):
            if time.monotonic() >= deadline:
                raise OwnedProcessError('command input deadline expired before allocation')
            written = os.write(descriptor, view[offset:])
            if not written:
                raise OwnedProcessError('command input could not make progress')
            offset += written
        os.lseek(descriptor, 0, os.SEEK_SET)
        seals = _INPUT_REQUIRED_SEALS
        fcntl.fcntl(descriptor, _INPUT_ADD_SEALS, seals)
        if fcntl.fcntl(descriptor, _INPUT_GET_SEALS) & seals != seals:
            raise OwnedProcessError('command input kernel seals are incomplete')
        identity = os.fstat(descriptor)
        return (descriptor, identity.st_dev, identity.st_ino)
    except BaseException:
        os.close(descriptor)
        raise


def run_owned_command(command, *, cwd, env, timeout_seconds, cleanup_seconds,
                      text=True, timeout_raises=False, raise_launch_errors=False, input_bytes=None):
    """Hold the supervisor unreaped until its child proof and both output EOFs."""
    lease = _native_lease
    if lease is not None and lease[1] != threading.get_ident():
        raise OwnedProcessError('native command cannot consume another thread native lease')
    leases = []
    while lease is not None:
        leases.append([lease[0], lease[2], lease[3]])
        lease = lease[4]
    lease_arguments = [str(value) for binding in leases for value in binding]
    inherited_descriptors = tuple(binding[0] for binding in leases)
    start = time.monotonic()
    body_deadline = start + timeout_seconds
    connection, inherited = socket.socketpair()
    process = None
    quiescent = False
    buffers = {'stdout': [], 'stderr': []}
    input_binding = None
    try:
        if input_bytes is not None:
            input_binding = _stage_command_input(input_bytes, body_deadline)
            inherited_descriptors = (*inherited_descriptors, input_binding[0])
            if time.monotonic() >= body_deadline:
                if timeout_raises:
                    raise subprocess.TimeoutExpired(command, timeout_seconds)
                raise OwnedProcessError('command input deadline expired before allocation')
        try:
            process = subprocess.Popen(
                [sys.executable, '-I', str(Path(__file__).resolve()), str(inherited.fileno()),
                 str(body_deadline), str(cleanup_seconds), *lease_arguments],
                cwd=cwd, env=env, pass_fds=(inherited.fileno(), *inherited_descriptors),
                stdout=subprocess.PIPE, stderr=subprocess.PIPE, start_new_session=True,
            )
        except OSError as exc:
            if raise_launch_errors:
                raise
            return subprocess.CompletedProcess(command, 126, '',
                f'bcf execution infrastructure failure: {exc}')
        inherited.close()
        ready = _receive(connection, body_deadline)
        expected_ready = {'type': 'ready', 'supervisor_pid': process.pid}
        if leases:
            expected_ready['native_leases'] = leases
        if (not isinstance(ready, dict) or type(ready.get('supervisor_pid')) is not int
                or ready != expected_ready):
            raise OwnedProcessError('child supervisor could not establish exclusive custody')
        request = {'command': command}
        if input_binding is not None:
            request['input'] = input_binding
        _send(connection, request)
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
            if raise_launch_errors:
                number, detail, filename = result.get('errno'), result.get('strerror'), result.get('filename')
                if (type(number) is not int or number <= 0 or not isinstance(detail, str)
                        or (filename is not None and not isinstance(filename, str))):
                    raise OwnedProcessError('typed failed-exec facts are missing or contradictory')
                raise OSError(number, detail, filename)
            return subprocess.CompletedProcess(command, 126, '',
                'bcf execution infrastructure failure: ' + result['detail'])
        if result['reason'] == 'timeout' and timeout_raises:
            raise subprocess.TimeoutExpired(command, timeout_seconds,
                output=b''.join(buffers['stdout']), stderr=b''.join(buffers['stderr']))
        if result['reason'] != 'exit':
            reason = {'timeout': 'command timed out', 'descendants': 'command left live descendants',
                      'cancelled': 'command was interrupted'}[result['reason']]
            return subprocess.CompletedProcess(command, 126, '',
                'bcf execution infrastructure failure: ' + reason)
        # Match subprocess text-mode decoding and universal newline semantics.
        if not text:
            return subprocess.CompletedProcess(command, result['returncode'],
                *[b''.join(buffers[name]) for name in ('stdout', 'stderr')])
        encoding = 'utf-8' if sys.flags.utf8_mode else locale.getencoding()
        output = [b''.join(buffers[name]).decode(encoding).replace('\r\n', '\n').replace('\r', '\n')
                  for name in ('stdout', 'stderr')]
        return subprocess.CompletedProcess(command, result['returncode'], *output)
    except (OwnedProcessError, subprocess.TimeoutExpired):
        raise
    except OSError as exc:
        if raise_launch_errors and (quiescent or process is None):
            raise
        raise OwnedProcessError('child cleanup could not be authenticated') from exc
    except UnicodeError as exc:
        if quiescent:
            raise
        raise OwnedProcessError('child cleanup could not be authenticated') from exc
    except Exception as exc:
        raise OwnedProcessError('child cleanup could not be authenticated') from exc
    finally:
        inherited.close()
        connection.close()
        if input_binding is not None:
            os.close(input_binding[0])
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


def _supervise(connection, body_deadline, cleanup_seconds, native_leases=()):
    _subreaper()
    ready = {'type': 'ready', 'supervisor_pid': os.getpid()}
    for descriptor, device, inode in native_leases:
        identity = os.fstat(descriptor)
        if (identity.st_dev, identity.st_ino) != (device, inode):
            raise OwnedProcessError('inherited native lease identity is contradictory')
    if native_leases:
        ready['native_leases'] = [list(binding) for binding in native_leases]
    _send(connection, ready)
    request = _receive(connection, body_deadline)
    command = request['command']
    if not isinstance(command, list) or not command or not all(isinstance(x, str) for x in command):
        raise OwnedProcessError('invalid owned command')
    if time.monotonic() >= body_deadline:
        raise OwnedProcessError('command deadline expired before allocation')
    input_binding = request.get('input')
    stdin = None
    if input_binding is not None:
        if (not isinstance(input_binding, list) or len(input_binding) != 3
                or any(type(value) is not int for value in input_binding)):
            raise OwnedProcessError('invalid command input descriptor binding')
        stdin, device, inode = input_binding
        if stdin <= 2 or stdin == connection.fileno() or stdin in {row[0] for row in native_leases}:
            raise OwnedProcessError('command input cannot expose custody descriptors')
        identity = os.fstat(stdin)
        seals = _INPUT_REQUIRED_SEALS
        if ((identity.st_dev, identity.st_ino) != (device, inode)
                or not stat.S_ISREG(identity.st_mode)
                or fcntl.fcntl(stdin, _INPUT_GET_SEALS) & seals != seals):
            raise OwnedProcessError('command input identity or immutable bytes are unbound')
    try:
        command_options = {'stdin': stdin} if stdin is not None else {}
        process = subprocess.Popen(command, start_new_session=True, close_fds=True, **command_options)
    except OSError as exc:
        try:
            os.waitid(os.P_ALL, 0, os.WEXITED | os.WNOHANG)
        except ChildProcessError:
            _send(connection, {'type': 'not-started', 'supervisor_pid': os.getpid(),
                'command_pid': None, 'quiescent': True, 'returncode': 126,
                'reason': 'launch-error', 'detail': str(exc),
                'errno': exc.errno, 'strerror': exc.strerror, 'filename': exc.filename})
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
            if (len(sys.argv) - 4) % 3:
                raise OwnedProcessError('inherited native lease binding is incomplete')
            _leases = tuple(tuple(int(value) for value in sys.argv[offset:offset + 3])
                            for offset in range(4, len(sys.argv), 3))
            _supervise(_connection, float(sys.argv[2]), int(sys.argv[3]), _leases)
        except BaseException:
            # Keep the inherited open-file-description lock until kernel proof
            # of no owned children. A failed report remains failure at the caller.
            if len(sys.argv) > 4:
                _retain_native_custody()
            sys.exit(126)
