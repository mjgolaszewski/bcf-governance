"""Mechanical held Python plans for the trusted outside coordinator.

This component grants no provider, semantic, runtime or network authority. Its
current network is shared; a privileged profile needs separate qualified network
admission. The caller's native guardian owns execution/Q/EOF/reap. Closing this
plan is transport cleanup only, never lease or source retirement authority.
"""
from __future__ import annotations

from dataclasses import dataclass
import json
import os
from pathlib import Path, PurePosixPath
import socket
import sys
import time

from .evidence_execution_owner import OwnerAdmissionError, ProcessIdentity
from .evidence_execution_view import WorkingView
from .evidence_held_peer import HeldPeerObservation, observe_held_namespace
from .evidence_immutable_source import ImmutableSource

from .evidence_namespace_bootstrap import ENTER_VIEW as _BOOTSTRAP

_HELD = '''import json,runpy,socket,sys
plan=json.loads(sys.argv[1])
with socket.socket(socket.AF_UNIX) as connection:
 connection.connect('\\0'+plan['address']);connection.sendall(b'held')
 assert connection.recv(1)==b'R'
for relative in reversed(plan['import_roots']):
 sys.path.insert(0,'/work' if relative=='.' else '/work/'+relative)
sys.argv=['/work/'+plan['script'],*plan['arguments']]
runpy.run_path(sys.argv[0],run_name='__main__')
'''


@dataclass
class HeldPythonPlan:
    command: list[str]
    bootstrap_descriptors: tuple[int, int, int] | tuple[int, int, int, int]
    source: ImmutableSource
    _listener: socket.socket
    _connection: socket.socket | None = None
    observation: HeldPeerObservation | None = None
    release_attempted: bool = False
    _closed: bool = False

    def observe(self, *, supervisor: ProcessIdentity, deadline: float) -> HeldPeerObservation:
        return self._observe_view(self.source.view, supervisor=supervisor, deadline=deadline)

    def _observe_view(self, expected_view: WorkingView, *, supervisor: ProcessIdentity,
                      deadline: float) -> HeldPeerObservation:
        if self._closed or self.observation is not None:
            raise OwnerAdmissionError('held plan cannot accept another process')
        connection, observation = observe_held_namespace(self._listener,
            expected_view=expected_view, supervisor=supervisor, deadline=deadline)
        self._listener.close()
        try:
            connection.settimeout(max(.001, deadline-time.monotonic()))
            raw = bytearray()
            while len(raw) < 4:
                if time.monotonic() >= deadline:
                    raise OwnerAdmissionError('held bootstrap observation expired')
                connection.settimeout(max(.001, deadline-time.monotonic()))
                part = connection.recv(4-len(raw))
                if not part:
                    raise OwnerAdmissionError('held bootstrap ended before readiness')
                raw.extend(part)
            if bytes(raw) != b'held' or ProcessIdentity.observe(observation.identity.pid) != observation.identity:
                raise OwnerAdmissionError('held bootstrap readiness is unproven')
        except BaseException:
            connection.close()
            raise
        self._connection, self.observation = connection, observation
        return observation

    def release(self) -> None:
        """Trusted coordinator only, after its independent admission and arming."""
        if (self._closed or self.release_attempted or self._connection is None
                or self.observation is None):
            raise OwnerAdmissionError('held invocation release is not available')
        if ProcessIdentity.observe(self.observation.identity.pid) != self.observation.identity:
            raise OwnerAdmissionError('held invocation changed before release')
        self.release_attempted = True  # Even uncertain delivery must never retry.
        try:
            self._connection.sendall(b'R')
        finally:
            self._connection.close()
            self._connection = None

    def close(self) -> None:
        if not self._closed:
            self._listener.close()
            if self._connection is not None:
                self._connection.close()
            for descriptor in self.bootstrap_descriptors:
                os.close(descriptor)
            self._closed = True


def prepare_held_python(source: ImmutableSource, *, script: str,
                        arguments: tuple[str, ...] = (),
                        import_roots: tuple[str, ...] = ('.',)) -> HeldPythonPlan:
    """Prepare before PID birth; only registered outside code may select inputs."""
    if type(source) is not ImmutableSource or source._closed:
        raise OwnerAdmissionError('retained immutable source is required')
    path = PurePosixPath(script)
    names = {row[0] for row in source.view.manifest}
    if (type(script) is not str or path.is_absolute() or '..' in path.parts
            or path.as_posix() != script or script not in names or path.suffix != '.py'):
        raise OwnerAdmissionError('held script is outside the frozen source')
    if (type(arguments) is not tuple or len(arguments) > 128
            or any(type(value) is not str or '\0' in value for value in arguments)
            or sum(len(value) for value in arguments) > 32768):
        raise OwnerAdmissionError('held arguments exceed the closed input budget')
    if type(import_roots) is not tuple or not 1 <= len(import_roots) <= 16:
        raise OwnerAdmissionError('held import roots are not bounded')
    for value in import_roots:
        if type(value) is not str:
            raise OwnerAdmissionError('held import root is invalid')
        relative = PurePosixPath(value)
        if (relative.is_absolute() or '..' in relative.parts or relative.as_posix() != value
                or (value != '.' and not any(name.startswith(value+'/') for name in names))):
            raise OwnerAdmissionError('held import root is outside immutable source')
    descriptors = source.duplicate_execution_capabilities()
    listener = socket.socket(socket.AF_UNIX)
    try:
        address = 'bcf-held-'+os.urandom(16).hex()
        listener.bind('\0'+address)
        listener.listen(1)
        prefix = Path(sys.base_prefix).resolve()
        command = ['/usr/bin/bwrap', '--unshare-user', '--unshare-pid', '--unshare-ipc',
            '--unshare-uts', '--new-session', '--die-with-parent', '--cap-drop', 'ALL',
            '--ro-bind', '/usr', '/usr', '--ro-bind', '/lib', '/lib',
            '--ro-bind', '/lib64', '/lib64', '--ro-bind', '/view', '/work',
            '--dev', '/dev', '--tmpfs', '/tmp', '--clearenv',
            '--setenv', 'LD_LIBRARY_PATH', str(prefix/'lib')]
        if not prefix.is_relative_to('/usr'):
            command.extend(['--ro-bind', str(prefix), str(prefix)])
        payload = json.dumps({'address': address, 'script': script,
            'arguments': arguments, 'import_roots': import_roots}, separators=(',', ':'))
        command.extend([str(Path(sys.executable).resolve()), '-I', '-S', '-B', '-c', _HELD, payload])
        launch = [str(Path(sys.executable).resolve()), '-I', '-S', '-B', '-c', _BOOTSTRAP,
                  *(str(fd) for fd in descriptors), *command]
        return HeldPythonPlan(launch, descriptors, source, listener)
    except BaseException:
        listener.close()
        for descriptor in descriptors:
            os.close(descriptor)
        raise
