"""Held Python with a frozen filesystem and an empty network namespace.

This no-network component grants no live issuer access, semantic admission, or
owner cleanup authority. The trusted coordinator still owns the native guardian.
"""
from __future__ import annotations

from dataclasses import dataclass, field
import json
import os
from pathlib import Path, PurePosixPath
import socket
import stat
import sys
import time

from .evidence_closed_runtime_image import ClosedImageInventory
from .evidence_execution_owner import OwnerAdmissionError, ProcessIdentity
from .evidence_execution_view import WorkingView, _digest
from .evidence_held_invocation import HeldPythonPlan
from .evidence_namespace_bootstrap import ENTER_VIEW as _BOOTSTRAP
from .evidence_held_peer import HeldPeerObservation
from .evidence_immutable_source import ImmutableSource

_HELD = '''import json,runpy,socket,sys
plan=json.loads(sys.argv[1])
with socket.socket(socket.AF_UNIX) as connection:
 connection.connect('/run/bcf/ready.sock');connection.sendall(b'held')
 assert connection.recv(1)==b'R'
for absolute in reversed(plan['import_roots']):sys.path.insert(0,absolute)
sys.argv=['/work/'+plan['script'],*plan['arguments']]
runpy.run_path(sys.argv[0],run_name='__main__')
'''


def _bounded(path: Path, limit: int) -> str:
    with path.open('rb') as stream:
        raw = stream.read(limit + 1)
    if len(raw) > limit:
        raise OwnerAdmissionError('held runtime observation exceeds its budget')
    return raw.decode('utf-8')


@dataclass
class ClosedHeldPythonPlan(HeldPythonPlan):
    inventory: ClosedImageInventory = field(kw_only=True)

    def observe(self, *, supervisor: ProcessIdentity, deadline: float) -> HeldPeerObservation:
        rows = tuple((name[5:], mode, size, digest)
                     for name, mode, size, digest in self.source.view.manifest if name.startswith('work/'))
        view = WorkingView(self.source.view.root/'work', rows, _digest(rows))
        if view.digest != self.inventory.source_digest:
            raise OwnerAdmissionError('held source subset differs from the original source')
        observation = self._observe_view(view, supervisor=supervisor, deadline=deadline)
        try:
            self._verify_runtime(observation.identity, deadline=deadline)
        except BaseException:
            # A failed observation never leaves a releasable plan.
            self.close()
            raise
        return observation

    def _verify_runtime(self, identity: ProcessIdentity, *, deadline: float) -> None:
        peer = Path('/proc', str(identity.pid))
        expected = os.fstat(self.source.directory_fd)
        actual = (peer/'root').stat()
        if (actual.st_dev, actual.st_ino) != (expected.st_dev, expected.st_ino):
            raise OwnerAdmissionError('held root is not the frozen execution image')
        if dict(identity.namespaces)['net'] == os.readlink('/proc/self/ns/net'):
            raise OwnerAdmissionError('held runtime shares the outside network namespace')
        interfaces = _bounded(peer/'net/dev', 8192).splitlines()[2:]
        if {line.split(':', 1)[0].strip() for line in interfaces} != {'lo'}:
            raise OwnerAdmissionError('held no-network profile has an external interface')
        mounts = [line.split() for line in _bounded(peer/'mountinfo', 131072).splitlines()]
        allowed = {'/', '/work', '/tmp', '/run/bcf/ready.sock'}
        if not mounts or len(mounts) > len(allowed):
            raise OwnerAdmissionError('held runtime has an unexpected mount population')
        for row in mounts:
            if len(row) < 10 or row[4] not in allowed or '-' not in row:
                raise OwnerAdmissionError('held runtime has an unexpected mount')
            if row[4] == '/tmp':
                if row[row.index('-')+1] != 'tmpfs' or row[2] == f'{os.major(expected.st_dev)}:{os.minor(expected.st_dev)}':
                    raise OwnerAdmissionError('held scratch aliases frozen runtime storage')
            elif 'ro' not in row[5].split(','):
                raise OwnerAdmissionError('held runtime has a writable frozen mount')
        root_rows = [row for row in mounts if row[4] == '/']
        if len(root_rows) != 1:
            raise OwnerAdmissionError('held runtime root mount is ambiguous')
        runtime_files = {}
        for name, _mode, _size, digest in self.source.view.manifest:
            if time.monotonic() >= deadline:
                raise OwnerAdmissionError('held runtime inspection deadline exhausted')
            if name.startswith('work/'):
                continue
            info = (self.source.view.root/name).stat()
            runtime_files[(info.st_dev, info.st_ino)] = digest
        binary = (peer/'exe').stat()
        selected = self.inventory.executable.removeprefix('/')
        digest = next(row[3] for row in self.source.view.manifest if row[0] == selected)
        if (runtime_files.get((binary.st_dev, binary.st_ino)) != digest
                or identity.executable_sha256 != digest):
            raise OwnerAdmissionError('held interpreter is not the frozen selected executable')
        mappings = _bounded(peer/'maps', 262144).splitlines()
        if len(mappings) > 4096:
            raise OwnerAdmissionError('held runtime mapping budget exhausted')
        for mapping in mappings:
            columns = mapping.split(maxsplit=5)
            if len(columns) < 5:
                raise OwnerAdmissionError('held runtime mapping is malformed')
            permissions = columns[1]
            inode = int(columns[4])
            if inode:
                major, minor = (int(part, 16) for part in columns[3].split(':'))
                if (os.makedev(major, minor), inode) not in runtime_files:
                    raise OwnerAdmissionError('held runtime maps bytes outside the frozen runtime')
                if len(permissions) != 4 or ('w' in permissions and permissions[3] == 's'):
                    raise OwnerAdmissionError('held runtime has a shared writable file mapping')
            elif 'x' in permissions and (len(columns) < 6 or columns[5] not in {'[vdso]', '[vsyscall]'}):
                raise OwnerAdmissionError('held runtime has an unqualified executable mapping')
        if time.monotonic() >= deadline or ProcessIdentity.observe(identity.pid) != identity:
            raise OwnerAdmissionError('held runtime changed during independent inspection')


def prepare_closed_held_python(source: ImmutableSource, inventory: ClosedImageInventory, *,
        ready_listener: socket.socket, script: str, arguments: tuple[str, ...] = (),
        import_roots: tuple[str, ...] = ('/work',),
        library_path: str) -> ClosedHeldPythonPlan:
    if (type(source) is not ImmutableSource or source._closed
            or type(inventory) is not ClosedImageInventory
            or source.view.manifest != inventory.image.manifest):
        raise OwnerAdmissionError('one actual frozen execution image is required')
    names = {row[0] for row in source.view.manifest}
    if inventory.executable.removeprefix('/') not in names:
        raise OwnerAdmissionError('closed held interpreter is outside frozen files')
    if type(script) is not str:
        raise OwnerAdmissionError('closed held script is outside frozen source')
    relative = PurePosixPath(script)
    if (type(script) is not str or relative.is_absolute() or '..' in relative.parts
            or relative.as_posix() != script or relative.suffix != '.py' or 'work/'+script not in names):
        raise OwnerAdmissionError('closed held script is outside frozen source')
    if (type(arguments) is not tuple or len(arguments) > 128
            or any(type(value) is not str or '\0' in value for value in arguments)
            or sum(map(len, arguments)) > 32768):
        raise OwnerAdmissionError('closed held arguments exceed their budget')
    if type(import_roots) is not tuple or not 1 <= len(import_roots) <= 16:
        raise OwnerAdmissionError('closed held import roots are not bounded')
    for value in (*import_roots, library_path):
        if type(value) is not str:
            raise OwnerAdmissionError('closed held import or library path is outside frozen files')
        path = PurePosixPath(value)
        if (type(value) is not str or not path.is_absolute() or '..' in path.parts
                or path.as_posix() != value or '\0' in value or ':' in value
                or not any(name.startswith(value[1:]+'/') for name in names)):
            raise OwnerAdmissionError('closed held import or library path is outside frozen files')
    address = ready_listener.getsockname()
    if (ready_listener.family != socket.AF_UNIX or type(address) is not str
            or ready_listener.getsockopt(socket.SOL_SOCKET, socket.SO_ACCEPTCONN) != 1):
        raise OwnerAdmissionError('closed held readiness requires the original filesystem listener')
    actual = (source.view.root/'run/bcf/ready.sock').lstat()
    expected = Path(address).lstat()
    if (not stat.S_ISSOCK(actual.st_mode)
            or (actual.st_dev, actual.st_ino) != (expected.st_dev, expected.st_ino)):
        raise OwnerAdmissionError('closed held image has another readiness socket')
    descriptors = source.duplicate_execution_capabilities()
    try:
        payload = json.dumps({'script': script, 'arguments': arguments,
                              'import_roots': import_roots}, separators=(',', ':'))
        command = ['/usr/bin/bwrap', '--unshare-user', '--unshare-pid', '--unshare-ipc',
            '--unshare-uts', '--unshare-net', '--new-session', '--die-with-parent',
            '--cap-drop', 'ALL', '--ro-bind', '/view', '/',
            '--ro-bind', '/view/work', '/work', '--tmpfs', '/tmp', '--chdir', '/work',
            '--clearenv', '--setenv', 'LD_LIBRARY_PATH', library_path,
            inventory.executable, '-I', '-S', '-B', '-c', _HELD, payload]
        launch = [str(Path(sys.executable).resolve()), '-I', '-S', '-B', '-c', _BOOTSTRAP,
                  *(str(fd) for fd in descriptors), *command]
        return ClosedHeldPythonPlan(launch, descriptors, source, ready_listener, inventory=inventory)
    except BaseException:
        for descriptor in descriptors:
            os.close(descriptor)
        raise
