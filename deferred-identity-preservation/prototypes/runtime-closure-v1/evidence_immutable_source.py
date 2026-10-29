"""Bounded immutable source cohorts backed by a pinned read-only mount namespace.

This materializer grants no execution or provider authority. Its directory and
namespace descriptors must be transferred to outside custody before a required
invocation starts; the materializer's process lifetime is not a lease keeper.
"""
from __future__ import annotations

from array import array
from dataclasses import dataclass
import fcntl
import hashlib
import json
import math
import os
from pathlib import Path,PurePosixPath
import socket
import stat
import struct
import subprocess
import sys
import time

from .evidence_execution_owner import OwnerAdmissionError,ProcessIdentity
from .evidence_execution_view import WorkingView,_read_regular
from .evidence_held_peer import _descends_from
from .evidence_namespace_bootstrap import ENTER_VIEW

# Stable Linux UAPI values from linux/fcntl.h. Some CPython builds omit
# their symbolic exports; the actual kernel must still attest every seal.
_LINUX_ADD_SEALS = 1033
_LINUX_GET_SEALS = 1034
_LINUX_SOURCE_SEALS = 0x000f

MAX_FILES = 4096
MAX_BYTES = 128*1024*1024
_HOLDER = 'import socket; c=socket.socket(fileno=0); c.send(b"ready"); assert c.recv(1)==b"Q"; c.send(b"closed")'
_MATERIALIZE = '''import hashlib,json,os,stat,struct,sys
from pathlib import Path,PurePosixPath
def read_exact(stream,count):
 raw=bytearray()
 while len(raw)<count:
  part=stream.read(count-len(raw))
  if not part:raise RuntimeError('truncated frozen image')
  raw.extend(part)
 return bytes(raw)
maximum,total_limit,layout=map(int,sys.argv[2:5])
assert 1<=maximum<=20000 and 0<total_limit<=512*1024*1024 and layout in (0,1)
with open(sys.argv[1],'rb') as stream:
 count,=struct.unpack('!I',read_exact(stream,4));assert 1<=count<=maximum
 seen=set();total=0
 for number in range(count):
  length,=struct.unpack('!I',read_exact(stream,4));assert 0<length<=8192
  row=json.loads(read_exact(stream,length));assert type(row)is dict and set(row)=={'name','mode','size','sha256'}
  name,mode,size,digest=(row[k] for k in ('name','mode','size','sha256'))
  assert type(name)is str and name and len(name)<=512 and '\\0'not in name
  path=PurePosixPath(name)
  assert not path.is_absolute() and '..'not in path.parts and path.as_posix()==name and name not in seen
  assert type(mode)is int and 0<=mode<=0o1777
  assert type(size)is int and 0<=size<=64*1024*1024
  total+=size;assert total<=total_limit;seen.add(name)
  raw=read_exact(stream,size);assert hashlib.sha256(raw).hexdigest()==digest
  target=Path('/view')/name;target.parent.mkdir(parents=True,exist_ok=True,mode=0o700)
  descriptor=os.open(target,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,0o600)
  with os.fdopen(descriptor,'wb') as output:
   output.write(raw);output.flush();os.fchmod(output.fileno(),mode)
 assert stream.read(1)==b''
if layout:Path('/view/tmp').mkdir(mode=0o700,exist_ok=False)
os.chdir('/');os.execv(sys.argv[5],sys.argv[5:])
'''


@dataclass
class ImmutableSource:
    directory_fd: int
    namespace_fd: int
    view: WorkingView
    namespace: str
    _closed: bool = False

    def duplicate_capabilities(self) -> tuple[int,int]:
        if self._closed:
            raise OwnerAdmissionError('immutable source custody is closed')
        directory = os.dup(self.directory_fd)
        try:
            namespace = os.dup(self.namespace_fd)
        except BaseException:
            os.close(directory)
            raise
        return directory,namespace

    def duplicate_execution_capabilities(self) -> tuple[int,int,int]:
        """Retain the kernel owning user namespace for a trusted mount handoff.

        NS_GET_USERNS is the Linux nsfs ioctl from linux/nsfs.h. It derives
        ownership from the retained mount namespace, never a caller PID/path.
        """
        directory,namespace = self.duplicate_capabilities()
        user_namespace = -1
        try:
            user_namespace = fcntl.ioctl(namespace,0xb701)
            os.set_inheritable(user_namespace,False)
            return directory,namespace,user_namespace
        except BaseException:
            os.close(directory)
            os.close(namespace)
            if user_namespace>=0:
                os.close(user_namespace)
            raise

    def close(self) -> None:
        if not self._closed:
            try:
                os.close(self.directory_fd)
            finally:
                os.close(self.namespace_fd)
                self._closed = True


def _sealed(raw: bytes) -> int:
    if sys.platform != 'linux':
        raise OwnerAdmissionError('immutable source requires the Linux sealing ABI')
    descriptor = os.memfd_create('bcf-source-input',os.MFD_CLOEXEC|os.MFD_ALLOW_SEALING)
    try:
        with os.fdopen(os.dup(descriptor),'wb') as output:
            output.write(raw)
            output.flush()
        os.lseek(descriptor,0,os.SEEK_SET)
        _seal_descriptor(descriptor)
        return descriptor
    except BaseException:
        os.close(descriptor)
        raise


def _seal_descriptor(descriptor: int) -> None:
    seals = _LINUX_SOURCE_SEALS
    fcntl.fcntl(descriptor,_LINUX_ADD_SEALS,seals)
    if fcntl.fcntl(descriptor,_LINUX_GET_SEALS)&seals != seals:
        raise OwnerAdmissionError('source input sealing is unavailable')


def _image_stream(view: WorkingView, *, deadline: float, max_bytes: int) -> int:
    descriptor = os.memfd_create('bcf-frozen-image', os.MFD_CLOEXEC|os.MFD_ALLOW_SEALING)
    try:
        with os.fdopen(os.dup(descriptor), 'wb') as output:
            output.write(struct.pack('!I', len(view.manifest)))
            total = 0
            for name, mode, size, digest in view.manifest:
                if time.monotonic() >= deadline:
                    raise OwnerAdmissionError('immutable image setup deadline exhausted')
                raw, actual_mode = _read_regular(view.root/name)
                total += len(raw)
                if (total > max_bytes or len(raw) != size or actual_mode != mode
                        or hashlib.sha256(raw).hexdigest() != digest):
                    raise OwnerAdmissionError('actual source changed before immutable materialization')
                header = json.dumps({'name': name, 'mode': mode, 'size': size,
                                     'sha256': digest}, separators=(',', ':')).encode('ascii')
                if not 0 < len(header) <= 8192:
                    raise OwnerAdmissionError('immutable image header exceeds its budget')
                output.write(struct.pack('!I', len(header))); output.write(header); output.write(raw)
            output.flush()
        os.lseek(descriptor, 0, os.SEEK_SET)
        _seal_descriptor(descriptor)
        return descriptor
    except BaseException:
        os.close(descriptor)
        raise


def _materializer_ready(connection: socket.socket, process: subprocess.Popen[bytes],
                        deadline: float) -> ProcessIdentity:
    connection.settimeout(max(.001,deadline-time.monotonic()))
    data, ancillary, flags, _ = connection.recvmsg(32,
        socket.CMSG_SPACE(struct.calcsize('3i'))+socket.CMSG_SPACE(16*array('i').itemsize))
    credentials = []
    unexpected = False
    for level, kind, raw in ancillary:
        if level == socket.SOL_SOCKET and kind == socket.SCM_CREDENTIALS and len(raw) == struct.calcsize('3i'):
            credentials.append(struct.unpack('3i', raw))
        elif level == socket.SOL_SOCKET and kind == socket.SCM_RIGHTS:
            rights = array('i'); rights.frombytes(raw[:len(raw)-len(raw)%rights.itemsize])
            for descriptor in rights:
                os.close(descriptor)
            unexpected = True
        else:
            unexpected = True
    if data != b'ready' or flags or unexpected or len(credentials) != 1:
        raise OwnerAdmissionError('immutable namespace readiness is unauthenticated')
    pid, uid, _gid = credentials[0]
    identity = ProcessIdentity.observe(pid)
    if uid != os.getuid() or identity.uid != uid or not _descends_from(pid, ProcessIdentity.observe(process.pid)):
        raise OwnerAdmissionError('immutable namespace belongs to another process')
    return identity


def _readonly_holder(writer: ProcessIdentity, directory: int) -> tuple[subprocess.Popen[bytes], socket.socket]:
    parent, child = socket.socketpair(socket.AF_UNIX, socket.SOCK_SEQPACKET)
    parent.setsockopt(socket.SOL_SOCKET, socket.SO_PASSCRED, 1)
    command = ['/usr/bin/bwrap', '--unshare-user', '--unshare-pid', '--unshare-ipc',
        '--unshare-uts', '--unshare-net', '--new-session', '--die-with-parent', '--cap-drop', 'ALL',
        '--bind', '/', '/', '--ro-bind', '/view', '/view', '--clearenv',
        '--setenv', 'LD_LIBRARY_PATH', str(Path(sys.base_prefix).resolve()/'lib')]
    command.extend([str(Path(sys.executable).resolve()), '-I', '-S', '-B', '-c', _HOLDER])
    mount = user = -1
    try:
        mount = os.open(Path('/proc', str(writer.pid), 'ns/mnt'), os.O_RDONLY|os.O_CLOEXEC)
        user = fcntl.ioctl(mount, 0xb701)
        os.set_inheritable(user, False)
        launch = [str(Path(sys.executable).resolve()), '-I', '-S', '-B', '-c', ENTER_VIEW,
                  str(directory), str(mount), str(user), *command]
        process = subprocess.Popen(launch, stdin=child.fileno(), stdout=subprocess.DEVNULL,
            stderr=None, pass_fds=(directory, mount, user), close_fds=True)
    except BaseException:
        parent.close()
        raise
    finally:
        child.close()
        if mount >= 0:
            os.close(mount)
        if user >= 0:
            os.close(user)
    return process, parent


def freeze_source(view: WorkingView, *, deadline: float) -> ImmutableSource:
    return _freeze_view(view, deadline=deadline, max_files=MAX_FILES, max_bytes=MAX_BYTES)


def freeze_execution_image(view: WorkingView, *, deadline: float,
                           ready_listener: socket.socket | None = None) -> ImmutableSource:
    """Freeze one combined image; this grants no runtime or network authority."""
    return _freeze_view(view, deadline=deadline, max_files=20000,
                        max_bytes=512*1024*1024, ready_listener=ready_listener, closed_layout=True)


def _freeze_view(view: WorkingView, *, deadline: float, max_files: int,
                 max_bytes: int, ready_listener: socket.socket | None = None,
                 closed_layout: bool = False) -> ImmutableSource:
    remaining = deadline-time.monotonic() if type(deadline) in (int,float) else 0
    if (type(view) is not WorkingView or not math.isfinite(remaining) or not 0<remaining<=30
            or not 1<=len(view.manifest)<=max_files):
        raise OwnerAdmissionError('immutable source cohort or deadline is unsupported')
    paths = [row[0] for row in view.manifest]
    if (len(set(paths))!=len(paths) or any(not name or len(name)>512
            or PurePosixPath(name).is_absolute() or '..' in PurePosixPath(name).parts
            or PurePosixPath(name).as_posix()!=name or chr(0) in name for name in paths)):
        raise OwnerAdmissionError('immutable source path population is invalid')
    ready_path: Path | None = None
    ready_identity: tuple[int, int, int] | None = None
    if ready_listener is not None:
        if (ready_listener.family != socket.AF_UNIX
                or ready_listener.getsockopt(socket.SOL_SOCKET, socket.SO_TYPE) != socket.SOCK_STREAM
                or ready_listener.getsockopt(socket.SOL_SOCKET, socket.SO_ACCEPTCONN) != 1):
            raise OwnerAdmissionError('ready channel must be an actual Unix listener')
        address = ready_listener.getsockname()
        if type(address) is not str or not address.startswith('/'):
            raise OwnerAdmissionError('ready channel requires a private filesystem address')
        ready_path = Path(address)
        info, parent_info = ready_path.lstat(), ready_path.parent.lstat()
        if (ready_path.resolve() != ready_path or not stat.S_ISSOCK(info.st_mode)
                or info.st_uid != os.getuid() or stat.S_IMODE(info.st_mode) != 0o600
                or not stat.S_ISDIR(parent_info.st_mode) or parent_info.st_uid != os.getuid()
                or stat.S_IMODE(parent_info.st_mode) != 0o700
                or any(name == 'run' or name.startswith('run/') for name in paths)):
            raise OwnerAdmissionError('ready listener filesystem custody is not private')
        ready_identity = (info.st_dev, info.st_ino, info.st_uid)
    parent,child = socket.socketpair(socket.AF_UNIX,socket.SOCK_SEQPACKET)
    parent.setsockopt(socket.SOL_SOCKET,socket.SO_PASSCRED,1)
    descriptors: list[int] = []
    process: subprocess.Popen[bytes] | None = None
    writer_process: subprocess.Popen[bytes] | None = None
    writer_channel: socket.socket | None = None
    directory = namespace = -1
    try:
        # This is a trusted setup namespace, never the workload namespace.
        # Its procfs supports only normal helper/new-child namespace setup;
        # the separate workload root must omit it and all bootstrap FDs.
        arguments = ['--unshare-user','--unshare-pid','--unshare-ipc','--unshare-uts',
            '--unshare-net','--new-session','--die-with-parent','--cap-drop','ALL',
            '--ro-bind','/usr','/usr','--ro-bind','/lib','/lib',
            '--ro-bind','/lib64','/lib64','--bind','/proc','/proc',
            '--dev','/dev','--tmpfs','/tmp',
            '--size',str(max_bytes),'--tmpfs','/view']
        prefix=Path(sys.base_prefix).resolve()
        if not prefix.is_relative_to('/usr'):
            arguments.extend(['--ro-bind',str(prefix),str(prefix)])
        image_fd = _image_stream(view, deadline=deadline, max_bytes=max_bytes)
        descriptors.append(image_fd)
        arguments.extend(['--ro-bind-data', str(image_fd), '/input.archive'])
        if ready_path is not None:
            info = ready_path.lstat()
            if (info.st_dev, info.st_ino, info.st_uid) != ready_identity:
                raise OwnerAdmissionError('ready listener changed before immutable mounting')
            arguments.extend(['--dir', '/view/run', '--dir', '/view/run/bcf',
                              '--ro-bind', str(ready_path), '/view/run/bcf/ready.sock'])
        arguments.extend(['--clearenv',
            '--setenv','LD_LIBRARY_PATH',str(prefix/'lib')])
        # Builder readiness grants nothing. A separate outside-started holder
        # mounts only the completed private directory read-only; all writer
        # processes and writable directory references close before return.
        readonly = [str(Path(sys.executable).resolve()), '-I', '-S', '-B', '-c', _HOLDER]
        args_fd = _sealed(bytes([0]).join(value.encode() for value in arguments)+bytes([0]))
        descriptors.append(args_fd)
        process = subprocess.Popen(['/usr/bin/bwrap','--args',str(args_fd),
            str(Path(sys.executable).resolve()),'-I','-S','-B','-c',_MATERIALIZE,
            '/input.archive',str(max_files),str(max_bytes),str(int(closed_layout)),*readonly],
            stdin=child.fileno(),stdout=subprocess.DEVNULL,stderr=None,
            pass_fds=tuple(descriptors),close_fds=True)
        child.close()
        writer_identity = _materializer_ready(parent, process, deadline)
        writer_directory = os.open(Path('/proc', str(writer_identity.pid), 'root/view'),
                                   os.O_RDONLY|os.O_DIRECTORY|os.O_CLOEXEC)
        writer_info = os.fstat(writer_directory)
        writer_process, writer_channel = process, parent
        try:
            if time.monotonic() >= deadline:
                raise OwnerAdmissionError('immutable holder setup deadline exhausted')
            process, parent = _readonly_holder(writer_identity, writer_directory)
        finally:
            os.close(writer_directory)
        identity = _materializer_ready(parent, process, deadline)
        if ProcessIdentity.observe(writer_identity.pid) != writer_identity:
            raise OwnerAdmissionError('writable image builder lifetime changed before mount capture')
        pid, uid = identity.pid, identity.uid
        supervisor = ProcessIdentity.observe(process.pid)
        writer_channel.settimeout(max(.001, deadline-time.monotonic()))
        writer_channel.send(b'Q')
        if (writer_channel.recv(32) != b'closed'
                or writer_process.wait(timeout=max(.001, deadline-time.monotonic())) != 0
                or Path('/proc', str(writer_identity.pid)).exists()):
            raise OwnerAdmissionError('writable image builder did not close')
        writer_channel.close()
        status = Path('/proc', str(pid), 'status').read_text()
        capabilities = {line.split(':', 1)[0]: int(line.split()[1], 16)
                        for line in status.splitlines() if line.startswith(
                            ('CapInh:', 'CapPrm:', 'CapEff:', 'CapBnd:', 'CapAmb:'))}
        if (set(capabilities) != {'CapInh', 'CapPrm', 'CapEff', 'CapBnd', 'CapAmb'}
                or any(capabilities.values()) or 'NoNewPrivs:\t1' not in status):
            raise OwnerAdmissionError('materializer retained setup privilege at readiness')
        if (uid!=os.getuid() or identity.uid!=uid or not _descends_from(pid,supervisor)
                or dict(identity.namespaces)['mnt']==os.readlink('/proc/self/ns/mnt')):
            raise OwnerAdmissionError('immutable namespace belongs to another process')
        directory=os.open(Path('/proc',str(pid),'root/view'),os.O_RDONLY|os.O_DIRECTORY|os.O_CLOEXEC)
        captured = os.fstat(directory)
        if (captured.st_dev, captured.st_ino) != (writer_info.st_dev, writer_info.st_ino):
            raise OwnerAdmissionError('read-only holder captured a different image directory')
        namespace=os.open(Path('/proc',str(pid),'ns/mnt'),os.O_RDONLY|os.O_CLOEXEC)
        root=Path('/proc',str(os.getpid()),'fd',str(directory))
        if not os.statvfs(root).f_flag&os.ST_RDONLY:
            raise OwnerAdmissionError('source namespace is not read-only')
        if ready_identity is not None:
            info = os.stat('run/bcf/ready.sock', dir_fd=directory, follow_symlinks=False)
            if (not stat.S_ISSOCK(info.st_mode)
                    or (info.st_dev, info.st_ino, info.st_uid) != ready_identity):
                raise OwnerAdmissionError('frozen ready channel is a different socket')
        for name,mode,size,digest in view.manifest:
            if time.monotonic() >= deadline:
                raise OwnerAdmissionError('immutable namespace inspection deadline exhausted')
            entry=os.open(name,os.O_RDONLY|os.O_NOFOLLOW,dir_fd=directory)
            try:
                info=os.fstat(entry);parts=[]
                while raw:=os.read(entry,1024*1024):
                    if time.monotonic() >= deadline:
                        raise OwnerAdmissionError('immutable namespace inspection deadline exhausted')
                    parts.append(raw)
                actual=b''.join(parts)
                if (not stat.S_ISREG(info.st_mode) or stat.S_IMODE(info.st_mode)!=mode
                        or len(actual)!=size or hashlib.sha256(actual).hexdigest()!=digest):
                    raise OwnerAdmissionError('immutable namespace bytes differ from actual inputs')
            finally:os.close(entry)
        namespace_name=os.readlink(Path('/proc/self/fd',str(namespace)))
        parent.send(b'Q')
        if parent.recv(32)!=b'closed' or process.wait(timeout=max(.001,deadline-time.monotonic()))!=0:
            raise OwnerAdmissionError('namespace materializer did not close')
        if Path('/proc',str(pid)).exists():
            raise OwnerAdmissionError('namespace materializer remains alive')
        result=ImmutableSource(directory,namespace,WorkingView(root,view.manifest,view.digest),namespace_name)
        directory=namespace=-1
        return result
    finally:
        parent.close();child.close()
        if writer_channel is not None:
            writer_channel.close()
        for descriptor in descriptors:os.close(descriptor)
        if directory>=0:os.close(directory)
        if namespace>=0:os.close(namespace)
        if process is not None and process.poll() is None:
            # Only setup code exists here: no caller has received a view or any
            # execution/provider grant. Closing stdin makes the fixed helper exit.
            process.wait(timeout=5)
        if writer_process is not None and writer_process.poll() is None:
            writer_process.wait(timeout=5)
