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

# Stable Linux UAPI values from linux/fcntl.h. Some CPython builds omit
# their symbolic exports; the actual kernel must still attest every seal.
_LINUX_ADD_SEALS = 1033
_LINUX_GET_SEALS = 1034
_LINUX_SOURCE_SEALS = 0x000f

MAX_FILES = 4096
MAX_BYTES = 128*1024*1024
_HOLDER = 'import socket; c=socket.socket(fileno=0); c.send(b"ready"); assert c.recv(1)==b"Q"; c.send(b"closed")'


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
        seals = _LINUX_SOURCE_SEALS
        fcntl.fcntl(descriptor,_LINUX_ADD_SEALS,seals)
        if fcntl.fcntl(descriptor,_LINUX_GET_SEALS)&seals != seals:
            raise OwnerAdmissionError('source input sealing is unavailable')
        return descriptor
    except BaseException:
        os.close(descriptor)
        raise


def freeze_source(view: WorkingView, *, deadline: float) -> ImmutableSource:
    remaining = deadline-time.monotonic() if type(deadline) in (int,float) else 0
    if (type(view) is not WorkingView or not math.isfinite(remaining) or not 0<remaining<=30
            or not 1<=len(view.manifest)<=MAX_FILES):
        raise OwnerAdmissionError('immutable source cohort or deadline is unsupported')
    paths = [row[0] for row in view.manifest]
    if (len(set(paths))!=len(paths) or any(not name or len(name)>512
            or PurePosixPath(name).is_absolute() or '..' in PurePosixPath(name).parts
            or PurePosixPath(name).as_posix()!=name or chr(0) in name for name in paths)):
        raise OwnerAdmissionError('immutable source path population is invalid')
    parent,child = socket.socketpair(socket.AF_UNIX,socket.SOCK_SEQPACKET)
    parent.setsockopt(socket.SOL_SOCKET,socket.SO_PASSCRED,1)
    descriptors: list[int] = []
    process: subprocess.Popen[bytes] | None = None
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
            '--size',str(MAX_BYTES),'--tmpfs','/view']
        prefix=Path(sys.base_prefix).resolve()
        if not prefix.is_relative_to('/usr'):
            arguments.extend(['--ro-bind',str(prefix),str(prefix)])
        directories = {str(parent) for name in paths for parent in PurePosixPath(name).parents
                       if str(parent)!='.'}
        for name in sorted(directories,key=lambda value:(len(PurePosixPath(value).parts),value)):
            arguments.extend(['--dir','/view/'+name])
        total = 0
        for name,mode,size,digest in view.manifest:
            if time.monotonic()>=deadline:
                raise OwnerAdmissionError('immutable source setup deadline exhausted')
            raw,actual_mode = _read_regular(view.root/name)
            total += len(raw)
            if (total>MAX_BYTES or len(raw)!=size or actual_mode!=mode
                    or hashlib.sha256(raw).hexdigest()!=digest):
                raise OwnerAdmissionError('actual source changed before immutable materialization')
            descriptor = _sealed(raw);descriptors.append(descriptor)
            arguments.extend(['--perms',format(mode,'o'),'--file',str(descriptor),'/view/'+name])
        arguments.extend(['--remount-ro','/view','--clearenv',
            '--setenv','LD_LIBRARY_PATH',str(prefix/'lib')])
        args_fd = _sealed(bytes([0]).join(value.encode() for value in arguments)+bytes([0]))
        descriptors.append(args_fd)
        process = subprocess.Popen(['/usr/bin/bwrap','--args',str(args_fd),
            str(Path(sys.executable).resolve()),'-I','-S','-B','-c',_HOLDER],
            stdin=child.fileno(),stdout=subprocess.DEVNULL,stderr=None,
            pass_fds=tuple(descriptors),close_fds=True)
        child.close()
        parent.settimeout(max(.001,deadline-time.monotonic()))
        data,ancillary,flags,_ = parent.recvmsg(32,socket.CMSG_SPACE(struct.calcsize('3i'))+socket.CMSG_SPACE(16*array('i').itemsize))
        credentials=[];unexpected=False
        for level,kind,raw in ancillary:
            if level==socket.SOL_SOCKET and kind==socket.SCM_CREDENTIALS and len(raw)==struct.calcsize('3i'):
                credentials.append(struct.unpack('3i',raw))
            elif level==socket.SOL_SOCKET and kind==socket.SCM_RIGHTS:
                rights=array('i');rights.frombytes(raw[:len(raw)-len(raw)%rights.itemsize])
                for value in rights:os.close(value)
                unexpected=True
            else:unexpected=True
        if data!=b'ready' or flags or unexpected or len(credentials)!=1:
            raise OwnerAdmissionError('immutable namespace readiness is unauthenticated')
        pid,uid,_gid=credentials[0]
        identity=ProcessIdentity.observe(pid)
        supervisor=ProcessIdentity.observe(process.pid)
        if (uid!=os.getuid() or identity.uid!=uid or not _descends_from(pid,supervisor)
                or dict(identity.namespaces)['mnt']==os.readlink('/proc/self/ns/mnt')):
            raise OwnerAdmissionError('immutable namespace belongs to another process')
        directory=os.open(Path('/proc',str(pid),'root/view'),os.O_RDONLY|os.O_DIRECTORY|os.O_CLOEXEC)
        namespace=os.open(Path('/proc',str(pid),'ns/mnt'),os.O_RDONLY|os.O_CLOEXEC)
        root=Path('/proc',str(os.getpid()),'fd',str(directory))
        if not os.statvfs(root).f_flag&os.ST_RDONLY:
            raise OwnerAdmissionError('source namespace is not read-only')
        for name,mode,size,digest in view.manifest:
            entry=os.open(name,os.O_RDONLY|os.O_NOFOLLOW,dir_fd=directory)
            try:
                info=os.fstat(entry);parts=[]
                while raw:=os.read(entry,1024*1024):parts.append(raw)
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
        for descriptor in descriptors:os.close(descriptor)
        if directory>=0:os.close(directory)
        if namespace>=0:os.close(namespace)
        if process is not None and process.poll() is None:
            # Only setup code exists here: no caller has received a view or any
            # execution/provider grant. Closing stdin makes the fixed helper exit.
            process.wait(timeout=5)
