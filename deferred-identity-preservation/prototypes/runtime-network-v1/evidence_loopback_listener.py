"""Fixed loopback listener capabilities in one retained image namespace.

Only trusted setup runs here. No route, provider, credential or external
destination is inferred from a listener. The outside coordinator owns its FD.
"""
from __future__ import annotations

from array import array
import fcntl
import json
import math
import os
from pathlib import Path
import socket
import struct
import subprocess
import sys
import time

from .evidence_execution_owner import OwnerAdmissionError, ProcessIdentity
from .evidence_immutable_source import ImmutableSource

_BIND = '''import array,fcntl,json,os,socket,struct,sys
network,user=map(int,sys.argv[1:3]);address=json.loads(sys.argv[3])
os.setns(user,0);os.setns(network,0)
for descriptor in (network,user):os.close(descriptor)
channel=socket.socket(fileno=0)
with socket.socket(socket.AF_INET,socket.SOCK_DGRAM) as control:
 request=struct.pack('16sH14s',b'lo',1,b'')
 fcntl.ioctl(control,0x8914,request)
listener=socket.socket(socket.AF_INET,socket.SOCK_STREAM)
listener.bind(tuple(address));listener.listen(4)
channel.sendmsg([b'listener'],[(socket.SOL_SOCKET,socket.SCM_RIGHTS,array.array('i',[listener.fileno()]))])
assert channel.recv(1)==b'Q'
listener.close();channel.send(b'closed')
'''


def bind_fixed_loopback(source: ImmutableSource, *, address: str, port: int,
                        deadline: float) -> socket.socket:
    """Bind one fixed service address, transfer its actual FD, then reap setup."""
    if (type(source) is not ImmutableSource or source._closed or source.network_fd < 0
            or address not in {'127.0.0.2', '127.0.0.3', '127.0.0.4'}
            or type(port) is not int or port != 443
            or type(deadline) not in {int, float} or not math.isfinite(deadline)
            or not 0 < deadline-time.monotonic() <= 30):
        raise OwnerAdmissionError('fixed loopback listener scope is invalid')
    network = os.dup(source.network_fd)
    user = -1
    parent, child = socket.socketpair(socket.AF_UNIX, socket.SOCK_SEQPACKET)
    parent.setsockopt(socket.SOL_SOCKET, socket.SO_PASSCRED, 1)
    parent.settimeout(max(.001, deadline-time.monotonic()))
    process: subprocess.Popen[bytes] | None = None
    received: list[int] = []
    listener: socket.socket | None = None
    try:
        user = fcntl.ioctl(network, 0xb701)
        os.set_inheritable(user, False)
        command = [str(Path(sys.executable).resolve()), '-I', '-S', '-B', '-c', _BIND,
                   str(network), str(user), json.dumps([address, port])]
        process = subprocess.Popen(command, stdin=child.fileno(), stdout=subprocess.DEVNULL,
                                   stderr=None, pass_fds=(network, user), close_fds=True)
        child.close()
        raw, ancillary, flags, _ = parent.recvmsg(
            32, socket.CMSG_SPACE(struct.calcsize('3i'))+socket.CMSG_SPACE(4))
        credentials = []
        for level, kind, data in ancillary:
            if level == socket.SOL_SOCKET and kind == socket.SCM_RIGHTS:
                values = array('i')
                values.frombytes(data)
                received.extend(values)
            elif level == socket.SOL_SOCKET and kind == socket.SCM_CREDENTIALS:
                credentials.append(struct.unpack('3i', data))
            else:
                raise OwnerAdmissionError('unexpected fixed listener ancillary data')
        if (raw != b'listener' or flags or len(received) != 1
                or len(credentials) != 1 or credentials[0][:2] != (process.pid, os.getuid())):
            raise OwnerAdmissionError('fixed listener transfer is unauthenticated')
        identity = ProcessIdentity.observe(process.pid)
        if (dict(identity.namespaces)['net'] != os.readlink('/proc/self/fd/'+str(network))
                or int(Path('/proc',str(process.pid),'stat').read_bytes().rsplit(b')',1)[1].split()[1]) != os.getpid()):
            raise OwnerAdmissionError('listener setup belongs to another namespace or parent')
        listener = socket.socket(fileno=received.pop())
        listener.set_inheritable(False)
        if (listener.family != socket.AF_INET or listener.type != socket.SOCK_STREAM
                or listener.getsockname() != (address, port)
                or listener.getsockopt(socket.SOL_SOCKET, socket.SO_ACCEPTCONN) != 1):
            raise OwnerAdmissionError('transferred listener differs from its original scope')
        if time.monotonic() >= deadline or ProcessIdentity.observe(process.pid) != identity:
            raise OwnerAdmissionError('listener setup changed during observation')
        parent.send(b'Q')
        if (parent.recv(32) != b'closed'
                or process.wait(timeout=max(.001, deadline-time.monotonic())) != 0
                or Path('/proc', str(process.pid)).exists()):
            raise OwnerAdmissionError('listener setup did not close')
        result, listener = listener, None
        return result
    finally:
        parent.close()
        child.close()
        if listener is not None:
            listener.close()
        for descriptor in received:
            os.close(descriptor)
        os.close(network)
        if user >= 0:
            os.close(user)
        if process is not None and process.poll() is None:
            # Trusted setup only: closing its control socket refuses handoff.
            process.wait(timeout=5)
