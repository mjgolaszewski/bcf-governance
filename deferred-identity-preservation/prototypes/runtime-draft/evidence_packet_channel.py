"""Finite per-message kernel credentials for the two private packet directions."""
from __future__ import annotations

from array import array
import math
import os
import socket
import struct
import time

from .evidence_execution_owner import OwnerAdmissionError, ProcessIdentity


def receive_authenticated_packet(connection: socket.socket, *, sender: ProcessIdentity,
                                 deadline: float, peer_label: str, maximum: int = 8192) -> bytes:
    if (peer_label not in {"controller", "coordinator"} or type(sender) is not ProcessIdentity
            or type(maximum) is not int or not 1 <= maximum <= 8192
            or connection.family != socket.AF_UNIX
            or connection.getsockopt(socket.SOL_SOCKET, socket.SO_TYPE) != socket.SOCK_SEQPACKET
            or connection.getsockopt(socket.SOL_SOCKET, socket.SO_PASSCRED) != 1):
        raise OwnerAdmissionError("private packet channel registration is invalid")
    remaining = deadline - time.monotonic() if type(deadline) in (int, float) else 0
    if not math.isfinite(remaining) or not 0 < remaining <= 30:
        raise OwnerAdmissionError(f"{peer_label} observation deadline is invalid")
    connection.settimeout(remaining)
    try:
        data, ancillary, flags, _address = connection.recvmsg(maximum,
            socket.CMSG_SPACE(struct.calcsize("3i")) + socket.CMSG_SPACE(16 * array("i").itemsize))
    except OSError as error:
        raise OwnerAdmissionError(f"{peer_label} packet observation failed") from error
    credentials = []
    unexpected = False
    for level, kind, raw in ancillary:
        if level == socket.SOL_SOCKET and kind == socket.SCM_CREDENTIALS:
            if len(raw) != struct.calcsize("3i"):
                unexpected = True
            else:
                credentials.append(struct.unpack("3i", raw))
        elif level == socket.SOL_SOCKET and kind == socket.SCM_RIGHTS:
            descriptors = array("i")
            descriptors.frombytes(raw[:len(raw) - len(raw) % descriptors.itemsize])
            for descriptor in descriptors:
                os.close(descriptor)
            unexpected = True
        else:
            unexpected = True
    if (not data or flags & (socket.MSG_TRUNC | socket.MSG_CTRUNC)
            or unexpected or len(credentials) != 1):
        raise OwnerAdmissionError(f"{peer_label} packet credentials or framing are invalid")
    pid, uid, _gid = credentials[0]
    if (pid != sender.pid or uid != sender.uid or ProcessIdentity.observe(pid) != sender):
        raise OwnerAdmissionError(f"message sender is not the registered {peer_label} lifetime")
    if time.monotonic() >= deadline:
        raise OwnerAdmissionError(f"{peer_label} observation deadline exhausted")
    return data
