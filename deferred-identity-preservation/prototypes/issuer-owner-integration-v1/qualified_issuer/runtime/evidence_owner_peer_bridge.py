"""Authenticate owner messages and actual workload FDs at the outside coordinator.

This kernel guard is not provider authority or a complete execution registry.
Its context, original deadlines, two owner lifetimes and private channels must
come from the installed launcher's original allocation, before candidate code.
No candidate path, claimed PID or JSON receipt selects an owner or workload.
"""
from __future__ import annotations

from array import array
import json
import math
import os
import re
import socket
import stat
from pathlib import Path
import struct
import time
from typing import Any
from threading import Lock

from .evidence_closed_held import ClosedHeldPythonPlan
from .evidence_execution_owner import OwnerAdmissionError, ProcessIdentity, _unique_object, _invalid_constant
from .evidence_execution_view import WorkingView, _digest
from .evidence_external_custody import require_external_custodian
from .evidence_held_peer import inspect_held_process

SCHEMA = 'bcf.owner-kernel-peer.v1'
_LIMIT = 1024


def _receive(channel: socket.socket, deadline: float) -> tuple[dict[str, Any], tuple[int,int,int], list[int]]:
    remaining=deadline-time.monotonic()
    if remaining<=0:
        raise OwnerAdmissionError('owner peer bridge original deadline exhausted')
    channel.settimeout(remaining)
    raw, ancillary, flags, _=channel.recvmsg(_LIMIT+1,
        socket.CMSG_SPACE(struct.calcsize('3i'))+socket.CMSG_SPACE(16),socket.MSG_CMSG_CLOEXEC)
    descriptors: list[int]=[]
    credentials=[]
    ancillary_error=False
    try:
        for level,kind,data in ancillary:
            if level==socket.SOL_SOCKET and kind==socket.SCM_RIGHTS:
                values=array('i');values.frombytes(data);descriptors.extend(values)
            elif level==socket.SOL_SOCKET and kind==socket.SCM_CREDENTIALS:
                if len(data)==12:credentials.append(struct.unpack('3i',data))
                else:ancillary_error=True
            else:
                ancillary_error=True
        if (ancillary_error or flags & ~(socket.MSG_CMSG_CLOEXEC|socket.MSG_EOR)
                or not 0<len(raw)<=_LIMIT or len(credentials)!=1):
            raise OwnerAdmissionError('owner bridge frame is unauthenticated or truncated')
        value=json.loads(raw,object_pairs_hook=_unique_object,parse_constant=_invalid_constant)
        if type(value)is not dict:
            raise OwnerAdmissionError('owner bridge requires a closed object')
        return value,credentials[0],descriptors
    except BaseException:
        for descriptor in descriptors:os.close(descriptor)
        raise


def _send(channel: socket.socket, value: dict[str, Any], descriptor: int | None = None) -> None:
    raw=json.dumps(value,separators=(',',':'),allow_nan=False).encode('ascii')
    if not 0<len(raw)<=_LIMIT:
        raise OwnerAdmissionError('owner bridge frame exceeds its bound')
    ancillary=[] if descriptor is None else [(socket.SOL_SOCKET,socket.SCM_RIGHTS,array('i',[descriptor]))]
    if channel.sendmsg([raw],ancillary)!=len(raw):
        raise OwnerAdmissionError('owner bridge delivery is uncertain')


class OwnerPeerBridge:
    """Original coordinator only; each role supplies its actual accepted FD."""

    def __init__(self, plan: ClosedHeldPythonPlan, *, context_digest: str,
                 owners: dict[str, ProcessIdentity], channels: dict[str, socket.socket],
                 access_deadline: float) -> None:
        if (type(plan)is not ClosedHeldPythonPlan or plan.observation is None
                or type(context_digest)is not str or re.fullmatch('[0-9a-f]{64}',context_digest)is None
                or set(owners)!={'issuer','custody'} or set(channels)!=set(owners)
                or type(access_deadline)not in (int,float) or not math.isfinite(access_deadline)
                or not 0<access_deadline-time.monotonic()<=21600):
            raise OwnerAdmissionError('original owner bridge allocation is invalid')
        coordinator=ProcessIdentity.observe(os.getpid())
        lifetimes=[coordinator,plan.observation.identity,plan.observation.supervisor,*owners.values()]
        if len({(p.pid,p.start_ticks) for p in lifetimes})!=5:
            raise OwnerAdmissionError('coordinator, budget, held peer and owners must be distinct')
        for identity in (coordinator,*owners.values()):
            require_external_custodian(identity,plan.observation.supervisor)
        if len({(os.fstat(c.fileno()).st_dev,os.fstat(c.fileno()).st_ino) for c in channels.values()})!=2:
            raise OwnerAdmissionError('owner bridge roles share a private channel')
        for role,channel in channels.items():
            if (channel.family!=socket.AF_UNIX or channel.type!=socket.SOCK_SEQPACKET
                    or ProcessIdentity.observe(owners[role].pid)!=owners[role]):
                raise OwnerAdmissionError('owner bridge channel or lifetime differs')
            channel.setsockopt(socket.SOL_SOCKET,socket.SO_PASSCRED,1)
        pending={role:(device,inode,uid) for role,device,inode,uid in plan.source.workload_sockets}
        if len(plan.source.workload_sockets)!=2 or set(pending)!={'issuer','custody'}:
            raise OwnerAdmissionError('both original pending owner listeners are required')
        self._pending=pending
        self._plan=plan
        self._context=context_digest
        self._owners=dict(owners)
        self._channels=dict(channels)
        self._coordinator=coordinator
        self._deadline=access_deadline
        self._sequence={role:0 for role in owners}
        self._nonces: set[str]=set()
        self._socket_keys: dict[str,tuple[int,int]]={}
        self._uncertain: set[str]=set()
        self._lock=Lock()

    def handle_once(self, role: str) -> None:
        with self._lock:
            if (role not in self._owners or role in self._uncertain
                    or self._sequence[role]>=64):
                raise OwnerAdmissionError('owner bridge role is absent, exhausted or uncertain')
            self._uncertain.add(role)
        descriptors: list[int]=[]
        connection: socket.socket | None=None
        try:
            if ProcessIdentity.observe(os.getpid())!=self._coordinator:
                raise OwnerAdmissionError('owner bridge belongs to another coordinator')
            request,credentials,descriptors=_receive(self._channels[role],self._deadline)
            expected_owner=self._owners[role]
            if (credentials[:2]!=(expected_owner.pid,expected_owner.uid)
                    or ProcessIdentity.observe(expected_owner.pid)!=expected_owner
                    or set(request)!={'schema','op','context','sequence','nonce'}
                    or request['schema']!=SCHEMA or request['op']!='authenticate_workload'
                    or request['context']!=self._context
                    or type(request['sequence'])is not int or request['sequence']!=self._sequence[role]+1
                    or type(request['nonce'])is not str or re.fullmatch('[0-9a-f]{32}',request['nonce'])is None
                    or request['nonce'] in self._nonces or len(descriptors)!=1):
                raise OwnerAdmissionError('owner bridge sender, context, sequence or FD differs')
            with self._lock:
                if request['sequence']!=self._sequence[role]+1 or request['nonce'] in self._nonces:
                    raise OwnerAdmissionError('owner bridge order or nonce was reused')
                self._sequence[role]+=1;self._nonces.add(request['nonce'])
            connection=socket.socket(fileno=descriptors.pop())
            if connection.family!=socket.AF_UNIX or connection.type!=socket.SOCK_STREAM:
                raise OwnerAdmissionError('owner bridge requires the actual accepted Unix connection')
            pid,uid,_gid=struct.unpack('3i',connection.getsockopt(socket.SOL_SOCKET,socket.SO_PEERCRED,12))
            observed=self._plan.observation
            if observed is None or (pid,uid)!=(observed.identity.pid,observed.identity.uid):
                raise OwnerAdmissionError('workload socket belongs to another peer')
            address=connection.getsockname()
            if type(address)is not str or not address.startswith('/'):
                raise OwnerAdmissionError('workload socket is not its registered pending listener')
            path=Path(address)
            info=path.lstat()
            if (path.resolve()!=path or not stat.S_ISSOCK(info.st_mode)
                    or stat.S_IMODE(info.st_mode)!=0o600
                    or (info.st_dev,info.st_ino,info.st_uid)!=self._pending[role]):
                raise OwnerAdmissionError('workload socket is not its registered pending listener')
            key=os.fstat(connection.fileno())
            actual_key=(key.st_dev,key.st_ino)
            if role in self._socket_keys and self._socket_keys[role]!=actual_key:
                raise OwnerAdmissionError('owner replaced its original workload connection')
            self._socket_keys[role]=actual_key
            rows=tuple((name[5:],mode,size,digest) for name,mode,size,digest in self._plan.source.view.manifest
                       if name.startswith('work/'))
            view=WorkingView(self._plan.source.view.root/'work',rows,_digest(rows))
            actual=inspect_held_process(observed.identity,expected_view=view,
                supervisor=observed.supervisor,deadline=min(self._deadline,time.monotonic()+5))
            if actual!=observed:
                raise OwnerAdmissionError('actual workload source context changed')
            self._plan._verify_runtime(actual.identity,deadline=min(self._deadline,time.monotonic()+5))
            if (time.monotonic()>=self._deadline
                    or ProcessIdentity.observe(expected_owner.pid)!=expected_owner):
                raise OwnerAdmissionError('owner bridge lifetime or original deadline expired')
            _send(self._channels[role],{**request,'status':'kernel-verified'})
            with self._lock:self._uncertain.remove(role)
        finally:
            if connection is not None:connection.close()
            for descriptor in descriptors:os.close(descriptor)


class OwnerPeerClient:
    """Trusted owner only; a response is bound to the original Root sender."""

    def __init__(self, channel: socket.socket, *, coordinator: ProcessIdentity,
                 context_digest: str, access_deadline: float) -> None:
        if (channel.family!=socket.AF_UNIX or channel.type!=socket.SOCK_SEQPACKET
                or ProcessIdentity.observe(coordinator.pid)!=coordinator
                or type(context_digest)is not str or re.fullmatch('[0-9a-f]{64}',context_digest)is None
                or type(access_deadline)not in (int,float) or not math.isfinite(access_deadline)
                or access_deadline<=time.monotonic()):
            raise OwnerAdmissionError('owner client original registration is invalid')
        channel.setsockopt(socket.SOL_SOCKET,socket.SO_PASSCRED,1)
        self._channel=channel;self._coordinator=coordinator;self._context=context_digest
        self._deadline=access_deadline;self._sequence=0;self._uncertain=False

    def authenticate(self, connection: socket.socket) -> None:
        if self._uncertain or time.monotonic()>=self._deadline:
            raise OwnerAdmissionError('owner client outcome is uncertain or expired')
        self._uncertain=True;self._sequence+=1
        self._channel.settimeout(self._deadline-time.monotonic())
        request={'schema':SCHEMA,'op':'authenticate_workload','context':self._context,
                 'sequence':self._sequence,'nonce':os.urandom(16).hex()}
        _send(self._channel,request,connection.fileno())
        response,credentials,descriptors=_receive(self._channel,self._deadline)
        try:
            if (descriptors or credentials[:2]!=(self._coordinator.pid,self._coordinator.uid)
                    or ProcessIdentity.observe(self._coordinator.pid)!=self._coordinator
                    or response!={**request,'status':'kernel-verified'}
                    or time.monotonic()>=self._deadline):
                raise OwnerAdmissionError('owner client response is not from its original coordinator')
            self._uncertain=False
        finally:
            for descriptor in descriptors:os.close(descriptor)
