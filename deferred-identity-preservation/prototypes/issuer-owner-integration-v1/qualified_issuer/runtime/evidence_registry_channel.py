"""Authenticated, bounded owner lookups into the original Root registry.

No wire operation creates an invocation, binds an owner, supplies a returncode,
or registers an execution ID. Only original Root APIs can do those operations.
Root dispatches these channels serially while owner lifecycle requests run in
separate owner processes; it never concurrently uses the native keeper stream.
"""
from __future__ import annotations

from dataclasses import asdict
import json
import math
import os
import re
import socket
import time
from typing import Any
from uuid import uuid4

from .evidence_execution_owner import OwnerAdmissionError, ProcessIdentity, _unique_object, _invalid_constant
from .evidence_invocation_registry import ActualInvocationRegistry, RegistryAdmission
from .evidence_packet_channel import receive_authenticated_packet

SCHEMA = 'bcf.original-invocation-registry.v1'
# Complete real issuer callbacks require more than the transport-only64 frames.
# This original implementation bound is not peer-selectable and renews no time.
MAX_QUERIES = 512
_KEYS = {'schema', 'operation', 'sequence', 'nonce', 'context', 'body'}
_OPERATIONS = {'admit', 'recheck', 'recover', 'native_closed'}


def admission_metadata(value: Any) -> RegistryAdmission:
    """Decode metadata only; registry equality and kernel checks confer admission."""
    keys = {'context', 'coordinator_lifetime', 'consuming_controller_lifetime',
            'held_peer_lifetime', 'tenant', 'access_deadline', 'cleanup_deadline'}
    if type(value) is not dict or set(value) != keys:
        raise OwnerAdmissionError('registry admission metadata is not closed')
    for name in ('context', 'coordinator_lifetime', 'consuming_controller_lifetime', 'held_peer_lifetime'):
        if type(value[name]) is not str or re.fullmatch('[0-9a-f]{64}', value[name]) is None:
            raise OwnerAdmissionError('registry lifetime metadata is invalid')
    if (type(value['tenant']) is not str or value['tenant'] == 'default'
            or re.fullmatch('[a-z][a-z0-9-]{1,62}', value['tenant']) is None
            or any(type(value[name]) not in (int, float) or not math.isfinite(value[name])
                   for name in ('access_deadline', 'cleanup_deadline'))
            or not value['access_deadline'] < value['cleanup_deadline']):
        raise OwnerAdmissionError('registry tenant or original window metadata is invalid')
    return RegistryAdmission(**value)


def _json(raw: bytes) -> dict[str, Any]:
    try:
        value = json.loads(raw, object_pairs_hook=_unique_object, parse_constant=_invalid_constant)
    except (ValueError, UnicodeError, RecursionError) as error:
        raise OwnerAdmissionError('registry channel requires bounded closed JSON') from error
    if type(value) is not dict:
        raise OwnerAdmissionError('registry channel requires a closed object')
    return value


def _send(channel: socket.socket, value: dict[str, Any], deadline: float) -> None:
    raw = json.dumps(value, separators=(',', ':'), allow_nan=False).encode('ascii')
    if len(raw) > 8192 or deadline <= time.monotonic():
        raise OwnerAdmissionError('registry channel frame or original deadline exceeded')
    channel.settimeout(min(5, deadline - time.monotonic()))
    if channel.send(raw) != len(raw):
        raise OwnerAdmissionError('registry channel delivery is uncertain')


class RegistryOwnerChannel:
    """One original channel per installed owner; no replacement after ambiguity."""

    def __init__(self, registry: ActualInvocationRegistry, *, role: str,
                 channel: socket.socket) -> None:
        if type(registry) is not ActualInvocationRegistry:
            raise OwnerAdmissionError('original registry object is required')
        registry._owner(role, cleanup=True)
        if (registry.held or role in registry._registry_channels
                or channel.family != socket.AF_UNIX
                or channel.getsockopt(socket.SOL_SOCKET, socket.SO_TYPE) != socket.SOCK_SEQPACKET):
            raise OwnerAdmissionError('original registry channel is absent or already installed')
        info = os.fstat(channel.fileno())
        key = (info.st_dev, info.st_ino)
        if key in registry._registry_channels.values():
            raise OwnerAdmissionError('registry owner roles share a control channel')
        registry._registry_channels[role] = key
        channel.setsockopt(socket.SOL_SOCKET, socket.SO_PASSCRED, 1)
        self._registry = registry
        self._role = role
        self._channel = channel
        self._sender = registry._owners[role]
        self._sequence = 0
        self._nonces: set[str] = set()
        self._failed = False

    def handle_once(self) -> None:
        registry = self._registry
        if self._failed or self._sequence >= MAX_QUERIES:
            raise OwnerAdmissionError('original registry channel is exhausted or uncertain')
        try:
            info = os.fstat(self._channel.fileno())
            if (info.st_dev, info.st_ino) != registry._registry_channels[self._role]:
                raise OwnerAdmissionError('original registry channel was replaced')
            # The shared packet decoder authenticates the registered sending
            # process per message; its direction label is not a role grant.
            request = _json(receive_authenticated_packet(self._channel, sender=self._sender,
                deadline=min(registry.admission.cleanup_deadline, time.monotonic() + 5),
                peer_label='controller'))
            if (set(request) != _KEYS or type(request['schema']) is not str or request['schema'] != SCHEMA
                    or type(request['operation']) is not str or request['operation'] not in _OPERATIONS
                    or type(request['sequence']) is not int or request['sequence'] != self._sequence + 1
                    or type(request['nonce']) is not str or re.fullmatch('[0-9a-f]{32}', request['nonce']) is None
                    or request['nonce'] in self._nonces or request['context'] != registry.admission.context
                    or type(request['body']) is not dict):
                raise OwnerAdmissionError('registry request identity, order or context differs')
            self._sequence += 1
            self._nonces.add(request['nonce'])
            body = request['body']; operation = request['operation']
            result: dict[str, Any] = {}
            if operation == 'admit' and set(body) == {'manifest_path', 'held_pid'}:
                result = asdict(registry.admit(self._role, context=request['context'],
                    manifest_path=body['manifest_path'], held_pid=body['held_pid']))
            elif operation == 'recheck' and set(body) == {'admission', 'cleanup'} and type(body['cleanup']) is bool:
                registry.recheck(self._role, admission_metadata(body['admission']), cleanup=body['cleanup'])
            elif operation == 'recover' and set(body) == {'coordinator_lifetime', 'execution_id'}:
                result = asdict(registry.recover(self._role, context=request['context'],
                    coordinator_lifetime=body['coordinator_lifetime'], execution_id=body['execution_id']))
            elif operation == 'native_closed' and set(body) == {'admission'}:
                registry.native_closed(self._role, admission_metadata(body['admission']))
            else:
                raise OwnerAdmissionError('registry wire operation cannot mutate its original allocation')
            if ProcessIdentity.observe(self._sender.pid) != self._sender:
                raise OwnerAdmissionError('original registry owner changed before observation completed')
            _send(self._channel, {**request, 'body': result, 'status': 'observed'},
                  min(registry.admission.cleanup_deadline, time.monotonic() + 5))
        except BaseException:
            self._failed = True
            registry._hold = True
            self._channel.close()
            raise

    def close(self) -> None:
        self._failed = True
        self._channel.close()


class RegistryOwnerClient:
    """Trusted owner-side metadata adapter; no retries or caller deadline renewal."""

    def __init__(self, channel: socket.socket, *, coordinator: ProcessIdentity,
                 context: str, cleanup_deadline: float) -> None:
        if (channel.family != socket.AF_UNIX
                or channel.getsockopt(socket.SOL_SOCKET, socket.SO_TYPE) != socket.SOCK_SEQPACKET
                or type(coordinator) is not ProcessIdentity
                or ProcessIdentity.observe(coordinator.pid) != coordinator
                or type(context) is not str or re.fullmatch('[0-9a-f]{64}', context) is None
                or type(cleanup_deadline) not in (int, float) or not math.isfinite(cleanup_deadline)
                or not time.monotonic() < cleanup_deadline <= time.monotonic() + 21900):
            raise OwnerAdmissionError('original owner registry capability is required')
        channel.setsockopt(socket.SOL_SOCKET, socket.SO_PASSCRED, 1)
        self._channel = channel
        self._coordinator = coordinator
        self._sender = ProcessIdentity.observe(os.getpid())
        self._context = context
        self._deadline = cleanup_deadline
        self._sequence = 0
        self._failed = False

    def _query(self, operation: str, body: dict[str, Any]) -> dict[str, Any]:
        if (self._failed or self._sequence >= MAX_QUERIES
                or ProcessIdentity.observe(os.getpid()) != self._sender
                or ProcessIdentity.observe(self._coordinator.pid) != self._coordinator):
            raise OwnerAdmissionError('original owner registry session is uncertain or changed')
        self._failed = True
        self._sequence += 1
        request = {'schema': SCHEMA, 'operation': operation, 'sequence': self._sequence,
                   'nonce': uuid4().hex, 'context': self._context, 'body': body}
        try:
            _send(self._channel, request, min(self._deadline, time.monotonic() + 5))
            response = _json(receive_authenticated_packet(self._channel, sender=self._coordinator,
                deadline=min(self._deadline, time.monotonic() + 5), peer_label='coordinator'))
            if (set(response) != _KEYS | {'status'} or response['status'] != 'observed'
                    or any(response[key] != request[key] for key in _KEYS - {'body'})
                    or type(response['body']) is not dict):
                raise OwnerAdmissionError('registry response differs from the original request')
            self._failed = False
            return dict(response['body'])
        except BaseException:
            self._channel.close()
            raise

    def admit(self, *, manifest_path: str, held_pid: int) -> RegistryAdmission:
        return admission_metadata(self._query('admit', {'manifest_path': manifest_path, 'held_pid': held_pid}))

    def recheck(self, admission: RegistryAdmission, *, cleanup: bool) -> None:
        if self._query('recheck', {'admission': asdict(admission), 'cleanup': cleanup}):
            raise OwnerAdmissionError('registry recheck returned unexpected metadata')

    def recover(self, *, coordinator_lifetime: str, execution_id: str) -> RegistryAdmission:
        return admission_metadata(self._query('recover', {
            'coordinator_lifetime': coordinator_lifetime, 'execution_id': execution_id}))

    def native_closed(self, admission: RegistryAdmission) -> None:
        if self._query('native_closed', {'admission': asdict(admission)}):
            raise OwnerAdmissionError('registry closure returned unexpected metadata')
