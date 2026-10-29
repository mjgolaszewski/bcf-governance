"""Finite controller-side transport to an independently registered coordinator.

This client cannot release custody. The outside coordinator must own native
execution, original leases and authenticated independent-owner reconciliation.
A decoded terminal is metadata from that coordinator, never a provider grant.
No backend is installed by importing or constructing this client.
"""
from __future__ import annotations

import base64
from dataclasses import dataclass
import hashlib
import json
import math
import os
import re
import socket
import time
from threading import Lock
from typing import Any
from uuid import uuid4

from .evidence_controller_channel import API_VERSION, MAX_PACKET, MAX_REQUESTS, _identity, _nonfinite, _unique
from .evidence_execution_owner import OwnerAdmissionError, ProcessIdentity
from .evidence_external_custody import require_external_custodian
from .evidence_owner_control import OwnerOutcomeUncertain
from .evidence_packet_channel import receive_authenticated_packet

MAX_OUTPUT = 64 * 1024 * 1024


@dataclass(frozen=True)
class OwnerClosure:
    role: str
    owner_pid: int
    execution_id: str
    context_digest: str
    response_digest: str


@dataclass(frozen=True)
class CoordinatorResult:
    returncode: int
    stdout: bytes
    stderr: bytes
    context_digest: str
    cleanup: tuple[OwnerClosure, OwnerClosure]
    terminal_digest: str


class CoordinatorClient:
    def __init__(self, connection: socket.socket, *, coordinator: ProcessIdentity,
                 budget_owner: ProcessIdentity, controller: ProcessIdentity, epoch: str) -> None:
        if (connection.family != socket.AF_UNIX
                or connection.getsockopt(socket.SOL_SOCKET, socket.SO_TYPE) != socket.SOCK_SEQPACKET
                or type(epoch) is not str or re.fullmatch('[0-9a-f]{32}', epoch) is None
                or type(controller) is not ProcessIdentity
                or ProcessIdentity.observe(os.getpid()) != controller or coordinator == controller):
            raise OwnerAdmissionError('registered private coordinator channel is required')
        require_external_custodian(coordinator, budget_owner)
        connection.setsockopt(socket.SOL_SOCKET, socket.SO_PASSCRED, 1)
        self._connection = connection
        self._coordinator = coordinator
        self._budget = budget_owner
        self._controller = controller
        self._epoch = epoch
        self._sequence = 0
        self._used: set[str] = set()
        self._failed = False
        self._lock = Lock()
        self.last_request_id: str | None = None

    def run_actual(self, *, invocation_id: str, producer: str, profile: str,
                   control: str, absolute_deadline: float) -> CoordinatorResult:
        if not self._lock.acquire(blocking=False):
            raise OwnerAdmissionError('coordinator session already has an invocation')
        try:
            return self._run_actual(invocation_id=invocation_id, producer=producer,
                profile=profile, control=control, absolute_deadline=absolute_deadline)
        finally:
            self._lock.release()

    def _run_actual(self, *, invocation_id: str, producer: str, profile: str,
                    control: str, absolute_deadline: float) -> CoordinatorResult:
        if (self._failed or len(self._used) >= MAX_REQUESTS or invocation_id in self._used
                or type(absolute_deadline) not in (int, float)
                or not math.isfinite(absolute_deadline)
                or not 0 < absolute_deadline - time.monotonic() <= 21900):
            raise OwnerAdmissionError('coordinator invocation allocation is invalid or uncertain')
        if ProcessIdentity.observe(os.getpid()) != self._controller:
            raise OwnerAdmissionError('coordinator binding belongs to another controller lifetime')
        require_external_custodian(self._coordinator, self._budget)
        body = {key: _identity(value) for key, value in {
            'invocation_id': invocation_id, 'producer': producer,
            'profile': profile, 'control': control}.items()}
        self._sequence += 1
        request_id = uuid4().hex
        packet = {'version': API_VERSION, 'epoch': self._epoch, 'request_id': request_id,
                  'sequence': self._sequence, 'operation': 'run_actual', 'body': body}
        raw = json.dumps(packet, sort_keys=True, separators=(',', ':'), allow_nan=False).encode()
        if len(raw) > MAX_PACKET:
            raise OwnerAdmissionError('coordinator request exceeds its closed packet budget')
        self.last_request_id = request_id
        self._used.add(invocation_id)
        # Sending can be accepted even when observation fails. Never retry a
        # consuming operation or permit another run on an uncertain session.
        self._failed = True
        try:
            self._connection.settimeout(min(30.0, absolute_deadline - time.monotonic()))
            if self._connection.send(raw) != len(raw):
                raise OwnerOutcomeUncertain('coordinator request delivery is uncertain')
            result = self._receive_result(request_id, invocation_id, absolute_deadline)
        except BaseException as error:
            # Closing the exclusive control endpoint informs the outside owner;
            # it does not release any physical lease or assert provider cleanup.
            self._connection.close()
            if isinstance(error, OwnerOutcomeUncertain) or not isinstance(error, Exception):
                raise
            raise OwnerOutcomeUncertain('registered coordinator outcome is uncertain') from error
        else:
            self._failed = False
            return result

    def _receive_result(self, request_id: str, invocation_id: str,
                        deadline: float) -> CoordinatorResult:
        outputs = {'stdout': bytearray(), 'stderr': bytearray()}
        for sequence in range(1, 100001):
            data = receive_authenticated_packet(self._connection, sender=self._coordinator,
                deadline=min(deadline, time.monotonic() + 29.0), peer_label='coordinator')
            try:
                frame = json.loads(data, object_pairs_hook=_unique, parse_constant=_nonfinite)
            except (ValueError, UnicodeError, RecursionError) as error:
                raise OwnerOutcomeUncertain('coordinator result is not closed JSON') from error
            keys = {'version', 'epoch', 'request_id', 'invocation_id', 'frame_sequence', 'kind', 'payload'}
            if (type(frame) is not dict or set(frame) != keys
                    or type(frame['version']) is not int or frame['version'] != API_VERSION
                    or frame['epoch'] != self._epoch or frame['request_id'] != request_id
                    or frame['invocation_id'] != invocation_id
                    or type(frame['frame_sequence']) is not int or frame['frame_sequence'] != sequence):
                raise OwnerOutcomeUncertain('coordinator result identity or sequence is invalid')
            payload = frame['payload']
            if type(payload) is not dict:
                raise OwnerOutcomeUncertain('coordinator result payload is invalid')
            if frame['kind'] == 'heartbeat':
                if (set(payload) != {'phase'} or type(payload['phase']) is not str
                        or payload['phase'] not in {'preparing', 'running', 'cleaning'}):
                    raise OwnerOutcomeUncertain('coordinator heartbeat is invalid')
            elif frame['kind'] == 'output':
                self._output(payload, outputs)
            elif frame['kind'] == 'terminal':
                return self._terminal(payload, outputs, hashlib.sha256(data).hexdigest())
            else:
                raise OwnerOutcomeUncertain('coordinator result kind is unsupported')
        raise OwnerOutcomeUncertain('coordinator result frame budget is exhausted')

    @staticmethod
    def _output(payload: dict[str, Any], outputs: dict[str, bytearray]) -> None:
        if (set(payload) != {'stream', 'offset', 'data'} or type(payload['stream']) is not str
                or payload['stream'] not in outputs or type(payload['offset']) is not int
                or payload['offset'] != len(outputs[payload['stream']])
                or type(payload['data']) is not str):
            raise OwnerOutcomeUncertain('coordinator output framing is invalid')
        try:
            raw = base64.b64decode(payload['data'], validate=True)
        except (ValueError, UnicodeError) as error:
            raise OwnerOutcomeUncertain('coordinator output encoding is invalid') from error
        if not 1 <= len(raw) <= 3072 or sum(map(len, outputs.values())) + len(raw) > MAX_OUTPUT:
            raise OwnerOutcomeUncertain('coordinator output byte budget is exhausted')
        outputs[payload['stream']].extend(raw)

    @staticmethod
    def _terminal(payload: dict[str, Any], outputs: dict[str, bytearray],
                  terminal_digest: str) -> CoordinatorResult:
        if (set(payload) != {'returncode', 'native_quiescent', 'context_digest', 'outputs', 'owner_cleanup'}
                or type(payload['returncode']) is not int or not -255 <= payload['returncode'] <= 255
                or payload['native_quiescent'] is not True
                or type(payload['context_digest']) is not str
                or re.fullmatch('[0-9a-f]{64}', payload['context_digest']) is None
                or type(payload['outputs']) is not dict or set(payload['outputs']) != set(outputs)):
            raise OwnerOutcomeUncertain('coordinator terminal custody is not closed')
        for name, raw in outputs.items():
            declared = payload['outputs'][name]
            if (type(declared) is not dict or set(declared) != {'bytes', 'sha256'}
                    or type(declared['bytes']) is not int or declared['bytes'] != len(raw)
                    or declared['sha256'] != hashlib.sha256(raw).hexdigest()):
                raise OwnerOutcomeUncertain('coordinator output terminal does not match received bytes')
        cleanup = payload['owner_cleanup']
        if type(cleanup) is not list or len(cleanup) != 2:
            raise OwnerOutcomeUncertain('separate owner closure is unavailable')
        closures = []
        for role, row in zip(('issuer', 'custody'), cleanup, strict=True):
            if (type(row) is not dict
                    or set(row) != {'role', 'owner_pid', 'execution_id', 'context_digest', 'response_digest'}
                    or row['role'] != role or type(row['owner_pid']) is not int or row['owner_pid'] <= 0
                    or row['context_digest'] != payload['context_digest']
                    or type(row['response_digest']) is not str
                    or re.fullmatch('[0-9a-f]{64}', row['response_digest']) is None):
                raise OwnerOutcomeUncertain('independent owner closure metadata is invalid')
            closures.append(OwnerClosure(role, row['owner_pid'], _identity(row['execution_id']),
                                         row['context_digest'], row['response_digest']))
        if closures[0].owner_pid == closures[1].owner_pid:
            raise OwnerOutcomeUncertain('independent owners cannot be one process')
        return CoordinatorResult(payload['returncode'], bytes(outputs['stdout']), bytes(outputs['stderr']),
                                 payload['context_digest'], (closures[0], closures[1]), terminal_digest)
