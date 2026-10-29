"""Real per-message sender credentials; no issuer or native admission claimed."""
from __future__ import annotations

from array import array
import importlib
import json
import multiprocessing
import os
from pathlib import Path
import socket
import struct
import sys
import time
import types

import pytest

PACKAGE = "_bcf_owner_runtime"
if PACKAGE not in sys.modules:
    package = types.ModuleType(PACKAGE)
    package.__path__ = [str(Path(__file__).parent)]
    sys.modules[PACKAGE] = package
module = importlib.import_module(PACKAGE + ".evidence_controller_channel")
owner = importlib.import_module(PACKAGE + ".evidence_execution_owner")
EPOCH = "e" * 32


def sender(connection, control):
    control.send(os.getpid())
    while True:
        message = control.recv()
        if message is None:
            return
        raw, rights = message
        if rights:
            descriptor = os.open('/dev/null', os.O_RDONLY)
            try:
                connection.sendmsg([raw], [(socket.SOL_SOCKET, socket.SCM_RIGHTS, array('i', [descriptor]))])
            finally:
                os.close(descriptor)
        else:
            connection.send(raw)
        control.send('sent')


@pytest.fixture
def channel():
    service, client = socket.socketpair(socket.AF_UNIX, socket.SOCK_SEQPACKET)
    parent, child = multiprocessing.Pipe()
    process = multiprocessing.Process(target=sender, args=(client, child))
    process.start()
    try:
        assert parent.poll(5)
        pid = parent.recv()
        registered = owner.ProcessIdentity.observe(pid)
        actual = module.ControllerChannel(service, controller=registered, epoch=EPOCH)
        def send(raw, rights=False):
            parent.send((raw, rights))
            assert parent.poll(5) and parent.recv() == 'sent'
        yield actual, send, service, client, registered
    finally:
        if process.is_alive():
            parent.send(None)
            process.join(2)
        if process.is_alive():
            process.terminate()
            process.join(2)
        assert not process.is_alive()
        service.close()
        client.close()
        parent.close()
        child.close()


def packet(*, sequence=1, request_id='a' * 32, operation='run_actual', body=None, **changes):
    payload = {'version': 1, 'epoch': EPOCH, 'request_id': request_id, 'sequence': sequence,
               'operation': operation, 'body': body if body is not None else {
                   'invocation_id': 'actual-1', 'producer': 'runtime-smoke',
                   'profile': 'production', 'control': 'positive'}}
    payload.update(changes)
    return json.dumps(payload, separators=(',', ':')).encode()


def receive(actual):
    return actual.receive(deadline=time.monotonic() + 2)


def test_later_controller_is_authenticated_instead_of_socketpair_creator(channel):
    actual, send, service, _client, registered = channel
    creator, _uid, _gid = struct.unpack('3i', service.getsockopt(socket.SOL_SOCKET, socket.SO_PEERCRED, struct.calcsize('3i')))
    assert creator == os.getpid() and creator != registered.pid
    send(packet())
    request = receive(actual)
    assert request.sender == registered and request.replayed is False


def test_shared_descriptor_cannot_impersonate_the_registered_sender(channel):
    actual, _send, _service, client, _registered = channel
    client.send(packet())
    with pytest.raises(owner.OwnerAdmissionError, match='registered controller lifetime'):
        receive(actual)


def test_candidate_sender_field_cannot_select_a_controller(channel):
    actual, send, _service, _client, registered = channel
    send(packet(sender_pid=registered.pid))
    with pytest.raises(owner.OwnerAdmissionError, match='closed schema'):
        receive(actual)


def test_identical_retry_is_an_acceptance_observation_not_new_execution(channel):
    actual, send, *_ = channel
    executions = 0
    for _ in range(2):
        send(packet())
        request = receive(actual)
        if not request.replayed:
            executions += 1
    assert executions == 1


def test_request_id_reuse_with_different_content_refuses(channel):
    actual, send, *_ = channel
    send(packet())
    receive(actual)
    send(packet(sequence=2))
    with pytest.raises(owner.OwnerAdmissionError, match='changed content'):
        receive(actual)


def test_skipped_sequence_permits_status_after_uncertain_delivery_but_old_new_run_refuses(channel):
    actual, send, *_ = channel
    send(packet(sequence=3, operation='status', body={'invocation_id': 'actual-1'}))
    receive(actual)
    send(packet(sequence=2, request_id='b' * 32))
    with pytest.raises(owner.OwnerAdmissionError, match='out of order'):
        receive(actual)


@pytest.mark.parametrize('changes', [
    {'operation': 'release'}, {'version': True}, {'epoch': 'f' * 32},
    {'body': {'invocation_id': 'actual-1', 'owner_endpoint': '/tmp/untrusted.sock'}},
], ids=['release-not-authority', 'boolean-version', 'wrong-epoch', 'candidate-owner-selection'])
def test_control_packet_never_grants_owner_or_release_authority(channel, changes):
    actual, send, *_ = channel
    send(packet(**changes))
    with pytest.raises(owner.OwnerAdmissionError):
        receive(actual)


def test_duplicate_fields_and_unexpected_rights_are_refused_without_fd_leak(channel):
    actual, send, *_ = channel
    send(b'{"version":1,"version":1}')
    with pytest.raises(owner.OwnerAdmissionError, match='duplicate fields'):
        receive(actual)
    descriptors = len(list(Path('/proc/self/fd').iterdir()))
    send(packet(), rights=True)
    with pytest.raises(owner.OwnerAdmissionError, match='credentials or framing'):
        receive(actual)
    assert len(list(Path('/proc/self/fd').iterdir())) == descriptors


def test_truncated_packet_refuses_before_dispatch(channel):
    actual, send, *_ = channel
    send(b'x' * (module.MAX_PACKET + 1))
    with pytest.raises(owner.OwnerAdmissionError, match='credentials or framing'):
        receive(actual)
