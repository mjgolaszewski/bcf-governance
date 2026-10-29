"""Real packet credentials and finite stream parsing; no native/provider proof.

The sibling service/budget fixtures test a selected ancestry relation only.
They are not the protected outside bootstrap for the actual consuming guardian.
Synthetic terminal metadata cannot establish actual Q or owner cleanup.
"""
from __future__ import annotations

from array import array
import base64
import hashlib
import importlib
import json
import multiprocessing
import os
from pathlib import Path
import socket
import sys
import time
import types

import pytest

PACKAGE = '_bcf_owner_runtime'
if PACKAGE not in sys.modules:
    package = types.ModuleType(PACKAGE)
    package.__path__ = [str(Path(__file__).parent)]
    sys.modules[PACKAGE] = package
module = importlib.import_module(PACKAGE+'.evidence_coordinator_client')
owner = importlib.import_module(PACKAGE+'.evidence_execution_owner')
EPOCH = 'e'*32
CONTEXT = 'a'*64


def idle(event):
    event.wait(10)


def serve(service, client, control, parent_control, mode):
    client.close()
    parent_control.close()
    control.send(os.getpid())
    request = json.loads(service.recv(8192))
    control.send(request)
    cleanup = [{'role': role, 'owner_pid': pid, 'execution_id': role+'-actual',
                'context_digest': CONTEXT, 'response_digest': 'b'*64}
               for role, pid in [('issuer', 101), ('custody', 102)]]
    terminal = {'returncode': 0, 'native_quiescent': True, 'context_digest': CONTEXT,
                'outputs': {'stdout': {'bytes': 3, 'sha256': hashlib.sha256(b'abc').hexdigest()},
                            'stderr': {'bytes': 0, 'sha256': hashlib.sha256(b'').hexdigest()}},
                'owner_cleanup': cleanup}
    frames = [('heartbeat', {'phase': 'running'}),
              ('output', {'stream': 'stdout', 'offset': 0, 'data': base64.b64encode(b'abc').decode()}),
              ('terminal', terminal)]
    if mode == 'wrong-output-digest': terminal['outputs']['stdout']['sha256'] = '0'*64
    if mode == 'missing-owner': terminal['owner_cleanup'].pop()
    if mode == 'same-owner': terminal['owner_cleanup'][1]['owner_pid'] = 101
    if mode == 'wrong-context': terminal['owner_cleanup'][1]['context_digest'] = 'c'*64
    if mode == 'not-quiescent': terminal['native_quiescent'] = False
    if mode == 'boolean-exit': terminal['returncode'] = True
    if mode == 'wrong-offset': frames[1][1]['offset'] = 1
    if mode == 'bad-base64': frames[1][1]['data'] = '%'
    if mode == 'bad-heartbeat': frames[0][1]['phase'] = []
    for sequence, (kind, payload) in enumerate(frames, 1):
        if mode == 'eof-before-terminal' and kind == 'terminal':
            service.close();control.recv();return
        frame = {'version': 1, 'epoch': EPOCH, 'request_id': request['request_id'],
                 'invocation_id': request['body']['invocation_id'], 'frame_sequence': sequence,
                 'kind': kind, 'payload': payload}
        if mode == 'boolean-version': frame['version'] = True
        if mode == 'wrong-epoch': frame['epoch'] = 'f'*32
        if mode == 'wrong-sequence': frame['frame_sequence'] = sequence+1
        if mode == 'wrong-invocation': frame['invocation_id'] = 'other'
        raw = json.dumps(frame, separators=(',', ':')).encode()
        if mode == 'unexpected-rights':
            descriptor = os.open('/dev/null', os.O_RDONLY)
            try: service.sendmsg([raw], [(socket.SOL_SOCKET, socket.SCM_RIGHTS, array('i', [descriptor]))])
            finally: os.close(descriptor)
        else:
            service.send(raw)
    control.recv()
    service.close()


@pytest.fixture
def setup_client():
    children = []
    resources = []
    def setup(mode='healthy'):
        event = multiprocessing.Event()
        budget = multiprocessing.Process(target=idle, args=(event,));budget.start()
        children.append((budget, event))
        service, client = socket.socketpair(socket.AF_UNIX, socket.SOCK_SEQPACKET)
        parent, child = multiprocessing.Pipe()
        process = multiprocessing.Process(target=serve, args=(service, client, child, parent, mode))
        process.start();children.append((process, None));child.close()
        assert parent.poll(5)
        pid = parent.recv()
        actual = module.CoordinatorClient(client, coordinator=owner.ProcessIdentity.observe(pid),
            budget_owner=owner.ProcessIdentity.observe(budget.pid),
            controller=owner.ProcessIdentity.observe(os.getpid()), epoch=EPOCH)
        resources.append((service, client, parent))
        return actual, parent
    yield setup
    for service, client, parent in resources:
        try: parent.send('stop')
        except (OSError, EOFError): pass
        service.close();client.close();parent.close()
    for process, event in children:
        if event is not None:event.set()
        process.join(2)
        if process.is_alive():process.terminate();process.join(2)
        assert not process.is_alive()


def run(client):
    return client.run_actual(invocation_id='actual-1', producer='runtime-smoke',
        profile='supported', control='baseline', absolute_deadline=time.monotonic()+2)


def test_authenticated_coordinator_stream_and_closed_terminal_are_parsed(setup_client):
    client, parent = setup_client()
    result = run(client)
    assert result.stdout == b'abc' and result.stderr == b'' and result.returncode == 0
    assert result.context_digest == CONTEXT and [row.role for row in result.cleanup] == ['issuer', 'custody']
    assert parent.poll(2)
    request = parent.recv()
    assert set(request['body']) == {'invocation_id', 'producer', 'profile', 'control'}
    assert request['request_id'] == client.last_request_id
    with pytest.raises(owner.OwnerAdmissionError, match='invalid or uncertain'):
        run(client)


@pytest.mark.parametrize('mode', ['wrong-output-digest', 'missing-owner', 'same-owner',
    'wrong-context', 'not-quiescent', 'boolean-exit', 'wrong-offset', 'bad-base64',
    'bad-heartbeat', 'boolean-version', 'wrong-epoch', 'wrong-sequence', 'wrong-invocation',
    'unexpected-rights', 'eof-before-terminal'])
def test_unclosed_or_malformed_response_cannot_be_retried_as_a_new_run(setup_client, mode):
    client, _parent = setup_client(mode)
    descriptors = len(list(Path('/proc/self/fd').iterdir()))
    with pytest.raises(module.OwnerOutcomeUncertain):
        run(client)
    assert client._connection.fileno() == -1
    assert len(list(Path('/proc/self/fd').iterdir())) == descriptors-1
    with pytest.raises(owner.OwnerAdmissionError, match='invalid or uncertain'):
        client.run_actual(invocation_id='another', producer='runtime-smoke', profile='supported',
            control='baseline', absolute_deadline=time.monotonic()+2)
