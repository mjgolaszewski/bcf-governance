"""Independent cleanup attempts; fake ports are orchestration controls only."""
from dataclasses import replace
import importlib
import json
import multiprocessing
import os
import socket
import struct
import threading
import time

import pytest

from test_owner_registration import installed as installed

owner = importlib.import_module('_bcf_owner_runtime.evidence_execution_owner')
registration = importlib.import_module('_bcf_owner_runtime.evidence_owner_registration')
control = importlib.import_module('_bcf_owner_runtime.evidence_owner_control')
CONTEXT = 'a'*64


def pair_for(binding, actual):
    with registration.bind_installed_execution_owner(binding):
        reserved = registration.reserve_owner_invocation(actual, required=True, timeout_seconds=10)
    return control.OwnerControlPair(reserved, context_digest=CONTEXT)


def closed(role):
    return {'contract': control.CONTRACT, 'role': role, 'context_digest': CONTEXT,
            'status': 'closed', 'execution_id': role+'.actual'}


@pytest.mark.parametrize('failed_role', ['issuer', 'custody'])
def test_each_cleanup_owner_is_attempted_when_the_other_fails(installed, monkeypatch, failed_role):
    binding, actual, _ = installed
    pair = pair_for(binding, actual)
    calls = []
    def call(role, _operation, **kwargs):
        calls.append(role)
        if role == failed_role: raise control.OwnerOutcomeUncertain('unreachable test port')
        return closed(role)
    monkeypatch.setattr(pair, '_call', call)
    assert pair.reconcile_owned() is False
    assert sorted(calls) == ['custody', 'issuer']
    assert set(pair._cleanup) == ({'issuer', 'custody'}-{failed_role})
    with pytest.raises(owner.OwnerAdmissionError): pair.verified_cleanup(CONTEXT)


def test_successful_owner_receipt_is_retained_and_not_replayed(installed, monkeypatch):
    binding, actual, _ = installed
    pair = pair_for(binding, actual)
    calls = [];fail = {'custody'}
    def call(role, _operation, **kwargs):
        calls.append(role)
        if role in fail: raise control.OwnerOutcomeUncertain('uncertain test port')
        return closed(role)
    monkeypatch.setattr(pair, '_call', call)
    assert pair.reconcile_owned() is False
    first = dict(pair._cleanup['issuer'])
    calls.clear();fail.clear()
    assert pair.reconcile_owned() is True
    assert calls == ['custody']
    assert pair.verified_cleanup(CONTEXT)[0] == first


def test_lost_prepare_without_ids_still_reconciles_both_contexts(installed, monkeypatch):
    binding, actual, _ = installed
    pair = pair_for(binding, actual)
    calls = []
    def call(role, operation, **kwargs):
        calls.append((role, operation, kwargs.get('execution_id')))
        if role == 'issuer': raise control.OwnerOutcomeUncertain('lost prepare outcome')
        return closed(role)
    monkeypatch.setattr(pair, '_call', call)
    assert pair.reconcile_owned() is False
    assert sorted(calls) == [('custody', 'reconcile_execution', None), ('issuer', 'reconcile_execution', None)]


def test_slow_owner_does_not_consume_the_other_owners_cleanup_window(installed, monkeypatch):
    binding, actual, _ = installed
    pair = pair_for(binding, actual)
    custody_started = threading.Event();observed = []
    def call(role, _operation, **kwargs):
        if role == 'issuer':
            observed.append(custody_started.wait(.3))
            raise control.OwnerOutcomeUncertain('slow issuer test port')
        custody_started.set()
        return closed(role)
    monkeypatch.setattr(pair, '_call', call)
    assert pair.reconcile_owned() is False
    assert observed == [True]
    assert set(pair._cleanup) == {'custody'}


def test_cleanup_deadline_is_finite_and_not_extended_by_reconciliation(installed, monkeypatch):
    binding, actual, _ = installed
    binding = replace(binding, absolute_deadline=time.monotonic()+1.4, cleanup_seconds=1)
    pair = pair_for(binding, actual)
    deadlines = []
    def call(role, _operation, **kwargs):
        deadlines.append(kwargs.get('cleanup_deadline'))
        raise control.OwnerOutcomeUncertain('unreachable test port')
    monkeypatch.setattr(pair, '_call', call)
    assert pair.reconcile_owned() is False
    assert len(deadlines) == 2 and all(type(value) is float for value in deadlines)
    assert deadlines[0] == deadlines[1] <= binding.absolute_deadline
    first = tuple(deadlines)
    time.sleep(1.05)
    assert pair.reconcile_owned() is False
    assert tuple(deadlines) == first


def cleanup_server(path, pipe):
    with socket.socket(socket.AF_UNIX) as listener:
        listener.bind(str(path));os.chmod(path,0o600);listener.listen(1)
        pipe.send(os.getpid())
        with listener.accept()[0] as connection:
            def receive(size):
                raw=b''
                while len(raw)<size:
                    part=connection.recv(size-len(raw));assert part
                    raw+=part
                return raw
            size,=struct.unpack('!I',receive(4))
            request=json.loads(receive(size));pipe.send(request)
            raw=json.dumps(closed('custody'),separators=(',',':')).encode()
            connection.sendall(struct.pack('!I',len(raw))+raw)
            pipe.recv()


def test_live_custody_cleanup_is_attempted_after_issuer_process_exits(installed, socket_root):
    binding, actual, children = installed
    parent, child = multiprocessing.Pipe()
    endpoint = socket_root/'cleanup.sock'
    process = multiprocessing.Process(target=cleanup_server,args=(endpoint,child))
    process.start()
    try:
        assert parent.poll(5)
        pid=parent.recv()
        binding=replace(binding,custody=owner.OwnerRegistration(endpoint,owner.ProcessIdentity.observe(pid)))
        pair=pair_for(binding,actual)
        children[0].terminate();children[0].join(2)
        assert pair.reconcile_owned() is False
        assert parent.poll(.5), 'live custody owner was never contacted'
        request=parent.recv()
        assert request['operation']=='reconcile_execution' and request['context_digest']==CONTEXT
        assert set(pair._cleanup)=={'custody'}
        with pytest.raises(owner.OwnerAdmissionError):pair.verified_cleanup(CONTEXT)
    finally:
        if process.is_alive():parent.send('stop');process.join(2)
        if process.is_alive():process.terminate();process.join(2)
        assert not process.is_alive()
        parent.close();child.close()


@pytest.mark.parametrize('change', ['digest','boolean-ordinal','zero-ordinal','extra-ordinal','route','deadline','nan'])
def test_owner_pair_refuses_mismatched_allocation_before_owner_connection(installed, change):
    binding, actual, _ = installed
    with registration.bind_installed_execution_owner(binding):
        reserved = registration.reserve_owner_invocation(actual, required=True, timeout_seconds=10)
    if change == 'digest':
        reserved = replace(reserved, allocation_digest='f'*64)
    elif change == 'boolean-ordinal':
        reserved = replace(reserved, ordinal=True)
    elif change == 'zero-ordinal':
        reserved = replace(reserved, ordinal=0)
    elif change == 'extra-ordinal':
        reserved = replace(reserved, ordinal=3)
    elif change == 'route':
        reserved = replace(reserved, actual=replace(actual, profile='undeclared'))
    elif change == 'deadline':
        reserved = replace(reserved, deadline=binding.absolute_deadline)
    else:
        reserved = replace(reserved, deadline=float('nan'))
    with pytest.raises(owner.OwnerAdmissionError, match='allocation'):
        control.OwnerControlPair(reserved, context_digest=CONTEXT)
