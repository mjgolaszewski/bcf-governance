"""Finite real-clock response budgets; fake I/O is not live owner authority."""
import importlib
import json
import os
import struct
import time
import pytest
from test_owner_registration import registration as _registration
owner=importlib.import_module('_bcf_owner_runtime.evidence_execution_owner')
class Connection:
    def __init__(self,dribble=False):
        raw=json.dumps({'status':'observed'}).encode();self.raw=struct.pack('!I',len(raw))+raw
        self.timeouts=[];self.sent=[];self.dribble=dribble
    def settimeout(self,value):self.timeouts.append(value)
    def sendall(self,raw):self.sent.append(raw)
    def recv(self,size):
        if self.dribble:time.sleep(.36);size=1
        part,self.raw=self.raw[:size],self.raw[size:];return part
    def close(self):pass

def session(connection,seconds=90):
    return owner.OwnerSession(connection,owner.ProcessIdentity.observe(os.getpid()),time.monotonic()+seconds)

def test_readiness_window_never_extends_absolute_allocation():
    connection=Connection();actual=session(connection)
    assert actual.request({'operation':'stage'},response_timeout_seconds=60)=={'status':'observed'}
    assert 59<connection.timeouts[0]<=60
    connection=Connection();actual=session(connection,seconds=2)
    actual.request({'operation':'stage'},response_timeout_seconds=60)
    assert 0<connection.timeouts[0]<=2

@pytest.mark.parametrize('value',[True,0,61,1.5,'60'])
def test_invalid_window_never_sends(value):
    connection=Connection();actual=session(connection)
    with pytest.raises(owner.OwnerAdmissionError,match='window'):
        actual.request({'operation':'stage'},response_timeout_seconds=value)
    assert connection.sent==[] and actual.delivery_uncertain is False

def test_dribble_cannot_renew_one_request_budget():
    connection=Connection(True);actual=session(connection,seconds=10);started=time.monotonic()
    with pytest.raises(owner.OwnerAdmissionError,match='deadline'):
        actual.request({'operation':'observe'},response_timeout_seconds=1)
    assert time.monotonic()-started<1.8 and actual.delivery_uncertain is True
    assert all(b<a for a,b in zip(connection.timeouts,connection.timeouts[1:]))
    with pytest.raises(owner.OwnerAdmissionError,match='uncertain'):
        actual.request({'operation':'observe'},response_timeout_seconds=60)


def test_complete_frame_after_deadline_is_still_uncertain(monkeypatch):
    connection=Connection();actual=session(connection)
    original=owner.ProcessIdentity.observe
    observations=[]
    def observe(pid):
        result=original(pid);observations.append(pid)
        if len(observations)==2:
            actual._request_deadline=time.monotonic()-1
        return result
    monkeypatch.setattr(owner.ProcessIdentity, 'observe', observe)
    with pytest.raises(owner.OwnerAdmissionError,match='deadline'):
        actual.request({'operation':'observe'})
    assert actual.delivery_uncertain is True
