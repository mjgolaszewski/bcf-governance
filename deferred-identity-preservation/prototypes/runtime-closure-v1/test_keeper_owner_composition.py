"""Synthetic lease/native core/real owner-channel composition, NOT provider proof."""
import fcntl
import importlib
import json
import multiprocessing
import os
from pathlib import Path
import socket
import struct
import sys
import time
import pytest
from test_owner_registration import registration as registration
owner=importlib.import_module('_bcf_owner_runtime.evidence_execution_owner')
control=importlib.import_module('_bcf_owner_runtime.evidence_owner_control')
keeper_module=importlib.import_module('_bcf_owner_runtime.evidence_lease_keeper')
CONTEXT='a'*64


def synthetic_owner(endpoint,role,ready,stop,drop):
    with socket.socket(socket.AF_UNIX) as listener:
        listener.bind(str(endpoint));os.chmod(endpoint,0o600);listener.listen(1)
        ready.send(os.getpid())
        with listener.accept()[0] as channel:
            def read(count):
                raw=b''
                while len(raw)<count:
                    part=channel.recv(count-len(raw));assert part;raw+=part
                return raw
            size,=struct.unpack('!I',read(4));request=json.loads(read(size))
            assert request['operation']=='reconcile_execution' and request['role']==role
            if not drop:
                response={'contract':control.CONTRACT,'role':role,'context_digest':CONTEXT,
                          'status':'closed','execution_id':role+'.synthetic'}
                raw=json.dumps(response,separators=(',',':')).encode()
                channel.sendall(struct.pack('!I',len(raw))+raw)
        stop.recv()


def idle_budget(ready,stop):
    ready.send(os.getpid());stop.recv()


def blocked(path):
    probe=os.open(path,os.O_RDWR)
    try:
        with pytest.raises(BlockingIOError):fcntl.flock(probe,fcntl.LOCK_EX|fcntl.LOCK_NB)
    finally:os.close(probe)


@pytest.mark.parametrize('late_binding',[False,True])
@pytest.mark.parametrize('lost_custody',[False,True])
def test_only_native_closure_and_both_authenticated_roles_release_synthetic_lease(tmp_path,socket_root,lost_custody,late_binding):
    children=[];stops=[];records=[];keeper=None;lease=-1
    try:
        for role in ('issuer','custody'):
            ready_parent,ready_child=multiprocessing.Pipe(False)
            stop_parent,stop_child=multiprocessing.Pipe()
            endpoint=socket_root/(role+'-keeper.sock')
            process=multiprocessing.Process(target=synthetic_owner,args=(endpoint,role,ready_child,stop_child,lost_custody and role=='custody'))
            process.start();children.append(process);stops.append(stop_parent)
            assert ready_parent.poll(5);pid=ready_parent.recv();ready_parent.close();ready_child.close();stop_child.close()
            records.append(owner.OwnerRegistration(endpoint,owner.ProcessIdentity.observe(pid)))
        ready_parent,ready_child=multiprocessing.Pipe(False)
        stop_parent,stop_child=multiprocessing.Pipe()
        budget=multiprocessing.Process(target=idle_budget,args=(ready_child,stop_child))
        budget.start();children.append(budget);stops.append(stop_parent)
        assert ready_parent.poll(5);budget_pid=ready_parent.recv();ready_parent.close();ready_child.close();stop_child.close()
        # All synthetic owner/budget peers were born BEFORE this OFD exists.
        path=tmp_path/'synthetic.lock';lease=os.open(path,os.O_CREAT|os.O_EXCL|os.O_RDWR,0o600);fcntl.flock(lease,fcntl.LOCK_EX)
        evidence=tmp_path/'keeper';evidence.mkdir(mode=0o700)
        keeper=keeper_module.ExecutionLeaseKeeper(lease_descriptors=(lease,),context_digest=None if late_binding else CONTEXT,
            evidence_root=evidence,timeout_seconds=2,cleanup_seconds=1,
            protected_budget_owner=owner.ProcessIdentity.observe(budget_pid))
        os.close(lease);lease=-1;blocked(path)
        script="import time;time.sleep(.6);print('synthetic-native')" if late_binding else "print('synthetic-native')"
        keeper.start([sys.executable,'-I','-B','-c',script],cwd=tmp_path,environment={'PATH':'/usr/bin:/bin','LANG':'C.UTF-8','PYTHONDONTWRITEBYTECODE':'1'})
        if late_binding:
            assert keeper.context_digest is None
            keeper.bind_actual_context(CONTEXT)
            assert keeper.context_digest==CONTEXT
        with pytest.raises(keeper_module.LeaseCustodyError):keeper.bind_actual_context('b'*64)
        deadline=time.monotonic()+8
        while True:
            terminal=keeper.status()
            if terminal['state']!='pending':break
            assert time.monotonic()<deadline
            time.sleep(.02)
        assert terminal['state']=='native_closed' and terminal['returncode']==0
        assert terminal['stdout']=='synthetic-native\n' and terminal['stderr']==''
        blocked(path)
        scope=registration.RequiredOwnerScope(tmp_path,frozenset({'synthetic'}),frozenset({'mechanical'}),frozenset({'baseline'}),(registration.OwnerInvocationRoute('synthetic','mechanical','baseline'),))
        binding=registration.InstalledOwnerBinding(owner.ProcessIdentity.observe(os.getpid()),scope,*records,time.monotonic()+12,1,3)
        actual=registration.ActualInvocationIdentity(tmp_path,'synthetic','mechanical','baseline')
        with registration.bind_installed_execution_owner(binding):
            reserved=registration.reserve_owner_invocation(actual,required=True,timeout_seconds=5)
        pair=control.OwnerControlPair(reserved,context_digest=CONTEXT)
        if lost_custody:
            assert pair.reconcile_owned() is False
            with pytest.raises(owner.OwnerAdmissionError):keeper.release_after_owner_cleanup(pair)
            blocked(path)
            keeper.disconnect();time.sleep(.1)
            assert keeper.process.poll() is None
            blocked(path)
        else:
            assert pair.reconcile_owned() is True
            keeper.release_after_owner_cleanup(pair)
            assert keeper.released and keeper.process.poll()==0
            probe=os.open(path,os.O_RDWR)
            try:fcntl.flock(probe,fcntl.LOCK_EX|fcntl.LOCK_NB)
            finally:os.close(probe)
    finally:
        if lease>=0:os.close(lease)
        if keeper is not None:
            keeper.disconnect()
            if keeper.process.poll() is None:keeper.process.terminate()
            keeper.process.communicate(timeout=5)
        for stop in stops:
            try:stop.send('done')
            except (BrokenPipeError,EOFError):pass
            stop.close()
        for process in children:
            process.join(2)
            if process.is_alive():process.terminate();process.join(2)
            assert not process.is_alive()
