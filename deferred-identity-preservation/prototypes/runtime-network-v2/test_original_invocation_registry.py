"""Real held image/guardian/keeper; synthetic owner metadata, no provider grant."""
from dataclasses import replace
import fcntl
import importlib
import json
import os
from pathlib import Path
import select
import socket
import subprocess
import sys
import time

import pytest

from test_closed_runtime_held import runtime_fixture, views, images, immutable, held, owner

registry_module = importlib.import_module('_bcf_owner_runtime.evidence_invocation_registry')
keepers = importlib.import_module('_bcf_owner_runtime.evidence_lease_keeper')
wire = importlib.import_module('_bcf_owner_runtime.evidence_registry_channel')


def _idle(*descriptors):
    script = "import os,sys;[os.fstat(int(v)) for v in sys.argv[1:]];print('ready',flush=True);sys.stdin.buffer.read()"
    process = subprocess.Popen([sys.executable, '-I', '-B', '-c', script,
        *[str(value) for value in descriptors]], stdin=subprocess.PIPE,
        stdout=subprocess.PIPE, stderr=subprocess.PIPE, pass_fds=descriptors)
    assert select.select([process.stdout], [], [], 5)[0]
    assert process.stdout.readline() == b'ready\n'
    return process


def _rpc_owner(registry, listener, held_pid):
    parent, child = socket.socketpair(socket.AF_UNIX, socket.SOCK_SEQPACKET)
    attacker = child.dup()
    program = """import importlib,json,os,socket,sys,types
package=types.ModuleType('_registry_owner');package.__path__=[sys.argv[1]];sys.modules[package.__name__]=package
wire=importlib.import_module(package.__name__+'.evidence_registry_channel')
identity=importlib.import_module(package.__name__+'.evidence_execution_owner').ProcessIdentity
os.fstat(int(sys.argv[2]));connection=socket.socket(fileno=int(sys.argv[3]))
client=wire.RegistryOwnerClient(connection,coordinator=identity.observe(int(sys.argv[4])),context=sys.argv[5],cleanup_deadline=float(sys.argv[6]))
manifest=sys.argv[7];peer=int(sys.argv[8]);admission=None
print('ready',flush=True)
for line in sys.stdin:
 command=json.loads(line)
 try:
  if command['operation']=='admit':admission=client.admit(manifest_path=manifest,held_pid=peer)
  elif command['operation']=='recheck':client.recheck(admission,cleanup=command['cleanup'])
  elif command['operation']=='recover':client.recover(coordinator_lifetime=admission.coordinator_lifetime,execution_id=command['execution_id'])
  elif command['operation']=='native_closed':client.native_closed(admission)
  elif command['operation']=='exhaust_cleanup':
   for _ in range(wire.MAX_QUERIES-client._sequence+1):client.recheck(admission,cleanup=True)
  elif command['operation']=='forged_native':client._query('native_closed',{'admission':__import__('dataclasses').asdict(admission),'native_returncode':0})
  else:raise AssertionError(command)
  assert admission.context==sys.argv[5]
  print('observed',flush=True)
 except Exception:
  print('refused',flush=True);sys.stdin.read();break
"""
    process = subprocess.Popen([sys.executable, '-I', '-B', '-c', program,
        str(Path(wire.__file__).parent),str(listener.fileno()),str(child.fileno()),
        str(os.getpid()),registry.admission.context,str(registry.admission.cleanup_deadline),
        str(registry.manifest_path),str(held_pid)],stdin=subprocess.PIPE,
        stdout=subprocess.PIPE,stderr=subprocess.PIPE,pass_fds=(listener.fileno(),child.fileno()))
    child.close()
    assert select.select([process.stdout],[],[],5)[0]
    assert process.stdout.readline()==b'ready\n'
    return process,parent,attacker


def _rpc_command(process,server,operation,**fields):
    process.stdin.write(json.dumps({'operation':operation,**fields}).encode()+b'\n');process.stdin.flush()
    server.handle_once()
    assert select.select([process.stdout],[],[],5)[0]
    assert process.stdout.readline()==b'observed\n'


def _blocked(path):
    descriptor = os.open(path, os.O_RDWR)
    try:
        with pytest.raises(BlockingIOError):
            fcntl.flock(descriptor, fcntl.LOCK_EX | fcntl.LOCK_NB)
    finally:
        os.close(descriptor)


@pytest.mark.parametrize('mode', ['direct', 'rpc', 'rpc-budget'])
def test_registry_uses_original_kernel_allocation_and_actual_native_closure(tmp_path, socket_root, mode):
    budget = _idle()
    processes = [budget]
    role_processes = {}; raw_channels = {}; servers = {}; attackers = {}
    runtime, binary, library_path, _pins = runtime_fixture(tmp_path)
    source = tmp_path / 'source'; source.mkdir()
    (source / 'application.py').write_text("print('registered-runtime',flush=True)\n")
    view = views.inspect_view(source, ('application.py',))
    image = images.compose_execution_image(view, runtime, destination=tmp_path/'image', executable=binary)
    listeners = {}
    for role in ('issuer', 'custody'):
        listener = socket.socket(socket.AF_UNIX)
        listener.bind(str(socket_root/(role+'.sock')))
        os.chmod(socket_root/(role+'.sock'), 0o600); listener.listen(1)
        listeners[role] = listener
    ready = socket.socket(socket.AF_UNIX);ready.bind(str(socket_root/'ready.sock'))
    os.chmod(socket_root/'ready.sock',0o600);ready.listen(1)
    frozen = plan = keeper = registry = None
    lease = -1
    try:
        frozen = immutable.freeze_execution_image(image.image, deadline=time.monotonic()+30,
            ready_listener=ready, workload_listeners=tuple(listeners.items()))
        plan = held.prepare_closed_held_python(frozen, image, ready_listener=ready,
            script='application.py', library_path=library_path)
        lock = tmp_path/'original.synthetic.lock'
        lease = os.open(lock, os.O_RDWR|os.O_CREAT|os.O_EXCL,0o600)
        fcntl.flock(lease,fcntl.LOCK_EX)
        keeper_root=tmp_path/'keeper';keeper_root.mkdir(mode=0o700)
        keeper=keepers.ExecutionLeaseKeeper(lease_descriptors=(lease,), evidence_root=keeper_root,
            timeout_seconds=120 if mode=='rpc-budget' else 20, cleanup_seconds=5,
            protected_budget_owner=owner.ProcessIdentity.observe(budget.pid),
            bootstrap_descriptors=plan.bootstrap_descriptors)
        os.close(lease);lease=-1
        keeper.start(plan.command,cwd=tmp_path,environment={
            'PATH':'/usr/bin:/bin','LANG':'C.UTF-8','PYTHONDONTWRITEBYTECODE':'1'})
        assert select.select([ready],[],[],5)[0]
        pending=keeper.status();assert pending['state']=='pending'
        observation=plan.observe(supervisor=owner.ProcessIdentity.observe(pending['native_supervisor_pid']),
                                  deadline=time.monotonic()+5)
        root=tmp_path/'registry';root.mkdir(mode=0o700)
        registry=registry_module.ActualInvocationRegistry(root=root,plan=plan,keeper=keeper,
            consuming_controller=owner.ProcessIdentity.observe(budget.pid),
            protected_budget_owner=owner.ProcessIdentity.observe(budget.pid),tenant='bcf239-qualification',
            listeners=listeners,producer='real-fixture',profile='closed-runtime',control='original-registry')
        assert registry.admission.context==keeper.context_digest
        assert registry.admission.access_deadline==keeper.access_deadline
        assert registry.admission.cleanup_deadline==keeper.deadline
        assert registry.manifest_path.stat().st_mode & 0o777==0o400
        with pytest.raises(owner.OwnerAdmissionError):
            registry.admit('issuer',context=registry.admission.context,
                manifest_path=str(registry.manifest_path),held_pid=observation.identity.pid)
        identities={}
        for role,listener in listeners.items():
            if mode in ('rpc', 'rpc-budget'):
                process,channel,attacker=_rpc_owner(registry,listener,observation.identity.pid)
                raw_channels[role]=channel;attackers[role]=attacker
            else:
                process=_idle(listener.fileno())
            processes.append(process);role_processes[role]=process
            identities[role]=owner.ProcessIdentity.observe(process.pid)
        with pytest.raises(owner.OwnerAdmissionError):
            registry.bind_owners({'issuer':identities['issuer'],'custody':identities['issuer']})
        registry.bind_owners(identities)
        with pytest.raises(owner.OwnerAdmissionError):registry.bind_owners(identities)
        if mode in ('rpc', 'rpc-budget'):
            for role,channel in raw_channels.items():
                servers[role]=wire.RegistryOwnerChannel(registry,role=role,channel=channel)
            with pytest.raises(owner.OwnerAdmissionError):
                wire.RegistryOwnerChannel(registry,role='issuer',channel=raw_channels['issuer'])
        for role in identities:
            if mode in ('rpc', 'rpc-budget'):_rpc_command(role_processes[role],servers[role],'admit')
            admitted=registry.admit(role,context=registry.admission.context,
                manifest_path=str(registry.manifest_path),held_pid=observation.identity.pid)
            assert admitted is registry.admission
            with pytest.raises(owner.OwnerAdmissionError):
                registry.admit(role,context='0'*64,
                    manifest_path=str(registry.manifest_path),held_pid=observation.identity.pid)
            with pytest.raises(owner.OwnerAdmissionError):
                registry.admit(role,context=admitted.context,
                    manifest_path='/candidate/selected.json',held_pid=observation.identity.pid)
            with pytest.raises(owner.OwnerAdmissionError):
                registry.admit(role,context=admitted.context,
                    manifest_path=str(registry.manifest_path),held_pid=budget.pid)
            with pytest.raises(owner.OwnerAdmissionError):
                registry.recheck(role,replace(admitted,access_deadline=admitted.access_deadline+60),cleanup=False)
            registry.recheck(role,admitted,cleanup=False)
            if mode in ('rpc', 'rpc-budget'):_rpc_command(role_processes[role],servers[role],'recheck',cleanup=False)
            registry.bind_execution(role,role+'.original-execution')
            with pytest.raises(owner.OwnerAdmissionError):registry.bind_execution(role,role+'.replacement')
            with pytest.raises(owner.OwnerAdmissionError):registry.native_closed(role,admitted)
        (source/'application.py').write_text("raise AssertionError('host source escaped freeze')\n")
        registry.recheck('issuer',registry.admission,cleanup=False)
        plan.release()
        deadline=time.monotonic()+5
        while True:
            terminal=keeper.status()
            if terminal['state']!='pending':break
            assert time.monotonic()<deadline
            time.sleep(.02)
        assert terminal['state']=='native_closed',terminal
        assert terminal['returncode']==0 and terminal['stdout']=='registered-runtime\n'
        assert terminal['stderr']==''
        for role in identities:
            registry.native_closed(role,registry.admission)
            if mode in ('rpc', 'rpc-budget'):
                _rpc_command(role_processes[role],servers[role],'native_closed')
                _rpc_command(role_processes[role],servers[role],'recover',execution_id=role+'.original-execution')
            assert registry.recover(role,context=registry.admission.context,
                coordinator_lifetime=registry.admission.coordinator_lifetime,
                execution_id=role+'.original-execution') is registry.admission
            with pytest.raises(owner.OwnerAdmissionError):
                registry.recover(role,context=registry.admission.context,
                    coordinator_lifetime=registry.admission.coordinator_lifetime,
                    execution_id=role+'.candidate-execution')
        _blocked(lock)  # Metadata/native closure has released no physical lease.
        if mode=='rpc-budget':
            process=role_processes['issuer'];server=servers['issuer']
            process.stdin.write(b'{"operation":"exhaust_cleanup"}\n');process.stdin.flush()
            remaining=wire.MAX_QUERIES-server._sequence
            for _ in range(remaining):server.handle_once()
            assert server._sequence==wire.MAX_QUERIES
            with pytest.raises(owner.OwnerAdmissionError,match='exhausted'):
                server.handle_once()
            assert select.select([process.stdout],[],[],5)[0]
            assert process.stdout.readline()==b'refused\n'
            _blocked(lock)  # Exhaustion and native Q still release no lease.
            return
        original=registry.manifest_path.read_bytes()
        registry.manifest_path.chmod(0o600);registry.manifest_path.write_bytes(b'forged')
        with pytest.raises(owner.OwnerAdmissionError):
            registry.recheck('issuer',registry.admission,cleanup=True)
        registry.manifest_path.write_bytes(original);registry.manifest_path.chmod(0o400)
        assert registry.held is True
        with pytest.raises(owner.OwnerAdmissionError,match='HOLD'):
            registry.recheck('issuer',registry.admission,cleanup=False)
        registry.recheck('issuer',registry.admission,cleanup=True)
        _blocked(lock)
        if mode in ('rpc', 'rpc-budget'):
            wrong_sender={'schema':wire.SCHEMA,'operation':'recheck',
                'sequence':servers['issuer']._sequence+1,'nonce':os.urandom(16).hex(),
                'context':registry.admission.context,'body':{
                    'admission':__import__('dataclasses').asdict(registry.admission),'cleanup':True}}
            attackers['issuer'].send(json.dumps(wrong_sender).encode())
            with pytest.raises(owner.OwnerAdmissionError,match='registered'):
                servers['issuer'].handle_once()
            process=role_processes['custody']
            process.stdin.write(b'{"operation":"forged_native"}\n');process.stdin.flush()
            with pytest.raises(owner.OwnerAdmissionError,match='wire operation'):
                servers['custody'].handle_once()
            assert select.select([process.stdout],[],[],5)[0]
            assert process.stdout.readline()==b'refused\n'
            assert registry.held is True;_blocked(lock)
        registry.close();_blocked(lock)
    finally:
        for server in servers.values():server.close()
        for channel in raw_channels.values():channel.close()
        for attacker in attackers.values():attacker.close()
        if lease>=0:os.close(lease)
        if registry is not None:registry.close()
        if plan is not None:plan.close()
        if keeper is not None:
            if keeper.process.poll() is None:
                try:
                    keeper.cancel();deadline=time.monotonic()+7
                    while keeper.status()['state']=='pending':
                        assert time.monotonic()<deadline
                        time.sleep(.02)
                finally:
                    # This is only the synthetic no-provider fixture lease.
                    keeper.process.kill();keeper.process.communicate(timeout=5)
        for process in processes:
            if process.poll() is None:
                try:process.communicate(input=b'',timeout=5)
                except subprocess.TimeoutExpired:process.kill();process.communicate(timeout=5)
            else:process.communicate(timeout=5)
        if frozen is not None:frozen.close()
        ready.close()
        for listener in listeners.values():listener.close()
