"""Actual retained namespace and listener FD exchange, without providers."""
import importlib
import os
from pathlib import Path
import socket
import subprocess
import struct
import sys
import select
import hashlib
import time
from threading import Thread

import pytest

from test_closed_runtime_held import runtime_fixture, views, images, immutable, held, owner

listeners = importlib.import_module('_bcf_owner_runtime.evidence_loopback_listener')
relays = importlib.import_module('_bcf_owner_runtime.evidence_fixed_relay')
bridges = importlib.import_module('_bcf_owner_runtime.evidence_owner_peer_bridge')


@pytest.mark.parametrize('mode', ['direct', 'relay', 'byte_limit'])
def test_actual_held_peer_uses_retained_fixed_listener(tmp_path, socket_root, mode):
    through_relay = mode != 'direct'
    runtime, binary, library_path, pins = runtime_fixture(tmp_path)
    source_root = tmp_path/'source'; source_root.mkdir()
    (source_root/'application.py').write_text('''import socket,os
for fd in range(3,64):
 try:os.fstat(fd)
 except OSError:pass
 else:raise AssertionError('bootstrap descriptor leaked')
with socket.socket(socket.AF_INET,socket.SOCK_STREAM) as connection:
 connection.settimeout(3);connection.connect(('127.0.0.2',443))
 connection.sendall(b'fixed-request')
 assert connection.recv(64)==b'fixed-response'
with socket.socket() as connection:
 connection.settimeout(.1)
 try:connection.connect(('1.1.1.1',443))
 except OSError:pass
 else:raise AssertionError('external route exposed')
for role in ('issuer','custody'):
 with socket.socket(socket.AF_UNIX) as connection:
  connection.settimeout(5);connection.connect('/run/bcf/'+role+'.sock')
  connection.sendall(b'peer-check');assert connection.recv(64)==b'peer-admitted'
print('fixed-network-running',flush=True)
''')
    if mode == 'byte_limit':
        application=source_root/'application.py'
        application.write_text(application.read_text().replace(
            "assert connection.recv(64)==b'fixed-response'",
            "assert connection.recv(64)==b''"))
    source = views.inspect_view(source_root, ('application.py',))
    image = images.compose_execution_image(source, runtime, destination=tmp_path/'image', executable=binary)
    ready = socket.socket(socket.AF_UNIX)
    ready.bind(str(socket_root/'ready.sock')); os.chmod(socket_root/'ready.sock',0o600);ready.listen(1)
    owner_listeners=[]
    for role in ('issuer','custody'):
        channel=socket.socket(socket.AF_UNIX)
        channel.bind(str(socket_root/(role+'.sock')));os.chmod(socket_root/(role+'.sock'),0o600)
        channel.listen(1);channel.settimeout(10);owner_listeners.append((role,channel))
    owner_workers=[];owner_channels={}
    frozen = plan = process = listener = relay = upstream = server = None
    try:
        frozen = immutable.freeze_execution_image(image.image, deadline=time.monotonic()+30,
                                                   ready_listener=ready,workload_listeners=tuple(owner_listeners))
        net = os.readlink('/proc/self/fd/'+str(frozen.network_fd))
        assert net != os.readlink('/proc/self/ns/net')
        listener = listeners.bind_fixed_loopback(frozen,address='127.0.0.2',port=443,
                                                 deadline=time.monotonic()+10)
        listener.settimeout(10)
        if through_relay:
            upstream=socket.socket();upstream.bind(('127.0.0.1',0));upstream.listen(1);upstream.settimeout(10)
            def serve():
                connection,_=upstream.accept()
                with connection:
                    connection.settimeout(5)
                    received=connection.recv(64)
                    if mode == 'byte_limit':
                        assert received == b''
                    else:
                        assert received==b'fixed-request'
                        connection.sendall(b'fixed-response')
            server=Thread(target=serve);server.start()
            relay=relays.FixedServiceRelay(listener,
                relays.FixedEndpoint(*upstream.getsockname()),access_deadline=time.monotonic()+15,
                cleanup_deadline=time.monotonic()+20,maximum_connections=1,
                maximum_bytes=12 if mode == 'byte_limit' else 1024)

        plan = held.prepare_closed_held_python(frozen,image,ready_listener=ready,
            script='application.py',library_path=library_path,retained_network=True)
        process = subprocess.Popen(plan.command,stdin=subprocess.PIPE,stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,text=True,pass_fds=plan.bootstrap_descriptors)
        assert select.select([ready],[],[],5)[0]
        observation = plan.observe(supervisor=owner.ProcessIdentity.observe(process.pid),
                                   deadline=time.monotonic()+15)
        assert dict(observation.identity.namespaces)['net']==net
        context=hashlib.sha256((source.digest+str(observation.identity)).encode()).hexdigest()
        owner_program="""import sys,os,socket,types,importlib
package=types.ModuleType('_owner_native');package.__path__=[sys.argv[1]];sys.modules[package.__name__]=package
bridge=importlib.import_module(package.__name__+'.evidence_owner_peer_bridge')
identity=importlib.import_module(package.__name__+'.evidence_execution_owner').ProcessIdentity
listener=socket.socket(fileno=int(sys.argv[2]));channel=socket.socket(fileno=int(sys.argv[3]))
client=bridge.OwnerPeerClient(channel,coordinator=identity.observe(int(sys.argv[4])),context_digest=sys.argv[5],access_deadline=float(sys.argv[6]))
channel.send(b'owner-ready')
listener.settimeout(10)
connection,_=listener.accept()
with connection:
 connection.settimeout(5);client.authenticate(connection)
 assert connection.recv(64)==b'peer-check'
 client.authenticate(connection);connection.sendall(b'peer-admitted')
listener.close();channel.close();print('owner-closed',flush=True)
""".replace('\n+','\n')
        if mode=='direct':
            from test_owner_peer_bridge_controls import exercise_rejected_frames
            exercise_rejected_frames(plan,context,time.monotonic()+30,tmp_path)
        identities={};bridge_deadline=time.monotonic()+15
        for role,channel in owner_listeners:
            parent,child=socket.socketpair(socket.AF_UNIX,socket.SOCK_SEQPACKET)
            worker=subprocess.Popen([sys.executable,'-I','-B','-c',owner_program,
                str(Path(bridges.__file__).parent),str(channel.fileno()),str(child.fileno()),
                str(os.getpid()),context,str(bridge_deadline)],stdin=subprocess.DEVNULL,
                stdout=subprocess.PIPE,stderr=subprocess.PIPE,pass_fds=(channel.fileno(),child.fileno()))
            child.close();parent.settimeout(5)
            assert parent.recv(64)==b'owner-ready'
            identities[role]=owner.ProcessIdentity.observe(worker.pid)
            owner_workers.append(worker);owner_channels[role]=parent
        verifier=bridges.OwnerPeerBridge(plan,context_digest=context,owners=identities,
            channels=owner_channels,access_deadline=bridge_deadline)

        plan.release()
        if not through_relay:
            try:
                connection, peer = listener.accept()
            except TimeoutError:
                if process.poll() is not None:
                    stdout,stderr=process.communicate(timeout=5)
                    raise AssertionError((process.returncode,stdout,stderr)) from None
                raise
            with connection:
                connection.settimeout(5)
                assert peer[0]=='127.0.0.1'
                assert connection.recv(64)==b'fixed-request'
                connection.sendall(b'fixed-response')
        for role in ('issuer','custody'):
            verifier.handle_once(role);verifier.handle_once(role)
        stdout,stderr=process.communicate(timeout=10)
        if relay is not None:
            server.join(5);assert not server.is_alive()
            relay.close()
            accepted,byte_count,failed=relay.result()
            assert accepted==1
            if mode == 'byte_limit':
                assert byte_count==0 and failed is True
            else:
                assert byte_count==27 and failed is False
        assert process.returncode==0,stderr
        assert stdout=='fixed-network-running\n'
        for worker in owner_workers:
            output,error=worker.communicate(timeout=5)
            assert worker.returncode==0,error
            assert output==b'owner-closed\n'
        assert not Path('/proc',str(observation.identity.pid)).exists()
    finally:
        if process is not None and process.poll() is None:
            process.kill();process.communicate(timeout=5)
        for _role,channel in owner_listeners:channel.close()
        for channel in owner_channels.values():channel.close()
        for worker in owner_workers:
            if worker.poll() is None:worker.kill()
            worker.communicate(timeout=5)
        if relay is not None:relay.close()
        if upstream is not None:upstream.close()
        if server is not None:server.join(11);assert not server.is_alive()
        if listener is not None:listener.close()
        if plan is not None:plan.close()
        ready.close()
        if frozen is not None:
            netfd=frozen.network_fd;frozen.close()
            with pytest.raises(OSError):os.fstat(netfd)
        assert all(views._read_regular(Path(path))==pin for path,pin in pins.items())


@pytest.mark.parametrize('address,port', [('0.0.0.0',443),('127.0.0.2',80),('1.1.1.1',443)])
def test_general_listener_requests_are_rejected_before_setup(address,port):
    with pytest.raises(owner.OwnerAdmissionError):
        listeners.bind_fixed_loopback(None,address=address,port=port,deadline=time.monotonic()+10)
