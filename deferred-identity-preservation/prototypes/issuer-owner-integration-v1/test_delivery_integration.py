"""Actual held peer, issuer listener, Root registry and peer bridge; no secrets."""
from dataclasses import asdict
import importlib
import json
import os
from pathlib import Path
import select
import socket
import subprocess
import sys
import sysconfig
import time
import pytest

from test_closed_runtime_held import runtime_fixture, views, images, immutable, held, owner
from test_original_invocation_registry import _idle, _blocked

registry_module = importlib.import_module('_bcf_owner_runtime.evidence_invocation_registry')
keepers = importlib.import_module('_bcf_owner_runtime.evidence_lease_keeper')
wire = importlib.import_module('_bcf_owner_runtime.evidence_registry_channel')
peers = importlib.import_module('_bcf_owner_runtime.evidence_owner_peer_bridge')
dispatch = importlib.import_module('_bcf_owner_runtime.evidence_serial_dispatch')


@pytest.mark.parametrize('wrong_peer,driver_mode,unknown_cleanup,policy_probe,factory_mode', [(False, False, False, False, False), (True, False, False, False, False), (False, True, False, False, False), (False, True, True, False, False), (False, True, False, True, False), (False, True, False, False, True)], ids=['manual-positive', 'manual-wrong-peer', 'driver-positive', 'driver-unknown-cleanup', 'driver-policy-probe', 'driver-factory-preflight'])
def test_real_held_peer_receives_only_through_original_delivery(tmp_path, socket_root, wrong_peer, driver_mode, unknown_cleanup, policy_probe, factory_mode, factory_admin_material):
    budget = _idle()
    processes = [budget]
    channels = []
    listeners = {}
    frozen = plan = keeper = registry = None
    ready = socket.socket(socket.AF_UNIX)
    lease = -1
    try:
        runtime, binary, library_path, _pins = runtime_fixture(tmp_path)
        if sys.version_info >= (3, 14):
            # This standalone build statically links the modules used by the
            # fixture. Preserve its actual extension-directory landmark too;
            # otherwise CPython emits an exec_prefix warning at startup.
            landmark = Path(sysconfig.get_config_var('DESTSHARED')) / ('_dbm' + sysconfig.get_config_var('EXT_SUFFIX'))
            raw, mode = views._read_regular(landmark)
            relative = str(landmark).removeprefix('/')
            target = runtime.root / relative
            target.parent.mkdir(parents=True, exist_ok=True)
            target.write_bytes(raw); target.chmod(mode)
            runtime = views.inspect_view(runtime.root, tuple(row[0] for row in runtime.manifest) + (relative,))
            (tmp_path / 'runtime-landmark.json').write_text(json.dumps({'origin': str(landmark),
                'sha256': __import__('hashlib').sha256(raw).hexdigest(), 'bytes': len(raw), 'mode': mode}))
        source = tmp_path / 'source'; source.mkdir()
        (source / 'application.py').write_text("import socket\nfor role in ('issuer','custody'):\n with socket.socket(socket.AF_UNIX) as c:\n  c.connect('/run/bcf/'+role+'.sock');c.sendall(b'G');assert c.recv(64)==b'qualified-nonsecret'\nprint('original-delivery',flush=True)\n")
        original_source = views.inspect_view(source, ('application.py',))
        image = images.compose_execution_image(original_source,
            runtime, destination=tmp_path / 'image', executable=binary)
        for role in ('issuer', 'custody'):
            listener = socket.socket(socket.AF_UNIX)
            listener.bind(str(socket_root / (role + '.sock')))
            os.chmod(socket_root / (role + '.sock'), 0o600); listener.listen(1)
            listeners[role] = listener
        ready.bind(str(socket_root / 'ready.sock'))
        os.chmod(socket_root / 'ready.sock', 0o600); ready.listen(1)
        frozen = immutable.freeze_execution_image(image.image, deadline=time.monotonic()+30,
            ready_listener=ready, workload_listeners=tuple(listeners.items()))
        plan = held.prepare_closed_held_python(frozen, image, ready_listener=ready,
            script='application.py', library_path=library_path)
        lock = tmp_path / 'synthetic.lock'; lease = os.open(lock, os.O_CREAT|os.O_RDWR, 0o600)
        import fcntl
        fcntl.flock(lease, fcntl.LOCK_EX)
        keeper_root = tmp_path / 'keeper'; keeper_root.mkdir(mode=0o700)
        keeper = keepers.ExecutionLeaseKeeper(evidence_root=keeper_root, lease_descriptors=(lease,),
            timeout_seconds=60, cleanup_seconds=20, protected_budget_owner=owner.ProcessIdentity.observe(budget.pid),
            bootstrap_descriptors=plan.bootstrap_descriptors)
        os.close(lease); lease = -1
        keeper.start(plan.command, cwd=tmp_path, environment={'PATH':'/usr/bin:/bin','LANG':'C.UTF-8','PYTHONDONTWRITEBYTECODE':'1'})
        assert select.select([ready], [], [], 5)[0]
        pending = keeper.status()
        observation = plan.observe(supervisor=owner.ProcessIdentity.observe(pending['native_supervisor_pid']), deadline=time.monotonic()+5)
        root = tmp_path / 'registry'; root.mkdir(mode=0o700)
        registry = registry_module.ActualInvocationRegistry(root=root, plan=plan, keeper=keeper,
            consuming_controller=owner.ProcessIdentity.observe(budget.pid), protected_budget_owner=owner.ProcessIdentity.observe(budget.pid),
            tenant='bcf239-4d2f529b2ec2' if driver_mode else 'bcf239-qualification',
            listeners=listeners, producer='delivery-fixture', profile='closed-runtime', control='actual-peer')
        owners = {}; registry_channels = {}; peer_channels = {}; role_processes = {}; endpoints = {}
        for role, listener in listeners.items():
            parent, child = socket.socketpair(socket.AF_UNIX, socket.SOCK_SEQPACKET)
            peer_parent, peer_child = socket.socketpair(socket.AF_UNIX, socket.SOCK_SEQPACKET)
            channels.extend((parent, peer_parent))
            endpoint = socket_root / (role + '.control.sock'); endpoints[role] = endpoint
            extra_arguments = [str(endpoint), role] if driver_mode else []
            if unknown_cleanup:
                extra_arguments.append('refuse-cleanup')
            elif policy_probe:
                extra_arguments.append('policy-probe')
            elif factory_mode:
                extra_arguments.append('factory-preflight')
            credential_descriptor = None
            if factory_mode and role == 'issuer':
                assert factory_admin_material is not None
                material = factory_admin_material
                reader, writer = os.pipe2(os.O_CLOEXEC)
                payload = json.dumps({'token': material.token, 'subject': material.subject,
                    'valid_until': material.valid_until, 'access': material.access, 'cleanup': material.cleanup}).encode()
                if len(payload) > 4096 or os.write(writer, payload) != len(payload):
                    raise RuntimeError('private factory owner handoff uncertain')
                os.close(writer); del payload
                credential_descriptor = reader
                extra_arguments.append(str(reader))
            process = subprocess.Popen([sys.executable, '-I', '-B', str(Path(__file__).with_name('delivery_actor.py')),
                str(Path(__file__).parent), str(listener.fileno()), str(child.fileno()), str(peer_child.fileno()), str(os.getpid()),
                json.dumps(asdict(registry.admission)), str(registry.manifest_path), str(observation.identity.pid), *extra_arguments],
                stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE, bufsize=0,
                pass_fds=(listener.fileno(), child.fileno(), peer_child.fileno(), *((credential_descriptor,) if credential_descriptor is not None else ())))
            if credential_descriptor is not None:
                os.close(credential_descriptor)
            processes.append(process); role_processes[role] = process
            child.close(); peer_child.close()
            assert select.select([process.stdout], [], [], 5)[0]
            assert process.stdout.readline() == b'ready\n'
            owners[role] = owner.ProcessIdentity.observe(process.pid)
            registry_channels[role] = parent; peer_channels[role] = peer_parent
        registry.bind_owners(owners)
        servers = {role: wire.RegistryOwnerChannel(registry, role=role, channel=c) for role, c in registry_channels.items()}
        bridge = peers.OwnerPeerBridge(plan, context_digest=registry.admission.context,
            owners=owners, channels=peer_channels, access_deadline=registry.admission.access_deadline)
        dispatcher = dispatch.OriginalRootDispatcher(registry, servers=servers, peers=bridge)

        def dispatch_until(predicate):
            deadline = time.monotonic()+10
            while not predicate():
                assert time.monotonic() < deadline
                dispatcher.poll()

        if driver_mode:
            registration = importlib.import_module('_bcf_owner_runtime.evidence_owner_registration')
            controls = importlib.import_module('_bcf_owner_runtime.evidence_owner_control')
            drivers = importlib.import_module('_bcf_owner_runtime.evidence_invocation_driver')
            route = registration.OwnerInvocationRoute('delivery-fixture', 'closed-runtime', 'actual-peer')
            scope = registration.RequiredOwnerScope(source, frozenset({route.producer}),
                frozenset({route.profile}), frozenset({route.control}), (route,))
            binding = registration.InstalledOwnerBinding(owner.ProcessIdentity.observe(os.getpid()), scope,
                owner.OwnerRegistration(endpoints['issuer'], owners['issuer']),
                owner.OwnerRegistration(endpoints['custody'], owners['custody']),
                registry.admission.cleanup_deadline, 1, 20)
            actual = registration.ActualInvocationIdentity(source, route.producer, route.profile, route.control)
            reserved = registration.ReservedOwnerInvocation(binding, actual, 1,
                registry.admission.access_deadline, scope.allocation_digest())
            pair = controls.OwnerControlPair(reserved, context_digest=registry.admission.context)
            driver = drivers.OriginalInvocationDriver(registry, dispatcher=dispatcher, owners=pair,
                original_source=original_source)
            if unknown_cleanup:
                with pytest.raises(controls.OwnerOutcomeUncertain, match='cleanup remains uncertain'):
                    driver.run()
                terminal = keeper.status()
                assert terminal['state'] == 'native_closed' and terminal['returncode'] == 0, terminal
                assert not keeper.released and keeper.process.poll() is None
                _blocked(lock)
                with pytest.raises(owner.OwnerAdmissionError):
                    pair.verified_cleanup(registry.admission.context)
                return
            terminal = driver.run()
            assert terminal['returncode'] == 0 and terminal['stdout'] == 'original-delivery\n', terminal
            assert keeper.released and keeper.process.returncode == 0
            pair.verified_cleanup(registry.admission.context)
            with pytest.raises(owner.OwnerAdmissionError, match='replayed'):
                driver.run()
            probe = os.open(lock, os.O_RDWR)
            try:
                fcntl.flock(probe, fcntl.LOCK_EX | fcntl.LOCK_NB)
            finally:
                os.close(probe)
            return

        for role, process in role_processes.items():
            process.stdin.write(b'prepare\n'); process.stdin.flush()
            dispatch_until(lambda: bool(select.select([process.stdout], [], [], 0)[0]))
            assert process.stdout.readline() == b'observed\n'
            registry.bind_execution(role, 'original.delivery-fixture')
            process.stdin.write(b'arm\n'); process.stdin.flush()
            dispatch_until(lambda: bool(select.select([process.stdout], [], [], 0)[0]))
            assert process.stdout.readline() == b'observed\n'
        if wrong_peer:
            with socket.socket(socket.AF_UNIX) as attacker:
                attacker.connect(str(socket_root / 'issuer.sock'))
                attacker.sendall(b'G')
                with pytest.raises(owner.OwnerAdmissionError, match='another peer'):
                    dispatch_until(lambda: bool(select.select([attacker], [], [], 0)[0]))
                assert registry.held
                dispatch_until(lambda: bool(select.select([attacker], [], [], 0)[0]))
                try:
                    assert attacker.recv(64) == b''
                except ConnectionResetError:
                    pass  # Refusal may reset unread attacker bytes; none were delivered.
            assert not plan.release_attempted
            keeper.cancel()  # No workload is released after uncertain admission.
        else:
            plan.release()
        dispatch_until(lambda: keeper.status()['state'] != 'pending')
        terminal = keeper.status()
        assert terminal['state'] == 'native_closed', terminal
        if wrong_peer:
            assert terminal['returncode'] != 0 and terminal['stdout'] == '', terminal
        else:
            assert terminal['returncode'] == 0 and terminal['stdout'] == 'original-delivery\n', terminal
            assert terminal['stderr'] == ''
        for process in role_processes.values():
            process.stdin.write(b'finish\n'); process.stdin.flush()
            dispatch_until(lambda: bool(select.select([process.stdout], [], [], 0)[0]))
            assert process.stdout.readline() == b'observed\n'
        _blocked(lock)
        assert all((socket_root / (role+'.sock')).exists() for role in listeners)
    finally:
        for channel in channels: channel.close()
        if lease >= 0: os.close(lease)
        if registry is not None: registry.close()
        if plan is not None: plan.close()
        if keeper is not None and keeper.process.poll() is None:
            try:
                keeper.cancel(); deadline = time.monotonic()+7
                while keeper.status()['state'] == 'pending':
                    assert time.monotonic() < deadline
                    time.sleep(.02)
            finally:
                keeper.process.kill(); keeper.process.communicate(timeout=5)
        for process in processes:
            if process.poll() is None:
                try: process.communicate(input=b'', timeout=5)
                except subprocess.TimeoutExpired: process.kill(); process.communicate(timeout=5)
            else: process.communicate(timeout=5)
        if frozen is not None: frozen.close()
        ready.close()
        for listener in listeners.values(): listener.close()
