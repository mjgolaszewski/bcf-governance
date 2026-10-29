"""No-secret integration actor using real coordinator and delivery classes."""
import asyncio
from dataclasses import asdict
import json
import os
from pathlib import Path
import socket
import sys

sys.path.insert(0, sys.argv[1])
from qualified_issuer.coordinator import OriginalCoordinator
from qualified_issuer.delivery import OriginalDeliveryRegistry
from qualified_issuer.runtime.evidence_execution_owner import ProcessIdentity
from qualified_issuer.runtime.evidence_owner_peer_bridge import OwnerPeerClient
from qualified_issuer.runtime.evidence_registry_channel import RegistryOwnerClient, admission_metadata

async def main():
    original = admission_metadata(json.loads(sys.argv[6]))
    root = ProcessIdentity.observe(int(sys.argv[5]))
    client = RegistryOwnerClient(socket.socket(fileno=int(sys.argv[3])), coordinator=root,
        context=original.context, cleanup_deadline=original.cleanup_deadline)
    coordinator = OriginalCoordinator(client, root=root, original=original)
    peers = OwnerPeerClient(socket.socket(fileno=int(sys.argv[4])), coordinator=root,
        context_digest=original.context, access_deadline=original.access_deadline)
    listener = socket.socket(fileno=int(sys.argv[2]))
    endpoint = Path(listener.getsockname())
    info = endpoint.lstat()
    delivery = OriginalDeliveryRegistry(listener=listener, endpoint=endpoint,
        pending_identity=(info.st_dev, info.st_ino, info.st_uid), coordinator=coordinator, peers=peers)
    admission = None
    execution = 'original.delivery-fixture'

    async def handler(reader, writer):
        assert await reader.readexactly(1) == b'G'
        delivery.authenticate(writer.get_extra_info('socket'), admission)
        writer.write(b'qualified-nonsecret')
        await writer.drain()

    if len(sys.argv) in (11, 12, 13):
        # Synthetic lifecycle controls exercise Root orchestration only. There
        # are no provider effects, credentials or production factory claims.
        from qualified_issuer.issuer.server import ControlServer
        role = sys.argv[10]
        execution = role + '.original-control-fixture'

        class NoEffectLifecycle:
            runtime = None
            canonical = None
            policy = None
            factory = None

            async def dispatch(self, request, *, coordinator_lifetime):
                nonlocal admission
                assert coordinator_lifetime == original.coordinator_lifetime
                assert request['context_digest'] == original.context and request['role'] == role
                operation = request['operation']
                if operation == 'prepare_actual_execution':
                    admission = coordinator.admit(original.context, request['manifest_path'], request['held_peer_pid'])
                    status = 'prepared'
                elif operation == 'stage_fresh_workload':
                    coordinator.recheck(admission, cleanup=False)
                    if role == 'issuer':
                        from qualified_issuer.runtime_guard import OriginalIssuerRuntimeGuard
                        self.runtime = OriginalIssuerRuntimeGuard(coordinator=coordinator,
                            delivery=delivery, admission=admission, handoff=Path(
                            '/docker/.bcf-235-maintenance-tools/release-239-completion-v1/evidence/issuer-dev-reset-11/operator-output/runtime-handoff.json'))
                        self.runtime.runtime_check(self.runtime.pin)
                        from qualified_issuer.canonical_inputs import open_canonical_issuer
                        self.canonical = open_canonical_issuer(deadline=original.access_deadline)
                        from qualified_issuer.issuer.workload import WorkloadConfig
                        from qualified_issuer.sandbox_profile import OriginalSandboxProfile
                        profile = OriginalSandboxProfile(runtime=self.runtime, admission=admission,
                            config=WorkloadConfig('direct', 'chrysalis-identity',
                                'bcf239-wrong-4d2f529b2ec2', 'qualification.invalid'),
                            registration=Path('/docker/.bcf-235-maintenance-tools/release-239-completion-v1/sandbox-runtime-registration.json'))
                        profile.attest_sandbox(admission, self.runtime.pin, admission.tenant)
                        if sys.argv[11:12] == ['factory-preflight']:
                            import ssl
                            import stat
                            from qualified_issuer.composition import build_original_issuer
                            from qualified_issuer.issuer.contracts import AdminSession
                            descriptor = int(sys.argv[12])
                            metadata = os.fstat(descriptor)
                            if not stat.S_ISFIFO(metadata.st_mode) or metadata.st_uid != os.getuid():
                                raise RuntimeError('original factory credential pipe required')
                            raw = os.read(descriptor, 4097)
                            if len(raw) > 4096 or os.read(descriptor, 1):
                                raise RuntimeError('factory credential frame refused')
                            os.close(descriptor)
                            material = json.loads(raw); del raw
                            if (original.access_deadline > material['access']
                                    or original.cleanup_deadline > material['cleanup']):
                                raise RuntimeError('normal credential allocation is not extended')
                            session = AdminSession(material['token'], material['subject'],
                                original.tenant, material['valid_until'])
                            del material
                            import tempfile
                            root = Path(tempfile.mkdtemp(prefix='issuer-factory-'))
                            journal = root / 'journal'; journal.mkdir(mode=0o700)
                            policy = root / 'policy'; policy.mkdir(mode=0o700)
                            self.factory = await build_original_issuer(profile=profile, session=session,
                                journal_root=journal, policy_root=policy, tls=ssl.create_default_context())
                            assert self.factory.owner.journal.find(original.context, original.coordinator_lifetime) is None
                        if sys.argv[11:] == ['policy-probe']:
                            from qualified_issuer.policy_observer import OriginalPolicyObserver
                            from qualified_issuer.issuer.contracts import Mutation
                            directory = Path(os.environ['TMPDIR']).parent / 'policy-operations' / ('issuer-' + str(os.getpid()))
                            directory.mkdir(mode=0o700)
                            self.policy = OriginalPolicyObserver(profile=profile, root=directory)
                            observation = await self.policy.observe(admission,
                                Mutation('POST', '/api/v1/admin/principals', b'{}', 'admin_create_principal'),
                                original.access_deadline)
                            assert observation.requires_strong_auth and observation.requires_step_up
                            assert observation.requires_approval is False
                    status = 'staged'
                elif operation == 'arm_delivery_once':
                    await delivery.arm(admission, execution, handler)
                    status = 'armed'
                elif operation in {'finish_execution', 'reconcile_execution'}:
                    if role == 'custody' and sys.argv[11:] == ['refuse-cleanup']:
                        raise RuntimeError('synthetic unknown cleanup')
                    coordinator.native_closed(admission)
                    await delivery.disarm(admission, execution)
                    if self.runtime is not None:
                        self.runtime.runtime_check(self.runtime.pin)
                    status = 'closed'
                else:
                    raise AssertionError(operation)
                if operation not in {'prepare_actual_execution', 'reconcile_execution'}:
                    assert request['execution_id'] == execution
                return {'contract': 'bcf.actual-invocation-owner.v1', 'role': role,
                        'context_digest': original.context, 'execution_id': execution, 'status': status}

        control = socket.socket(socket.AF_UNIX)
        endpoint = Path(sys.argv[9])
        control.bind(str(endpoint)); os.chmod(endpoint, 0o600); control.listen(4)
        lifecycle = NoEffectLifecycle()
        server = await ControlServer(lifecycle, observe_identity=ProcessIdentity.observe,
            authenticate_control=coordinator.authenticate_control,
            control_deadline=coordinator.control_deadline).start(control, endpoint)
        print('ready', flush=True)
        await asyncio.to_thread(sys.stdin.read)
        server.close(); await server.wait_closed()
        if lifecycle.factory is not None:
            await lifecycle.factory.close_transports()
        if lifecycle.policy is not None:
            lifecycle.policy.close()
        if lifecycle.canonical is not None:
            lifecycle.canonical.close()
        return

    print('ready', flush=True)
    while line := await asyncio.to_thread(sys.stdin.readline):
        operation = line.strip()
        if operation == 'prepare':
            admission = coordinator.admit(original.context, sys.argv[7], int(sys.argv[8]))
            assert asdict(admission) == asdict(original)
        elif operation == 'arm':
            await delivery.arm(admission, execution, handler)
        elif operation == 'finish':
            coordinator.native_closed(admission)
            await delivery.disarm(admission, execution)
            await delivery.disarm(admission, execution)
            try:
                await delivery.arm(admission, execution, handler)
            except Exception:
                pass
            else:
                raise AssertionError('retired delivery reopened')
        else:
            raise AssertionError(operation)
        print('observed', flush=True)

asyncio.run(main())
