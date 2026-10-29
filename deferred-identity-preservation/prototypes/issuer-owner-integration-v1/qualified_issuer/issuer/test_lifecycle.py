"""UNRUN fake-port controls; none establish live provider or custody acceptance."""
import asyncio
import tempfile
import time
import unittest
from pathlib import Path

from .contracts import Admission, Refused, Uncertain
from .factory import build_registered_issuer_owner
from .http_exchange import Endpoint, HttpExchange
from .journal import Journal
from .lifecycle import CONTRACT, IssuerLifecycle


class FakeCoordinator:
    def __init__(self):
        self.terminal = False
        self.recoveries = 0
        self.admissions = {}

    def admit(self, context, _manifest, _pid):
        if context not in self.admissions:
            self.admissions[context] = Admission(context, 'coordinator', 'consumer', 'held', 'sandbox',
                time.monotonic() + 30, time.monotonic() + 60)
        return self.admissions[context]

    def recheck(self, _admission, *, cleanup):
        return None

    def recover(self, context, controller, execution):
        self.recoveries += 1
        return self.admit(context, '', 1)

    def native_closed(self, admission):
        if not self.terminal:
            raise Refused()


class FakeProvider:
    def __init__(self):
        self.calls = []
        self.fail_stage = False
        self.cleanup_result = None

    async def stage(self, admission, execution, intent, outcome):
        self.calls.append('stage')
        intent('create', {'email': 'synthetic@example.invalid'})
        if self.fail_stage:
            raise Uncertain()
        outcome('create', {'principal_id': 'owned'})

    async def arm(self, admission, execution, consume):
        self.calls.append('arm')
        self.consume = consume

    async def revoke_and_cleanup(self, admission, execution, journal, *, reconcile):
        self.calls.append('cleanup')
        return self.cleanup_result


class LifecycleControls(unittest.IsolatedAsyncioTestCase):
    async def asyncSetUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        Path(self.tmp.name).chmod(0o700)
        self.journal = Journal(Path(self.tmp.name), cap=2)
        self.coord, self.provider = FakeCoordinator(), FakeProvider()
        self.owner = IssuerLifecycle(coordinator=self.coord, provider=self.provider,
                                      journal=self.journal)
        self.context = 'a' * 64
        response = await self.call('prepare_actual_execution', manifest_path='/owned', held_peer_pid=1)
        self.execution = response['execution_id']

    async def asyncTearDown(self):
        self.journal.close()
        self.tmp.cleanup()

    async def call(self, operation, **fields):
        request = {'contract': CONTRACT, 'operation': operation, 'role': 'issuer',
                   'context_digest': self.context, **fields}
        return await self.owner.dispatch(request, coordinator_lifetime='coordinator')

    async def stage_arm(self):
        await self.call('stage_fresh_workload', execution_id=self.execution)
        await self.call('arm_delivery_once', execution_id=self.execution)

    async def test_unconfigured_factory_refuses(self):
        with self.assertRaises(Refused):
            await build_registered_issuer_owner()

    async def test_prepare_exact_repeat_metadata_only(self):
        result = await self.call('prepare_actual_execution', manifest_path='/owned', held_peer_pid=1)
        self.assertEqual(result['execution_id'], self.execution)
        self.assertEqual(self.provider.calls, [])

    async def test_unknown_fields_refuse_before_provider(self):
        with self.assertRaises(Refused):
            await self.call('stage_fresh_workload', execution_id=self.execution, target='foreign')
        self.assertEqual(self.provider.calls, [])

    async def test_failed_stage_is_not_replayed(self):
        self.provider.fail_stage = True
        for _ in range(2):
            with self.assertRaises(Refused):
                await self.call('stage_fresh_workload', execution_id=self.execution)
        self.assertEqual(self.provider.calls, ['stage'])
        self.assertEqual(self.journal.events(self.execution)[0]['kind'], 'intent')

    async def test_delivery_consumed_once(self):
        await self.stage_arm()
        self.provider.consume()
        with self.assertRaises(Uncertain):
            self.provider.consume()

    async def test_caller_returncode_cannot_close(self):
        await self.stage_arm()
        with self.assertRaises(Refused):
            await self.call('finish_execution', execution_id=self.execution, native_returncode=0)
        self.assertNotIn('cleanup', self.provider.calls)

    async def test_cleanup_boolean_does_not_close(self):
        await self.stage_arm()
        self.coord.terminal = True
        self.provider.cleanup_result = False
        with self.assertRaises(Uncertain):
            await self.call('finish_execution', execution_id=self.execution, native_returncode=0)
        self.assertEqual(self.journal.find(self.context, 'coordinator')[1], 'armed')

    async def test_reconcile_lost_prepare_without_id(self):
        result = await self.call('reconcile_execution')
        self.assertEqual(result['status'], 'closed')
        self.assertEqual(self.provider.calls, ['cleanup'])

    async def test_reconcile_restart_uses_independent_registry(self):
        self.owner._admitted.clear()
        result = await self.call('reconcile_execution')
        self.assertEqual(result['status'], 'closed')
        self.assertEqual(self.coord.recoveries, 1)

    async def test_closed_repeat_does_not_repeat_cleanup(self):
        await self.call('reconcile_execution')
        self.owner._admitted.clear()
        result = await self.call('reconcile_execution')
        self.assertEqual(result['status'], 'closed')
        self.assertEqual(self.provider.calls, ['cleanup'])

    async def test_foreign_execution_refused(self):
        with self.assertRaises(Refused):
            await self.call('reconcile_execution', execution_id='foreign')
        self.assertEqual(self.provider.calls, [])

    async def test_endpoint_origin_override_refused(self):
        for path in ('https://other.invalid/x', '//other.invalid/x', '/a/../b'):
            with self.assertRaises(Refused):
                HttpExchange._validate_endpoint(Endpoint('GET', path, frozenset({200}), False))

    async def test_prepare_cannot_extend_deadline(self):
        from dataclasses import replace
        original = self.coord.admissions[self.context]
        self.coord.admissions[self.context] = replace(original,
            access_deadline=original.access_deadline + 1,
            cleanup_deadline=original.cleanup_deadline + 1)
        with self.assertRaises(Refused):
            await self.call('prepare_actual_execution', manifest_path='/owned', held_peer_pid=1)
        self.assertEqual(self.provider.calls, [])

    async def test_nonfinite_deadline_refuses_before_effects(self):
        from dataclasses import replace
        self.owner._admitted[self.execution] = replace(self.owner._admitted[self.execution],
            access_deadline=float('nan'))
        with self.assertRaises(Refused):
            await self.call('stage_fresh_workload', execution_id=self.execution)
        self.assertEqual(self.provider.calls, [])

    async def test_expired_access_reconciliation_still_has_finite_cleanup(self):
        from dataclasses import replace
        self.owner._admitted[self.execution] = replace(self.owner._admitted[self.execution],
            access_deadline=time.monotonic() - 1)
        result = await self.call('reconcile_execution')
        self.assertEqual(result['status'], 'closed')

    async def test_coordinator_cannot_be_consuming_controller(self):
        from dataclasses import replace
        self.owner._admitted[self.execution] = replace(self.owner._admitted[self.execution],
            consuming_controller_lifetime='coordinator')
        with self.assertRaises(Refused):
            await self.call('stage_fresh_workload', execution_id=self.execution)
        self.assertEqual(self.provider.calls, [])

    async def test_wrong_control_caller_binding_refuses_prepare(self):
        from dataclasses import replace
        self.coord.admissions[self.context] = replace(self.coord.admissions[self.context],
            coordinator_lifetime='foreign-coordinator')
        with self.assertRaises(Refused):
            await self.call('prepare_actual_execution', manifest_path='/owned', held_peer_pid=1)
        self.assertEqual(self.provider.calls, [])
