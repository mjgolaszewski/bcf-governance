"""UNRUN fake-stream request-window controls, not real kernel/owner proof."""
import asyncio
import json
import socket
import struct
import time
from types import SimpleNamespace
import unittest
from unittest.mock import patch

from .contracts import Uncertain
from .lifecycle import CONTRACT
from .server import ControlServer
from .workload import ConcreteWorkloadProvider


class FakeSocket:
    family = socket.AF_UNIX

    def getsockopt(self, *args):
        return struct.pack('3i', 123, 1001, 1001)


class FakeReader:
    def __init__(self, operation):
        raw = json.dumps({'contract': CONTRACT, 'operation': operation,
                          'role': 'issuer', 'context_digest': 'a' * 64}).encode()
        self.raw = struct.pack('!I', len(raw)) + raw

    async def readexactly(self, count):
        value, self.raw = self.raw[:count], self.raw[count:]
        return value


class FakeWriter:
    def __init__(self):
        self.written = []

    def get_extra_info(self, name):
        return FakeSocket()

    def write(self, raw):
        self.written.append(raw)

    async def drain(self):
        return None

    def close(self):
        return None

    async def wait_closed(self):
        return None


class FakeLifecycle:
    def __init__(self, delay=0):
        self.delay, self.calls = delay, []

    async def dispatch(self, request, **kwargs):
        self.calls.append(request)
        await asyncio.sleep(self.delay)
        return {'contract': CONTRACT, 'role': 'issuer', 'context_digest': 'a' * 64,
                'execution_id': 'owned', 'status': 'staged'}


class Windows(unittest.IsolatedAsyncioTestCase):
    async def exercise(self, operation, *, aggregate=120, contextual=120, delay=0):
        identity = SimpleNamespace(pid=123, uid=1001)
        lifecycle, writer = FakeLifecycle(delay), FakeWriter()
        start = time.monotonic()
        server = ControlServer(lifecycle, observe_identity=lambda pid: identity,
            authenticate_control=lambda peer: 'coordinator',
            control_deadline=lambda peer, context, op: start + (aggregate if context is None else contextual))
        recorded = []
        original = asyncio.timeout

        class Window:
            def __init__(self, seconds):
                self.inner = original(seconds)

            async def __aenter__(self):
                await self.inner.__aenter__()
                return self

            async def __aexit__(self, *args):
                return await self.inner.__aexit__(*args)

            def reschedule(self, deadline):
                recorded.append(deadline - asyncio.get_running_loop().time())
                self.inner.reschedule(deadline)

        with patch.object(asyncio, 'timeout', Window):
            await server.handle(FakeReader(operation), writer)
        return lifecycle, writer, recorded

    async def test_stage_response_has_fixed_sixty_cap(self):
        lifecycle, writer, windows = await self.exercise('stage_fresh_workload')
        self.assertTrue(writer.written)
        self.assertTrue(29 <= windows[0] <= 30)
        self.assertTrue(59 <= windows[1] <= 60)

    async def test_prepare_keeps_thirty_cap(self):
        lifecycle, writer, windows = await self.exercise('prepare_actual_execution')
        self.assertTrue(writer.written)
        self.assertTrue(29 <= windows[1] <= 30)

    async def test_original_authority_clips_sixty_cap(self):
        lifecycle, writer, windows = await self.exercise('arm_delivery_once', contextual=5)
        self.assertTrue(writer.written)
        self.assertTrue(4 <= windows[1] <= 5)

    async def test_expired_aggregate_never_dispatches(self):
        lifecycle, writer, windows = await self.exercise('stage_fresh_workload', aggregate=-1)
        self.assertEqual(lifecycle.calls, [])
        self.assertEqual(writer.written, [])

    async def test_expired_during_operation_never_writes_success(self):
        lifecycle, writer, windows = await self.exercise('stage_fresh_workload', contextual=0.01, delay=0.1)
        self.assertEqual(len(lifecycle.calls), 1)
        self.assertEqual(writer.written, [])

    async def test_workload_delivery_refuses_missing_counter_readiness(self):
        provider = ConcreteWorkloadProvider.__new__(ConcreteWorkloadProvider)
        admission = object()
        provider._states = {'owned': SimpleNamespace(admission=admission,
            delivery_consumed=False, seed='FAKE', confirmed_counter=int(time.time() // 30) + 1)}
        consumed = []
        with self.assertRaises(Uncertain):
            await provider.login_material(admission, 'owned', lambda: consumed.append(True))
        self.assertEqual(consumed, [])
