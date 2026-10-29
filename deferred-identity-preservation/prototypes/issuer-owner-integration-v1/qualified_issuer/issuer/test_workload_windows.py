"""UNRUN short fake-stream deadline controls. Production window stays30seconds."""
import asyncio
import json
import time
import struct
from types import SimpleNamespace
import unittest
from unittest.mock import AsyncMock, patch

from . import workload_delivery
from .workload_delivery import SCHEMA, WorkloadSession


class FakeReader:
    def __init__(self, operation, *, header_delay=0, body_delay=0, eof_delay=0):
        body = json.dumps({'schema': SCHEMA, 'op': operation, 'sequence': 1,
                           'nonce': 'a' * 32}).encode()
        self.parts = [struct.pack('!I', len(body))[:1], struct.pack('!I', len(body))[1:], body]
        self.delays = [0, header_delay, body_delay]
        self.eof_delay = eof_delay

    async def readexactly(self, count):
        if not self.parts:
            raise asyncio.IncompleteReadError(b'', count)
        await asyncio.sleep(self.delays.pop(0))
        raw = self.parts.pop(0)
        assert len(raw) == count
        return raw

    async def read(self, count):
        await asyncio.sleep(self.eof_delay)
        return b''


class FakeWriter:
    def __init__(self, drain_delay=0):
        self.written, self.closed = [], False
        self.drain_delay = drain_delay

    def get_extra_info(self, name):
        import socket
        return SimpleNamespace(family=socket.AF_UNIX)

    def write(self, raw):
        self.written.append(raw)

    async def drain(self):
        await asyncio.sleep(self.drain_delay)

    def close(self):
        self.closed = True

    async def wait_closed(self):
        pass


class WorkloadWindows(unittest.IsolatedAsyncioTestCase):
    async def exercise(self, operation='login_once', *, header=0, body=0, eof=0, drain=0,
                       provider_delay=0, auth_delay=0):
        calls = []

        async def login(admission, execution, consume):
            await asyncio.sleep(provider_delay)
            calls.append('login')
            consume()
            return {'fake-unit': 'bounded'}

        auth_calls = []
        def authenticate(*args):
            auth_calls.append(True)
            if len(auth_calls) == 3 and auth_delay:
                time.sleep(auth_delay)  # Fake synchronous verifier, no clock change.
            return None

        provider = SimpleNamespace(login_material=login,
            deps=SimpleNamespace(delivery_registry=SimpleNamespace(authenticate=authenticate)),
            _journal=SimpleNamespace(workload_outcome=lambda *args: {'outcome': 'confirmed'}))
        admission = SimpleNamespace(access_deadline=time.monotonic() + 1)
        consumed = []
        session = WorkloadSession(provider, admission, 'owned', lambda: consumed.append(True))
        writer = FakeWriter(drain)
        # Explicit fake-port timebox, not a production config or live clock warp.
        with patch.object(workload_delivery, 'OPERATION_SECONDS', 0.02):
            await session.handle(FakeReader(operation, header_delay=header,
                                           body_delay=body, eof_delay=eof), writer)
        return calls, consumed, writer

    async def test_slow_remaining_header_never_calls_provider(self):
        calls, consumed, writer = await self.exercise(header=0.05)
        self.assertEqual((calls, consumed, writer.written), ([], [], []))
        self.assertTrue(writer.closed)

    async def test_header_and_body_do_not_renew_window(self):
        calls, consumed, writer = await self.exercise(header=0.015, body=0.015)
        self.assertEqual((calls, consumed, writer.written), ([], [], []))

    async def test_slow_provider_never_emits_response(self):
        calls, consumed, writer = await self.exercise(provider_delay=0.05)
        self.assertEqual((calls, consumed, writer.written), ([], [], []))

    async def test_close_eof_is_bounded_after_response(self):
        calls, consumed, writer = await self.exercise('close', eof=0.05)
        self.assertEqual(len(writer.written), 1)
        self.assertTrue(writer.closed)
        self.assertEqual(consumed, [])

    async def test_slow_drain_keeps_delivery_consumed(self):
        calls, consumed, writer = await self.exercise(drain=0.05)
        self.assertEqual(calls, ['login'])
        self.assertEqual(consumed, [True])
        self.assertEqual(len(writer.written), 1)
        self.assertTrue(writer.closed)

    async def test_synchronous_final_auth_delay_cannot_write_late_secret(self):
        calls, consumed, writer = await self.exercise(auth_delay=0.04)
        self.assertEqual(calls, ['login'])
        self.assertEqual(consumed, [True])
        self.assertEqual(writer.written, [])
        self.assertTrue(writer.closed)
