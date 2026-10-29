"""UNRUN explicit fake-port cleanup/route controls; never live issuer proof."""
from dataclasses import replace
from types import SimpleNamespace
import time
import unittest
from unittest.mock import AsyncMock

from .contracts import Admission, Refused, Uncertain
from .http_exchange import Endpoint, HttpExchange, HttpResult
from .test_http_exchange import FakeClient, FakeResponse
from .workload import ConcreteWorkloadProvider, Dependencies, PrivateState, WorkloadConfig
from .workload_cleanup import cleanup_owned

EMAIL = 'jit-owned@qualification.example.com'
PRINCIPAL = '0d3a3609-d239-48b1-833f-c1f9acc09b3e'


class FakeGateway:
    def __init__(self):
        self.calls = []
        self.status = 'active'
        self.user = SimpleNamespace(close=AsyncMock())

    async def admin(self, admission, method, path, body, *, deadline):
        self.calls.append((method, path, body))
        if method == 'GET':
            return {'principal': {'id': PRINCIPAL, 'email': EMAIL, 'status': self.status}}
        if method == 'PATCH':
            self.status = body['status']
            return {'id': PRINCIPAL, 'status': self.status}
        return {'principal_id': PRINCIPAL, 'revoked_count': 1}


class WorkloadControls(unittest.IsolatedAsyncioTestCase):
    def admission(self):
        return Admission('a' * 64, 'coordinator', 'consumer', 'held', 'sandbox',
                         time.monotonic() + 30, time.monotonic() + 60)

    def provider(self, rows):
        admission = self.admission()
        gateway = FakeGateway()
        events = []
        state = PrivateState(admission, gateway, EMAIL, '',
                             lambda *args: events.append(args), lambda *args: events.append(args))
        authority = SimpleNamespace(
            register_email=lambda email, **kwargs: '/owned-query',
            read=AsyncMock(return_value=HttpResult(200, rows)),
            register_principal=lambda principal, *, attest_owned: attest_owned(principal))
        registry = SimpleNamespace(disarm=AsyncMock(return_value=None))
        provider = ConcreteWorkloadProvider.__new__(ConcreteWorkloadProvider)
        provider.config = WorkloadConfig('direct', 'chrysalis-identity', 'wrong', 'qualification.example.com')
        provider.authority = authority
        provider.deps = SimpleNamespace(delivery_registry=registry, attest_owned=lambda *args: None)
        provider._states, provider._clients = {'execution': state}, {'execution': gateway.user}
        journal = ({'kind': 'intent', 'step': 'create', 'role': 'direct', 'email': EMAIL},
                   {'kind': 'outcome', 'step': 'lookup', 'email': EMAIL,
                    'outcome': 'absent_before_create'})
        return provider, admission, gateway, journal

    async def test_lost_create_empty_lookup_remains_unknown(self):
        provider, admission, gateway, journal = self.provider([])
        with self.assertRaises(Uncertain):
            await cleanup_owned(provider, admission, 'execution', journal, reconcile=True)
        self.assertEqual(gateway.calls, [])

    async def test_lost_create_ambiguous_lookup_remains_unknown(self):
        provider, admission, gateway, journal = self.provider([
            {'email': EMAIL, 'id': PRINCIPAL}, {'email': EMAIL, 'id': PRINCIPAL}])
        with self.assertRaises(Uncertain):
            await cleanup_owned(provider, admission, 'execution', journal, reconcile=True)
        self.assertEqual(gateway.calls, [])

    async def test_lost_create_substring_match_is_not_ownership(self):
        provider, admission, gateway, journal = self.provider([
            {'email': 'prefix-' + EMAIL, 'id': PRINCIPAL}])
        with self.assertRaises(Uncertain):
            await cleanup_owned(provider, admission, 'execution', journal, reconcile=True)
        self.assertEqual(gateway.calls, [])

    async def test_exact_owned_lookup_cleans_only_owned_id(self):
        provider, admission, gateway, journal = self.provider([{'email': EMAIL, 'id': PRINCIPAL}])
        await cleanup_owned(provider, admission, 'execution', journal, reconcile=True)
        self.assertEqual(gateway.status, 'disabled')
        self.assertTrue(all(PRINCIPAL in path for _, path, _ in gateway.calls))
        self.assertEqual([method for method, _, _ in gateway.calls], ['GET', 'POST', 'PATCH', 'GET'])
        self.assertEqual(gateway.calls[1][2], {'reason': 'Owned uncertain-execution cleanup'})
        provider.deps.delivery_registry.disarm.assert_awaited_once()
        gateway.user.close.assert_awaited_once()

    async def test_wrong_tenant_or_role_audience_refused(self):
        config = WorkloadConfig('direct', 'chrysalis-identity', 'sandbox', 'qualification.example.com')
        with self.assertRaises(Refused):
            config.validate(self.admission())
        with self.assertRaises(Refused):
            replace(config, role='bff', wrong_tenant='wrong').validate(self.admission())

    async def test_incomplete_delivery_registry_refused(self):
        with self.assertRaises(Refused):
            Dependencies(lambda: None, lambda: None, lambda: None,
                         SimpleNamespace(arm=lambda: None)).validate()

    async def test_owned_route_boolean_receipt_is_not_authority(self):
        exchange = HttpExchange.__new__(HttpExchange)
        exchange._endpoints = {}
        with self.assertRaises(Refused):
            exchange.register_owned_principal(PRINCIPAL, attest_owned=lambda value: False)
        self.assertEqual(exchange._endpoints, {})

    async def test_list_shape_is_only_registered_principal_query(self):
        with self.assertRaises(Refused):
            HttpExchange._validate_endpoint(Endpoint('GET', '/other', frozenset({200}), False,
                                                    'principal_list'))
        exchange = HttpExchange.__new__(HttpExchange)
        response = FakeResponse(b'[{"id":"owned"}]')
        exchange._client = FakeClient([response])
        result = await exchange._send(Endpoint('GET', '/api/v1/admin/principals?query=owned&limit=2',
                                              frozenset({200}), False, 'principal_list'), {}, None)
        self.assertEqual(result.value, [{'id': 'owned'}])
        self.assertTrue(response.closed)
