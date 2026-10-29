"""UNRUN: pinned real route/DTO plus synthetic HTTP and revocation controls."""
import ast
from dataclasses import replace
import hashlib
from pathlib import Path
from types import SimpleNamespace
import unittest
from unittest.mock import AsyncMock

import chrysalis_identity
from chrysalis_identity.schemas_account_readmodels import AccountProfileResponse

from .account_evidence import active_profile, revoked_session_witness
from .contracts import Refused, Uncertain, tenant_selector
from .gateway import Gateway
from .http_exchange import Endpoint, HttpExchange, HttpResult
from .issuer_provider_v4 import IssuerBoundary
from .test_context_evidence import admission, PIN, PRINCIPAL
from .workload import ConcreteWorkloadProvider

SID = '22222222-2222-4222-8222-222222222222'
OTHER = '33333333-3333-4333-8333-333333333333'


def session_value(audience='racecar', *, revoked=False, current=True):
    return {'id': SID, 'application_id': OTHER, 'application_audience': audience,
        'application_name': 'Synthetic', 'created_at': '2026-10-27T00:00:00Z',
        'revoked_at': '2026-10-27T01:00:00Z' if revoked else None,
        'status': 'revoked' if revoked else 'active', 'is_current': current,
        'authentication_methods': ['pwd']}


def profile_value(audience='racecar'):
    palette = {key: '#112233' for key in ('primary', 'accent', 'background', 'surface', 'text')}
    value = {'principal_id': PRINCIPAL, 'subject': 'principal:' + PRINCIPAL,
        'status': 'active', 'current_audience': audience, 'roles': [], 'capabilities': [],
        'permissions_version': 'synthetic-version', 'external_identities': [],
        'sessions': [session_value(audience)], 'applications': [],
        'branding': {'version': 0, 'is_custom': False, 'palette': palette,
            'derived': {key: '#223344' for key in ('primary_hover', 'accent_hover', 'focus')}}}
    return AccountProfileResponse.model_validate(value).model_dump(mode='json')


def workbench_value(*, revoked=True):
    return {'principal': {'id': PRINCIPAL, 'status': 'active', 'is_deleted': False},
            'sessions': [session_value(revoked=revoked)]}


class AccountEvidence(unittest.TestCase):
    def test_pinned_real_route_has_profile_and_no_old_account_root(self):
        source = Path(chrysalis_identity.__file__).parent / 'api/account.py'
        raw = source.read_bytes()
        self.assertEqual(hashlib.sha256(raw).hexdigest(),
                         'e10c3f794b6629323813942f7e4d61b26c219813b0546295c0b61e6f238ecee9')
        routes = []
        for node in ast.walk(ast.parse(raw)):
            if (isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute)
                    and node.func.attr == 'get' and node.args
                    and isinstance(node.args[0], ast.Constant)):
                routes.append(node.args[0].value)
        self.assertIn('/api/v1/account/profile', routes)
        self.assertNotIn('/api/v1/account', routes)

    def test_real_profile_dto_positive_both_audiences(self):
        for audience in ('racecar', 'chrysalis-identity'):
            with self.subTest(audience=audience):
                self.assertIsNone(active_profile(profile_value(audience), principal_id=PRINCIPAL,
                    session_id=SID, subject='principal:' + PRINCIPAL, audience=audience))

    def test_foreign_owned_identity_or_audience_refused(self):
        for key, other in [('principal_id', OTHER), ('subject', 'principal:' + OTHER),
                           ('current_audience', 'other'), ('status', 'disabled')]:
            value = profile_value(); value[key] = other
            with self.subTest(key=key), self.assertRaises(Refused):
                active_profile(value, principal_id=PRINCIPAL, session_id=SID,
                               subject='principal:' + PRINCIPAL, audience='racecar')

    def test_current_session_binding_required(self):
        for key, other in [('id', OTHER), ('application_audience', 'other'),
                           ('is_current', False), ('status', 'revoked'),
                           ('revoked_at', '2026-10-27T01:00:00Z')]:
            value = profile_value(); value['sessions'][0][key] = other
            with self.subTest(key=key), self.assertRaises(Refused):
                active_profile(value, principal_id=PRINCIPAL, session_id=SID,
                               subject='principal:' + PRINCIPAL, audience='racecar')

    def test_missing_or_duplicate_current_session_refused(self):
        for rows in ([], [session_value(), session_value()]):
            value = profile_value(); value['sessions'] = rows
            with self.subTest(rows=len(rows)), self.assertRaises(Refused):
                active_profile(value, principal_id=PRINCIPAL, session_id=SID,
                               subject='principal:' + PRINCIPAL, audience='racecar')

    def test_exact_revoked_session_readback_positive(self):
        self.assertIsNone(revoked_session_witness(workbench_value(), principal_id=PRINCIPAL,
                                                  session_id=SID, audience='racecar'))

    def test_missing_foreign_or_still_active_session_is_no_witness(self):
        values = [workbench_value(revoked=False), workbench_value(), workbench_value()]
        values[1]['sessions'] = []
        values[2]['sessions'][0]['id'] = OTHER
        for value in values:
            with self.subTest(value=value), self.assertRaises(Refused):
                revoked_session_witness(value, principal_id=PRINCIPAL, session_id=SID,
                                        audience='racecar')

    def test_disabled_principal_or_timestamp_absent_is_no_witness(self):
        value = workbench_value(); value['principal']['status'] = 'disabled'
        other = workbench_value(); other['sessions'][0]['revoked_at'] = None
        for row in (value, other):
            with self.assertRaises(Refused):
                revoked_session_witness(row, principal_id=PRINCIPAL, session_id=SID,
                                        audience='racecar')

    def test_canonical_tenant_exact_no_repair_and_63_bound(self):
        for value in ('a' * 63, 'sandbox', 'a_b.c-d'):
            self.assertEqual(tenant_selector(value), value)
        for value in ('a' * 64, 'Sandbox', ' sandbox ', 'default', '_sandbox', ''):
            with self.subTest(value=value), self.assertRaises(Refused):
                tenant_selector(value)

    def test_invalid_tenant_not_bound_or_admitted(self):
        for value in ('a' * 64, 'Sandbox', ' sandbox '):
            exchange = HttpExchange.__new__(HttpExchange)
            with self.subTest(value=value), self.assertRaises(Refused):
                exchange.bind_tenant(value)
            self.assertFalse(hasattr(exchange, '_tenant'))
            with self.assertRaises(Refused):
                replace(admission(), tenant=value).validate(cleanup=False)


class AccountOracle(unittest.IsolatedAsyncioTestCase):
    async def test_gateway_uses_exact_profile_route_both_audiences(self):
        boundary = IssuerBoundary(runtime_pin=PIN, tenant='sandbox',
            runtime_check=lambda pin: None, subject_producer=lambda value: 'principal:' + value,
            token_verifier=lambda **kwargs: {})
        for audience in ('racecar', 'chrysalis-identity'):
            user = SimpleNamespace(request=AsyncMock(return_value=HttpResult(200, profile_value(audience))))
            gateway = Gateway(boundary, None, user)
            await gateway.account(admission(), 'synthetic-token', audience, principal_id=PRINCIPAL,
                                  session_id=SID, cleanup=True)
            args = user.request.call_args
            self.assertEqual(args.args, ('GET', '/api/v1/account/profile?audience=' + audience))

    async def test_old_route_is_unconfigured_without_http_call(self):
        exchange = HttpExchange.__new__(HttpExchange)
        exchange._closed = False
        exchange._endpoints = {('GET', '/api/v1/account/profile?audience=racecar'):
            Endpoint('GET', '/api/v1/account/profile?audience=racecar', frozenset({200}), False)}
        exchange._client = SimpleNamespace(stream=AsyncMock())
        with self.assertRaises(Refused):
            await exchange.request('GET', '/api/v1/account?audience=racecar',
                                   deadline=admission().cleanup_deadline)
        exchange._client.stream.assert_not_called()

    async def exercise_oracle(self, *, rejection=401, witnessed=True):
        admitted = admission(); events = []
        boundary = SimpleNamespace(subject=lambda value: 'principal:' + value,
                                   verify_token=lambda *args: {'sid': SID})
        before = workbench_value(revoked=False)
        after = workbench_value(revoked=witnessed)
        gateway = SimpleNamespace(boundary=boundary,
            admin=AsyncMock(side_effect=[before, {'principal_id': PRINCIPAL, 'revoked_count': 1}, after]),
            account=AsyncMock(side_effect=[HttpResult(200, profile_value()),
                HttpResult(rejection, {'detail': 'Invalid token'})]))
        state = SimpleNamespace(admission=admitted, token='synthetic-token', principal_id=PRINCIPAL,
            gateway=gateway, revoked=False, intent=lambda *args: None,
            outcome=lambda *args: events.append(args))
        provider = ConcreteWorkloadProvider.__new__(ConcreteWorkloadProvider)
        provider._states = {'execution': state}; provider.config = SimpleNamespace(audience='racecar')
        provider._attest_owned = lambda *args: None
        return provider, state, admitted, events

    async def test_generic_403_does_not_establish_revocation(self):
        provider, state, admitted, events = await self.exercise_oracle(rejection=403)
        with self.assertRaises(Uncertain):
            await provider.revoke_sessions(admitted, 'execution')
        self.assertFalse(state.revoked)

    async def test_generic_401_without_matching_revoked_sid_refuses(self):
        provider, state, admitted, events = await self.exercise_oracle(witnessed=False)
        with self.assertRaises(Refused):
            await provider.revoke_sessions(admitted, 'execution')
        self.assertFalse(state.revoked)

    async def test_observed_401_plus_same_sid_revoked_active_owner(self):
        provider, state, admitted, events = await self.exercise_oracle()
        await provider.revoke_sessions(admitted, 'execution')
        self.assertTrue(state.revoked)
        self.assertEqual(events[-1][0], 'revocation_oracle')
