"""UNRUN: strict canonical JSON DTO and explicitly nominated admin-home controls."""
from dataclasses import replace
import unittest
from unittest.mock import AsyncMock

from .account_evidence import active_profile, revoked_session_witness
from .context_evidence import AdminContextPolicy, RegisteredAdminContextGuard
from .contracts import AdminSession, Refused, admin_home_selector, tenant_selector
from .current_admin import CurrentAdminSessionVerifier
from .http_exchange import HttpExchange, HttpResult
from .test_account_evidence import profile_value, workbench_value, SID
from .test_context_evidence import admission, context_value, PIN, PRINCIPAL


class StrictJsonAndHome(unittest.TestCase):
    def test_profile_boolean_coercions_refused(self):
        for value in (1, 0, 'true', 'false'):
            profile = profile_value(); profile['sessions'][0]['is_current'] = value
            with self.subTest(value=value), self.assertRaises(Refused):
                active_profile(profile, principal_id=PRINCIPAL, session_id=SID,
                               subject='principal:' + PRINCIPAL, audience='racecar')

    def test_profile_integer_coercion_refused(self):
        profile = profile_value(); profile['branding']['version'] = '0'
        with self.assertRaises(Refused):
            active_profile(profile, principal_id=PRINCIPAL, session_id=SID,
                           subject='principal:' + PRINCIPAL, audience='racecar')

    def test_nonfinite_json_refused(self):
        profile = profile_value(); profile['branding']['version'] = float('nan')
        with self.assertRaises(Refused):
            active_profile(profile, principal_id=PRINCIPAL, session_id=SID,
                           subject='principal:' + PRINCIPAL, audience='racecar')

    def test_numeric_datetime_is_not_canonical_json_witness(self):
        value = workbench_value(); value['sessions'][0]['revoked_at'] = 1793142000
        with self.assertRaises(Refused):
            revoked_session_witness(value, principal_id=PRINCIPAL, session_id=SID,
                                    audience='racecar')

    def test_legitimate_iso_datetime_json_still_valid(self):
        self.assertIsNone(active_profile(profile_value(), principal_id=PRINCIPAL,
            session_id=SID, subject='principal:' + PRINCIPAL, audience='racecar'))
        self.assertIsNone(revoked_session_witness(workbench_value(), principal_id=PRINCIPAL,
                                                  session_id=SID, audience='racecar'))

    def test_default_only_allowed_for_explicit_admin_home(self):
        self.assertEqual(admin_home_selector('default'), 'default')
        with self.assertRaises(Refused):
            tenant_selector('default')
        with self.assertRaises(Refused):
            replace(admission(), tenant='default').validate(cleanup=False)

    def test_admin_home_is_not_silently_normalized(self):
        for value in ('Default', ' default ', '', 'a' * 64):
            with self.subTest(value=value), self.assertRaises(Refused):
                admin_home_selector(value)

    def test_cross_tenant_default_admin_requires_registered_sandbox(self):
        value = context_value(); value['operator_home_tenant']['id'] = 'default'
        policy = AdminContextPolicy('principal:' + PRINCIPAL, 'default', 'development')
        guard = RegisteredAdminContextGuard(admission=admission(), policy=policy,
                                           attest_sandbox=lambda *args: None)
        self.assertIsNone(guard(value, PIN, 'sandbox'))
        with self.assertRaises(Refused):
            RegisteredAdminContextGuard(admission=admission(), policy=policy)(value, PIN, 'sandbox')


class CurrentDefaultAdmin(unittest.IsolatedAsyncioTestCase):
    def fixture(self, *, home='default', sid=SID):
        admitted = admission()
        value = context_value(); value['operator_home_tenant']['id'] = home
        exchange = HttpExchange.__new__(HttpExchange)
        exchange.request = AsyncMock(return_value=HttpResult(200, value))
        session = AdminSession('synthetic-token', 'principal:' + PRINCIPAL, 'sandbox',
                               admitted.cleanup_deadline + 30)
        claims = {'sub': session.subject, 'tenant_id': home, 'sid': sid}
        verifier = CurrentAdminSessionVerifier(exchange=exchange,
            canonical_verify=lambda **kwargs: claims, issuer=PIN['issuer'],
            audience='chrysalis-identity', environment='development',
            nominated_subject=session.subject, home_tenant=home)
        return verifier, session, admitted, exchange, value, claims

    async def test_existing_default_home_checks_actual_current_context(self):
        verifier, session, admitted, exchange, value, claims = self.fixture()
        self.assertIsNone(await verifier(session, admitted, admitted.access_deadline))
        exchange.request.assert_awaited_once_with('GET', '/api/v1/admin/context',
            token=session.token, deadline=admitted.access_deadline)

    async def test_foreign_home_claim_refused_before_live_check(self):
        verifier, session, admitted, exchange, value, claims = self.fixture()
        claims['tenant_id'] = 'foreign'
        with self.assertRaises(Refused):
            await verifier(session, admitted, admitted.access_deadline)
        exchange.request.assert_not_awaited()

    async def test_missing_signed_sid_refused_before_live_check(self):
        verifier, session, admitted, exchange, value, claims = self.fixture(sid=None)
        with self.assertRaises(Refused):
            await verifier(session, admitted, admitted.access_deadline)
        exchange.request.assert_not_awaited()

    async def test_default_home_does_not_bypass_strong_auth(self):
        verifier, session, admitted, exchange, value, claims = self.fixture()
        value['auth_assurance']['strong_auth_satisfied'] = False
        with self.assertRaises(Refused):
            await verifier(session, admitted, admitted.access_deadline)
