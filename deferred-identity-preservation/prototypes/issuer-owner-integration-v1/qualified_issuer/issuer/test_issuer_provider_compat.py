"""Offline authored controls; synthetic dependencies, no live acceptance."""
import json
import unittest
from contextlib import contextmanager

from .issuer_provider_v4 import IssuerProviderTransport, ProviderRejected, ProviderRequest

from .test_context_evidence import context_value, guard

ISSUER = 'https://identity.west.golaszewski.net'
TENANT = 'fixture-sandbox'
TARGET = '11111111-1111-4111-8111-111111111111'


class FixtureExchange:
    def __init__(self):
        self.calls = []
        self.status = 200
        self.payload = {'id': TARGET, 'status': 'disabled'}
        self.raw = None
        self.error = None
        self.chunks = None
        self.closed = 0

    @contextmanager
    def __call__(self, request, *, deadline):
        self.calls.append(request)
        if self.error:
            raise self.error
        try:
            raw = self.raw if self.raw is not None else json.dumps(self.payload).encode()
            yield self.status, iter(self.chunks if self.chunks is not None else [raw])
        finally:
            self.closed += 1


class ProviderControls(unittest.TestCase):
    def setUp(self):
        self.admin = FixtureExchange()
        self.user = FixtureExchange()
        self.authorized = []
        self.targets = []
        self.pin = {'issuer': ISSUER, 'source': 'a' * 40, 'image': 'sha256:' + 'b' * 64}
        self.claims = {'iss': ISSUER, 'tenant_id': TENANT, 'sub': 'principal:' + TARGET,
                       'aud': 'racecar', 'type': 'access'}
        self.provider = IssuerProviderTransport(
            runtime_pin=self.pin, tenant=TENANT,
            runtime_check=lambda pin: None,
            subject_producer=lambda target: 'principal:' + target,
            token_verifier=lambda **kwargs: self.claims,
            admin_exchange=self.admin, user_exchange=self.user,
            control_producer=self.control, target_check=self.target,
            context_validator=guard(tenant=TENANT, attest=lambda *args: None))

    def control(self, request):
        self.authorized.append(request)
        return {'x-identity-admin-control-artifact': 'fixture-control'}

    def target(self, request):
        self.targets.append(request)

    def disable(self, body=None):
        return self.provider.admin('PATCH', '/api/v1/admin/principals/' + TARGET + '/status',
                                   body or {'status': 'disabled', 'reason': 'fixture'}, TENANT)

    def test_fixed_cleanup_route_success(self):
        self.assertEqual(self.disable()['status'], 'disabled')
        self.assertEqual(len(self.authorized), 1)
        self.assertEqual(len(self.targets), 1)
        self.assertEqual(len(self.user.calls), 0)
        self.assertEqual(self.admin.closed, 1)

    def test_missing_control_denies_before_exchange(self):
        self.provider.control_producer = None
        with self.assertRaises(ProviderRejected): self.disable()
        self.assertFalse(self.admin.calls)

    def test_missing_target_policy_denies(self):
        self.provider.target_check = None
        with self.assertRaises(ProviderRejected): self.disable()
        self.assertFalse(self.admin.calls)

    def test_target_policy_failure_denies(self):
        def deny(request): raise ValueError('fixture secret')
        self.provider.target_check = deny
        with self.assertRaisesRegex(ProviderRejected, '^private issuer provider rejected$'):
            self.disable()
        self.assertFalse(self.admin.calls)

    def test_unknown_route_or_target_or_tenant_denied(self):
        for path, tenant in [('https://evil.invalid', TENANT),
                             ('/api/v1/admin/principals/not-uuid/status', TENANT),
                             ('/api/v1/admin/principals/' + TARGET + '/status?x=1', TENANT),
                             ('/api/v1/admin/principals/' + TARGET + '/status', 'default')]:
            with self.subTest(path=path, tenant=tenant):
                with self.assertRaises(ProviderRejected):
                    self.provider.admin('PATCH', path, {'status': 'disabled', 'reason': 'fixture'}, tenant)
        self.assertFalse(self.admin.calls)

    def test_unknown_body_key_or_enable_denied(self):
        for body in [{'status': 'active', 'reason': 'fixture'},
                     {'status': 'disabled', 'reason': 'fixture', 'admin': True}]:
            with self.assertRaises(ProviderRejected): self.disable(body)
        self.assertFalse(self.admin.calls)

    def test_optional_permissions_version_is_not_mandatory(self):
        self.admin.payload = {'status': 'ok'}
        for suffix in [{}, {'expected_permissions_version': 'fixture-version'}]:
            self.provider.admin('POST', '/api/v1/admin/principals/' + TARGET + '/capabilities',
                                {'audience': 'racecar', 'capability_name': 'racecar:access', **suffix}, TENANT)
        self.assertEqual(len(self.admin.calls), 2)

    def test_capability_cross_audience_denied(self):
        with self.assertRaises(ProviderRejected):
            self.provider.admin('POST', '/api/v1/admin/principals/' + TARGET + '/capabilities',
                                {'audience': 'racecar', 'capability_name': 'identity:access_read'}, TENANT)
        self.assertFalse(self.admin.calls)

    def test_sessions_revoke_omits_session_id_and_never_disables(self):
        self.admin.payload = {'principal_id': TARGET, 'revoked_count': 1}
        self.provider.admin('POST', '/api/v1/admin/principals/' + TARGET + '/sessions/revoke',
                            {'reason': 'fixture'}, TENANT)
        self.assertEqual(json.loads(self.admin.calls[0].body), {'reason': 'fixture'})
        self.assertEqual(len(self.admin.calls), 1)
        with self.assertRaises(ProviderRejected):
            self.provider.admin('POST', '/api/v1/admin/principals/' + TARGET + '/sessions/revoke',
                                {'reason': 'fixture', 'session_id': 'fixture'}, TENANT)

    def test_timeout_is_one_attempt_and_private(self):
        self.admin.error = TimeoutError('fixture secret')
        with self.assertRaisesRegex(ProviderRejected, '^private issuer provider rejected$'):
            self.disable()
        self.assertEqual(len(self.admin.calls), 1)

    def test_redirect_conflict_and_nonexact_status_are_not_success(self):
        for status in [202, 204, 301, 307, 409, 500]:
            self.admin.status = status
            with self.assertRaises(ProviderRejected): self.disable()
        self.assertEqual(len(self.admin.calls), 6)
        self.assertEqual(self.admin.closed, 6)

    def test_bounded_malformed_duplicate_and_nonfinite_json(self):
        for raw in [b'x' * 65537, b'{', b'{"id":"x","id":"y"}', b'{"value":NaN}', b'[]']:
            self.admin.raw = raw
            with self.assertRaises(ProviderRejected): self.disable()
        self.assertEqual(self.admin.closed, 5)

    def test_wrong_success_shape_is_not_confirmation(self):
        self.admin.payload = {'id': TARGET, 'status': 'active'}
        with self.assertRaises(ProviderRejected): self.disable()
        self.assertEqual(len(self.admin.calls), 1)

    def test_login_202_is_not_token(self):
        self.user.status = 202
        self.user.payload = {'challenge_token': 'fixture'}
        with self.assertRaises(ProviderRejected):
            self.provider.user('POST', '/api/v1/auth/login',
                               {'email': 'fixture@example.com', 'password': 'fixture-password',
                                'audience': 'racecar', 'identity_tenant': TENANT}, TENANT)
        self.assertFalse(self.admin.calls)

    def test_user_token_is_private_and_only_user_channel(self):
        self.user.payload = {'factor_id': 'fixture-factor', 'secret': 'FIXTURE',
                             'provisioning_uri': 'fixture', 'qr_code_data_uri': 'fixture',
                             'issuer': 'fixture', 'account_name': 'fixture'}
        self.provider.user('POST', '/api/v1/account/mfa/totp/enroll?audience=racecar',
                           {'display_name': 'fixture'}, TENANT, 'fixture-token')
        self.assertFalse(self.admin.calls)
        self.assertNotIn('fixture-token', repr(self.user.calls[0]))
        self.assertNotIn('fixture-control', repr(self.user.calls[0]))

    def test_subject_uses_canonical_injected_producer(self):
        self.assertEqual(self.provider.subject(TARGET), 'principal:' + TARGET)
        with self.assertRaises(ProviderRejected): self.provider.subject(TARGET.upper() + 'x')

    def test_runtime_pin_mismatch_denied(self):
        with self.assertRaises(ProviderRejected):
            self.provider.check_runtime({**self.pin, 'source': 'c' * 40})

    def test_verified_claims_require_expected_tenant_subject_issuer_audience(self):
        self.assertEqual(self.provider.verify_token('fixture-token', TENANT, 'principal:' + TARGET, 'racecar'), self.claims)
        for key, value in [('iss', 'https://other.invalid'), ('tenant_id', 'default'),
                           ('sub', 'principal:other'), ('aud', 'other')]:
            prior = self.claims[key]; self.claims[key] = value
            with self.assertRaises(ProviderRejected):
                self.provider.verify_token('fixture-token', TENANT, 'principal:' + TARGET, 'racecar')
            self.claims[key] = prior

    def test_request_private_representation(self):
        request = ProviderRequest('POST', '/fixed', TENANT, b'fixture-password', 'fixture-token', {})
        self.assertNotIn('fixture-password', repr(request))
        self.assertNotIn('fixture-token', repr(request))


    def test_runtime_guard_unexpected_returns_deny_before_transport(self):
        for value in [False, True, 0, {}, 'denied']:
            self.provider.runtime_check = lambda pin, result=value: result
            with self.assertRaises(ProviderRejected): self.disable()
        self.assertFalse(self.admin.calls)

    def test_target_guard_unexpected_returns_deny_before_control_or_transport(self):
        for value in [False, True, 0, {}, 'denied']:
            self.provider.target_check = lambda request, result=value: result
            with self.assertRaises(ProviderRejected): self.disable()
        self.assertFalse(self.authorized)
        self.assertFalse(self.admin.calls)

    def test_context_positive_endpoint_shape(self):
        self.admin.payload = context_value(TENANT)
        self.assertEqual(self.provider.admin('GET', '/api/v1/admin/context', None, TENANT), self.admin.payload)
        self.assertFalse(self.authorized)

    def test_catalog_positive_endpoint_shape(self):
        self.admin.payload = {'capabilities': [{'name': 'racecar:access'}]}
        self.assertEqual(self.provider.admin('GET', '/api/v1/admin/applications/racecar/access-catalog',
                                             None, TENANT), self.admin.payload)

    def test_create_positive_endpoint_shape(self):
        self.admin.payload = {'id': TARGET, 'email': 'fixture@example.com', 'status': 'active'}
        self.assertEqual(self.provider.admin('POST', '/api/v1/admin/principals',
                        {'email': 'fixture@example.com', 'password': 'fixture-password',
                         'display_name': 'fixture'}, TENANT), self.admin.payload)
        self.assertEqual(len(self.authorized), 1)

    def test_workbench_positive_endpoint_shape(self):
        self.admin.payload = {'principal': {'id': TARGET, 'email': 'fixture@example.com',
                                            'is_deleted': False}, 'applications': []}
        self.assertEqual(self.provider.admin('GET', '/api/v1/admin/principals/' + TARGET + '/workbench',
                                             None, TENANT), self.admin.payload)

    def test_login_positive_endpoint_shape(self):
        self.user.payload = {'access_token': 'fixture-token', 'token_type': 'Bearer', 'expires_in': 60}
        self.assertEqual(self.provider.user('POST', '/api/v1/auth/login',
                        {'email': 'fixture@example.com', 'password': 'fixture-password',
                         'audience': 'racecar', 'identity_tenant': TENANT}, TENANT), self.user.payload)
        self.assertFalse(self.admin.calls)

    def test_confirm_positive_endpoint_shape(self):
        self.user.payload = {'id': 'fixture-factor', 'factor_type': 'totp', 'status': 'active'}
        self.assertEqual(self.provider.user('POST', '/api/v1/account/mfa/totp/confirm?audience=racecar',
                        {'factor_id': 'fixture-factor', 'code': '123456'}, TENANT, 'fixture-token'), self.user.payload)

    def test_incremental_chunks_positive_and_cap_enforced(self):
        self.admin.chunks = [b'{"id":"', TARGET.encode(), b'","status":"disabled"}']
        self.assertEqual(self.disable()['id'], TARGET)
        self.admin.chunks = [b'x' * 32768, b'y' * 32768, b'z']
        with self.assertRaises(ProviderRejected): self.disable()
        self.assertEqual(self.admin.closed, 2)

    def test_empty_and_wrong_type_chunks_denied_and_closed(self):
        for chunks in [[b''], ['fixture'], []]:
            self.admin.chunks = chunks
            with self.assertRaises(ProviderRejected): self.disable()
        self.assertEqual(self.admin.closed, 3)

    def test_deadline_checked_before_exchange_and_during_chunks(self):
        times = iter([0, 31])
        self.provider.clock = lambda: next(times)
        with self.assertRaises(ProviderRejected): self.disable()
        self.assertFalse(self.admin.calls)
        times = iter([0, 1, 31])
        self.provider.clock = lambda: next(times)
        with self.assertRaises(ProviderRejected): self.disable()
        self.assertEqual(self.admin.closed, 1)


if __name__ == '__main__':
    unittest.main()
