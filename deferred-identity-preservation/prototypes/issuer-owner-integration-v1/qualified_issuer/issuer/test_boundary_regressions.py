"""UNRUN route/result characterization, no live provider or actual JWT fixture."""
import unittest

from .issuer_provider_v4 import IssuerBoundary, ProviderRejected
from .test_context_evidence import context_value, guard


class BoundaryRegressions(unittest.TestCase):
    def setUp(self):
        self.boundary = IssuerBoundary(runtime_pin={
            'issuer': 'https://identity.west.golaszewski.net',
            'source': 'a' * 40, 'image': 'sha256:' + 'b' * 64}, tenant='sandbox',
            runtime_check=lambda pin: None, subject_producer=lambda value: 'principal:' + value,
            token_verifier=lambda **kwargs: {},
            context_validator=guard(attest=lambda *args: None))

    def test_context_uses_boundary_tenant(self):
        value = context_value()
        self.assertIs(self.boundary._validate_admin_result('context', None, None, value), value)

    def test_foreign_context_is_refused(self):
        with self.assertRaises(ProviderRejected):
            self.boundary._validate_admin_result('context', None, None,
                context_value('foreign'))

    def test_direct_enrollment_route_is_supported(self):
        action, raw = self.boundary._user_route('POST',
            '/api/v1/account/mfa/totp/enroll?audience=chrysalis-identity',
            {'display_name': 'Owned factor'}, 'fake-unit-token')
        self.assertEqual(action, 'enroll')

    def test_direct_confirmation_route_is_supported(self):
        action, raw = self.boundary._user_route('POST',
            '/api/v1/account/mfa/totp/confirm?audience=chrysalis-identity',
            {'factor_id': 'fake-unit-factor', 'code': '123456'}, 'fake-unit-token')
        self.assertEqual(action, 'confirm')

    def test_unknown_audience_mfa_routes_stay_refused(self):
        for action in ('enroll', 'confirm'):
            body = {'display_name': 'Owned factor'} if action == 'enroll' else {
                'factor_id': 'fake-unit-factor', 'code': '123456'}
            with self.subTest(action=action), self.assertRaises(ProviderRejected):
                self.boundary._user_route('POST',
                    '/api/v1/account/mfa/totp/' + action + '?audience=unknown', body, 'fake-unit-token')
