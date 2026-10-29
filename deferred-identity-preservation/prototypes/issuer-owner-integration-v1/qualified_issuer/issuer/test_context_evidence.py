"""UNRUN: actual canonical summary DTO plus explicit synthetic registry controls."""
from dataclasses import replace
import time
import unittest
from unittest.mock import patch

from chrysalis_identity.schemas_admin_readmodels import AdminAuthAssuranceResponse
from chrysalis_identity.schemas_admin_tenant import AdminTenantSummaryResponse

from .context_evidence import AdminContextPolicy, RegisteredAdminContextGuard
from .contracts import Admission, Refused
from .issuer_provider_v4 import IssuerBoundary, ProviderRejected

PRINCIPAL = '11111111-1111-4111-8111-111111111111'
PIN = {'issuer': 'https://identity.west.golaszewski.net',
       'source': 'a' * 40, 'image': 'sha256:' + 'b' * 64}


def context_value(tenant='sandbox'):
    # Real canonical DTO constructors, not an invented environment_type field.
    summary = AdminTenantSummaryResponse(id=tenant, display_name='Synthetic sandbox',
                                        status='active').model_dump(mode='json')
    home = AdminTenantSummaryResponse(id='home', display_name='Synthetic admin home',
                                     status='active').model_dump(mode='json')
    assurance = AdminAuthAssuranceResponse(method='bearer', amr=['pwd', 'otp'],
        strong_auth_satisfied=True).model_dump(mode='json')
    return {'tenant_id': tenant, 'selected_tenant': summary,
            'operator_principal_id': PRINCIPAL, 'operator_home_tenant': home,
            'environment': 'development', 'auth_assurance': assurance}


def admission(tenant='sandbox'):
    now = time.monotonic()
    return Admission('a' * 64, 'coord', 'consumer', 'held', tenant, now + 60, now + 120)


def guard(*, tenant='sandbox', attest=None):
    return RegisteredAdminContextGuard(admission=admission(tenant),
        policy=AdminContextPolicy('principal:' + PRINCIPAL, 'home', 'development'),
        attest_sandbox=attest)


class ContextEvidence(unittest.TestCase):
    def test_actual_summary_positive_requires_independent_registration(self):
        calls = []
        value = context_value()
        self.assertNotIn('environment_type', value['selected_tenant'])
        validator = guard(attest=lambda *args: calls.append(args))
        self.assertIsNone(validator(value, PIN, 'sandbox'))
        self.assertEqual(calls[0][1:], (PIN, 'sandbox'))
        self.assertEqual(calls[0][0].context, 'a' * 64)

    def test_absent_registration_refuses_actual_valid_response(self):
        with self.assertRaises(Refused):
            guard()(context_value(), PIN, 'sandbox')

    def test_boolean_is_not_registration_authority(self):
        for receipt in (False, True):
            with self.subTest(receipt=receipt), self.assertRaises(Refused):
                guard(attest=lambda *args: receipt)(context_value(), PIN, 'sandbox')

    def test_foreign_registered_tenant_refused(self):
        def registered(admitted, pin, tenant):
            if tenant != 'other' or admitted.tenant != 'other':
                raise Refused()
        with self.assertRaises(Refused):
            guard(attest=registered)(context_value(), PIN, 'sandbox')

    def test_foreign_registered_runtime_refused(self):
        def registered(admitted, pin, tenant):
            if pin['source'] != 'c' * 40:
                raise Refused()
        with self.assertRaises(Refused):
            guard(attest=registered)(context_value(), PIN, 'sandbox')

    def test_foreign_context_lifetime_refused_by_registry(self):
        def registered(admitted, pin, tenant):
            if admitted.coordinator_lifetime != 'other-lifetime':
                raise Refused()
        with self.assertRaises(Refused):
            guard(attest=registered)(context_value(), PIN, 'sandbox')

    def test_actual_evidence_mismatches_refused_before_attestor(self):
        mutations = [('tenant_id', 'foreign'), ('operator_principal_id', 'foreign'),
                     ('environment', 'production')]
        calls = []
        for key, replacement in mutations:
            value = context_value(); value[key] = replacement
            with self.subTest(key=key), self.assertRaises(Refused):
                guard(attest=lambda *args: calls.append(args))(value, PIN, 'sandbox')
        self.assertEqual(calls, [])

    def test_nested_evidence_mismatches_refused(self):
        for parent, key, replacement in [
                ('selected_tenant', 'id', 'foreign'),
                ('selected_tenant', 'status', 'suspended'),
                ('operator_home_tenant', 'id', 'foreign'),
                ('auth_assurance', 'method', 'bootstrap'),
                ('auth_assurance', 'strong_auth_satisfied', False),
                ('auth_assurance', 'strong_auth_satisfied', 1)]:
            value = context_value(); value[parent][key] = replacement
            with self.subTest(parent=parent, key=key), self.assertRaises(Refused):
                guard(attest=lambda *args: None)(value, PIN, 'sandbox')

    def test_invented_sandbox_metadata_grants_no_authority(self):
        value = context_value()
        value['environment'] = 'sandbox'
        value['selected_tenant']['environment_type'] = 'sandbox'
        with self.assertRaises(Refused):
            guard()(value, PIN, 'sandbox')

    def test_boundary_default_refuses_context_without_validator(self):
        boundary = IssuerBoundary(runtime_pin=PIN, tenant='sandbox',
            runtime_check=lambda pin: None, subject_producer=lambda value: value,
            token_verifier=lambda **kwargs: {})
        with self.assertRaises(ProviderRejected):
            boundary._validate_admin_result('context', None, None, context_value())

    def test_expired_original_admission_not_renewed(self):
        validator = guard(attest=lambda *args: None)
        validator._admission = replace(validator._admission,
                                      cleanup_deadline=time.monotonic() - 1)
        with self.assertRaises(Refused):
            validator(context_value(), PIN, 'sandbox')

    def test_synchronous_attestor_cannot_outlive_original_budget(self):
        # Deterministically model elapsed time inside the synchronous registry;
        # do not sleep, renew admission, or use a timeout that needs an await.
        now = time.monotonic()
        clock = [now]
        called = []
        def slow_attestor(admitted, pin, tenant):
            called.append(admitted)
            clock[0] = admitted.cleanup_deadline + 1
        validator = guard(attest=slow_attestor)
        original = validator._admission
        with patch.object(time, 'monotonic', side_effect=lambda: clock[0]):
            with self.assertRaises(Refused):
                validator(context_value(), PIN, 'sandbox')
        self.assertEqual(called, [original])
        self.assertIs(validator._admission, original)
