"""Actual admin-context response plus independently registered sandbox authority.

UNRUN. The registry attestor is an imperative guard over original admission and
qualified runtime/tenant pins; it is not supplied by a workload message.
"""
from __future__ import annotations

from dataclasses import dataclass
import json
from uuid import UUID

from .contracts import Admission, Refused, admin_home_selector


@dataclass(frozen=True)
class AdminContextPolicy:
    subject: str
    home_tenant: str
    app_environment: str

    def principal(self) -> str:
        admin_home_selector(self.home_tenant)
        if (type(self.subject) is not str or not self.subject.startswith('principal:')
                or type(self.home_tenant) is not str or not self.home_tenant
                or type(self.app_environment) is not str or not self.app_environment):
            raise Refused()
        value = self.subject.removeprefix('principal:')
        try:
            if str(UUID(value)) != value:
                raise Refused()
        except ValueError:
            raise Refused() from None
        return value


class RegisteredAdminContextGuard:
    def __init__(self, *, admission: Admission, policy: AdminContextPolicy,
                 attest_sandbox=None) -> None:
        if type(admission) is not Admission or type(policy) is not AdminContextPolicy:
            raise Refused()
        self._principal = policy.principal()
        self._admission, self._policy = admission, policy
        self._attest = attest_sandbox

    def __call__(self, value: dict, pin: dict, tenant: str) -> None:
        self._admission.validate(cleanup=True)
        if not callable(self._attest) or tenant != self._admission.tenant:
            raise Refused()
        if type(value) is not dict or type(pin) is not dict:
            raise Refused()
        selected, home = value.get('selected_tenant'), value.get('operator_home_tenant')
        assurance = value.get('auth_assurance')
        if (value.get('tenant_id') != tenant
                or value.get('operator_principal_id') != self._principal
                or value.get('environment') != self._policy.app_environment
                or type(selected) is not dict or selected.get('id') != tenant
                or selected.get('status') != 'active'
                or type(home) is not dict or home.get('id') != self._policy.home_tenant
                or type(assurance) is not dict or assurance.get('method') != 'bearer'
                or assurance.get('strong_auth_satisfied') is not True):
            raise Refused()
        # Do not read invented summary fields, substitute app_env for tenant
        # classification, or accept a caller's sandbox assertion. The actual
        # registry must independently find sandbox authorization for THIS
        # admission, lifetimes, runtime pins and tenant. None-or-raise only.
        if self._attest(self._admission, json.loads(json.dumps(pin, allow_nan=False)),
                        tenant) is not None:
            raise Refused()

        # A synchronous registry lookup may consume the remaining budget.
        # Success cannot renew or outlive the original cleanup authority.
        self._admission.validate(cleanup=True)
