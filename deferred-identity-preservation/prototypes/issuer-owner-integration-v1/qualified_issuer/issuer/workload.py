"""Concrete genuine issuer staging/verification/delivery material; UNRUN.

Actual admin/registry bindings remain unconfigured dependencies. No credential
file/environment lookup, signer fallback, synthetic token or provider retry.
One fresh principal per actual invocation; direct and BFF invocations never share.
"""
from __future__ import annotations

import asyncio
from dataclasses import dataclass, field
import hashlib
import json
import re
import secrets
import time
from uuid import UUID

from .contracts import tenant_selector, Admission, Refused, Uncertain
from .gateway import Gateway
from .account_evidence import revoked_session_witness


@dataclass(frozen=True)
class WorkloadConfig:
    role: str
    audience: str
    wrong_tenant: str
    email_domain: str

    def validate(self, admission: Admission) -> None:
        admission.validate(cleanup=False)
        if ((self.role, self.audience) not in {('direct', 'chrysalis-identity'), ('bff', 'racecar')}
                or self.wrong_tenant == admission.tenant
                or tenant_selector(self.wrong_tenant) != self.wrong_tenant
                or re.fullmatch('[a-z0-9.-]{1,100}', self.email_domain) is None):
            raise Refused()


@dataclass(frozen=True)
class Dependencies:
    runtime_check: object
    attest_profile: object
    attest_owned: object
    delivery_registry: object
    attest_sandbox: object = None

    def validate(self) -> None:
        if (not all(callable(item) for item in (self.runtime_check, self.attest_profile,
                                               self.attest_owned, self.attest_sandbox))
                or not callable(getattr(self.delivery_registry, 'arm', None))
                or not callable(getattr(self.delivery_registry, 'authenticate', None))
                or not callable(getattr(self.delivery_registry, 'disarm', None))):
            raise Refused()


@dataclass(repr=False)
class PrivateState:
    admission: Admission
    gateway: Gateway
    email: str
    password: str = field(repr=False)
    intent: object = field(repr=False)
    outcome: object = field(repr=False)
    principal_id: str | None = None
    token: str | None = field(default=None, repr=False)
    seed: str | None = field(default=None, repr=False)
    factor_id: str | None = None
    confirmed_counter: int = -1
    revoked: bool = False
    delivery_consumed: bool = False


class ConcreteWorkloadProvider:
    def __init__(self, *, authority, config: WorkloadConfig, dependencies: Dependencies,
                 user_factory, boundary_factory, journal):
        dependencies.validate()
        self.authority, self.config, self.deps = authority, config, dependencies
        self._user_factory, self._boundary_factory = user_factory, boundary_factory
        self._journal = journal
        self._states: dict[str, PrivateState] = {}
        self._clients: dict[str, object] = {}

    def _attest_owned(self, state: PrivateState, execution: str, principal: str) -> None:
        if (type(principal) is not str or str(UUID(principal)) != principal or state.principal_id != principal
                or self.deps.attest_owned(state.admission, execution, state.email, principal) is not None):
            raise Refused()

    async def stage(self, admission: Admission, execution_id: str, intent, outcome) -> None:
        self.config.validate(admission)
        if (execution_id in self._states or admission.access_deadline - time.monotonic() <= 35
                or self.deps.attest_profile(admission, self.config) is not None):
            raise Refused()
        user = self._user_factory(self.config.audience)
        self._clients[execution_id] = user
        # Actual fixed-origin public keys are fetched, then deep-frozen by the
        # canonical verifier composition; no candidate JWKS or arbitrary URL.
        keys = await user.request('GET', '/api/v1/auth/.well-known/jwks.json',
                                  deadline=admission.access_deadline)
        if type(keys.value) is not dict or type(keys.value.get('keys')) is not list:
            raise Refused()
        boundary = self._boundary_factory(keys.value['keys'], self.authority, user, admission)
        gateway = Gateway(boundary, self.authority, user)
        await gateway.admin(admission, 'GET', '/api/v1/admin/context', None,
                            deadline=admission.access_deadline)
        catalog = await gateway.admin(admission, 'GET', '/api/v1/admin/applications/'
            + self.config.audience + '/access-catalog', None, deadline=admission.access_deadline)
        capability = 'racecar:access' if self.config.audience == 'racecar' else 'identity:access_read'
        if not any(row.get('name') == capability for row in catalog['capabilities']):
            raise Refused()  # No implicit catalog/bootstrap modification.
        email = 'jit-' + secrets.token_hex(16) + '@' + self.config.email_domain
        state = PrivateState(admission, gateway, email, secrets.token_urlsafe(40), intent, outcome)
        self._states[execution_id] = state
        intent('create', {'email': email, 'role': self.config.role})
        path = self.authority.register_email(email, attest_intent=lambda supplied:
            None if supplied == state.email else self._reject())
        before = await self.authority.read(admission, path, deadline=admission.access_deadline)
        if before.value != []:
            raise Refused()
        outcome('lookup', {'email': email, 'outcome': 'absent_before_create'})
        result = await gateway.admin(admission, 'POST', '/api/v1/admin/principals',
            {'email': email, 'password': state.password, 'display_name': 'Owned JIT qualification'},
            deadline=admission.access_deadline)
        principal = result['id']
        state.principal_id = principal
        outcome('create', {'email': email, 'principal_id': principal, 'role': self.config.role})
        self.authority.register_principal(principal,
            attest_owned=lambda value: self._attest_owned(state, execution_id, value))
        intent('grant', {'principal_id': principal, 'audience': self.config.audience})
        await gateway.admin(admission, 'POST', '/api/v1/admin/principals/' + principal + '/capabilities',
            {'audience': self.config.audience, 'capability_name': capability},
            deadline=admission.access_deadline)
        outcome('grant', {'principal_id': principal, 'outcome': 'accepted'})
        token = (await gateway.user_request(admission, 'POST', '/api/v1/auth/login',
            {'email': email, 'password': state.password, 'audience': self.config.audience,
             'identity_tenant': admission.tenant}))['access_token']
        boundary.verify_token(token, admission.tenant, boundary.subject(principal), self.config.audience)
        state.token = token
        intent('enroll', {'principal_id': principal})
        factor = await gateway.user_request(admission, 'POST',
            '/api/v1/account/mfa/totp/enroll?audience=' + self.config.audience,
            {'display_name': 'Owned qualification factor'}, token=token)
        state.seed, state.factor_id = factor['secret'], factor['factor_id']
        outcome('enroll', {'principal_id': principal, 'factor_id': state.factor_id})
        import pyotp
        state.confirmed_counter = int(time.time() // 30)
        code = pyotp.TOTP(state.seed, digits=6, interval=30).at(state.confirmed_counter * 30)
        intent('confirm', {'principal_id': principal, 'factor_id': state.factor_id})
        await gateway.user_request(admission, 'POST',
            '/api/v1/account/mfa/totp/confirm?audience=' + self.config.audience,
            {'factor_id': state.factor_id, 'code': code}, token=token)
        outcome('confirm', {'principal_id': principal, 'factor_id': state.factor_id,
                            'outcome': 'accepted'})

    @staticmethod
    def _reject():
        raise Refused()

    async def arm(self, admission: Admission, execution_id: str, consume_delivery) -> None:
        state = self._states.get(execution_id)
        if state is None or state.admission != admission or state.seed is None:
            raise Uncertain()
        while int(time.time() // 30) <= state.confirmed_counter:
            remaining = admission.access_deadline - time.monotonic()
            if remaining <= 0:
                raise Uncertain()
            await asyncio.sleep(min(0.2, remaining))
        from .workload_delivery import WorkloadSession
        handler = WorkloadSession(self, admission, execution_id, consume_delivery)
        if await self.deps.delivery_registry.arm(admission, execution_id, handler.handle) is not None:
            raise Uncertain()

    async def login_material(self, admission: Admission, execution: str, consume) -> dict[str, str]:
        state = self._states[execution]
        if state.admission != admission or state.delivery_consumed or state.seed is None:
            raise Uncertain()
        if int(time.time() // 30) <= state.confirmed_counter:
            # arm already waited for genuine readiness. A regressed clock or
            # missing readiness refuses instead of extending workload-v2 RPC.
            raise Uncertain()
        import pyotp
        code = pyotp.TOTP(state.seed, digits=6, interval=30).now()
        # Reserve/fsync BEFORE the response writer can receive secret material.
        consume()
        state.delivery_consumed = True
        return {'tenant_id': admission.tenant, 'principal_id': state.gateway.boundary.subject(state.principal_id),
                'wrong_tenant_id': self.config.wrong_tenant, 'email': state.email,
                'password': state.password, 'totp_code': code}

    async def revoke_sessions(self, admission: Admission, execution: str) -> None:
        state = self._states[execution]
        if state.admission != admission or state.token is None or state.principal_id is None:
            raise Uncertain()
        principal, gateway = state.principal_id, state.gateway
        self._attest_owned(state, execution, principal)
        workbench = await gateway.admin(admission, 'GET',
            '/api/v1/admin/principals/' + principal + '/workbench', None,
            deadline=admission.cleanup_deadline)
        if workbench['principal'].get('status') != 'active':
            raise Uncertain()
        claims = gateway.boundary.verify_token(state.token, admission.tenant,
            gateway.boundary.subject(principal), self.config.audience)
        sid = claims.get('sid')
        if type(sid) is not str or not sid:
            raise Uncertain()
        if (await gateway.account(admission, state.token, self.config.audience,
                principal_id=principal, session_id=sid, cleanup=True)).status != 200:
            raise Uncertain()
        state.intent('revoke', {'principal_id': principal})
        await gateway.admin(admission, 'POST', '/api/v1/admin/principals/' + principal + '/sessions/revoke',
            {'reason': 'Owned JIT qualification session revocation'}, deadline=admission.cleanup_deadline)
        state.outcome('revoke', {'principal_id': principal, 'outcome': 'accepted'})
        rejected = await gateway.account(admission, state.token, self.config.audience,
            principal_id=principal, session_id=sid, cleanup=True)
        if rejected.status != 401 or rejected.value != {'detail': 'Invalid token'}:
            raise Uncertain()
        active = await gateway.admin(admission, 'GET',
            '/api/v1/admin/principals/' + principal + '/workbench', None,
            deadline=admission.cleanup_deadline)
        if active['principal'].get('status') != 'active':
            raise Uncertain()
        revoked_session_witness(active, principal_id=principal, session_id=sid,
                                audience=self.config.audience)
        state.revoked = True
        state.outcome('revocation_oracle', {'principal_id': principal, 'outcome': 'rejected_while_active'})

    async def revoke_and_cleanup(self, admission: Admission, execution_id: str,
                                 journal: tuple[dict, ...], *, reconcile: bool) -> None:
        from .workload_cleanup import cleanup_owned
        await cleanup_owned(self, admission, execution_id, journal, reconcile=reconcile)
