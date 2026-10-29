"""Supported strong-session/control composition; no signer or bootstrap fallback."""
from __future__ import annotations

import asyncio
import time

from .normal_policy import InstalledPolicyControls
from .contracts import Admission, AdminSession, ControlSource, Mutation, Refused
from .http_exchange import HttpExchange, HttpResult, safe_header


class AdminAuthority:
    def __init__(self, exchange: HttpExchange, session: AdminSession,
                 source: ControlSource, verify_current_session) -> None:
        if source is None or not callable(verify_current_session):
            raise Refused()
        self._exchange, self._session = exchange, session
        self._source, self._verify = source, verify_current_session

    async def read(self, admission: Admission, path: str, *, deadline: float) -> HttpResult:
        if (self._session.tenant != admission.tenant
                or deadline > admission.cleanup_deadline
                or self._session.expires_at_monotonic <= time.monotonic()
                or await self._verify(self._session, admission, deadline) is not None):
            raise Refused()
        return await self._exchange.request('GET', path, token=self._session.token,
                                             deadline=deadline)

    def register_email(self, email: str, *, attest_intent) -> str:
        return self._exchange.register_owned_email(email, attest_intent=attest_intent)

    def register_principal(self, principal_id: str, *, attest_owned) -> None:
        self._exchange.register_owned_principal(principal_id, attest_owned=attest_owned)

    def register_intent(self, intent_id: str, *, attest_binding) -> str:
        return self._exchange.register_control_intent(intent_id, attest_binding=attest_binding)

    async def mutate(self, admission: Admission, mutation: Mutation,
                     *, deadline: float) -> HttpResult:
        if (deadline > admission.cleanup_deadline or deadline <= time.monotonic()
                or self._session.tenant != admission.tenant
                or self._session.expires_at_monotonic <= time.monotonic()
                or not safe_header(self._session.token)):
            raise Refused()
        async with asyncio.timeout(deadline - time.monotonic()):
            # Actual canonical token + current strong/admin evidence dependency.
            # None-on-success only. A boolean receipt grants nothing.
            if await self._verify(self._session, admission, deadline) is not None:
                raise Refused()
            headers = await self._source.authorize(admission, mutation, self._session, deadline)
            if (type(headers) is not dict
                    or not set(headers) <= {'x-identity-admin-control-artifact',
                                           'x-identity-admin-mutation-intent'}):
                raise Refused()
            if type(self._source) is InstalledPolicyControls:
                await self._source.consume(admission,mutation,self._session,headers,deadline)
            elif not headers:
                raise Refused()  # Generic/candidate empty headers grant nothing.
            # Recheck actual current context after policy/approval await, before HTTP.
            if await self._verify(self._session, admission, deadline) is not None:
                raise Refused()
            return await self._exchange.request(mutation.method, mutation.path,
                body=mutation.body, token=self._session.token, control=headers, deadline=deadline)


class ApprovalQueries:
    """Separate exact installed endpoints/statuses; no broad Provider relaxation."""
    def __init__(self, exchange: HttpExchange, session: AdminSession) -> None:
        self._exchange, self._session = exchange, session

    async def read(self, path: str, *, deadline: float) -> HttpResult:
        if not (path.startswith('/api/v1/admin/mutation-intents/')
                or path == '/api/v1/auth/.well-known/jwks.json'):
            raise Refused()
        if deadline >= self._session.expires_at_monotonic:
            raise Refused()
        # Installed exchange still requires the exact registered GET path.
        token = None if path == '/api/v1/auth/.well-known/jwks.json' else self._session.token
        return await self._exchange.request('GET', path, token=token,
                                             deadline=deadline)
