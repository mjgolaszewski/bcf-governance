"""Current nominated admin session: canonical JWT plus live admin-context check.

Source-only, UNRUN. Stage beside the qualified issuer_owner modules. No login,
signer, bootstrap, credential discovery or authority inferred from tenant metadata.
"""
from __future__ import annotations

import asyncio
import math
import time
from uuid import UUID

from .contracts import Admission, AdminSession, Refused, admin_home_selector
from .http_exchange import HttpExchange, safe_header


class CurrentAdminSessionVerifier:
    """Use a dedicated real HttpExchange bound to the selected sandbox tenant.

    canonical_verify is the existing PinnedAccessTokenVerifier configured with
    pinned public JWKS and the installed admin audience. Construction and
    attestation of this trusted composition belong to the outside registry.
    """

    def __init__(self, *, exchange: HttpExchange, canonical_verify,
                 issuer: str, audience: str, environment: str,
                 nominated_subject: str, home_tenant: str) -> None:
        if (type(exchange) is not HttpExchange or not callable(canonical_verify)
                or audience != 'chrysalis-identity'
                or issuer != 'https://identity.west.golaszewski.net'
                or type(environment) is not str or not environment
                or not nominated_subject.startswith('principal:')
                or admin_home_selector(home_tenant) != home_tenant):
            raise Refused()
        principal = nominated_subject.removeprefix('principal:')
        try:
            if str(UUID(principal)) != principal:
                raise Refused()
        except (ValueError, TypeError, AttributeError):
            raise Refused() from None
        self._exchange, self._verify = exchange, canonical_verify
        self._issuer, self._audience = issuer, audience
        self._environment, self._subject = environment, nominated_subject
        self._principal, self._home = principal, home_tenant

    async def __call__(self, session: AdminSession, admission: Admission,
                       deadline: float) -> None:
        admission.validate(cleanup=True)
        now = time.monotonic()
        if (type(session) is not AdminSession or not safe_header(session.token)
                or session.subject != self._subject
                or session.tenant != admission.tenant
                or type(deadline) not in (float, int) or not math.isfinite(deadline)
                or not now < deadline <= admission.cleanup_deadline
                or not deadline < session.expires_at_monotonic):
            raise Refused()
        async with asyncio.timeout(deadline - now):
            claims = self._verify(token=session.token, issuer=self._issuer,
                                  audience=self._audience)
            if (type(claims) is not dict or claims.get('sub') != self._subject
                    or claims.get('tenant_id') != self._home
                    or type(claims.get('sid')) is not str or not claims['sid']):
                raise Refused()
            # This real endpoint validates signature, token revocation, the sid's
            # current session, active principal and current permissions version.
            result = await self._exchange.request('GET', '/api/v1/admin/context',
                token=session.token, deadline=deadline)
            value = result.value
            if result.status != 200 or type(value) is not dict:
                raise Refused()
            assurance = value.get('auth_assurance')
            selected = value.get('selected_tenant')
            home = value.get('operator_home_tenant')
            if (value.get('operator_principal_id') != self._principal
                    or value.get('tenant_id') != admission.tenant
                    or value.get('environment') != self._environment
                    or type(selected) is not dict
                    or selected.get('id') != admission.tenant
                    or selected.get('status') != 'active'
                    or type(home) is not dict or home.get('id') != self._home
                    or type(assurance) is not dict
                    or assurance.get('method') != 'bearer'
                    or assurance.get('strong_auth_satisfied') is not True
                    or time.monotonic() >= deadline):
                raise Refused()
        # Freshness and method semantics belong to the server's canonical
        # strong_authentication_satisfied, not a reimplementation here.
