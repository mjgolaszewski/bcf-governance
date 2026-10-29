"""Actual canonical JWT/current-admin verifier bracketed by original Root checks.

The verifier's real fixed-origin exchange and pinned canonical JWT implementation
are required. No caller-selected callback or boolean attestation grants access.
"""
from __future__ import annotations

import time

from .issuer.canonical_verifier import PinnedAccessTokenVerifier
from .issuer.contracts import Admission, AdminSession, Refused
from .issuer.current_admin import CurrentAdminSessionVerifier
from .issuer.http_exchange import HttpExchange
from .sandbox_profile import OriginalSandboxProfile


class OriginalCurrentSessionPort:
    def __init__(self, *, profile: OriginalSandboxProfile, session: AdminSession,
                 verifier: CurrentAdminSessionVerifier) -> None:
        if (type(profile) is not OriginalSandboxProfile or type(session) is not AdminSession
                or type(verifier) is not CurrentAdminSessionVerifier
                or type(verifier._verify) is not PinnedAccessTokenVerifier
                or type(verifier._exchange) is not HttpExchange
                or verifier._exchange.tenant != profile._admission.tenant
                or verifier._subject != session.subject or verifier._home != 'default'
                or session.tenant != profile._admission.tenant):
            raise Refused()
        self._profile = profile
        self._session = session
        self._verifier = verifier

    async def __call__(self, session: AdminSession, admission: Admission, deadline: float) -> None:
        if session is not self._session:
            raise Refused()
        self._profile._current(admission)
        await self._verifier(session, admission, deadline)
        # Actual held source/runtime (or original post-Q cleanup scope) is
        # rechecked after the network await and before caller mutation dispatch.
        self._profile._current(admission)
        if time.monotonic() >= deadline:
            raise Refused()
