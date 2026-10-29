"""Explicit broker edge results; credential custody belongs to the consuming application."""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Literal

from chrysalis_identity_client.claims import IdentityClaims

BrokerOutcome = Literal[
    "retryable_transport",
    "retryable_provider",
    "reauth_required",
    "invalid_response",
    "client_rejected",
]


class BrokerGrantError(ValueError):
    """Sanitized outcome, never a provider body or credential."""

    def __init__(self, outcome: BrokerOutcome) -> None:
        self.outcome = outcome
        super().__init__(outcome)


@dataclass(frozen=True)
class GrantOwner:
    tenant_id: str
    subject: str


@dataclass(frozen=True)
class FreshAuthority:
    owner: GrantOwner
    claims: IdentityClaims = field(repr=False)
    access_expires_at: int
    session_absolute_expires_at: int


@dataclass(frozen=True)
class BrokerCredentials:
    access_token: str = field(repr=False)
    refresh_token: str = field(repr=False)
    scope: str


@dataclass(frozen=True)
class GrantExchangeResult:
    """Persist a received successor even when subsequent authority validation is unavailable."""

    credentials: BrokerCredentials = field(repr=False)
    authority: FreshAuthority | None
    failure: BrokerGrantError | None = None
