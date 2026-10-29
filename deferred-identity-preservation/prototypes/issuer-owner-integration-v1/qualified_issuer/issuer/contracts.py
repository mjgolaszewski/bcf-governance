"""Installed infrastructure ports; candidate messages cannot construct authority."""
from __future__ import annotations

from dataclasses import dataclass, field
import math
import re
import time
from typing import Callable, Protocol


class Refused(RuntimeError):
    def __init__(self) -> None:
        super().__init__('issuer owner refused')


class Uncertain(Refused):
    """No replay or custody release until independently reconciled."""


def _canonical_tenant(value: str) -> str:
    """Delegate canonical routing; refuse repairs before any provider effects."""
    from chrysalis_identity.domain.tenancy import normalize_tenant_id
    try:
        if (type(value) is not str or not 1 <= len(value) <= 63
                or normalize_tenant_id(value) != value):
            raise Refused()
    except (ValueError, TypeError):
        raise Refused() from None
    return value


def tenant_selector(value: str) -> str:
    """Workload target and wrong-tenant selector must remain nondefault."""
    result = _canonical_tenant(value)
    if result == 'default':
        raise Refused()
    return result


def admin_home_selector(value: str) -> str:
    """Only explicitly nominated EXISTING admin home may be canonical default."""
    return _canonical_tenant(value)


@dataclass(frozen=True)
class Admission:
    context: str
    coordinator_lifetime: str
    consuming_controller_lifetime: str
    held_peer_lifetime: str
    tenant: str
    access_deadline: float
    cleanup_deadline: float

    def validate(self, *, cleanup: bool) -> None:
        now = time.monotonic()
        tenant_selector(self.tenant)
        if (type(self.context) is not str or re.fullmatch('[0-9a-f]{64}', self.context) is None
                or type(self.coordinator_lifetime) is not str or not self.coordinator_lifetime
                or type(self.consuming_controller_lifetime) is not str or not self.consuming_controller_lifetime
                or type(self.held_peer_lifetime) is not str or not self.held_peer_lifetime
                or len({self.coordinator_lifetime, self.consuming_controller_lifetime, self.held_peer_lifetime}) != 3
                or type(self.tenant) is not str or self.tenant == 'default'
                or any(type(value) not in (int, float) or not math.isfinite(value)
                       for value in (self.access_deadline, self.cleanup_deadline))
                or self.cleanup_deadline <= self.access_deadline
                or self.cleanup_deadline <= now
                or (not cleanup and self.access_deadline <= now)):
            raise Refused()


@dataclass(frozen=True)
class Mutation:
    method: str
    path: str
    body: bytes = field(repr=False)
    operation: str


@dataclass(frozen=True)
class AdminSession:
    token: str = field(repr=False)
    subject: str
    tenant: str
    expires_at_monotonic: float


class Coordinator(Protocol):
    def admit(self, context: str, manifest_path: str, held_pid: int) -> Admission:
        """Independently inspect registered frozen view and actual accepted peer."""
        ...

    def recheck(self, admission: Admission, *, cleanup: bool) -> None: ...

    def recover(self, context: str, coordinator_lifetime: str,
                execution_id: str) -> Admission:
        """Independent durable registry lookup, never reconstruct from request."""
        ...

    def native_closed(self, admission: Admission) -> None:
        """Direct trusted registry Q/bothEOF/reap; caller returncode is not proof."""
        ...


class ControlSource(Protocol):
    async def authorize(self, admission: Admission, mutation: Mutation,
                        session: AdminSession, deadline: float) -> dict[str, str]:
        """Real supported approval/artifact issuer; never candidate-selected."""
        ...


class WorkloadProvider(Protocol):
    async def stage(self, admission: Admission, execution_id: str,
                    intent: Callable[[str, dict[str, str]], None],
                    outcome: Callable[[str, dict[str, str]], None]) -> None:
        """Actual APIs/JWKS, per-effect durable callbacks, secrets private."""
        ...

    async def arm(self, admission: Admission, execution_id: str,
                  consume_delivery: Callable[[], None]) -> None:
        """Bind unchanged workload ABI; consume BEFORE every secret write."""
        ...

    async def revoke_and_cleanup(self, admission: Admission, execution_id: str,
                                 journal: tuple[dict, ...], *, reconcile: bool) -> None:
        """Owned-target/current-revocation oracle; unknown target means refusal."""
        ...
