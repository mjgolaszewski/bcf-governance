"""Source-only normal controls bound to actual server policy and Root authority.

Observations/JSON do not grant authority: an independent installed Root attestor
must bind each actual observation to admission, runtime, mutation and session.
No bootstrap signer, dummy intent, policy relaxation or candidate-chosen origin.
"""
from dataclasses import dataclass
import math
import re
import time
from .contracts import Admission, AdminSession, Mutation, Refused


@dataclass(frozen=True)
class PolicyPin:
    runtime_id: str
    started_at: str
    configuration_sha256: str
    profile: str
    source_origin: str
    source_sha256: str


@dataclass(frozen=True)
class PolicyObservation:
    pin: PolicyPin
    operation: str
    method: str
    path: str
    requires_approval: bool
    requires_strong_auth: bool
    requires_step_up: bool
    observed_at: float

    def decision(self):
        return (self.pin, self.operation, self.method, self.path,
                self.requires_approval, self.requires_strong_auth, self.requires_step_up)


class InstalledPolicyControls:
    """Exact trusted implementation is required for header-free normal requests."""
    def __init__(self, *, pin, observe_policy, attest_policy, approved_intent=None):
        if (type(pin) is not PolicyPin or not callable(observe_policy)
                or not callable(attest_policy) or pin.profile != 'openbao-kms'
                or pin.source_origin != '/app/src/chrysalis_identity/api/admin_context_policy.py'
                or type(pin.started_at) is not str or not pin.started_at
                or any(type(value) is not str or re.fullmatch('[0-9a-f]{64}',value) is None
                       for value in (pin.runtime_id,pin.configuration_sha256,pin.source_sha256))):
            raise Refused()
        self.pin=pin; self._observe=observe_policy; self._attest=attest_policy
        self._approved=approved_intent; self._pending={}

    async def _current(self, admission, mutation, session, deadline):
        if (type(admission) is not Admission or type(mutation) is not Mutation
                or type(session) is not AdminSession or session.tenant != admission.tenant
                or type(deadline) not in (int,float) or not math.isfinite(deadline)
                or not time.monotonic() < deadline <= admission.cleanup_deadline
                or not deadline < session.expires_at_monotonic):
            raise Refused()
        admission.validate(cleanup=True)
        value=await self._observe(admission,mutation,deadline)
        now=time.monotonic()
        if (type(value) is not PolicyObservation or value.pin != self.pin
                or (value.operation,value.method,value.path) != (mutation.operation,mutation.method,mutation.path)
                or any(type(flag) is not bool for flag in
                       (value.requires_approval,value.requires_strong_auth,value.requires_step_up))
                or value.requires_strong_auth is not True or value.requires_step_up is not True
                or type(value.observed_at) not in (int,float) or not math.isfinite(value.observed_at)
                or not 0 <= now-value.observed_at <= 5 or not now < deadline):
            raise Refused()
        # Imperative None-or-raise guard over actual original Root registry.
        # Neither a boolean nor a candidate observation may substitute for it.
        if self._attest(admission,mutation,session,value,self.pin) is not None:
            raise Refused()
        if time.monotonic() >= deadline:
            raise Refused()
        return value

    async def authorize(self, admission, mutation, session, deadline):
        if id(mutation) in self._pending or len(self._pending)>=128:
            raise Refused()
        value=await self._current(admission,mutation,session,deadline)
        headers={}
        if value.requires_approval:
            if not callable(self._approved):
                raise Refused()
            headers=await self._approved(admission,mutation,session,deadline)
            if (type(headers) is not dict or set(headers) != {'x-identity-admin-mutation-intent'}
                    or type(headers['x-identity-admin-mutation-intent']) is not str
                    or not 1 <= len(headers['x-identity-admin-mutation-intent']) <= 160
                    or any(ord(c)<33 or ord(c)>126 for c in headers['x-identity-admin-mutation-intent'])):
                raise Refused()
        if id(mutation) in self._pending or len(self._pending)>=128 or time.monotonic()>=deadline:
            raise Refused()
        self._pending[id(mutation)]=(admission,mutation,session,value,deadline,dict(headers))
        return headers

    async def consume(self, admission, mutation, session, headers, deadline):
        prior=self._pending.pop(id(mutation),None)
        if (prior is None or prior[0] is not admission or prior[1] is not mutation
                or prior[2] is not session or prior[4] != deadline or prior[5] != headers):
            raise Refused()
        current=await self._current(admission,mutation,session,deadline)
        if current.decision() != prior[3].decision():
            raise Refused()
        # One consumed authorization, not an approval receipt or native grant.
