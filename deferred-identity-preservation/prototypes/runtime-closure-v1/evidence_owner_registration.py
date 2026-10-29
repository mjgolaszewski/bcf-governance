"""Trusted-launcher binding of independent owners to one controller lifetime.

This is an in-process installation interface, not a candidate registration RPC,
CLI flag or environment selector. Candidate code executes in a separate process
and namespace; importing candidate code into this controller is unsupported.
A binding is not an issuer grant, source admission or cleanup receipt.
"""
from __future__ import annotations

import hashlib
import json
import math
import os
import time
from _thread import LockType
from collections.abc import Iterator
from contextlib import contextmanager
from contextvars import ContextVar
from dataclasses import dataclass, field
from pathlib import Path
from threading import Lock

from .evidence_execution_owner import OwnerAdmissionError, OwnerRegistration, ProcessIdentity

EXECUTION_OWNER_API_VERSION = 1


@dataclass(frozen=True)
class OwnerInvocationRoute:
    producer: str
    profile: str
    control: str

    def validate(self) -> None:
        for value in (self.producer, self.profile, self.control):
            if type(value) is not str or not value or len(value) > 256 or "\x00" in value:
                raise OwnerAdmissionError("exact invocation allocation contains an invalid route")


@dataclass(frozen=True)
class RequiredOwnerScope:
    repository: Path
    producers: frozenset[str]
    profiles: frozenset[str]
    controls: frozenset[str]
    allocation: tuple[OwnerInvocationRoute, ...] = ()

    def validate(self) -> None:
        if (not self.repository.is_absolute() or self.repository.is_symlink()
                or self.repository.resolve() != self.repository):
            raise OwnerAdmissionError("owner repository scope must be canonical")
        for population in (self.producers, self.profiles, self.controls):
            if type(population) is not frozenset or not population or any(
                    type(value) is not str or not value for value in population):
                raise OwnerAdmissionError("owner producer profile and control scope must be closed")

        if type(self.allocation) is not tuple or not 1 <= len(self.allocation) <= 4096:
            raise OwnerAdmissionError("exact invocation allocation must be a nonempty bounded tuple")
        for route in self.allocation:
            if type(route) is not OwnerInvocationRoute:
                raise OwnerAdmissionError("exact invocation allocation contains an unsupported route")
            route.validate()
        if (frozenset(route.producer for route in self.allocation) != self.producers
                or frozenset(route.profile for route in self.allocation) != self.profiles
                or frozenset(route.control for route in self.allocation) != self.controls):
            raise OwnerAdmissionError("scope membership must equal exact invocation allocation projections")

    def allocation_digest(self) -> str:
        """Identify the ordered trusted plan; not source or provider authority."""
        self.validate()
        data = {"repository": str(self.repository), "invocations": [
            {"ordinal": ordinal, "producer": route.producer,
             "profile": route.profile, "control": route.control}
            for ordinal, route in enumerate(self.allocation, 1)]}
        return hashlib.sha256(json.dumps(data, sort_keys=True,
            separators=(",", ":"), allow_nan=False).encode()).hexdigest()


@dataclass(frozen=True)
class InstalledOwnerBinding:
    controller: ProcessIdentity
    scope: RequiredOwnerScope
    issuer: OwnerRegistration
    custody: OwnerRegistration
    absolute_deadline: float
    maximum_invocations: int
    cleanup_seconds: int
    api_version: int = EXECUTION_OWNER_API_VERSION

    def _validate_common(self, *, cleanup_only: bool) -> None:
        if type(cleanup_only) is not bool:
            raise OwnerAdmissionError("owner validation mode is invalid")
        if type(self.api_version) is not int or self.api_version != EXECUTION_OWNER_API_VERSION:
            raise OwnerAdmissionError("installed execution-owner API version is unsupported")
        self.scope.validate()
        if ProcessIdentity.observe(os.getpid()) != self.controller:
            raise OwnerAdmissionError("owner binding belongs to a different controller lifetime")
        if self.issuer.owner == self.custody.owner:
            raise OwnerAdmissionError("issuer and workload custody must have independent owners")
        if (type(self.maximum_invocations) is not int
                or self.maximum_invocations != len(self.scope.allocation)
                or type(self.absolute_deadline) not in (int, float)
                or not math.isfinite(self.absolute_deadline)
                or type(self.cleanup_seconds) is not int or not 1 <= self.cleanup_seconds <= 300
                or self.absolute_deadline <= time.monotonic()
                or (not cleanup_only and self.absolute_deadline - self.cleanup_seconds <= time.monotonic())):
            raise OwnerAdmissionError("owner aggregate allocation is not finite and live")

    @staticmethod
    def _validate_peer(registration: OwnerRegistration) -> None:
        if ProcessIdentity.observe(registration.owner.pid) != registration.owner:
            raise OwnerAdmissionError("independent owner lifetime changed")

    def validate(self, *, cleanup_only: bool = False) -> None:
        self._validate_common(cleanup_only=cleanup_only)
        for registration in (self.issuer, self.custody):
            self._validate_peer(registration)

    def validate_cleanup_owner(self, registration: OwnerRegistration) -> None:
        """Authorize only one installed cleanup peer, independently of the other."""
        self._validate_common(cleanup_only=True)
        if (type(registration) is not OwnerRegistration
                or not any(registration is value for value in (self.issuer, self.custody))):
            raise OwnerAdmissionError("cleanup peer is outside the installed owner binding")
        self._validate_peer(registration)


@dataclass(frozen=True)
class ActualInvocationIdentity:
    repository: Path
    producer: str
    profile: str
    control: str


@dataclass(frozen=True)
class ReservedOwnerInvocation:
    binding: InstalledOwnerBinding
    actual: ActualInvocationIdentity
    ordinal: int
    deadline: float
    allocation_digest: str


    def validate_allocation(self) -> None:
        """Reject inconsistent reservation metadata before any owner connection."""
        scope = self.binding.scope
        scope.validate()
        if (type(self.ordinal) is not int or not 1 <= self.ordinal <= len(scope.allocation)
                or type(self.actual) is not ActualInvocationIdentity
                or type(self.allocation_digest) is not str
                or self.allocation_digest != scope.allocation_digest()
                or type(self.deadline) not in (int, float) or not math.isfinite(self.deadline)
                or self.deadline <= 0
                or self.deadline > self.binding.absolute_deadline - self.binding.cleanup_seconds):
            raise OwnerAdmissionError("reservation does not bind its exact invocation allocation")
        route = scope.allocation[self.ordinal - 1]
        if (self.actual.repository.resolve() != scope.repository
                or (self.actual.producer, self.actual.profile, self.actual.control) != (
                    route.producer, route.profile, route.control)):
            raise OwnerAdmissionError("reservation route differs from its exact invocation allocation")


@dataclass
class _InstalledState:
    binding: InstalledOwnerBinding
    reservations: int = 0
    lock: LockType = field(default_factory=Lock, repr=False)


_installed: ContextVar[_InstalledState | None] = ContextVar("bcf_installed_execution_owner", default=None)


@contextmanager
def bind_installed_execution_owner(binding: InstalledOwnerBinding) -> Iterator[None]:
    """Trusted launcher only; no nested replacement or candidate-selected owner."""
    if type(binding) is not InstalledOwnerBinding or _installed.get() is not None:
        raise OwnerAdmissionError("controller owner binding cannot be replaced")
    binding.validate()
    token = _installed.set(_InstalledState(binding))
    try:
        yield
    finally:
        _installed.reset(token)


def reserve_owner_invocation(actual: ActualInvocationIdentity, *, required: bool,
                             timeout_seconds: int) -> ReservedOwnerInvocation | None:
    """Derive the actual bounded route before either execution-state branch.

    The required bit is a requirement from the maintained execution plan; it
    cannot name an owner or grant provider authority. An installed launcher can
    independently require its scoped producers even when that bit is absent.
    The independent owners must also enforce their own durable aggregate caps.
    """
    if (type(actual) is not ActualInvocationIdentity or type(required) is not bool
            or type(timeout_seconds) is not int or not 1 <= timeout_seconds <= 21600):
        raise OwnerAdmissionError("actual invocation identity or timeout is invalid")
    state = _installed.get()
    if state is None:
        if required:
            raise OwnerAdmissionError("required independent execution owner is unconfigured")
        return None
    state.binding.validate()
    scope = state.binding.scope
    repository = actual.repository.resolve()
    if repository != scope.repository or actual.producer not in scope.producers:
        # A scoped controller cannot silently fall back to legacy execution by
        # changing a repository or producer label in candidate-authored data.
        raise OwnerAdmissionError("actual invocation is outside installed owner scope")
    if actual.profile not in scope.profiles or actual.control not in scope.controls:
        raise OwnerAdmissionError("actual profile or control is outside installed owner scope")
    with state.lock:
        now = time.monotonic()
        if state.reservations >= state.binding.maximum_invocations:
            raise OwnerAdmissionError("owner aggregate invocation allocation is exhausted")
        route = scope.allocation[state.reservations]
        if (actual.producer, actual.profile, actual.control) != (
                route.producer, route.profile, route.control):
            raise OwnerAdmissionError("actual invocation does not match the next exact allocation ordinal")
        deadline = min(state.binding.absolute_deadline - state.binding.cleanup_seconds,
                       now + timeout_seconds)
        if deadline <= now:
            raise OwnerAdmissionError("owner aggregate deadline is exhausted")
        # Reserve before any connection or provider request. Uncertain attempts
        # consume this local cap; they never receive a new implicit allocation.
        state.reservations += 1
        return ReservedOwnerInvocation(state.binding, actual, state.reservations, deadline,
                                       scope.allocation_digest())

