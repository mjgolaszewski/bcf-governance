"""Concrete original issuer factory graph; never installs a backend at import.

Functional qualification is pending genuine normal-session preflight. Creation
opens private journals/transports only; it grants no workload execution or proof
that provider effects have closed. The Root driver owns those lifecycle calls.
"""
from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
import ssl
from typing import Any, Callable, cast

from .coordinator import OriginalCoordinator
from .current_session import OriginalCurrentSessionPort
from .issuer.canonical_verifier import PinnedAccessTokenVerifier
from .issuer.context_evidence import AdminContextPolicy
from .issuer.contracts import AdminSession, Refused
from .issuer.current_admin import CurrentAdminSessionVerifier
from .issuer.factory import Installation, RegisteredIssuerOwner, build_registered_issuer_owner
from .issuer.http_exchange import Endpoint, HttpExchange
from .issuer.normal_policy import InstalledPolicyControls
from .issuer.workload import Dependencies, WorkloadConfig
from .owned_readback import OriginalOwnedPrincipalReadback
from .policy_observer import OriginalPolicyObserver
from .runtime.evidence_execution_owner import ProcessIdentity
from .sandbox_profile import OriginalSandboxProfile

ALGORITHMS = ('RS256', 'EdDSA')
ADMIN_ENDPOINTS = tuple(Endpoint('GET', path, frozenset({200}), False) for path in (
    '/api/v1/admin/context', '/api/v1/admin/applications/racecar/access-catalog',
    '/api/v1/admin/applications/chrysalis-identity/access-catalog')) + (
    Endpoint('POST', '/api/v1/admin/principals', frozenset({200}), True),)


class OriginalFactoryAttestation:
    def __init__(self, *, profile: OriginalSandboxProfile, session: AdminSession,
                 current: OriginalCurrentSessionPort, readback: OriginalOwnedPrincipalReadback,
                 policy: OriginalPolicyObserver, controls: InstalledPolicyControls,
                 dependencies: Dependencies, installation: Installation) -> None:
        if (type(profile) is not OriginalSandboxProfile or type(session) is not AdminSession
                or type(current) is not OriginalCurrentSessionPort
                or type(readback) is not OriginalOwnedPrincipalReadback
                or type(policy) is not OriginalPolicyObserver or type(controls) is not InstalledPolicyControls
                or type(dependencies) is not Dependencies or type(installation) is not Installation
                or current._profile is not profile or readback._profile is not profile
                or policy._profile is not profile or current._session is not session
                or readback._session is not session or policy._session is not session
                or controls._observe != policy.observe or controls._attest != policy.attest
                or controls.pin != policy.pin or controls._approved is not None):
            raise Refused()
        self.profile, self.session, self.current = profile, session, current
        self.readback, self.policy, self.controls = readback, policy, controls
        self.dependencies, self.installation = dependencies, installation
        self._bound = False

    def __call__(self, installation: Installation, coordinator: OriginalCoordinator,
                 controls: InstalledPolicyControls, session: AdminSession,
                 config: WorkloadConfig, dependencies: Dependencies,
                 runtime_pin: dict[str, Any], algorithms: tuple[str, ...]) -> None:
        runtime = self.profile._runtime
        if (self._bound or installation is not self.installation or controls is not self.controls
                or session is not self.session or dependencies is not self.dependencies
                or coordinator is not runtime._coordinator or config != self.profile._config
                or runtime_pin != runtime.pin or algorithms != ALGORITHMS
                or installation.tenant != self.profile._admission.tenant
                or installation.maximum_invocations != 1 or installation.admin_endpoints != ADMIN_ENDPOINTS
                or installation.context_policy != AdminContextPolicy(self.session.subject, 'default', 'development')
                or dependencies.runtime_check != runtime.runtime_check
                or dependencies.attest_profile != self.profile.attest_profile
                or dependencies.attest_owned is not self.readback
                or dependencies.delivery_registry is not runtime._delivery
                or dependencies.attest_sandbox != self.profile.attest_sandbox
                or self.readback._journal is not None):
            raise Refused()
        self.profile._current(self.profile._admission)

    def bind_owner(self, owner: RegisteredIssuerOwner) -> None:
        runtime = self.profile._runtime
        if (self._bound or type(owner) is not RegisteredIssuerOwner
                or owner.workload.deps is not self.dependencies
                or owner.workload.config != self.profile._config
                or owner.lifecycle._coordinator is not runtime._coordinator
                or owner.lifecycle._provider is not owner.workload
                or owner.lifecycle._journal is not owner.journal
                or owner.workload.authority._session is not self.session
                or owner.workload.authority._verify is not self.current
                or owner.workload.authority._source is not self.controls
                or owner.workload.authority._exchange is not owner.admin_http
                or owner.server._authenticate != runtime._coordinator.authenticate_control
                or owner.server._deadline != runtime._coordinator.control_deadline
                or owner.server._observe != ProcessIdentity.observe):
            raise Refused()
        self.readback.bind_journal(owner.journal)
        self._bound = True


@dataclass
class OriginalIssuerComposition:
    owner: RegisteredIssuerOwner
    attestation: OriginalFactoryAttestation
    context_http: HttpExchange

    async def close_transports(self) -> None:
        # This is NOT provider cleanup or permission to release the original FD.
        try:
            await self.owner.close_transports()
        finally:
            try:
                await self.context_http.close()
            finally:
                try:
                    self.attestation.readback.close()
                finally:
                    self.attestation.policy.close()


async def build_original_issuer(*, profile: OriginalSandboxProfile, session: AdminSession,
                                journal_root: Path, policy_root: Path,
                                tls: ssl.SSLContext) -> OriginalIssuerComposition:
    if type(profile) is not OriginalSandboxProfile or type(session) is not AdminSession:
        raise Refused()
    profile._current(profile._admission)
    context = HttpExchange(tls=tls, endpoints=(
        Endpoint('GET', '/api/v1/auth/.well-known/jwks.json', frozenset({200}), False),
        Endpoint('GET', '/api/v1/admin/context', frozenset({200}), False)),
        csrf_cookie='csrfToken', csrf_header='X-CSRF-Token')
    context.bind_tenant(profile._admission.tenant)
    readback = policy = owner = None
    try:
        keys = await context.request('GET', '/api/v1/auth/.well-known/jwks.json',
                                     deadline=profile._admission.access_deadline)
        if type(keys.value) is not dict or type(keys.value.get('keys')) is not list:
            raise Refused()
        profile._current(profile._admission)
        verify = PinnedAccessTokenVerifier(public_jwks=keys.value['keys'],
            algorithms=ALGORITHMS, audiences=('chrysalis-identity',))
        canonical = CurrentAdminSessionVerifier(exchange=context, canonical_verify=verify,
            issuer='https://identity.west.golaszewski.net', audience='chrysalis-identity',
            environment='development', nominated_subject=session.subject, home_tenant='default')
        current = OriginalCurrentSessionPort(profile=profile, session=session, verifier=canonical)
        await current(session, profile._admission, profile._admission.access_deadline)
        readback = OriginalOwnedPrincipalReadback(profile=profile, session=session, tls=tls)
        policy = OriginalPolicyObserver(profile=profile, session=session, root=policy_root)
        # The upstream constructor is untyped. This typing bridge does not
        # replace it; attestation below requires its exact actual implementation.
        construct_controls = cast(Callable[..., InstalledPolicyControls], InstalledPolicyControls)
        controls = construct_controls(pin=policy.pin, observe_policy=policy.observe, attest_policy=policy.attest)
        dependencies = Dependencies(profile._runtime.runtime_check, profile.attest_profile,
            readback, profile._runtime._delivery, profile.attest_sandbox)
        installation = Installation(profile._admission.tenant, journal_root, 1,
            AdminContextPolicy(session.subject, 'default', 'development'), ADMIN_ENDPOINTS)
        attestation = OriginalFactoryAttestation(profile=profile, session=session, current=current,
            readback=readback, policy=policy, controls=controls, dependencies=dependencies, installation=installation)
        coordinator = profile._runtime._coordinator
        owner = await build_registered_issuer_owner(installation, coordinator=coordinator,
            controls=controls, admin_session=session, verify_current_session=current,
            attest_installation=attestation, observe_identity=ProcessIdentity.observe,
            authenticate_control=coordinator.authenticate_control, control_deadline=coordinator.control_deadline,
            workload_config=profile._config, workload_dependencies=dependencies,
            runtime_pin=profile._runtime.pin, algorithms=ALGORITHMS, tls=tls)
        attestation.bind_owner(owner)
        return OriginalIssuerComposition(owner, attestation, context)
    except BaseException:
        if owner is not None:
            await owner.close_transports()
        await context.close()
        if readback is not None:
            readback.close()
        if policy is not None:
            policy.close()
        raise
