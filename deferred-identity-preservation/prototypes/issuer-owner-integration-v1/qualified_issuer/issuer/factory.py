"""Concrete installed issuer composition; all real authority inputs required, UNRUN."""
from __future__ import annotations

import asyncio
from contextlib import AsyncExitStack
from dataclasses import dataclass
from pathlib import Path
import ssl

from .admin_authority import AdminAuthority
from .context_evidence import AdminContextPolicy, RegisteredAdminContextGuard
from .contracts import AdminSession, ControlSource, Coordinator, Refused, tenant_selector, admin_home_selector
from .http_exchange import Endpoint, HttpExchange
from .journal import Journal
from .lifecycle import IssuerLifecycle
from .server import ControlServer
from .workload import ConcreteWorkloadProvider, Dependencies, WorkloadConfig


@dataclass(frozen=True)
class Installation:
    tenant: str
    journal_root: Path
    maximum_invocations: int
    context_policy: AdminContextPolicy
    admin_endpoints: tuple[Endpoint, ...]
    csrf_cookie: str = 'csrfToken'
    csrf_header: str = 'X-CSRF-Token'


@dataclass
class RegisteredIssuerOwner:
    lifecycle: IssuerLifecycle
    server: ControlServer
    admin_http: HttpExchange
    workload: ConcreteWorkloadProvider
    journal: Journal

    async def close_transports(self) -> None:
        # NOT issuer-target cleanup, native closure or permission to release FD.
        try:
            await self.admin_http.close()
        finally:
            try:
                await asyncio.gather(*(client.close() for client in self.workload._clients.values()),
                                     return_exceptions=True)
            finally:
                self.journal.close()


async def build_registered_issuer_owner(installation: Installation | None = None, *,
        coordinator: Coordinator | None = None, controls: ControlSource | None = None,
        admin_session: AdminSession | None = None, verify_current_session=None,
        attest_installation=None, observe_identity=None, authenticate_control=None, control_deadline=None,
        workload_config: WorkloadConfig | None = None,
        workload_dependencies: Dependencies | None = None,
        runtime_pin: dict | None = None, algorithms: tuple[str, ...] | None = None,
        tls: ssl.SSLContext | None = None) -> RegisteredIssuerOwner:
    required = (coordinator, controls, admin_session, verify_current_session,
                attest_installation, observe_identity, authenticate_control, control_deadline,
                workload_config, workload_dependencies, runtime_pin, algorithms, tls)
    if type(installation) is not Installation or any(value is None for value in required):
        raise Refused()
    if (type(installation.maximum_invocations) is not int or installation.maximum_invocations <= 0
            or type(admin_session) is not AdminSession or admin_session.tenant != installation.tenant
            or type(installation.context_policy) is not AdminContextPolicy
            or type(workload_config) is not WorkloadConfig
            or type(workload_dependencies) is not Dependencies):
        raise Refused()
    tenant_selector(installation.tenant)
    admin_home_selector(installation.context_policy.home_tenant)
    tenant_selector(workload_config.wrong_tenant)
    workload_dependencies.validate()
    installation.context_policy.principal()
    if installation.context_policy.subject != admin_session.subject:
        raise Refused()
    if attest_installation(installation, coordinator, controls, admin_session,
                           workload_config, workload_dependencies, runtime_pin, algorithms) is not None:
        raise Refused()
    # Snapshot caller-owned public runtime configuration before any await.
    import json
    pin = json.loads(json.dumps(runtime_pin, allow_nan=False))
    approved_algorithms = tuple(algorithms)
    async with AsyncExitStack() as stack:
        admin = HttpExchange(tls=tls, endpoints=installation.admin_endpoints,
            csrf_cookie=installation.csrf_cookie, csrf_header=installation.csrf_header)
        stack.push_async_callback(admin.close)
        admin.bind_tenant(installation.tenant)
        authority = AdminAuthority(admin, admin_session, controls, verify_current_session)
        journal = Journal(installation.journal_root, cap=installation.maximum_invocations)
        stack.callback(journal.close)

        def user_factory(audience):
            if audience not in {'racecar', 'chrysalis-identity'}:
                raise Refused()
            endpoints = (
                Endpoint('GET', '/api/v1/auth/.well-known/jwks.json', frozenset({200}), False),
                Endpoint('POST', '/api/v1/auth/login', frozenset({200}), True),
                Endpoint('POST', '/api/v1/account/mfa/totp/enroll?audience=' + audience,
                         frozenset({200}), True),
                Endpoint('POST', '/api/v1/account/mfa/totp/confirm?audience=' + audience,
                         frozenset({200}), True),
                Endpoint('GET', '/api/v1/account/profile?audience=' + audience,
                         frozenset({200, 401, 403}), False),
            )
            exchange = HttpExchange(tls=tls, endpoints=endpoints,
                csrf_cookie=installation.csrf_cookie, csrf_header=installation.csrf_header)
            exchange.bind_tenant(installation.tenant)
            return exchange

        def boundary_factory(keys, owner_authority, user, admission):
            # Real canonical decoder/model projection and subject producer.
            # Imports execute only in a separately qualified owner process.
            from chrysalis_identity.subjects import principal_subject
            from .canonical_verifier import PinnedAccessTokenVerifier
            from .issuer_provider_v4 import IssuerBoundary
            verifier = PinnedAccessTokenVerifier(public_jwks=keys,
                algorithms=approved_algorithms, audiences=('racecar', 'chrysalis-identity'))
            return IssuerBoundary(runtime_pin=pin, tenant=installation.tenant,
                runtime_check=workload_dependencies.runtime_check,
                subject_producer=principal_subject, token_verifier=verifier,
                context_validator=RegisteredAdminContextGuard(admission=admission,
                    policy=installation.context_policy,
                    attest_sandbox=workload_dependencies.attest_sandbox))

        # No arbitrary injected WorkloadProvider/provider_builder: stage logic is
        # this fixed concrete implementation. Fake ports remain unit tests only.
        provider = ConcreteWorkloadProvider(authority=authority, config=workload_config,
            dependencies=workload_dependencies, user_factory=user_factory,
            boundary_factory=boundary_factory, journal=journal)
        lifecycle = IssuerLifecycle(coordinator=coordinator, provider=provider, journal=journal)
        server = ControlServer(lifecycle, observe_identity=observe_identity,
                               authenticate_control=authenticate_control, control_deadline=control_deadline)
        owner = RegisteredIssuerOwner(lifecycle, server, admin, provider, journal)
        stack.pop_all()
        return owner
