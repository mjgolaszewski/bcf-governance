"""Concrete finite HTTPX exchange, no requests at import/construction time.

UNRUN. The separate process envelope and pinned dependency cohort remain required.
No caller-supplied transport, hooks, proxy, redirects or endpoint origin.
"""
from __future__ import annotations

import asyncio
from dataclasses import dataclass
import json
import math
import ssl
import time
from urllib.parse import urlsplit

from .contracts import Refused, Uncertain, tenant_selector

ORIGIN = 'https://identity.west.golaszewski.net'
MAX_BODY = 65536
UNSAFE = frozenset({'POST', 'PUT', 'PATCH', 'DELETE'})


@dataclass(frozen=True)
class Endpoint:
    method: str
    path: str
    statuses: frozenset[int]
    csrf: bool
    shape: str = 'object'


@dataclass(frozen=True)
class HttpResult:
    status: int
    value: dict | list[dict]
    intent_id: str | None = None


def unique(pairs: list[tuple[str, object]]) -> dict:
    value: dict = {}
    for key, item in pairs:
        if key in value:
            raise Refused()
        value[key] = item
    return value


def constant(_value: str) -> None:
    raise Refused()


def safe_header(value: object) -> bool:
    return (type(value) is str and 0 < len(value) <= 32768
            and all(ord(char) >= 32 and ord(char) != 127 for char in value))


class HttpExchange:
    """One role-local cookie jar; serialize prime/unsafe/rotation together."""

    def __init__(self, *, tls: ssl.SSLContext, endpoints: tuple[Endpoint, ...],
                 csrf_cookie: str, csrf_header: str) -> None:
        if (tls.verify_mode != ssl.CERT_REQUIRED or not tls.check_hostname
                or not endpoints or not safe_header(csrf_cookie)
                or not safe_header(csrf_header)):
            raise Refused()
        if len({(row.method, row.path) for row in endpoints}) != len(endpoints):
            raise Refused()
        for row in endpoints:
            self._validate_endpoint(row)
        import httpx
        self._client = httpx.AsyncClient(base_url=ORIGIN, verify=tls,
            trust_env=False, follow_redirects=False, http2=False,
            limits=httpx.Limits(max_connections=1, max_keepalive_connections=0),
            timeout=10.0, headers={'accept': 'application/json', 'accept-encoding': 'identity'})
        self._endpoints = {(row.method, row.path): row for row in endpoints}
        self._cookie, self._header = csrf_cookie, csrf_header
        self._lock = asyncio.Lock()
        self._closed = False

    @staticmethod
    def _validate_endpoint(row: Endpoint) -> None:
        parts = urlsplit(row.path)
        if (row.method not in {'GET', 'POST', 'PUT', 'PATCH', 'DELETE'}
                or parts.scheme or parts.netloc or parts.fragment
                or not row.path.startswith('/') or row.path.startswith('//')
                or '\\' in row.path or '%' in parts.path
                or any(part in {'.', '..'} for part in parts.path.split('/'))
                or any(ord(char) < 33 or ord(char) == 127 for char in row.path)
                or row.shape not in {'object', 'principal_list'}
                or (row.shape == 'principal_list' and not (row.method == 'GET'
                    and parts.path == '/api/v1/admin/principals'))
                or not row.statuses or any(type(code) is not int or code not in {200, 201, 401, 403}
                                           for code in row.statuses)):
            raise Refused()

    def register_owned_principal(self, principal_id: str, *, attest_owned) -> None:
        from uuid import UUID
        if (type(principal_id) is not str or str(UUID(principal_id)) != principal_id
                or not callable(attest_owned) or attest_owned(principal_id) is not None):
            raise Refused()
        base = '/api/v1/admin/principals/' + principal_id
        for method, suffix in (('GET', '/workbench'), ('POST', '/capabilities'),
                               ('PATCH', '/status'), ('POST', '/sessions/revoke')):
            endpoint = Endpoint(method, base + suffix, frozenset({200}), True)
            self._validate_endpoint(endpoint)
            self._endpoints[method, endpoint.path] = endpoint

    def register_owned_email(self, email: str, *, attest_intent) -> str:
        from urllib.parse import urlencode
        if (type(email) is not str or not 1 <= len(email) <= 255
                or not safe_header(email) or not callable(attest_intent)
                or attest_intent(email) is not None):
            raise Refused()
        path = '/api/v1/admin/principals?' + urlencode({'query': email, 'limit': 2})
        endpoint = Endpoint('GET', path, frozenset({200}), False, 'principal_list')
        self._validate_endpoint(endpoint)
        self._endpoints['GET', path] = endpoint
        return path

    def register_control_intent(self, intent_id: str, *, attest_binding) -> str:
        import re
        if (type(intent_id) is not str or re.fullmatch('[A-Za-z0-9._:-]{1,128}', intent_id) is None
                or not callable(attest_binding) or attest_binding(intent_id) is not None):
            raise Refused()
        path = '/api/v1/admin/mutation-intents/' + intent_id
        endpoint = Endpoint('GET', path, frozenset({200}), False)
        self._validate_endpoint(endpoint)
        self._endpoints['GET', path] = endpoint
        return path

    async def close(self) -> None:
        self._closed = True
        await self._client.aclose()

    async def request(self, method: str, path: str, *, deadline: float,
                      body: bytes | None = None, token: str | None = None,
                      control: dict[str, str] | None = None) -> HttpResult:
        if (self._closed or type(deadline) not in (int, float)
                or not math.isfinite(deadline) or deadline <= time.monotonic()
                or (method, path) not in self._endpoints
                or (body is not None and (type(body) is not bytes or len(body) > 8192))):
            raise Refused()
        endpoint = self._endpoints[method, path]
        headers = {'x-chrysalis-tenant': self.tenant}
        if token is not None:
            if not safe_header(token):
                raise Refused()
            headers['authorization'] = 'Bearer ' + token
        if control:
            if (not set(control) <= {'x-identity-admin-control-artifact',
                                     'x-identity-admin-mutation-intent'}
                    or not all(safe_header(value) for value in control.values())):
                raise Refused()
            headers.update(control)
        if body is not None:
            headers['content-type'] = 'application/json'
        # asyncio cancellation encloses pool/connect/TLS/prime/read, rather than
        # checking time only between potentially blocking synchronous reads.
        sent = False
        try:
            async with asyncio.timeout(deadline - time.monotonic()):
                async with self._lock:
                    if endpoint.csrf and method in UNSAFE:
                        cookie = self._client.cookies.get(self._cookie)
                        if cookie is None:
                            await self._send(Endpoint('GET', '/api/v1/auth/csrf',
                                                     frozenset({200}), False),
                                             {'x-chrysalis-tenant': self.tenant}, None)
                            cookie = self._client.cookies.get(self._cookie)
                        if not safe_header(cookie):
                            raise Refused()
                        headers[self._header] = cookie
                    sent = True  # Conservative: request may be accepted after here.
                    return await self._send(endpoint, headers, body)
        except asyncio.CancelledError:
            raise
        except Exception:
            if sent and method in UNSAFE:
                raise Uncertain() from None
            raise Refused() from None

    async def _send(self, endpoint: Endpoint, headers: dict[str, str],
                    body: bytes | None) -> HttpResult:
        async with self._client.stream(endpoint.method, endpoint.path,
                                       headers=headers, content=body) as response:
            if (response.status_code not in endpoint.statuses
                    or response.headers.get('content-encoding', 'identity') != 'identity'):
                raise Refused()
            raw = bytearray()
            async for part in response.aiter_raw():
                if len(part) > MAX_BODY - len(raw):
                    raise Refused()
                raw.extend(part)
            value = json.loads(bytes(raw), object_pairs_hook=unique, parse_constant=constant)
            if endpoint.shape == 'principal_list':
                if (type(value) is not list or len(value) > 2
                        or not all(type(row) is dict for row in value)):
                    raise Refused()
            elif type(value) is not dict:
                raise Refused()
            intent = response.headers.get('x-identity-admin-mutation-intent')
            if intent is not None and not safe_header(intent):
                raise Refused()
            return HttpResult(response.status_code, value, intent)

    @property
    def tenant(self) -> str:
        return self._tenant

    def bind_tenant(self, tenant: str) -> None:
        # Called only by installed composition, once, before any request.
        import re
        if (hasattr(self, '_tenant') or type(tenant) is not str or tenant == 'default'
                or tenant_selector(tenant) != tenant):
            raise Refused()
        self._tenant = tenant
