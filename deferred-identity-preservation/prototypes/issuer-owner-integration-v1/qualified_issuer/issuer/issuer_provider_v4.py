"""Private issuer Provider boundary. No HTTP client, credentials, CLI or defaults.

Injected exchanges MUST enforce deadline during connect/read and disable redirects,
proxy/environment fallback; keep distinct admin/user cookie, CSRF and authorization
state. They yield (status, byte chunks) from a context manager that closes on every
outcome. This source supplies no concrete live exchange or trusted JIT admission.
Target policy is independently reviewed owner authority, not UUID syntax alone.
Runtime and target guards MUST return None on success or raise on denial; other
returns, including False/True, are rejected before transport.
Pure token verification is distinct from current revocation/introspection proof.
"""
from __future__ import annotations

from dataclasses import dataclass, field, replace
from functools import wraps
import json
import re
import time
from types import MappingProxyType
from uuid import UUID

from .contracts import tenant_selector

ISSUER = 'https://identity.west.golaszewski.net'
MAX_RESPONSE = 65536
CONTROL_HEADER = 'x-identity-admin-control-artifact'
INTENT_HEADER = 'x-identity-admin-mutation-intent'


class ProviderRejected(RuntimeError):
    def __init__(self):
        super().__init__('private issuer provider rejected')


def require(condition):
    if not condition:
        raise ProviderRejected()


def private(method):
    @wraps(method)
    def guarded(*args, **kwargs):
        try:
            return method(*args, **kwargs)
        except ProviderRejected:
            raise
        except Exception:
            raise ProviderRejected() from None
    return guarded


@dataclass(frozen=True)
class ProviderRequest:
    method: str
    path: str
    tenant: str
    body: bytes | None = field(repr=False)
    token: str | None = field(repr=False)
    control_headers: object = field(repr=False)


def text(value, maximum, *, minimum=1):
    return (type(value) is str and minimum <= len(value) <= maximum
            and '\r' not in value and '\n' not in value)


def canonical_uuid(value):
    require(type(value) is str and str(UUID(value)) == value)
    return value


def unique(pairs):
    result = {}
    for key, value in pairs:
        require(key not in result)
        result[key] = value
    return result


def invalid_constant(value):
    raise ProviderRejected()


class IssuerBoundary:
    """Canonical private validation shared by sync Provider and async Gateway."""
    def __init__(self, *, runtime_pin, tenant, runtime_check, subject_producer,
                 token_verifier, clock=time.monotonic, context_validator=None):
        self.pin = json.loads(json.dumps(runtime_pin, allow_nan=False))
        require(set(self.pin) == {'issuer', 'source', 'image'})
        require(self.pin['issuer'] == ISSUER)
        require(re.fullmatch('[0-9a-f]{40}', self.pin['source']) is not None)
        require(re.fullmatch('sha256:[0-9a-f]{64}', self.pin['image']) is not None)
        require(tenant_selector(tenant) == tenant)
        require(callable(runtime_check) and callable(subject_producer) and callable(token_verifier))
        self.tenant, self.runtime_check = tenant, runtime_check
        self.subject_producer, self.token_verifier = subject_producer, token_verifier
        self.clock = clock
        self.context_validator = context_validator

    @private
    def check_runtime(self, pin):
        require(pin == self.pin)
        require(self.runtime_check(json.loads(json.dumps(self.pin))) is None)


    @private
    def subject(self, principal_id):
        canonical_uuid(principal_id)
        value = self.subject_producer(principal_id)
        require(text(value, 128) and value == 'principal:' + principal_id)
        return value


    @private
    def verify_token(self, token, tenant, subject, audience):
        require(tenant == self.tenant and audience in {'racecar', 'chrysalis-identity'})
        require(text(token, 32768) and text(subject, 128))
        self.check_runtime(self.pin)
        # Signature/JWKS/algorithm/time/typ verification MUST be done by this
        # supported injected verifier, never by trusting decoded candidate JSON.
        claims = self.token_verifier(token=token, issuer=ISSUER, audience=audience)
        require(type(claims) is dict and claims.get('iss') == ISSUER
                and claims.get('tenant_id') == tenant and claims.get('sub') == subject)
        aud = claims.get('aud')
        require(aud == audience or (type(aud) is list and audience in aud
                                    and all(type(item) is str for item in aud)))
        return claims


    def _body(self, body, required, optional=()):
        require(type(body) is dict and set(required) <= set(body)
                and set(body) <= set(required) | set(optional))
        raw = json.dumps(body, sort_keys=True, separators=(',', ':'), allow_nan=False).encode()
        require(len(raw) <= 8192)
        return json.loads(raw), raw


    def _admin_route(self, method, path, body):
        if method == 'GET' and path == '/api/v1/admin/context':
            require(body is None)
            return 'context', None, None
        if method == 'GET' and path in {
            '/api/v1/admin/applications/racecar/access-catalog',
            '/api/v1/admin/applications/chrysalis-identity/access-catalog',
        }:
            require(body is None)
            return 'catalog', None, None
        if method == 'POST' and path == '/api/v1/admin/principals':
            data, raw = self._body(body, {'email', 'password', 'display_name'})
            require(text(data['email'], 320) and text(data['password'], 1024, minimum=8)
                    and text(data['display_name'], 255))
            return 'create', raw, None
        match = re.fullmatch('/api/v1/admin/principals/([0-9a-f-]{36})/(workbench|capabilities|status|sessions/revoke)', path)
        require(match is not None)
        target, action = match.groups()
        canonical_uuid(target)
        if action == 'workbench':
            require(method == 'GET' and body is None)
            return action, None, target
        if action == 'capabilities':
            require(method == 'POST')
            data, raw = self._body(body, {'audience', 'capability_name'}, {'expected_permissions_version'})
            require((data['audience'], data['capability_name']) in {
                ('racecar', 'racecar:access'), ('chrysalis-identity', 'identity:access_read')})
            if 'expected_permissions_version' in data:
                require(data['expected_permissions_version'] is None
                        or text(data['expected_permissions_version'], 256))
            return action, raw, target
        if action == 'status':
            require(method == 'PATCH')
            data, raw = self._body(body, {'status', 'reason'})
            require(data['status'] == 'disabled' and text(data['reason'], 512))
            return action, raw, target
        require(action == 'sessions/revoke' and method == 'POST')
        data, raw = self._body(body, {'reason'})
        require(text(data['reason'], 512))
        return action, raw, target


    def _user_route(self, method, path, body, token):
        require(method == 'POST')
        if path == '/api/v1/auth/login':
            require(token is None)
            data, raw = self._body(body, {'email', 'password', 'audience', 'identity_tenant'})
            require(text(data['email'], 320) and text(data['password'], 1024, minimum=8)
                    and data['audience'] in {'racecar', 'chrysalis-identity'} and data['identity_tenant'] == self.tenant)
            return 'login', raw
        require(text(token, 32768))
        if path in {'/api/v1/account/mfa/totp/enroll?audience=racecar',
                    '/api/v1/account/mfa/totp/enroll?audience=chrysalis-identity'}:
            data, raw = self._body(body, {'display_name'})
            require(data['display_name'] is None or text(data['display_name'], 120))
            return 'enroll', raw
        require(path in {'/api/v1/account/mfa/totp/confirm?audience=racecar',
                         '/api/v1/account/mfa/totp/confirm?audience=chrysalis-identity'})
        data, raw = self._body(body, {'factor_id', 'code'})
        require(text(data['factor_id'], 128) and re.fullmatch('[0-9]{6}', data['code']) is not None)
        return 'confirm', raw


    @private
    def _validate_admin_result(self, action, raw, target, value):
        if action == 'context':
            # Canonical API summary deliberately carries no environment_type.
            # Independent registered authority owns sandbox classification;
            # neither a tenant label nor app_env is sufficient authority.
            require(callable(self.context_validator))
            require(self.context_validator(value, self.pin, self.tenant) is None)
        elif action == 'catalog':
            require(type(value.get('capabilities')) is list
                    and all(type(item) is dict and text(item.get('name'), 160)
                            for item in value['capabilities']))
        elif action == 'create':
            canonical_uuid(value.get('id'))
            require(value.get('email') == json.loads(raw)['email'] and value.get('status') == 'active')
        elif action == 'workbench':
            principal = value.get('principal')
            require(type(principal) is dict and principal.get('id') == target
                    and text(principal.get('email'), 320) and principal.get('is_deleted') is False
                    and type(value.get('applications')) is list)
        elif action == 'capabilities':
            require(value == {'status': 'ok'})
        elif action == 'status':
            require(value == {'id': target, 'status': 'disabled'})
        else:
            require(set(value) == {'principal_id', 'revoked_count'}
                    and value['principal_id'] == target and type(value['revoked_count']) is int
                    and value['revoked_count'] >= 0)
        return value


    def _validate_user_result(self, action, raw, value):
        if action == 'login':
            require(text(value.get('access_token'), 32768))
        elif action == 'enroll':
            require(all(text(value.get(key), maximum) for key, maximum in {
                'factor_id': 128, 'secret': 1024, 'provisioning_uri': 8192,
                'qr_code_data_uri': 60000, 'issuer': 255, 'account_name': 320}.items()))
        else:
            require(value.get('id') == json.loads(raw)['factor_id']
                    and value.get('status') == 'active' and value.get('factor_type') == 'totp')
        return value


class IssuerProviderTransport(IssuerBoundary):
    """Original five-symbol synchronous Provider, preserved for its existing users."""
    def __init__(self, *, runtime_pin, tenant, runtime_check, subject_producer,
                 token_verifier, admin_exchange, user_exchange, control_producer,
                 target_check, clock=time.monotonic, context_validator=None):
        super().__init__(runtime_pin=runtime_pin, tenant=tenant, runtime_check=runtime_check,
                         subject_producer=subject_producer, token_verifier=token_verifier, clock=clock,
                         context_validator=context_validator)
        require(callable(admin_exchange) and callable(user_exchange) and admin_exchange is not user_exchange)
        self.admin_exchange, self.user_exchange = admin_exchange, user_exchange
        self.control_producer, self.target_check = control_producer, target_check

    def _exchange(self, exchange, request):
        self.check_runtime(self.pin)
        require(callable(self.target_check))
        require(self.target_check(request) is None)  # Imperative guard: None or raise only.
        deadline = self.clock() + 30
        if request.method != 'GET' and exchange is self.admin_exchange:
            require(callable(self.control_producer))
            headers = self.control_producer(request)
            require(type(headers) is dict and CONTROL_HEADER in headers
                    and set(headers) <= {CONTROL_HEADER, INTENT_HEADER})
            require(all(text(value, 32768) for value in headers.values()))
            request = replace(request, control_headers=MappingProxyType(dict(headers)))
        require(self.clock() < deadline)
        # Context manager must close response even when status/decoding fails.
        # Exchange enforces deadline DURING blocking I/O; loop also checks it.
        with exchange(request, deadline=deadline) as (status, chunks):
            require(type(status) is int and status == 200)
            result = bytearray()
            for chunk in chunks:
                require(self.clock() < deadline and type(chunk) is bytes
                        and len(chunk) > 0 and len(chunk) <= MAX_RESPONSE - len(result))
                result.extend(chunk)
            require(self.clock() < deadline and result)
            value = json.loads(result.decode('utf8'), object_pairs_hook=unique,
                               parse_constant=invalid_constant)
            require(type(value) is dict)
            return value


    @private
    def admin(self, method, path, body, tenant):
        require(tenant == self.tenant and type(path) is str)
        action, raw, target = self._admin_route(method, path, body)
        request = ProviderRequest(method, path, tenant, raw, None, MappingProxyType({}))
        value = self._exchange(self.admin_exchange, request)
        return self._validate_admin_result(action, raw, target, value)


    @private
    def user(self, method, path, body, tenant, token=None):
        require(tenant == self.tenant)
        action, raw = self._user_route(method, path, body, token)
        request = ProviderRequest(method, path, tenant, raw, token, MappingProxyType({}))
        value = self._exchange(self.user_exchange, request)
        return self._validate_user_result(action, raw, value)


