"""Versioned authorization context for encrypted server custody; no persistence or HTTP."""

from __future__ import annotations

import base64
import hashlib
import secrets
import re
import time
from collections import Counter
from collections.abc import Sequence
from dataclasses import asdict, dataclass, field
from hmac import compare_digest
from urllib.parse import parse_qsl, urlsplit

from chrysalis_identity_client.broker_models import BrokerGrantError

_RESERVED = {"code", "state", "iss", "error", "error_description", "error_uri"}


@dataclass(frozen=True, repr=False, kw_only=True)
class AuthorizationRequest:
    issuer: str
    client_id: str
    audience: str
    tenant_id: str
    sender_thumbprint: str
    authentication_method: str
    security_profile: str
    redirect_uri: str
    scopes: tuple[str, ...]
    state: str = field(repr=False)
    nonce: str = field(repr=False)
    code_verifier: str = field(repr=False)
    authorization_url: str = field(repr=False)
    expires_at: int
    version: int = 1

    def to_custody_dict(self) -> dict:
        """Contains secrets. Encrypt/authenticate server-side; never expose to the browser."""
        value = asdict(self)
        value["scopes"] = list(self.scopes)
        return value

    @classmethod
    def from_custody_dict(cls, value: dict) -> AuthorizationRequest:
        try:
            if set(value) != set(cls.__dataclass_fields__):
                raise ValueError()
            if type(value["version"]) is not int or value["version"] != 1:
                raise ValueError()
            if type(value["expires_at"]) is not int or value["expires_at"] <= 0:
                raise ValueError()
            for key in set(value) - {"version", "expires_at", "scopes"}:
                if not isinstance(value[key], str) or not value[key]:
                    raise ValueError()
            scopes = value["scopes"]
            if not isinstance(scopes, list):
                raise ValueError()
            for name in ("state", "nonce"):
                if re.fullmatch(r"[A-Za-z0-9_-]{43}", value[name]) is None:
                    raise ValueError()
            if re.fullmatch(r"[A-Za-z0-9._~-]{43,128}", value["code_verifier"]) is None:
                raise ValueError()
            validate_redirect_uri(value["redirect_uri"])
            return cls(**{**value, "scopes": authorization_scopes(scopes)})
        except (TypeError, ValueError, KeyError):
            raise BrokerGrantError("invalid_response") from None


def authorization_scopes(scopes: Sequence[str]) -> tuple[str, ...]:
    if isinstance(scopes, (str, bytes)) or not isinstance(scopes, Sequence):
        raise ValueError("explicit OIDC offline scopes are required")
    frozen = tuple(scopes)
    if (
        not frozen
        or any(
            not isinstance(s, str) or re.fullmatch(r"[\x21\x23-\x5b\x5d-\x7e]+", s) is None
            for s in frozen
        )
        or len(set(frozen)) != len(frozen)
        or not {"openid", "offline_access"}.issubset(frozen)
    ):
        raise ValueError("explicit OIDC offline scopes are required")
    return frozen


def new_authorization_secrets() -> tuple[str, str, str, str]:
    state, nonce, verifier = (secrets.token_urlsafe(32) for _ in range(3))
    challenge = (
        base64.urlsafe_b64encode(hashlib.sha256(verifier.encode()).digest()).rstrip(b"=").decode()
    )
    return state, nonce, verifier, challenge


def validate_redirect_uri(uri: str) -> None:
    parsed = urlsplit(uri)
    if (
        parsed.scheme != "https"
        or not parsed.hostname
        or parsed.username
        or parsed.password
        or parsed.fragment
        or any(k in _RESERVED for k, _ in parse_qsl(parsed.query))
    ):
        raise ValueError("exact registered HTTPS redirect URI is required")


def authorization_code(callback_url: str, request: AuthorizationRequest) -> str:
    try:
        if request.version != 1 or request.expires_at <= time.time():
            raise ValueError()
        validate_redirect_uri(request.redirect_uri)
        callback, redirect = urlsplit(callback_url), urlsplit(request.redirect_uri)
        if callback.fragment or (callback.scheme, callback.netloc, callback.path) != (
            redirect.scheme,
            redirect.netloc,
            redirect.path,
        ):
            raise ValueError()
        fixed = Counter(parse_qsl(redirect.query, keep_blank_values=True))
        fixed_names = {key for key, _ in fixed}
        pairs = parse_qsl(callback.query, keep_blank_values=True, strict_parsing=True)
        parameters: dict[str, str] = {}
        seen: set[str] = set()
        for key, value in pairs:
            if fixed[(key, value)]:
                fixed[(key, value)] -= 1
            elif key in fixed_names or key in seen:
                raise ValueError()
            else:
                seen.add(key)
                if key in _RESERVED:
                    parameters[key] = value
        if any(fixed.values()) or "error" in parameters:
            raise ValueError()
        if (
            set(parameters) != {"code", "state", "iss"}
            or not parameters["code"]
            or not compare_digest(parameters["state"], request.state)
            or parameters["iss"] != request.issuer
        ):
            raise ValueError()
        return parameters["code"]
    except (ValueError, TypeError, KeyError):
        raise BrokerGrantError("reauth_required") from None
