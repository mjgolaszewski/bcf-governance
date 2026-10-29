from __future__ import annotations

import os
from dataclasses import dataclass
from urllib.parse import urlparse


DEFAULT_ISSUER_URL = "http://localhost:61310"
DEFAULT_AUDIENCE = "chrysalis-apps"
DEFAULT_ACCEPTED_ALGORITHMS = ("RS256", "EdDSA")
SUPPORTED_SIGNING_ALGORITHMS = frozenset(DEFAULT_ACCEPTED_ALGORITHMS)
_PRODUCTION_ENV_VALUES = {"prod", "production"}
_LOCAL_HOSTNAMES = {"localhost", "127.0.0.1", "::1"}


@dataclass(frozen=True)
class IdentityClientConfig:
    issuer_url: str
    audience: str | None = None
    jwks_url: str | None = None
    timeout_seconds: float = 5.0
    accepted_algorithms: tuple[str, ...] = DEFAULT_ACCEPTED_ALGORITHMS
    accepted_algorithms_explicit: bool = True
    require_introspection: bool = False
    permission_freshness_ttl_seconds: int = 0

    @classmethod
    def from_env(cls, *, validate_production: bool | None = None) -> "IdentityClientConfig":
        timeout = os.environ.get("CHRYSALIS_IDENTITY_TIMEOUT_SECONDS", "5")
        algorithms = os.environ.get("CHRYSALIS_IDENTITY_ALGORITHMS")
        accepted_algorithms = (
            _parse_algorithms(algorithms) if algorithms is not None else DEFAULT_ACCEPTED_ALGORITHMS
        )
        first_party_app = _truthy(os.environ.get("CHRYSALIS_IDENTITY_FIRST_PARTY_APP"))
        require_introspection = _truthy(
            os.environ.get("CHRYSALIS_IDENTITY_REQUIRE_INTROSPECTION"),
            default=first_party_app,
        )
        freshness_default = "30" if require_introspection else "0"
        freshness_ttl = int(
            os.environ.get(
                "CHRYSALIS_IDENTITY_PERMISSION_FRESHNESS_TTL_SECONDS",
                freshness_default,
            )
        )
        config = cls(
            issuer_url=os.environ.get(
                "CHRYSALIS_IDENTITY_ISSUER_URL",
                DEFAULT_ISSUER_URL,
            ).rstrip("/"),
            audience=os.environ.get("CHRYSALIS_IDENTITY_AUDIENCE", DEFAULT_AUDIENCE),
            jwks_url=os.environ.get("CHRYSALIS_IDENTITY_JWKS_URL"),
            timeout_seconds=float(timeout),
            accepted_algorithms=accepted_algorithms,
            accepted_algorithms_explicit=algorithms is not None,
            require_introspection=require_introspection,
            permission_freshness_ttl_seconds=freshness_ttl,
        )
        should_validate_production = (
            _production_env_selected() if validate_production is None else validate_production
        )
        if should_validate_production:
            config.validate_production()
        return config

    @property
    def resolved_jwks_url(self) -> str:
        if self.jwks_url:
            return self.jwks_url
        return f"{self.issuer_url.rstrip('/')}/api/v1/auth/.well-known/jwks.json"

    def validate_production(self) -> "IdentityClientConfig":
        issuer = _parsed_url(self.issuer_url, field_name="issuer_url")
        if issuer.scheme != "https" or _is_local_hostname(issuer.hostname):
            raise ValueError("production identity issuer_url must be HTTPS and non-local")
        if self.jwks_url:
            jwks = _parsed_url(self.jwks_url, field_name="jwks_url")
            if jwks.scheme != "https" or _is_local_hostname(jwks.hostname):
                raise ValueError("production identity jwks_url must be HTTPS and non-local")
        if not self.audience or self.audience == DEFAULT_AUDIENCE:
            raise ValueError("production identity audience must be explicit and non-default")
        if not self.accepted_algorithms_explicit:
            raise ValueError("production identity accepted algorithms must be explicit")
        if not self.accepted_algorithms:
            raise ValueError("production identity accepted algorithms must not be empty")
        unsupported = set(self.accepted_algorithms) - SUPPORTED_SIGNING_ALGORITHMS
        if unsupported:
            raise ValueError("production identity accepted algorithms include unsupported values")
        if self.timeout_seconds <= 0:
            raise ValueError("production identity timeout_seconds must be greater than zero")
        if self.permission_freshness_ttl_seconds < 0:
            raise ValueError("permission freshness TTL must not be negative")
        if self.permission_freshness_ttl_seconds and not self.require_introspection:
            raise ValueError("permission freshness TTL requires introspection")
        if self.require_introspection and self.permission_freshness_ttl_seconds > 300:
            raise ValueError("permission freshness TTL must be bounded to five minutes or less")
        return self


def _parse_algorithms(value: str) -> tuple[str, ...]:
    return tuple(algorithm for algorithm in value.replace(",", " ").split() if algorithm)


def _truthy(value: str | None, *, default: bool = False) -> bool:
    if value is None:
        return default
    return value.strip().lower() in {"1", "true", "yes", "on"}


def _production_env_selected() -> bool:
    for name in ("CHRYSALIS_IDENTITY_ENV", "APP_ENV", "ENVIRONMENT"):
        value = os.environ.get(name, "").strip().lower()
        if value in _PRODUCTION_ENV_VALUES:
            return True
    return False


def _parsed_url(value: str, *, field_name: str):
    parsed = urlparse(value)
    if not parsed.scheme or not parsed.netloc:
        raise ValueError(f"identity {field_name} must be an absolute URL")
    return parsed


def _is_local_hostname(hostname: str | None) -> bool:
    return (hostname or "").lower() in _LOCAL_HOSTNAMES
