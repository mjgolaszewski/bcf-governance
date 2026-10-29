from __future__ import annotations

import hashlib
import time
from dataclasses import dataclass
from typing import Any

from chrysalis_identity_client.claims import IdentityClaims
from chrysalis_identity_client.config import IdentityClientConfig
from chrysalis_identity_client.discovery import DiscoveryClient
from chrysalis_identity_client.introspection import IntrospectionClient
from chrysalis_identity_client.jwks import JWKSClient
from chrysalis_identity_client.validation import UnknownJWKSKeyError, decode_access_token


@dataclass(frozen=True)
class IdentityAuthResult:
    claims: IdentityClaims
    introspected: bool = False
    freshness_cache_hit: bool = False


class IdentityAuthenticator:
    def __init__(
        self,
        config: IdentityClientConfig,
        *,
        discovery_client: DiscoveryClient | None = None,
        jwks_client: JWKSClient | None = None,
        introspection_client: IntrospectionClient | None = None,
        http_client: Any | None = None,
        require_introspection: bool | None = None,
        freshness_ttl_seconds: int | None = None,
    ) -> None:
        self._config = config
        self._discovery_client = discovery_client
        self._jwks_client = jwks_client
        self._introspection_client = introspection_client
        self._http_client = http_client
        self._require_introspection = (
            config.require_introspection if require_introspection is None else require_introspection
        )
        self._freshness_ttl_seconds = (
            config.permission_freshness_ttl_seconds
            if freshness_ttl_seconds is None
            else freshness_ttl_seconds
        )
        if self._freshness_ttl_seconds < 0:
            raise ValueError("freshness_ttl_seconds must not be negative")
        if self._freshness_ttl_seconds and not self._require_introspection:
            raise ValueError("freshness_ttl_seconds requires introspection")
        self._introspection_cache: dict[tuple[str, str | None], float] = {}

    async def validate_access_token(self, token: str) -> IdentityAuthResult:
        metadata = await self._metadata()
        jwks_client = self._jwks_client or JWKSClient(
            self._config.resolved_jwks_url if self._config.jwks_url else metadata.jwks_uri,
            timeout_seconds=self._config.timeout_seconds,
            http_client=self._http_client,
        )
        key_set = await jwks_client.get_key_set()
        try:
            claims = decode_access_token(
                token,
                key_set,
                issuer=metadata.issuer,
                audience=self._config.audience or "chrysalis-apps",
                algorithms=self._config.accepted_algorithms,
            )
        except UnknownJWKSKeyError:
            key_set = await jwks_client.refresh_key_set()
            claims = decode_access_token(
                token,
                key_set,
                issuer=metadata.issuer,
                audience=self._config.audience or "chrysalis-apps",
                algorithms=self._config.accepted_algorithms,
            )

        if self._require_introspection:
            if self._introspection_client is None:
                raise ValueError("token introspection is required but no introspection client is configured")
            cache_key = (_token_cache_digest(token), self._config.audience)
            now = time.monotonic()
            if self._freshness_ttl_seconds:
                expires_at = self._introspection_cache.get(cache_key, 0.0)
                if now < expires_at:
                    return IdentityAuthResult(
                        claims=claims,
                        introspected=True,
                        freshness_cache_hit=True,
                    )
            result = await self._introspection_client.introspect(
                token,
                audience=self._config.audience,
            )
            if result is None or not result.active:
                self._introspection_cache.pop(cache_key, None)
                raise ValueError("token introspection rejected the access token")
            if self._freshness_ttl_seconds:
                self._introspection_cache[cache_key] = now + self._freshness_ttl_seconds
            return IdentityAuthResult(claims=claims, introspected=True)

        return IdentityAuthResult(claims=claims)

    async def _metadata(self):
        if self._discovery_client is None:
            return await DiscoveryClient(self._config, http_client=self._http_client).get_metadata()
        return await self._discovery_client.get_metadata()


def _token_cache_digest(token: str) -> str:
    return hashlib.sha256(token.encode("utf-8")).hexdigest()
