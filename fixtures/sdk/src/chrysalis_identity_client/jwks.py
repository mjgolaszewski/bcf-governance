from __future__ import annotations

import time
from collections.abc import Sequence
from typing import Any, cast

import httpx
import jwt


class JWKSClient:
    def __init__(
        self,
        jwks_url: str,
        *,
        timeout_seconds: float = 5.0,
        ttl_seconds: int = 300,
        http_client: httpx.AsyncClient | None = None,
    ) -> None:
        self._jwks_url = jwks_url
        self._timeout_seconds = timeout_seconds
        self._ttl_seconds = ttl_seconds
        self._http_client = http_client
        self._cache: dict[str, Any] | None = None
        self._cache_expires_at = 0.0

    async def get_key_set(self) -> dict[str, Any]:
        now = time.monotonic()
        if self._cache is not None and now < self._cache_expires_at:
            return self._cache

        if self._http_client is None:
            async with httpx.AsyncClient(timeout=self._timeout_seconds) as client:
                response = await client.get(self._jwks_url)
        else:
            response = await self._http_client.get(self._jwks_url)

        response.raise_for_status()
        payload = response.json()
        if not isinstance(payload, dict) or not isinstance(payload.get("keys"), list):
            raise ValueError("JWKS endpoint returned an invalid key set")

        self._cache = payload
        self._cache_expires_at = now + self._ttl_seconds
        return payload

    async def refresh_key_set(self) -> dict[str, Any]:
        self.clear_cache()
        return await self.get_key_set()

    def clear_cache(self) -> None:
        self._cache = None
        self._cache_expires_at = 0.0


def decode_unverified_claims(token: str) -> dict[str, Any]:
    payload = jwt.decode(token, options={"verify_signature": False})
    if not isinstance(payload, dict):
        raise ValueError("JWT payload must be an object")
    return payload


def decode_with_key(
    token: str,
    key: object,
    *,
    issuer: str,
    audience: str | Sequence[str],
    algorithms: Sequence[str],
) -> dict[str, Any]:
    payload = jwt.decode(
        token,
        key=cast(Any, key),
        issuer=issuer,
        audience=audience,
        algorithms=list(algorithms),
    )
    if not isinstance(payload, dict):
        raise ValueError("JWT payload must be an object")
    return payload
