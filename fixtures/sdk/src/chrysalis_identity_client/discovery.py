from __future__ import annotations

from dataclasses import dataclass

import httpx

from chrysalis_identity_client.config import IdentityClientConfig


@dataclass(frozen=True)
class IssuerMetadata:
    issuer: str
    jwks_uri: str
    authorization_endpoint: str | None = None
    introspection_endpoint: str | None = None
    token_endpoint: str | None = None
    userinfo_endpoint: str | None = None
    response_types_supported: tuple[str, ...] = ()
    scopes_supported: tuple[str, ...] = ()
    claims_supported: tuple[str, ...] = ()
    id_token_signing_alg_values_supported: tuple[str, ...] = ()
    token_endpoint_auth_methods_supported: tuple[str, ...] = ()

    @classmethod
    def from_mapping(cls, payload: dict[str, object]) -> "IssuerMetadata":
        issuer = payload.get("issuer")
        jwks_uri = payload.get("jwks_uri")
        if not isinstance(issuer, str) or not issuer:
            raise ValueError("issuer metadata is missing issuer")
        if not isinstance(jwks_uri, str) or not jwks_uri:
            raise ValueError("issuer metadata is missing jwks_uri")
        return cls(
            issuer=issuer,
            jwks_uri=jwks_uri,
            authorization_endpoint=_optional_str(payload.get("authorization_endpoint")),
            introspection_endpoint=_optional_str(payload.get("introspection_endpoint")),
            token_endpoint=_optional_str(payload.get("token_endpoint")),
            userinfo_endpoint=_optional_str(payload.get("userinfo_endpoint")),
            response_types_supported=_str_tuple(payload.get("response_types_supported")),
            scopes_supported=_str_tuple(payload.get("scopes_supported")),
            claims_supported=_str_tuple(payload.get("claims_supported")),
            id_token_signing_alg_values_supported=_str_tuple(
                payload.get("id_token_signing_alg_values_supported")
            ),
            token_endpoint_auth_methods_supported=_str_tuple(
                payload.get("token_endpoint_auth_methods_supported")
            ),
        )


def _optional_str(value: object) -> str | None:
    return value if isinstance(value, str) and value else None


def _str_tuple(value: object) -> tuple[str, ...]:
    if not isinstance(value, list):
        return ()
    return tuple(str(item) for item in value if isinstance(item, str) and item)


class DiscoveryClient:
    def __init__(
        self,
        config: IdentityClientConfig,
        *,
        http_client: httpx.AsyncClient | None = None,
    ) -> None:
        self._config = config
        self._http_client = http_client

    async def get_metadata(self) -> IssuerMetadata:
        metadata_url = f"{self._config.issuer_url.rstrip('/')}/.well-known/openid-configuration"
        if self._http_client is None:
            async with httpx.AsyncClient(timeout=self._config.timeout_seconds) as client:
                response = await client.get(metadata_url)
        else:
            response = await self._http_client.get(metadata_url)
        response.raise_for_status()
        payload = response.json()
        if not isinstance(payload, dict):
            raise ValueError("issuer metadata must be a JSON object")
        metadata = IssuerMetadata.from_mapping(payload)
        if metadata.issuer != self._config.issuer_url.rstrip("/"):
            raise ValueError("issuer metadata issuer mismatch")
        return metadata
