from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from chrysalis_identity_client.auth import IdentityAuthenticator
from chrysalis_identity_client.claims import IdentityClaims
from chrysalis_identity_client.config import IdentityClientConfig
from chrysalis_identity_client.introspection import IntrospectionClient
from chrysalis_identity_client.permissions import require_capability

BDMCP_AUDIENCE = "bdmcp"
BDMCP_SESSION_READ = "bdmcp:session_read"


@dataclass(frozen=True)
class BDMCPIdentityConfig:
    issuer_url: str = "http://localhost:61310"
    jwks_url: str | None = None
    audience: str = BDMCP_AUDIENCE
    timeout_seconds: float = 5.0
    require_introspection: bool = False
    introspection_endpoint: str | None = None
    introspection_client_id: str | None = None
    introspection_client_secret: str | None = field(default=None, repr=False)
    introspection_client_secret_file: str | None = None
    accepted_algorithms: tuple[str, ...] = ("RS256", "EdDSA")
    permission_freshness_ttl_seconds: int = 30

    def to_identity_config(self) -> IdentityClientConfig:
        return IdentityClientConfig(
            issuer_url=self.issuer_url,
            audience=self.audience,
            jwks_url=self.jwks_url,
            timeout_seconds=self.timeout_seconds,
            accepted_algorithms=self.accepted_algorithms,
            accepted_algorithms_explicit=True,
            require_introspection=self.require_introspection,
            permission_freshness_ttl_seconds=(
                self.permission_freshness_ttl_seconds if self.require_introspection else 0
            ),
        )

    @property
    def resolved_introspection_endpoint(self) -> str:
        if self.introspection_endpoint:
            return self.introspection_endpoint
        return f"{self.issuer_url.rstrip('/')}/api/v1/auth/introspect"

    def resolved_introspection_client_secret(self) -> str | None:
        if self.introspection_client_secret is not None:
            return self.introspection_client_secret
        if self.introspection_client_secret_file is None:
            return None
        value = Path(self.introspection_client_secret_file).read_text(encoding="utf-8").strip()
        if not value:
            raise ValueError("BDMCP introspection client secret file must not be empty")
        return value


def _bdmcp_introspection_client(
    config: BDMCPIdentityConfig,
    *,
    http_client: Any | None,
) -> IntrospectionClient | None:
    if not config.require_introspection:
        return None
    client_id = (config.introspection_client_id or "").strip()
    client_secret = config.resolved_introspection_client_secret()
    if not client_id or client_secret is None:
        raise ValueError("BDMCP introspection requires client_id and client_secret")
    return IntrospectionClient(
        endpoint=config.resolved_introspection_endpoint,
        client_id=client_id,
        client_secret=client_secret,
        timeout_seconds=config.timeout_seconds,
        http_client=http_client,
    )


def create_bdmcp_authenticator(
    config: BDMCPIdentityConfig,
    *,
    http_client: Any | None = None,
) -> IdentityAuthenticator:
    return IdentityAuthenticator(
        config.to_identity_config(),
        introspection_client=_bdmcp_introspection_client(config, http_client=http_client),
        http_client=http_client,
    )


def require_bdmcp_capability(claims: IdentityClaims, capability: str) -> IdentityClaims:
    if not capability.startswith("bdmcp:"):
        raise ValueError("BDMCP capabilities must be scoped with the bdmcp: prefix")
    return require_capability(claims, capability)
